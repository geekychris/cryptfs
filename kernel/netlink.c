// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - generic netlink interface
 *
 * Provides a userspace interface for managing policies, loading keys,
 * and querying status via generic netlink.
 */

#include "cryptofs.h"
#include <net/genetlink.h>

/* Forward declaration */
static struct genl_family cryptofs_genl_family;

/* Netlink policy for attribute validation */
static const struct nla_policy cryptofs_nl_policy[CRYPTOFS_ATTR_MAX + 1] = {
	[CRYPTOFS_ATTR_POLICY_ID]	= { .type = NLA_U32 },
	[CRYPTOFS_ATTR_POLICY_TYPE]	= { .type = NLA_U32 },
	[CRYPTOFS_ATTR_POLICY_ACTION]	= { .type = NLA_U32 },
	[CRYPTOFS_ATTR_POLICY_VALUE]	= { .type = NLA_STRING,
					    .len = CRYPTOFS_MAX_PATH_LEN },
	[CRYPTOFS_ATTR_MASTER_KEY]	= { .type = NLA_BINARY,
					    .len = CRYPTOFS_KEY_SIZE },
	[CRYPTOFS_ATTR_MOUNT_PATH]	= { .type = NLA_STRING, .len = PATH_MAX },
	[CRYPTOFS_ATTR_STATUS]		= { .type = NLA_STRING, .len = 4096 },
};

/* Helper: get the active SBI (requires active mount) */
static struct cryptofs_sb_info *get_active_sbi(void)
{
	struct cryptofs_sb_info *sbi = NULL;

	mutex_lock(&cryptofs_active_sb_mutex);
	if (cryptofs_active_sb)
		sbi = CRYPTOFS_SB(cryptofs_active_sb);
	mutex_unlock(&cryptofs_active_sb_mutex);

	return sbi;
}

/* CMD: Add a policy rule */
static int cryptofs_nl_add_policy(struct sk_buff *skb, struct genl_info *info)
{
	struct cryptofs_sb_info *sbi;
	struct cryptofs_policy_rule *rule;
	u32 type, action;
	const char *value;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	sbi = get_active_sbi();
	if (!sbi)
		return -ENODEV;

	if (!info->attrs[CRYPTOFS_ATTR_POLICY_TYPE] ||
	    !info->attrs[CRYPTOFS_ATTR_POLICY_ACTION] ||
	    !info->attrs[CRYPTOFS_ATTR_POLICY_VALUE])
		return -EINVAL;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return -ENOMEM;

	type = nla_get_u32(info->attrs[CRYPTOFS_ATTR_POLICY_TYPE]);
	action = nla_get_u32(info->attrs[CRYPTOFS_ATTR_POLICY_ACTION]);
	value = nla_data(info->attrs[CRYPTOFS_ATTR_POLICY_VALUE]);

	rule->type = type;
	rule->action = action;

	switch (type) {
	case CRYPTOFS_POLICY_UID:
		rule->match.uid = make_kuid(current_user_ns(),
					    simple_strtoul(value, NULL, 10));
		break;
	case CRYPTOFS_POLICY_GID:
		rule->match.gid = make_kgid(current_user_ns(),
					    simple_strtoul(value, NULL, 10));
		break;
	case CRYPTOFS_POLICY_BINARY_PATH:
		strscpy(rule->match.binary_path, value,
			sizeof(rule->match.binary_path));
		break;
	case CRYPTOFS_POLICY_BINARY_HASH:
		if (nla_len(info->attrs[CRYPTOFS_ATTR_POLICY_VALUE]) <
		    CRYPTOFS_HASH_SIZE) {
			kfree(rule);
			return -EINVAL;
		}
		memcpy(rule->match.binary_hash, value, CRYPTOFS_HASH_SIZE);
		break;
	case CRYPTOFS_POLICY_PROCESS_NAME:
		strscpy(rule->match.process_name, value,
			sizeof(rule->match.process_name));
		break;
	default:
		kfree(rule);
		return -EINVAL;
	}

	ret = cryptofs_policy_add(sbi, rule);
	kfree(rule);
	return (ret > 0) ? 0 : ret;
}

/* CMD: Delete a policy rule */
static int cryptofs_nl_del_policy(struct sk_buff *skb, struct genl_info *info)
{
	struct cryptofs_sb_info *sbi;
	u32 rule_id;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	sbi = get_active_sbi();
	if (!sbi)
		return -ENODEV;

	if (!info->attrs[CRYPTOFS_ATTR_POLICY_ID])
		return -EINVAL;

	rule_id = nla_get_u32(info->attrs[CRYPTOFS_ATTR_POLICY_ID]);
	return cryptofs_policy_del(sbi, rule_id);
}

/* CMD: Set master key */
static int cryptofs_nl_set_key(struct sk_buff *skb, struct genl_info *info)
{
	struct cryptofs_sb_info *sbi;
	const void *key_data;
	int key_len;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	sbi = get_active_sbi();
	if (!sbi)
		return -ENODEV;

	if (!info->attrs[CRYPTOFS_ATTR_MASTER_KEY])
		return -EINVAL;

	key_data = nla_data(info->attrs[CRYPTOFS_ATTR_MASTER_KEY]);
	key_len = nla_len(info->attrs[CRYPTOFS_ATTR_MASTER_KEY]);

	if (key_len != CRYPTOFS_KEY_SIZE)
		return -EINVAL;

	memcpy(sbi->master_key, key_data, CRYPTOFS_KEY_SIZE);
	sbi->master_key_loaded = true;

	pr_info("cryptofs: master key loaded (%d bytes)\n", key_len);
	cryptofs_audit_log(CRYPTOFS_AUDIT_KEY_LOAD, NULL, true, "");

	return 0;
}

/* CMD: Get status */
static int cryptofs_nl_get_status(struct sk_buff *skb, struct genl_info *info)
{
	struct cryptofs_sb_info *sbi;
	struct sk_buff *msg;
	void *hdr;
	char status[512];

	sbi = get_active_sbi();

	snprintf(status, sizeof(status),
		 "{\"mounted\":%s,\"master_key_loaded\":%s,\"policy_count\":%d}",
		 sbi ? "true" : "false",
		 (sbi && sbi->master_key_loaded) ? "true" : "false",
		 sbi ? sbi->policy_count : 0);

	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &cryptofs_genl_family, 0, CRYPTOFS_CMD_GET_STATUS);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	nla_put_string(msg, CRYPTOFS_ATTR_STATUS, status);
	genlmsg_end(msg, hdr);

	return genlmsg_reply(msg, info);
}

/* Generic netlink operations */
static const struct genl_small_ops cryptofs_nl_ops[] = {
	{
		.cmd	= CRYPTOFS_CMD_ADD_POLICY,
		.doit	= cryptofs_nl_add_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= CRYPTOFS_CMD_DEL_POLICY,
		.doit	= cryptofs_nl_del_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= CRYPTOFS_CMD_SET_KEY,
		.doit	= cryptofs_nl_set_key,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= CRYPTOFS_CMD_GET_STATUS,
		.doit	= cryptofs_nl_get_status,
	},
};

/* Generic netlink family */
static struct genl_family cryptofs_genl_family = {
	.name		= CRYPTOFS_GENL_NAME,
	.version	= CRYPTOFS_GENL_VERSION,
	.maxattr	= CRYPTOFS_ATTR_MAX,
	.policy		= cryptofs_nl_policy,
	.small_ops	= cryptofs_nl_ops,
	.n_small_ops	= ARRAY_SIZE(cryptofs_nl_ops),
	.module		= THIS_MODULE,
};

int cryptofs_netlink_init(void)
{
	return genl_register_family(&cryptofs_genl_family);
}

void cryptofs_netlink_exit(void)
{
	genl_unregister_family(&cryptofs_genl_family);
}
