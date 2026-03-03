// SPDX-License-Identifier: GPL-2.0
/*
 * add_policy - add a CryptoFS access policy via generic netlink.
 *
 * Usage:
 *   add_policy --type <0-4> --value <string> --perm <0|1>
 *              [--key-id <32-hex-chars>] [--access-mode <0|1>]
 *
 * Policy types:
 *   0 = uid          Match by user ID
 *   1 = gid          Match by group ID
 *   2 = binary-path  Match by executable path
 *   3 = binary-hash  Match by SHA-256 of executable (hex)
 *   4 = process-name Match by task comm
 *
 * Permission:
 *   0 = deny
 *   1 = allow
 *
 * Access mode (optional):
 *   0 = transparent (default) — key from kernel key table
 *   1 = guarded               — key from process session keyring
 *
 * Key ID (optional):
 *   32 hex characters (16 bytes). Default: all zeros.
 *
 * Build: gcc -o add_policy add_policy.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <linux/genetlink.h>
#include <sys/socket.h>

/* ---- nlmsg helpers (same pattern as set_key.c) ---- */

#define NLMSG_ALIGN(len)  (((len)+3) & ~3)
#define NLA_ALIGN(len)    (((len)+3) & ~3)
#define NLA_HDRLEN        (NLA_ALIGN(sizeof(struct nlattr)))
#define GENL_HDRLEN       NLMSG_ALIGN(sizeof(struct genlmsghdr))

/* Must match kernel/cryptofs.h */
#define CRYPTOFS_GENL_NAME        "cryptofs"
#define CRYPTOFS_GENL_VERSION     1

#define CRYPTOFS_CMD_ADD_POLICY   1
#define CRYPTOFS_CMD_DEL_POLICY   2

#define CRYPTOFS_ATTR_POLICY_ID     1   /* u32 */
#define CRYPTOFS_ATTR_POLICY_TYPE   2   /* u32 */
#define CRYPTOFS_ATTR_POLICY_ACTION 3   /* u32 */
#define CRYPTOFS_ATTR_POLICY_VALUE  4   /* string / binary */
#define CRYPTOFS_ATTR_KEY_ID        6   /* binary 16 bytes */
#define CRYPTOFS_ATTR_ACCESS_MODE   7   /* u32 */

#define CRYPTOFS_KEY_ID_SIZE 16

static uint16_t genl_family_id;
static uint32_t genl_seq;

static int nl_open(void)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	struct timeval tv = { .tv_sec = 3 };
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) { perror("socket"); return -1; }
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind"); close(fd); return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int resolve_family(int fd)
{
	char buf[4096];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct nlattr *nla;
	int len, attrlen;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++genl_seq;

	genl = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genl->cmd = CTRL_CMD_GETFAMILY;
	genl->version = 1;

	nla = (struct nlattr *)((char *)genl + GENL_HDRLEN);
	nla->nla_type = CTRL_ATTR_FAMILY_NAME;
	nla->nla_len = NLA_HDRLEN + strlen(CRYPTOFS_GENL_NAME) + 1;
	memcpy((char *)nla + NLA_HDRLEN, CRYPTOFS_GENL_NAME,
	       strlen(CRYPTOFS_GENL_NAME) + 1);
	nlh->nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(fd, buf, nlh->nlmsg_len, 0) < 0) {
		perror("send(ctrl)"); return -1;
	}

	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) { perror("recv(ctrl)"); return -1; }

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nlh);
		fprintf(stderr, "GETFAMILY error: %d\n", err->error);
		return -1;
	}

	genl = NLMSG_DATA(nlh);
	nla = (struct nlattr *)((char *)genl + GENL_HDRLEN);
	attrlen = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

	while (attrlen >= (int)NLA_HDRLEN) {
		if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
			genl_family_id = *(uint16_t *)((char *)nla + NLA_HDRLEN);
			return 0;
		}
		int step = NLA_ALIGN(nla->nla_len);
		nla = (struct nlattr *)((char *)nla + step);
		attrlen -= step;
	}
	fprintf(stderr, "Could not resolve family ID\n");
	return -1;
}

/* Append a u32 NLA attribute */
static struct nlattr *nla_put_u32(char *pos, uint16_t type, uint32_t val)
{
	struct nlattr *nla = (struct nlattr *)pos;
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + sizeof(uint32_t);
	*(uint32_t *)((char *)nla + NLA_HDRLEN) = val;
	return (struct nlattr *)(pos + NLA_ALIGN(nla->nla_len));
}

/* Append a binary/string NLA attribute */
static struct nlattr *nla_put_data(char *pos, uint16_t type,
				   const void *data, int len)
{
	struct nlattr *nla = (struct nlattr *)pos;
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	return (struct nlattr *)(pos + NLA_ALIGN(nla->nla_len));
}

static int hex_to_bytes(const char *hex, uint8_t *out, int max)
{
	int len = strlen(hex);
	if (len % 2 != 0 || len / 2 > max) return -1;
	for (int i = 0; i < len / 2; i++) {
		unsigned int v;
		if (sscanf(hex + 2*i, "%2x", &v) != 1) return -1;
		out[i] = (uint8_t)v;
	}
	return len / 2;
}

static int send_del_policy(int fd, uint32_t rule_id)
{
	char buf[4096];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	char *pos;
	int len;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = genl_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++genl_seq;

	genl = NLMSG_DATA(nlh);
	genl->cmd = CRYPTOFS_CMD_DEL_POLICY;
	genl->version = CRYPTOFS_GENL_VERSION;

	pos = (char *)genl + GENL_HDRLEN;
	pos = (char *)nla_put_u32(pos, CRYPTOFS_ATTR_POLICY_ID, rule_id);
	nlh->nlmsg_len = (pos - buf);

	if (send(fd, buf, nlh->nlmsg_len, 0) < 0) {
		perror("send(del_policy)"); return -1;
	}

	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) { perror("recv(del_policy)"); return -1; }

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nlh);
		if (err->error != 0) {
			fprintf(stderr, "DEL_POLICY error: %d (%s)\n",
				err->error, strerror(-err->error));
			return err->error;
		}
	}
	return 0;
}

static int send_add_policy(int fd, uint32_t type, uint32_t action,
			   const char *value, const uint8_t *key_id,
			   int has_access_mode, uint32_t access_mode)
{
	char buf[4096];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	char *pos;
	int len;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = genl_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++genl_seq;

	genl = NLMSG_DATA(nlh);
	genl->cmd = CRYPTOFS_CMD_ADD_POLICY;
	genl->version = CRYPTOFS_GENL_VERSION;

	pos = (char *)genl + GENL_HDRLEN;

	/* Required: POLICY_TYPE, POLICY_ACTION, POLICY_VALUE */
	pos = (char *)nla_put_u32(pos, CRYPTOFS_ATTR_POLICY_TYPE, type);
	pos = (char *)nla_put_u32(pos, CRYPTOFS_ATTR_POLICY_ACTION, action);
	pos = (char *)nla_put_data(pos, CRYPTOFS_ATTR_POLICY_VALUE,
				   value, strlen(value) + 1);

	/* Optional: KEY_ID */
	if (key_id)
		pos = (char *)nla_put_data(pos, CRYPTOFS_ATTR_KEY_ID,
					   key_id, CRYPTOFS_KEY_ID_SIZE);

	/* Optional: ACCESS_MODE */
	if (has_access_mode)
		pos = (char *)nla_put_u32(pos, CRYPTOFS_ATTR_ACCESS_MODE,
					  access_mode);

	nlh->nlmsg_len = (pos - buf);

	if (send(fd, buf, nlh->nlmsg_len, 0) < 0) {
		perror("send(add_policy)"); return -1;
	}

	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) { perror("recv(add_policy)"); return -1; }

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nlh);
		if (err->error != 0) {
			fprintf(stderr, "ADD_POLICY error: %d (%s)\n",
				err->error, strerror(-err->error));
			return err->error;
		}
	}
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --type <0-4> --value <str> --perm <0|1>\n"
		"          [--key-id <32-hex-chars>] [--access-mode <0|1>]\n"
		"       %s --delete <rule-id>\n"
		"\n"
		"Types: 0=uid, 1=gid, 2=binary-path, 3=binary-hash, 4=process-name\n"
		"Perm:  0=deny, 1=allow\n"
		"Mode:  0=transparent (default), 1=guarded\n",
		prog, prog);
}

int main(int argc, char **argv)
{
	int fd;
	uint32_t type = UINT32_MAX;
	uint32_t perm = UINT32_MAX;
	const char *value = NULL;
	uint8_t key_id[CRYPTOFS_KEY_ID_SIZE];
	int has_key_id = 0;
	uint32_t access_mode = 0;
	int has_access_mode = 0;
	uint32_t delete_id = 0;
	int do_delete = 0;

	static struct option long_opts[] = {
		{ "type",        required_argument, NULL, 't' },
		{ "value",       required_argument, NULL, 'v' },
		{ "perm",        required_argument, NULL, 'p' },
		{ "key-id",      required_argument, NULL, 'k' },
		{ "access-mode", required_argument, NULL, 'm' },
		{ "delete",      required_argument, NULL, 'd' },
		{ "help",        no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "t:v:p:k:m:d:h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 't': type = atoi(optarg); break;
		case 'v': value = optarg; break;
		case 'p': perm = atoi(optarg); break;
		case 'd': delete_id = atoi(optarg); do_delete = 1; break;
		case 'k':
			if (hex_to_bytes(optarg, key_id, CRYPTOFS_KEY_ID_SIZE)
			    != CRYPTOFS_KEY_ID_SIZE) {
				fprintf(stderr, "Bad key-id (need %d hex chars)\n",
					CRYPTOFS_KEY_ID_SIZE * 2);
				return 1;
			}
			has_key_id = 1;
			break;
		case 'm':
			access_mode = atoi(optarg);
			has_access_mode = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	fd = nl_open();
	if (fd < 0) return 1;

	if (resolve_family(fd) < 0) {
		close(fd); return 1;
	}

	if (do_delete) {
		if (send_del_policy(fd, delete_id) < 0) {
			close(fd); return 1;
		}
		printf("Policy %u deleted\n", delete_id);
		close(fd);
		return 0;
	}

	if (type == UINT32_MAX || perm == UINT32_MAX || !value) {
		fprintf(stderr, "Error: --type, --value, and --perm are required\n");
		usage(argv[0]);
		return 1;
	}

	if (send_add_policy(fd, type, perm, value,
			    has_key_id ? key_id : NULL,
			    has_access_mode, access_mode) < 0) {
		close(fd); return 1;
	}

	printf("Policy added: type=%u value=%s perm=%s",
	       type, value, perm ? "allow" : "deny");
	if (has_key_id) {
		printf(" key_id=");
		for (int i = 0; i < CRYPTOFS_KEY_ID_SIZE; i++)
			printf("%02x", key_id[i]);
	}
	if (has_access_mode)
		printf(" mode=%s", access_mode ? "guarded" : "transparent");
	printf("\n");

	close(fd);
	return 0;
}
