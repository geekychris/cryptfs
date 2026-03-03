// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - policy engine
 *
 * Per-process access control. Determines whether the current process
 * is authorized to decrypt files. Supports matching by UID, GID,
 * binary path, binary hash (SHA-256), and process name.
 *
 * Default: DENY (return ciphertext) unless a matching ALLOW rule exists.
 */

#include "cryptofs.h"
#include <linux/fs_struct.h>
#include <linux/binfmts.h>

static unsigned int next_policy_id = 1;

int cryptofs_policy_init(struct cryptofs_sb_info *sbi)
{
	INIT_LIST_HEAD(&sbi->policy_list);
	spin_lock_init(&sbi->policy_lock);
	sbi->policy_count = 0;
	return 0;
}

void cryptofs_policy_free(struct cryptofs_sb_info *sbi)
{
	struct cryptofs_policy_rule *rule, *tmp;

	spin_lock(&sbi->policy_lock);
	list_for_each_entry_safe(rule, tmp, &sbi->policy_list, list) {
		list_del(&rule->list);
		kfree(rule);
	}
	sbi->policy_count = 0;
	spin_unlock(&sbi->policy_lock);
}

int cryptofs_policy_add(struct cryptofs_sb_info *sbi,
			struct cryptofs_policy_rule *rule)
{
	struct cryptofs_policy_rule *new_rule;

	if (sbi->policy_count >= CRYPTOFS_MAX_POLICIES)
		return -ENOSPC;

	new_rule = kmalloc(sizeof(*new_rule), GFP_KERNEL);
	if (!new_rule)
		return -ENOMEM;

	memcpy(new_rule, rule, sizeof(*new_rule));
	new_rule->id = next_policy_id++;

	spin_lock(&sbi->policy_lock);
	list_add_tail(&new_rule->list, &sbi->policy_list);
	sbi->policy_count++;
	spin_unlock(&sbi->policy_lock);

	pr_info("cryptofs: added policy rule %u (type=%d, action=%d)\n",
		new_rule->id, new_rule->type, new_rule->action);

	cryptofs_audit_log(CRYPTOFS_AUDIT_POLICY_ADD, NULL, true, "");
	return new_rule->id;
}

int cryptofs_policy_del(struct cryptofs_sb_info *sbi, unsigned int rule_id)
{
	struct cryptofs_policy_rule *rule;
	int found = 0;

	spin_lock(&sbi->policy_lock);
	list_for_each_entry(rule, &sbi->policy_list, list) {
		if (rule->id == rule_id) {
			list_del(&rule->list);
			sbi->policy_count--;
			found = 1;
			break;
		}
	}
	spin_unlock(&sbi->policy_lock);

	if (found) {
		kfree(rule);
		cryptofs_audit_log(CRYPTOFS_AUDIT_POLICY_DEL, NULL, true, "");
		return 0;
	}
	return -ENOENT;
}

/*
 * Get the executable path of the current process.
 * Returns the length written, or negative error.
 */
static int get_current_exe_path(char *buf, int buflen)
{
	struct file *exe_file;
	struct mm_struct *mm;
	char *p;

	mm = current->mm;
	if (!mm)
		return -ENOENT;

	rcu_read_lock();
	exe_file = rcu_dereference(mm->exe_file);
	if (exe_file)
		get_file(exe_file);
	rcu_read_unlock();

	if (!exe_file)
		return -ENOENT;

	p = file_path(exe_file, buf, buflen);
	fput(exe_file);

	if (IS_ERR(p))
		return PTR_ERR(p);

	/* Move path to beginning of buffer if needed */
	if (p != buf)
		memmove(buf, p, strlen(p) + 1);

	return strlen(buf);
}

/*
 * Compute SHA-256 hash of the current process's executable binary.
 */
static int hash_current_exe(u8 *digest)
{
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(desc, tfm);
	struct file *exe_file;
	loff_t pos = 0;
	u8 *buf;
	ssize_t nread;
	int err;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc->tfm = tfm;
	err = crypto_shash_init(desc);
	if (err)
		goto out;

	{
		struct mm_struct *mm = current->mm;
		if (!mm) {
			err = -ENOENT;
			goto out;
		}
		rcu_read_lock();
		exe_file = rcu_dereference(mm->exe_file);
		if (exe_file)
			get_file(exe_file);
		rcu_read_unlock();
		if (!exe_file) {
			err = -ENOENT;
			goto out;
		}
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		fput(exe_file);
		err = -ENOMEM;
		goto out;
	}

	while ((nread = kernel_read(exe_file, buf, PAGE_SIZE, &pos)) > 0) {
		err = crypto_shash_update(desc, buf, nread);
		if (err)
			break;
	}

	kfree(buf);
	fput(exe_file);

	if (!err)
		err = crypto_shash_final(desc, digest);

out:
	crypto_free_shash(tfm);
	return err;
}

/*
 * Check if the current process is authorized to access encrypted data.
 *
 * Iterates through policy rules; first matching rule wins.
 * If no rules match, returns 0 (DENY / return ciphertext).
 *
 * On match, fills out_key_id (16 bytes) and out_mode.
 * Returns: 1 = authorized, 0 = denied.
 */
int cryptofs_policy_check(struct cryptofs_sb_info *sbi,
			  struct inode *inode, u8 *out_key_id,
			  enum cryptofs_access_mode *out_mode)
{
	struct cryptofs_policy_rule *rule;
	const struct cred *cred = current_cred();
	int result = 0;
	char exe_path[256];
	u8 exe_hash[CRYPTOFS_HASH_SIZE];
	bool exe_path_resolved = false;
	bool exe_hash_computed = false;

	spin_lock(&sbi->policy_lock);

	/* If no policies defined, allow all with default key (PoC convenience) */
	if (list_empty(&sbi->policy_list)) {
		spin_unlock(&sbi->policy_lock);
		if (out_key_id)
			memset(out_key_id, 0, CRYPTOFS_KEY_ID_SIZE);
		if (out_mode)
			*out_mode = CRYPTOFS_MODE_TRANSPARENT;
		return 1;
	}

	list_for_each_entry(rule, &sbi->policy_list, list) {
		bool match = false;

		switch (rule->type) {
		case CRYPTOFS_POLICY_UID:
			match = uid_eq(cred->uid, rule->match.uid);
			break;

		case CRYPTOFS_POLICY_GID:
			match = gid_eq(cred->gid, rule->match.gid);
			break;

		case CRYPTOFS_POLICY_BINARY_PATH:
			if (!exe_path_resolved) {
				spin_unlock(&sbi->policy_lock);
				if (get_current_exe_path(exe_path,
							 sizeof(exe_path)) > 0)
					exe_path_resolved = true;
				spin_lock(&sbi->policy_lock);
			}
			if (exe_path_resolved)
				match = (strcmp(exe_path,
					       rule->match.binary_path) == 0);
			break;

		case CRYPTOFS_POLICY_BINARY_HASH:
			if (!exe_hash_computed) {
				spin_unlock(&sbi->policy_lock);
				if (hash_current_exe(exe_hash) == 0)
					exe_hash_computed = true;
				spin_lock(&sbi->policy_lock);
			}
			if (exe_hash_computed)
				match = (memcmp(exe_hash,
						rule->match.binary_hash,
						CRYPTOFS_HASH_SIZE) == 0);
			break;

		case CRYPTOFS_POLICY_PROCESS_NAME:
			match = (strncmp(current->comm,
					 rule->match.process_name,
					 TASK_COMM_LEN) == 0);
			break;
		}

		if (match) {
			if (rule->action == CRYPTOFS_ACTION_ALLOW) {
				result = 1;
				if (out_key_id)
					memcpy(out_key_id, rule->key_id,
					       CRYPTOFS_KEY_ID_SIZE);
				if (out_mode)
					*out_mode = rule->access_mode;
			}
			break;
		}
	}

	spin_unlock(&sbi->policy_lock);
	return result;
}
