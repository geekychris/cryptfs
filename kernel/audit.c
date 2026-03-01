// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - audit logging
 *
 * Maintains a ring buffer of recent access events for security
 * monitoring. Events include reads, writes, access denials,
 * key loads, and policy changes.
 */

#include "cryptofs.h"

static struct cryptofs_audit_entry *audit_ring;
static unsigned int audit_head;
static unsigned int audit_count;
static DEFINE_SPINLOCK(audit_lock);

int cryptofs_audit_init(void)
{
	audit_ring = kvcalloc(CRYPTOFS_AUDIT_RING_SIZE,
			      sizeof(struct cryptofs_audit_entry),
			      GFP_KERNEL);
	if (!audit_ring)
		return -ENOMEM;

	audit_head = 0;
	audit_count = 0;
	return 0;
}

void cryptofs_audit_exit(void)
{
	kvfree(audit_ring);
	audit_ring = NULL;
}

static const char *audit_op_str(enum cryptofs_audit_op op)
{
	switch (op) {
	case CRYPTOFS_AUDIT_READ:	return "READ";
	case CRYPTOFS_AUDIT_WRITE:	return "WRITE";
	case CRYPTOFS_AUDIT_OPEN:	return "OPEN";
	case CRYPTOFS_AUDIT_CREATE:	return "CREATE";
	case CRYPTOFS_AUDIT_DENIED:	return "DENIED";
	case CRYPTOFS_AUDIT_KEY_LOAD:	return "KEY_LOAD";
	case CRYPTOFS_AUDIT_POLICY_ADD:	return "POLICY_ADD";
	case CRYPTOFS_AUDIT_POLICY_DEL:	return "POLICY_DEL";
	default:			return "UNKNOWN";
	}
}

void cryptofs_audit_log(enum cryptofs_audit_op op, struct inode *inode,
			bool authorized, const char *filename)
{
	struct cryptofs_audit_entry *entry;
	unsigned long flags;

	if (!audit_ring)
		return;

	spin_lock_irqsave(&audit_lock, flags);

	entry = &audit_ring[audit_head % CRYPTOFS_AUDIT_RING_SIZE];
	entry->timestamp = ktime_get_real();
	entry->pid = current->pid;
	entry->uid = current_uid();
	entry->op = op;
	entry->authorized = authorized;

	if (filename)
		strscpy(entry->filename, filename, sizeof(entry->filename));
	else
		entry->filename[0] = '\0';

	get_task_comm(entry->comm, current);

	audit_head++;
	if (audit_count < CRYPTOFS_AUDIT_RING_SIZE)
		audit_count++;

	spin_unlock_irqrestore(&audit_lock, flags);

	/* Also log to kernel log for debugging */
	if (!authorized || op == CRYPTOFS_AUDIT_DENIED) {
		pr_notice("cryptofs: AUDIT %s pid=%d uid=%u comm=%s file=%s authorized=%s\n",
			  audit_op_str(op), current->pid,
			  from_kuid(&init_user_ns, current_uid()),
			  current->comm,
			  filename ? filename : "(none)",
			  authorized ? "yes" : "NO");
	}
}
