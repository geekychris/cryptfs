// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - dentry operations
 */

#include "cryptofs.h"

/*
 * Revalidate a cached dentry by checking the lower dentry.
 */
static int cryptofs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct path lower_path;
	struct dentry *lower_dentry;
	struct cryptofs_dentry_info *info;
	int err = 1; /* valid by default */

	/*
	 * In RCU-walk mode we cannot take the per-dentry spinlock,
	 * so just return 1 (valid).  The lower fs (typically tmpfs)
	 * does not need revalidation, and returning -ECHILD here
	 * can cause an infinite RCU-to-ref retry loop in
	 * path_lookupat when many cryptofs dentries are cached.
	 */
	if (flags & LOOKUP_RCU)
		return 1;

	info = CRYPTOFS_D(dentry);
	if (!info)
		return 0; /* invalid: no private data */

	cryptofs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	/* If the lower dentry was unhashed (removed), invalidate ours */
	if (!lower_dentry || d_unhashed(lower_dentry)) {
		err = 0;
		goto out;
	}

	/* Check positive/negative match: both must agree */
	if (d_inode(dentry) && !d_inode(lower_dentry)) {
		err = 0;
		goto out;
	}
	if (!d_inode(dentry) && d_inode(lower_dentry)) {
		err = 0;
		goto out;
	}

	/* Delegate to lower dentry's revalidate if it has one */
	if (lower_dentry->d_flags & DCACHE_OP_REVALIDATE)
		err = lower_dentry->d_op->d_revalidate(lower_dentry, flags);

out:
	cryptofs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * Release a dentry: free our private data and drop the lower path.
 */
static void cryptofs_d_release(struct dentry *dentry)
{
	struct cryptofs_dentry_info *info = CRYPTOFS_D(dentry);

	if (info) {
		/* Drop reference to lower path */
		path_put(&info->lower_path);
		kfree(info);
		dentry->d_fsdata = NULL;
	}
}

const struct dentry_operations cryptofs_dops = {
	.d_revalidate	= cryptofs_d_revalidate,
	.d_release	= cryptofs_d_release,
};

/* Dentry info cache (optional: for high-performance allocation) */
int cryptofs_init_dentry_cache(void)
{
	/* Using kmalloc directly for now; can switch to kmem_cache if needed */
	return 0;
}

void cryptofs_destroy_dentry_cache(void)
{
	/* Nothing to destroy when using kmalloc */
}
