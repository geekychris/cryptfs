// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - lookup and interpose operations
 *
 * Handles the dentry lookup path: when the VFS asks to resolve a name
 * in a directory, we look it up in the lower filesystem and create
 * a corresponding cryptofs inode/dentry pair.
 */

#include "cryptofs.h"

/*
 * Interpose: connect an upper dentry with a lower path.
 * Creates a cryptofs inode that wraps the lower inode.
 */
int cryptofs_interpose(struct dentry *dentry, struct super_block *sb,
		       struct path *lower_path)
{
	struct inode *inode;
	struct inode *lower_inode;
	int err = 0;

	lower_inode = d_inode(lower_path->dentry);

	/* Get or create a cryptofs inode for this lower inode */
	inode = cryptofs_iget(sb, lower_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	d_instantiate(dentry, inode);

out:
	return err;
}

/*
 * Lookup: resolve a name in a directory.
 * Look up the name in the lower directory and interpose.
 */
struct dentry *cryptofs_lookup(struct inode *dir, struct dentry *dentry,
			       unsigned int flags)
{
	struct dentry *ret, *parent;
	struct path lower_parent_path, lower_path;
	struct dentry *lower_dir_dentry;
	struct dentry *lower_dentry;
	struct cryptofs_dentry_info *info;
	const char *name;
	int err = 0;

	parent = dget_parent(dentry);

	/* Get the lower directory path */
	cryptofs_get_lower_path(parent, &lower_parent_path);
	lower_dir_dentry = lower_parent_path.dentry;

	/* Perform the actual lookup in the lower filesystem */
	name = dentry->d_name.name;
	lower_dentry = lookup_one_len_unlocked(name, lower_dir_dentry,
					       dentry->d_name.len);
	if (IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		goto out_put_parent;
	}

	/* Allocate and initialize dentry private data */
	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		err = -ENOMEM;
		goto out_dput;
	}

	spin_lock_init(&info->lock);
	lower_path.dentry = lower_dentry;
	lower_path.mnt = mntget(lower_parent_path.mnt);
	info->lower_path = lower_path;
	dentry->d_fsdata = info;

	/*
	 * If the lower dentry has an inode, create a cryptofs inode and
	 * attach it.  We must use d_add() here — NOT d_instantiate() —
	 * because the VFS passes us an "in-lookup" dentry whose d_u union
	 * is occupied by d_in_lookup_hash.  d_instantiate() would trigger
	 * BUG_ON(!hlist_unhashed(&entry->d_u.d_alias)).
	 *
	 * d_add() calls __d_add() which properly calls __d_lookup_unhash()
	 * for in-lookup dentries before setting up the alias.
	 *
	 * If it's a negative dentry (doesn't exist), we still set up
	 * the dentry info so that create operations work later.
	 */
	if (d_inode(lower_dentry)) {
		struct inode *inode;

		inode = cryptofs_iget(dir->i_sb, d_inode(lower_dentry));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			kfree(info);
			dentry->d_fsdata = NULL;
			goto out_mntput;
		}
		d_add(dentry, inode);
	} else {
		/* Negative dentry: file doesn't exist yet */
		d_add(dentry, NULL);
	}

	ret = NULL; /* success: return NULL to indicate dentry is set up */
	goto out_put_parent;

out_mntput:
	mntput(lower_path.mnt);
out_dput:
	dput(lower_dentry);
out_put_parent:
	cryptofs_put_lower_path(parent, &lower_parent_path);
	dput(parent);

	if (err)
		return ERR_PTR(err);
	return ret;
}

/*
 * iget5 callbacks: match by lower inode pointer.
 */
static int cryptofs_inode_test(struct inode *inode, void *data)
{
	struct inode *lower_inode = data;
	return CRYPTOFS_I(inode)->lower_inode == lower_inode;
}

static int cryptofs_inode_set(struct inode *inode, void *data)
{
	struct inode *lower_inode = data;
	CRYPTOFS_I(inode)->lower_inode = igrab(lower_inode);
	if (!CRYPTOFS_I(inode)->lower_inode)
		return -ESTALE;
	inode->i_ino = lower_inode->i_ino;
	return 0;
}

/*
 * Get or create a cryptofs inode for a given lower inode.
 * Uses the inode hash to avoid creating duplicates.
 */
struct inode *cryptofs_iget(struct super_block *sb, struct inode *lower_inode)
{
	struct cryptofs_inode_info *info;
	struct inode *inode;
	int err;

	/* Try to find an existing inode first */
	inode = iget5_locked(sb, (unsigned long)lower_inode->i_ino,
			     cryptofs_inode_test, cryptofs_inode_set,
			     lower_inode);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode->i_state & I_NEW))
		return inode;

	/* New inode: set it up (lower_inode and i_ino set by cryptofs_inode_set) */
	info = CRYPTOFS_I(inode);
	if (!info->lower_inode) {
		err = -ESTALE;
		goto out_bad;
	}

	/* Copy attributes from lower inode */
	cryptofs_copy_inode_attr(inode, lower_inode);

	/*
	 * Set file size.  For regular files the logical (plaintext) size
	 * is stored in the on-disk header and will be loaded during
	 * cryptofs_open().  Use 0 here so that reads before the header
	 * is parsed return nothing rather than raw ciphertext.
	 */
	if (S_ISREG(lower_inode->i_mode))
		inode->i_size = 0;
	else
		inode->i_size = lower_inode->i_size;

	/* Set operations based on inode type */
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &cryptofs_main_iops;
		inode->i_fop = &cryptofs_main_fops;
		/* No a_ops: all I/O goes through read_iter/write_iter.
		 * Page-cache writeback is not supported because we lack
		 * a lower file handle in the writeback context. */
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &cryptofs_dir_iops;
		inode->i_fop = &cryptofs_dir_fops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &cryptofs_symlink_iops;
	} else {
		inode->i_op = &cryptofs_main_iops;
		init_special_inode(inode, inode->i_mode,
				   lower_inode->i_rdev);
	}

	unlock_new_inode(inode);
	return inode;

out_bad:
	iget_failed(inode);
	return ERR_PTR(err);
}

/*
 * Copy relevant attributes from a lower inode to our inode.
 */
void cryptofs_copy_inode_attr(struct inode *dest, const struct inode *src)
{
	dest->i_mode = src->i_mode;
	dest->i_uid = src->i_uid;
	dest->i_gid = src->i_gid;
	inode_set_atime_to_ts(dest, inode_get_atime(src));
	inode_set_mtime_to_ts(dest, inode_get_mtime(src));
	inode_set_ctime_to_ts(dest, inode_get_ctime(src));
	dest->i_blkbits = src->i_blkbits;
	dest->i_flags = src->i_flags;
	set_nlink(dest, src->i_nlink);
}
