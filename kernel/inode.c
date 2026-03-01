// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - inode operations
 *
 * Handles create, mkdir, unlink, rename, and other inode-level operations
 * by delegating to the lower filesystem.
 */

#include <linux/fs_stack.h>
#include "cryptofs.h"

/*
 * Helper: create a lower file/dir and interpose.
 */
static int cryptofs_create(struct mnt_idmap *idmap,
			   struct inode *dir, struct dentry *dentry,
			   umode_t mode, bool excl)
{
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry;
	struct path lower_path, lower_parent_path;
	int err;

	cryptofs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	cryptofs_get_lower_path(dentry->d_parent, &lower_parent_path);
	lower_parent_dentry = lower_parent_path.dentry;

	err = vfs_create(idmap, d_inode(lower_parent_dentry),
			 lower_dentry, mode, excl);
	if (err)
		goto out;

	err = cryptofs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	/* Update parent directory timestamps */
	fsstack_copy_attr_times(dir, d_inode(lower_parent_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

	cryptofs_audit_log(CRYPTOFS_AUDIT_CREATE, d_inode(dentry), true,
			   dentry->d_name.name);

out:
	cryptofs_put_lower_path(dentry->d_parent, &lower_parent_path);
	cryptofs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * mkdir: create a directory in the lower filesystem.
 */
static int cryptofs_mkdir(struct mnt_idmap *idmap,
			  struct inode *dir, struct dentry *dentry,
			  umode_t mode)
{
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry;
	struct path lower_path, lower_parent_path;
	int err;

	cryptofs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	cryptofs_get_lower_path(dentry->d_parent, &lower_parent_path);
	lower_parent_dentry = lower_parent_path.dentry;

	err = vfs_mkdir(idmap, d_inode(lower_parent_dentry),
			lower_dentry, mode);
	if (err)
		goto out;

	err = cryptofs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, d_inode(lower_parent_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	set_nlink(dir, d_inode(lower_parent_dentry)->i_nlink);

out:
	cryptofs_put_lower_path(dentry->d_parent, &lower_parent_path);
	cryptofs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * rmdir: remove a directory.
 */
static int cryptofs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct path lower_path, lower_dir_path;
	int err;

	cryptofs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	cryptofs_get_lower_path(dentry->d_parent, &lower_dir_path);
	lower_dir_dentry = lower_dir_path.dentry;

	err = vfs_rmdir(&nop_mnt_idmap, d_inode(lower_dir_dentry), lower_dentry);
	if (!err) {
		d_drop(dentry);
		fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
		fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
		set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);
	}

	cryptofs_put_lower_path(dentry->d_parent, &lower_dir_path);
	cryptofs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * unlink: delete a file.
 */
static int cryptofs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct path lower_path, lower_dir_path;
	int err;

	cryptofs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	cryptofs_get_lower_path(dentry->d_parent, &lower_dir_path);
	lower_dir_dentry = lower_dir_path.dentry;

	err = vfs_unlink(&nop_mnt_idmap, d_inode(lower_dir_dentry), lower_dentry, NULL);
	if (!err) {
		d_drop(dentry);
		fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
		fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	}

	cryptofs_put_lower_path(dentry->d_parent, &lower_dir_path);
	cryptofs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * rename: rename a file or directory.
 */
static int cryptofs_rename(struct mnt_idmap *idmap,
			   struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry,
			   unsigned int flags)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_old_dir_dentry;
	struct dentry *lower_new_dir_dentry;
	struct path lower_old_path, lower_new_path;
	struct path lower_old_dir_path, lower_new_dir_path;
	struct renamedata rd;
	int err;

	if (flags)
		return -EINVAL;

	cryptofs_get_lower_path(old_dentry, &lower_old_path);
	lower_old_dentry = lower_old_path.dentry;
	cryptofs_get_lower_path(new_dentry, &lower_new_path);
	lower_new_dentry = lower_new_path.dentry;

	cryptofs_get_lower_path(old_dentry->d_parent, &lower_old_dir_path);
	lower_old_dir_dentry = lower_old_dir_path.dentry;
	cryptofs_get_lower_path(new_dentry->d_parent, &lower_new_dir_path);
	lower_new_dir_dentry = lower_new_dir_path.dentry;

	rd.old_mnt_idmap = idmap;
	rd.old_dir = d_inode(lower_old_dir_dentry);
	rd.old_dentry = lower_old_dentry;
	rd.new_mnt_idmap = idmap;
	rd.new_dir = d_inode(lower_new_dir_dentry);
	rd.new_dentry = lower_new_dentry;
	rd.delegated_inode = NULL;
	rd.flags = flags;

	err = vfs_rename(&rd);
	if (!err) {
		fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
		fsstack_copy_attr_all(old_dir, d_inode(lower_old_dir_dentry));
	}

	cryptofs_put_lower_path(new_dentry->d_parent, &lower_new_dir_path);
	cryptofs_put_lower_path(old_dentry->d_parent, &lower_old_dir_path);
	cryptofs_put_lower_path(new_dentry, &lower_new_path);
	cryptofs_put_lower_path(old_dentry, &lower_old_path);
	return err;
}

/*
 * getattr: get file attributes, reporting the logical (plaintext) size.
 *
 * We use generic_fillattr on our own inode rather than calling vfs_getattr
 * on the lower path.  This avoids a second LSM (AppArmor) permission check
 * on the lower path, which would fail because the process opened the file
 * through the cryptofs mount, not the lower mount.
 */
static int cryptofs_getattr(struct mnt_idmap *idmap,
			    const struct path *path, struct kstat *stat,
			    u32 request_mask, unsigned int query_flags)
{
	struct dentry *dentry = path->dentry;
	struct inode *inode = d_inode(dentry);
	struct inode *lower_inode;
	struct path lower_path;

	cryptofs_get_lower_path(dentry, &lower_path);
	lower_inode = d_inode(lower_path.dentry);

	/* Sync attributes from the lower inode (times, mode, uid, gid, etc.) */
	cryptofs_copy_inode_attr(inode, lower_inode);
	inode->i_blocks = lower_inode->i_blocks;

	/* Fill stat from our inode */
	generic_fillattr(idmap, request_mask, inode, stat);

	/* Override size with the logical (plaintext) file size */
	if (S_ISREG(inode->i_mode))
		stat->size = i_size_read(inode);

	cryptofs_put_lower_path(dentry, &lower_path);
	return 0;
}

/*
 * setattr: set file attributes (chmod, chown, truncate, etc.)
 */
static int cryptofs_setattr(struct mnt_idmap *idmap,
			    struct dentry *dentry, struct iattr *ia)
{
	struct inode *inode = d_inode(dentry);
	struct inode *lower_inode;
	struct dentry *lower_dentry;
	struct path lower_path;
	struct iattr lower_ia;
	int err;

	cryptofs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = d_inode(lower_dentry);

	/* Copy the iattr, adjusting size for the encryption overhead */
	memcpy(&lower_ia, ia, sizeof(lower_ia));

	if (ia->ia_valid & ATTR_SIZE) {
		/*
		 * Truncate: adjust the lower file size to account for
		 * header + encrypted extent overhead.
		 */
		u64 logical_size = ia->ia_size;
		u64 num_extents = (logical_size + CRYPTOFS_EXTENT_SIZE - 1) /
				  CRYPTOFS_EXTENT_SIZE;
		lower_ia.ia_size = CRYPTOFS_HEADER_SIZE +
				   (num_extents * CRYPTOFS_EXTENT_DISK_SIZE);
	}

	inode_lock(lower_inode);
	err = notify_change(idmap, lower_dentry, &lower_ia, NULL);
	inode_unlock(lower_inode);

	if (!err) {
		fsstack_copy_attr_all(inode, lower_inode);
		if (ia->ia_valid & ATTR_SIZE)
			i_size_write(inode, ia->ia_size);
	}

	cryptofs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * symlink: create a symbolic link.
 */
static int cryptofs_symlink(struct mnt_idmap *idmap,
			    struct inode *dir, struct dentry *dentry,
			    const char *symname)
{
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry;
	struct path lower_path, lower_parent_path;
	int err;

	cryptofs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	cryptofs_get_lower_path(dentry->d_parent, &lower_parent_path);
	lower_parent_dentry = lower_parent_path.dentry;

	err = vfs_symlink(idmap, d_inode(lower_parent_dentry),
			  lower_dentry, symname);
	if (err)
		goto out;

	err = cryptofs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, d_inode(lower_parent_dentry));

out:
	cryptofs_put_lower_path(dentry->d_parent, &lower_parent_path);
	cryptofs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * link: create a hard link.
 */
static int cryptofs_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	struct path lower_old_path, lower_new_path, lower_dir_path;
	int err;

	cryptofs_get_lower_path(old_dentry, &lower_old_path);
	lower_old_dentry = lower_old_path.dentry;
	cryptofs_get_lower_path(new_dentry, &lower_new_path);
	lower_new_dentry = lower_new_path.dentry;
	cryptofs_get_lower_path(new_dentry->d_parent, &lower_dir_path);
	lower_dir_dentry = lower_dir_path.dentry;

	err = vfs_link(lower_old_dentry, &nop_mnt_idmap,
		       d_inode(lower_dir_dentry), lower_new_dentry, NULL);
	if (err)
		goto out;

	err = cryptofs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));

out:
	cryptofs_put_lower_path(new_dentry->d_parent, &lower_dir_path);
	cryptofs_put_lower_path(new_dentry, &lower_new_path);
	cryptofs_put_lower_path(old_dentry, &lower_old_path);
	return err;
}

/* Directory inode operations */
const struct inode_operations cryptofs_dir_iops = {
	.create		= cryptofs_create,
	.lookup		= cryptofs_lookup,
	.link		= cryptofs_link,
	.unlink		= cryptofs_unlink,
	.symlink	= cryptofs_symlink,
	.mkdir		= cryptofs_mkdir,
	.rmdir		= cryptofs_rmdir,
	.rename		= cryptofs_rename,
	.setattr	= cryptofs_setattr,
	.getattr	= cryptofs_getattr,
};

/* Regular file inode operations */
const struct inode_operations cryptofs_main_iops = {
	.setattr	= cryptofs_setattr,
	.getattr	= cryptofs_getattr,
};
