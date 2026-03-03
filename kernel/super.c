// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - superblock operations
 *
 * Handles mounting, inode allocation, and superblock lifecycle.
 */

#include <linux/statfs.h>
#include "cryptofs.h"

/*
 * Allocate a new cryptofs inode from the slab cache.
 */
static struct inode *cryptofs_alloc_inode(struct super_block *sb)
{
	struct cryptofs_inode_info *i;

	i = alloc_inode_sb(sb, cryptofs_inode_cache, GFP_KERNEL);
	if (!i)
		return NULL;

	i->lower_inode = NULL;
	i->fek_loaded = false;
	i->crypto_initialized = false;
	i->tfm = NULL;
	i->hmac_tfm = NULL;
	mutex_init(&i->fek_mutex);
	atomic64_set(&i->vfs_inode.i_version, 1);
	return &i->vfs_inode;
}

/*
 * Free a cryptofs inode back to the slab cache.
 */
static void cryptofs_free_inode(struct inode *inode)
{
	struct cryptofs_inode_info *i = CRYPTOFS_I(inode);

	/* Securely wipe the FEK from memory */
	memzero_explicit(i->fek, CRYPTOFS_KEY_SIZE);
	i->fek_loaded = false;
	kmem_cache_free(cryptofs_inode_cache, i);
}

/*
 * Called when an inode is evicted from the cache.
 * Drop references to the lower inode.
 */
static void cryptofs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

	truncate_inode_pages(&inode->i_data, 0);
	clear_inode(inode);

	/* Free per-inode crypto transforms */
	cryptofs_inode_crypto_free(CRYPTOFS_I(inode));

	lower_inode = cryptofs_lower_inode(inode);
	if (lower_inode) {
		cryptofs_set_lower_inode(inode, NULL);
		iput(lower_inode);
	}
}

/*
 * statfs: report filesystem statistics from the lower filesystem.
 */
static int cryptofs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct dentry *lower_dentry;
	struct path lower_path;
	int err;

	cryptofs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	err = vfs_statfs(&lower_path, buf);

	/* Override magic number with our own */
	buf->f_type = CRYPTOFS_MAGIC;

	cryptofs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * put_super: clean up when the superblock is released.
 */
static void cryptofs_put_super(struct super_block *sb)
{
	struct cryptofs_sb_info *sbi = CRYPTOFS_SB(sb);

	if (!sbi)
		return;

	/* Unregister from active sb tracking */
	mutex_lock(&cryptofs_active_sb_mutex);
	if (cryptofs_active_sb == sb)
		cryptofs_active_sb = NULL;
	mutex_unlock(&cryptofs_active_sb_mutex);

	/* Free crypto transforms */
	cryptofs_crypto_free(sbi);

	/* Free policies */
	cryptofs_policy_free(sbi);

	/* Free key table (securely wipes all keys) */
	cryptofs_key_table_free(sbi);

	sb->s_fs_info = NULL;
	kfree(sbi);
}

const struct super_operations cryptofs_sops = {
	.alloc_inode	= cryptofs_alloc_inode,
	.free_inode	= cryptofs_free_inode,
	.evict_inode	= cryptofs_evict_inode,
	.put_super	= cryptofs_put_super,
	.statfs		= cryptofs_statfs,
	.drop_inode	= generic_delete_inode,
};

/*
 * Fill the superblock during mount.
 * Parse mount options, set up the lower filesystem reference,
 * and initialize the crypto engine.
 */
static int cryptofs_fill_super(struct super_block *sb, void *raw_data,
			       int silent)
{
	struct cryptofs_sb_info *sbi;
	struct inode *inode;
	struct path lower_path;
	const char *dev_name = (const char *)raw_data;
	int err;

	/* Allocate superblock info */
	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;

	/* Resolve the lower path (the directory we stack on) */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &lower_path);
	if (err) {
		pr_err("cryptofs: could not resolve lower path '%s': %d\n",
		       dev_name, err);
		goto out_free;
	}

	/* Set lower superblock */
	sbi->lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&sbi->lower_sb->s_active);

	/* Inherit settings from lower sb */
	sb->s_maxbytes = lower_path.dentry->d_sb->s_maxbytes;
	sb->s_blocksize = lower_path.dentry->d_sb->s_blocksize;
	sb->s_magic = CRYPTOFS_MAGIC;
	sb->s_op = &cryptofs_sops;
	sb->s_time_gran = lower_path.dentry->d_sb->s_time_gran;
	sb->s_xattr = NULL; /* We handle xattrs ourselves if needed */

	/* Initialize crypto engine */
	err = cryptofs_crypto_init(sbi);
	if (err) {
		pr_err("cryptofs: failed to init crypto engine: %d\n", err);
		goto out_deactivate;
	}

	/* Initialize key table (multi-key support) */
	cryptofs_key_table_init(sbi);

	/* Initialize policy engine */
	err = cryptofs_policy_init(sbi);
	if (err) {
		pr_err("cryptofs: failed to init policy engine: %d\n", err);
		goto out_crypto;
	}

	/* Create root inode from the lower directory inode */
	inode = cryptofs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_policy;
	}

	/* Set up root dentry with the inode */
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_policy;
	}

	/* Allocate dentry info for the root dentry */
	sb->s_root->d_fsdata = kmalloc(sizeof(struct cryptofs_dentry_info),
				       GFP_KERNEL);
	if (!sb->s_root->d_fsdata) {
		err = -ENOMEM;
		goto out_root;
	}
	spin_lock_init(&CRYPTOFS_D(sb->s_root)->lock);
	cryptofs_set_lower_path(sb->s_root, &lower_path);

	/* Set dentry operations */
	sb->s_root->d_op = &cryptofs_dops;
	sb->s_d_op = &cryptofs_dops;

	/* Track as active superblock */
	mutex_lock(&cryptofs_active_sb_mutex);
	cryptofs_active_sb = sb;
	mutex_unlock(&cryptofs_active_sb_mutex);

	/* We keep the path reference for the sb lifetime */
	return 0;

out_root:
	dput(sb->s_root);
	sb->s_root = NULL;
out_policy:
	cryptofs_policy_free(sbi);
out_crypto:
	cryptofs_crypto_free(sbi);
out_deactivate:
	deactivate_super(sbi->lower_sb);
	path_put(&lower_path);
out_free:
	sb->s_fs_info = NULL;
	kfree(sbi);
	return err;
}

/*
 * Mount the filesystem.
 * dev_name is the lower directory path.
 */
struct dentry *cryptofs_mount(struct file_system_type *fs_type, int flags,
			      const char *dev_name, void *raw_data)
{
	/*
	 * We pass dev_name through raw_data to fill_super,
	 * since mount_nodev doesn't pass dev_name directly.
	 */
	return mount_nodev(fs_type, flags, (void *)dev_name,
			   cryptofs_fill_super);
}
