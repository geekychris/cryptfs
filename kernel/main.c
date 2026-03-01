// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - main module entry point
 *
 * Registers the cryptofs filesystem type, initializes caches,
 * and sets up the netlink interface and audit subsystem.
 */

#include "cryptofs.h"
#include <linux/module.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CryptoFS Project");
MODULE_DESCRIPTION("Transparent encryption stacked filesystem");
MODULE_VERSION("0.1");

/* Global caches */
struct kmem_cache *cryptofs_inode_cache;
struct kmem_cache *cryptofs_dentry_cache;

/* Active superblock reference (for netlink to find policies) */
struct super_block *cryptofs_active_sb;
DEFINE_MUTEX(cryptofs_active_sb_mutex);

/* Filesystem type declaration */
static struct file_system_type cryptofs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= CRYPTOFS_NAME,
	.mount		= cryptofs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= 0,
};

/* Inode cache constructor */
static void cryptofs_inode_init_once(void *obj)
{
	struct cryptofs_inode_info *i = obj;

	inode_init_once(&i->vfs_inode);
	i->lower_inode = NULL;
	i->fek_loaded = false;
	i->crypto_initialized = false;
	i->tfm = NULL;
	i->hmac_tfm = NULL;
	mutex_init(&i->fek_mutex);
	memset(i->fek, 0, CRYPTOFS_KEY_SIZE);
}

static int __init cryptofs_init_inode_cache(void)
{
	cryptofs_inode_cache = kmem_cache_create("cryptofs_inode_cache",
		sizeof(struct cryptofs_inode_info), 0,
		SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
		cryptofs_inode_init_once);
	if (!cryptofs_inode_cache)
		return -ENOMEM;
	return 0;
}

static void cryptofs_destroy_inode_cache(void)
{
	if (cryptofs_inode_cache) {
		kmem_cache_destroy(cryptofs_inode_cache);
		cryptofs_inode_cache = NULL;
	}
}

static int __init cryptofs_init(void)
{
	int err;

	pr_info("cryptofs: initializing v%d\n", CRYPTOFS_VERSION);

	/* Initialize inode cache */
	err = cryptofs_init_inode_cache();
	if (err) {
		pr_err("cryptofs: failed to init inode cache\n");
		goto out;
	}

	/* Initialize dentry cache */
	err = cryptofs_init_dentry_cache();
	if (err) {
		pr_err("cryptofs: failed to init dentry cache\n");
		goto out_inode_cache;
	}

	/* Initialize audit subsystem */
	err = cryptofs_audit_init();
	if (err) {
		pr_err("cryptofs: failed to init audit\n");
		goto out_dentry_cache;
	}

	/* Initialize netlink interface */
	err = cryptofs_netlink_init();
	if (err) {
		pr_err("cryptofs: failed to init netlink\n");
		goto out_audit;
	}

	/* Register the filesystem */
	err = register_filesystem(&cryptofs_fs_type);
	if (err) {
		pr_err("cryptofs: failed to register filesystem\n");
		goto out_netlink;
	}

	pr_info("cryptofs: module loaded successfully\n");
	return 0;

out_netlink:
	cryptofs_netlink_exit();
out_audit:
	cryptofs_audit_exit();
out_dentry_cache:
	cryptofs_destroy_dentry_cache();
out_inode_cache:
	cryptofs_destroy_inode_cache();
out:
	return err;
}

static void __exit cryptofs_exit(void)
{
	unregister_filesystem(&cryptofs_fs_type);
	cryptofs_netlink_exit();
	cryptofs_audit_exit();
	cryptofs_destroy_dentry_cache();
	cryptofs_destroy_inode_cache();
	pr_info("cryptofs: module unloaded\n");
}

module_init(cryptofs_init);
module_exit(cryptofs_exit);
