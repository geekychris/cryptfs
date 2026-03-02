/* SPDX-License-Identifier: GPL-2.0 */
/*
 * CryptoFS - Kernel-level transparent encryption stacked filesystem
 *
 * Inspired by Thales CipherTrust Transparent Encryption (CTE).
 * Provides per-directory AES-256-GCM encryption with per-process
 * access control policies.
 */

#ifndef _CRYPTOFS_H_
#define _CRYPTOFS_H_

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/crypto.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/key.h>
#include <linux/cred.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/genetlink.h>
#include <linux/audit.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/xattr.h>
#include <linux/security.h>

/* ========== Constants ========== */

#define CRYPTOFS_NAME           "cryptofs"
#define CRYPTOFS_MAGIC          0x43525946  /* "CRYF" */
#define CRYPTOFS_VERSION        1

/* File header magic: "CRYPFS01" */
#define CRYPTOFS_FILE_MAGIC     0x4352595046533031ULL
#define CRYPTOFS_FILE_MAGIC_LEN 8

/* Encryption constants */
#define CRYPTOFS_KEY_SIZE       32   /* AES-256: 32 bytes */
#define CRYPTOFS_NONCE_SIZE     12   /* GCM nonce: 12 bytes */
#define CRYPTOFS_TAG_SIZE       16   /* GCM auth tag: 16 bytes */
#define CRYPTOFS_EXTENT_SIZE    4096 /* Encryption extent: 4KB (page-aligned) */

/* On-disk sizes */
#define CRYPTOFS_HEADER_SIZE    128
#define CRYPTOFS_EXTENT_DISK_SIZE (CRYPTOFS_EXTENT_SIZE + CRYPTOFS_TAG_SIZE) /* 4112 */

/* Policy constants */
#define CRYPTOFS_MAX_POLICIES   256
#define CRYPTOFS_MAX_PATH_LEN   PATH_MAX
#define CRYPTOFS_HASH_SIZE      32   /* SHA-256 digest */

/* Netlink family */
#define CRYPTOFS_GENL_NAME      "cryptofs"
#define CRYPTOFS_GENL_VERSION   1
#define CRYPTOFS_GENL_MCGRP     "cryptofs_events"

/* Audit ring buffer size */
#define CRYPTOFS_AUDIT_RING_SIZE 1024

/* ========== On-disk file header ========== */

/*
 * Stored at offset 0 of the lower file.
 * Total: 128 bytes.
 */
struct cryptofs_file_header {
	__le64 magic;                           /*   0: "CRYPFS01" */
	__le32 version;                         /*   8: header version */
	__le32 flags;                           /*  12: flags */
	__u8   encrypted_fek[CRYPTOFS_KEY_SIZE + CRYPTOFS_TAG_SIZE]; /* 16: FEK wrapped by master key (48 bytes) */
	__u8   fek_nonce[CRYPTOFS_NONCE_SIZE];  /*  64: nonce used to wrap FEK */
	__le64 file_size;                       /*  76: logical (plaintext) file size */
	__u8   reserved[44];                    /*  84: reserved for future use */
} __packed;                                     /* Total: 128 bytes */

/* Header flags */
#define CRYPTOFS_FLAG_ENCRYPTED  0x01

/* ========== Per-superblock info ========== */

struct cryptofs_sb_info {
	struct super_block *lower_sb;
	struct crypto_aead *tfm;          /* AES-256-GCM transform */
	struct crypto_shash *hmac_tfm;    /* HMAC-SHA256 for nonce derivation */
	struct mutex crypto_lock;         /* Serializes access to tfm/hmac_tfm */

	/* Master key (loaded from userspace via keyring/netlink) */
	u8 master_key[CRYPTOFS_KEY_SIZE];
	bool master_key_loaded;

	/* Policy list for this mount */
	struct list_head policy_list;
	spinlock_t policy_lock;
	int policy_count;
};

/* ========== Per-inode info ========== */

struct cryptofs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;

	/* Cached file encryption key (decrypted from header) */
	u8 fek[CRYPTOFS_KEY_SIZE];
	bool fek_loaded;
	struct mutex fek_mutex;

	/* Per-inode crypto transforms (key set once, then lock-free) */
	struct crypto_aead *tfm;
	struct crypto_shash *hmac_tfm;
	bool crypto_initialized;
};

/* ========== Per-file info ========== */

struct cryptofs_file_info {
	struct file *lower_file;
};

/* ========== Per-dentry info ========== */

struct cryptofs_dentry_info {
	struct path lower_path;
	spinlock_t lock;
};

/* ========== Policy types ========== */

enum cryptofs_policy_type {
	CRYPTOFS_POLICY_UID = 0,         /* Match by UID */
	CRYPTOFS_POLICY_GID,             /* Match by GID */
	CRYPTOFS_POLICY_BINARY_PATH,     /* Match by executable path */
	CRYPTOFS_POLICY_BINARY_HASH,     /* Match by SHA-256 of executable */
	CRYPTOFS_POLICY_PROCESS_NAME,    /* Match by task comm */
};

enum cryptofs_policy_action {
	CRYPTOFS_ACTION_DENY = 0,
	CRYPTOFS_ACTION_ALLOW,
};

struct cryptofs_policy_rule {
	struct list_head list;
	unsigned int id;
	enum cryptofs_policy_type type;
	enum cryptofs_policy_action action;

	union {
		kuid_t uid;
		kgid_t gid;
		char binary_path[CRYPTOFS_MAX_PATH_LEN];
		u8 binary_hash[CRYPTOFS_HASH_SIZE];
		char process_name[TASK_COMM_LEN];
	} match;
};

/* ========== Audit entry ========== */

enum cryptofs_audit_op {
	CRYPTOFS_AUDIT_READ = 0,
	CRYPTOFS_AUDIT_WRITE,
	CRYPTOFS_AUDIT_OPEN,
	CRYPTOFS_AUDIT_CREATE,
	CRYPTOFS_AUDIT_DENIED,
	CRYPTOFS_AUDIT_KEY_LOAD,
	CRYPTOFS_AUDIT_POLICY_ADD,
	CRYPTOFS_AUDIT_POLICY_DEL,
};

struct cryptofs_audit_entry {
	ktime_t timestamp;
	pid_t pid;
	kuid_t uid;
	enum cryptofs_audit_op op;
	bool authorized;
	char filename[NAME_MAX];
	char comm[TASK_COMM_LEN];
};

/* ========== Netlink commands ========== */

enum cryptofs_nl_commands {
	CRYPTOFS_CMD_UNSPEC = 0,
	CRYPTOFS_CMD_ADD_POLICY,
	CRYPTOFS_CMD_DEL_POLICY,
	CRYPTOFS_CMD_LIST_POLICIES,
	CRYPTOFS_CMD_SET_KEY,
	CRYPTOFS_CMD_GET_STATUS,
	CRYPTOFS_CMD_GET_AUDIT,
	__CRYPTOFS_CMD_MAX,
};
#define CRYPTOFS_CMD_MAX (__CRYPTOFS_CMD_MAX - 1)

enum cryptofs_nl_attrs {
	CRYPTOFS_ATTR_UNSPEC = 0,
	CRYPTOFS_ATTR_POLICY_ID,        /* u32 */
	CRYPTOFS_ATTR_POLICY_TYPE,      /* u32 (enum cryptofs_policy_type) */
	CRYPTOFS_ATTR_POLICY_ACTION,    /* u32 (enum cryptofs_policy_action) */
	CRYPTOFS_ATTR_POLICY_VALUE,     /* string or binary data */
	CRYPTOFS_ATTR_MASTER_KEY,       /* binary: 32 bytes */
	CRYPTOFS_ATTR_MOUNT_PATH,       /* string: mount point */
	CRYPTOFS_ATTR_STATUS,           /* string: JSON status */
	CRYPTOFS_ATTR_AUDIT_ENTRY,      /* nested: audit entry */
	__CRYPTOFS_ATTR_MAX,
};
#define CRYPTOFS_ATTR_MAX (__CRYPTOFS_ATTR_MAX - 1)

/* ========== Inline helpers ========== */

static inline struct cryptofs_sb_info *CRYPTOFS_SB(const struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct cryptofs_inode_info *CRYPTOFS_I(const struct inode *inode)
{
	return container_of(inode, struct cryptofs_inode_info, vfs_inode);
}

static inline struct cryptofs_file_info *CRYPTOFS_F(const struct file *file)
{
	return file->private_data;
}

static inline struct cryptofs_dentry_info *CRYPTOFS_D(const struct dentry *dentry)
{
	return dentry->d_fsdata;
}

/* Get the lower superblock */
static inline struct super_block *cryptofs_lower_super(const struct super_block *sb)
{
	return CRYPTOFS_SB(sb)->lower_sb;
}

/* Get the lower inode */
static inline struct inode *cryptofs_lower_inode(const struct inode *inode)
{
	return CRYPTOFS_I(inode)->lower_inode;
}

/* Set the lower inode */
static inline void cryptofs_set_lower_inode(struct inode *inode,
					    struct inode *lower_inode)
{
	CRYPTOFS_I(inode)->lower_inode = lower_inode;
}

/* Get the lower file */
static inline struct file *cryptofs_lower_file(const struct file *file)
{
	return CRYPTOFS_F(file)->lower_file;
}

/* Set the lower file */
static inline void cryptofs_set_lower_file(struct file *file,
					   struct file *lower_file)
{
	CRYPTOFS_F(file)->lower_file = lower_file;
}

/* Path copy helper */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}

/* Get/set lower path from dentry */
static inline void cryptofs_get_lower_path(const struct dentry *dentry,
					   struct path *lower_path)
{
	spin_lock(&CRYPTOFS_D(dentry)->lock);
	pathcpy(lower_path, &CRYPTOFS_D(dentry)->lower_path);
	path_get(lower_path);
	spin_unlock(&CRYPTOFS_D(dentry)->lock);
}

static inline void cryptofs_put_lower_path(const struct dentry *dentry,
					   struct path *lower_path)
{
	path_put(lower_path);
}

static inline void cryptofs_set_lower_path(const struct dentry *dentry,
					   struct path *lower_path)
{
	spin_lock(&CRYPTOFS_D(dentry)->lock);
	pathcpy(&CRYPTOFS_D(dentry)->lower_path, lower_path);
	spin_unlock(&CRYPTOFS_D(dentry)->lock);
}

static inline void cryptofs_reset_lower_path(const struct dentry *dentry)
{
	spin_lock(&CRYPTOFS_D(dentry)->lock);
	CRYPTOFS_D(dentry)->lower_path.dentry = NULL;
	CRYPTOFS_D(dentry)->lower_path.mnt = NULL;
	spin_unlock(&CRYPTOFS_D(dentry)->lock);
}

/* ========== Function declarations: super.c ========== */

extern const struct super_operations cryptofs_sops;
extern struct dentry *cryptofs_mount(struct file_system_type *fs_type,
				     int flags, const char *dev_name,
				     void *raw_data);

/* ========== Function declarations: inode.c ========== */

extern const struct inode_operations cryptofs_dir_iops;
extern const struct inode_operations cryptofs_symlink_iops;
extern const struct inode_operations cryptofs_main_iops;
struct inode *cryptofs_iget(struct super_block *sb, struct inode *lower_inode);
void cryptofs_copy_inode_attr(struct inode *dest, const struct inode *src);

/* ========== Function declarations: file.c ========== */

extern const struct file_operations cryptofs_main_fops;
extern const struct file_operations cryptofs_dir_fops;

/* ========== Function declarations: dentry.c ========== */

extern const struct dentry_operations cryptofs_dops;
int cryptofs_init_dentry_cache(void);
void cryptofs_destroy_dentry_cache(void);

/* ========== Function declarations: lookup.c ========== */

struct dentry *cryptofs_lookup(struct inode *dir, struct dentry *dentry,
			       unsigned int flags);
int cryptofs_interpose(struct dentry *dentry, struct super_block *sb,
		       struct path *lower_path);

/* ========== Function declarations: mmap.c ========== */

extern const struct address_space_operations cryptofs_aops;

/* ========== Function declarations: crypto.c ========== */

int cryptofs_crypto_init(struct cryptofs_sb_info *sbi);
void cryptofs_crypto_free(struct cryptofs_sb_info *sbi);
int cryptofs_encrypt_extent(struct cryptofs_inode_info *iinfo,
			    u64 inode_no, u64 extent_idx,
			    const u8 *plaintext, u8 *ciphertext, u8 *tag);
int cryptofs_decrypt_extent(struct cryptofs_inode_info *iinfo,
			    u64 inode_no, u64 extent_idx,
			    const u8 *ciphertext, const u8 *tag, u8 *plaintext);
int cryptofs_generate_fek(u8 *fek);
int cryptofs_wrap_fek(struct cryptofs_sb_info *sbi, const u8 *fek,
		      u8 *wrapped_fek, u8 *nonce, u8 *tag);
int cryptofs_unwrap_fek(struct cryptofs_sb_info *sbi, const u8 *wrapped_fek,
			const u8 *nonce, const u8 *tag, u8 *fek);
int cryptofs_derive_nonce(struct cryptofs_inode_info *iinfo,
			  u64 inode_no, u64 extent_idx, u8 *nonce);
int cryptofs_inode_crypto_init(struct cryptofs_inode_info *iinfo, const u8 *fek);
void cryptofs_inode_crypto_free(struct cryptofs_inode_info *iinfo);
int cryptofs_read_file_header(struct file *lower_file,
			      struct cryptofs_file_header *hdr);
int cryptofs_write_file_header(struct file *lower_file,
			       const struct cryptofs_file_header *hdr);
int cryptofs_ensure_fek(struct inode *inode);

/* Offset translation helpers */
static inline loff_t cryptofs_logical_to_lower(loff_t logical_offset)
{
	u64 extent_idx = logical_offset / CRYPTOFS_EXTENT_SIZE;
	u64 extent_off = logical_offset % CRYPTOFS_EXTENT_SIZE;
	return CRYPTOFS_HEADER_SIZE +
	       (extent_idx * CRYPTOFS_EXTENT_DISK_SIZE) + extent_off;
}

static inline u64 cryptofs_extent_index(loff_t logical_offset)
{
	return logical_offset / CRYPTOFS_EXTENT_SIZE;
}

static inline u64 cryptofs_extent_offset(loff_t logical_offset)
{
	return logical_offset % CRYPTOFS_EXTENT_SIZE;
}

/* ========== Function declarations: policy.c ========== */

int cryptofs_policy_init(struct cryptofs_sb_info *sbi);
void cryptofs_policy_free(struct cryptofs_sb_info *sbi);
int cryptofs_policy_add(struct cryptofs_sb_info *sbi,
			struct cryptofs_policy_rule *rule);
int cryptofs_policy_del(struct cryptofs_sb_info *sbi, unsigned int rule_id);
bool cryptofs_policy_check(struct cryptofs_sb_info *sbi,
			   struct inode *inode);

/* ========== Function declarations: netlink.c ========== */

int cryptofs_netlink_init(void);
void cryptofs_netlink_exit(void);

/* ========== Function declarations: audit.c ========== */

int cryptofs_audit_init(void);
void cryptofs_audit_exit(void);
void cryptofs_audit_log(enum cryptofs_audit_op op, struct inode *inode,
			bool authorized, const char *filename);

/* ========== Global state ========== */

extern struct kmem_cache *cryptofs_inode_cache;
extern struct kmem_cache *cryptofs_dentry_cache;

/* We keep a reference to the mounted superblock for netlink to find policies */
extern struct super_block *cryptofs_active_sb;
extern struct mutex cryptofs_active_sb_mutex;

#endif /* _CRYPTOFS_H_ */
