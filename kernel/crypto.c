// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - encryption engine
 *
 * AES-256-GCM encryption/decryption of file extents using the
 * Linux kernel Crypto API. Each 4KB extent is independently
 * encrypted with a per-file key (FEK) and a deterministic nonce
 * derived from HMAC-SHA256(FEK, inode_no || extent_index).
 */

#include "cryptofs.h"
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/key.h>
#include <keys/user-type.h>

/*
 * Initialize the crypto engine for a mount.
 * Allocates AES-256-GCM and HMAC-SHA256 transforms.
 */
int cryptofs_crypto_init(struct cryptofs_sb_info *sbi)
{
	struct crypto_aead *tfm;
	struct crypto_shash *hmac_tfm;

	/* Allocate AES-256-GCM AEAD transform */
	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("cryptofs: failed to allocate gcm(aes): %ld\n",
		       PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	/* Set auth tag size */
	if (crypto_aead_setauthsize(tfm, CRYPTOFS_TAG_SIZE)) {
		pr_err("cryptofs: failed to set GCM auth size\n");
		crypto_free_aead(tfm);
		return -EINVAL;
	}

	sbi->tfm = tfm;

	/* Allocate HMAC-SHA256 for nonce derivation */
	hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(hmac_tfm)) {
		pr_err("cryptofs: failed to allocate hmac(sha256): %ld\n",
		       PTR_ERR(hmac_tfm));
		crypto_free_aead(tfm);
		sbi->tfm = NULL;
		return PTR_ERR(hmac_tfm);
	}

	sbi->hmac_tfm = hmac_tfm;
	mutex_init(&sbi->crypto_lock);

	return 0;
}

/*
 * Free crypto transforms.
 */
void cryptofs_crypto_free(struct cryptofs_sb_info *sbi)
{
	if (sbi->tfm) {
		crypto_free_aead(sbi->tfm);
		sbi->tfm = NULL;
	}
	if (sbi->hmac_tfm) {
		crypto_free_shash(sbi->hmac_tfm);
		sbi->hmac_tfm = NULL;
	}
}

/*
 * Initialize per-inode crypto transforms.
 *
 * Allocates AES-256-GCM and HMAC-SHA256 transforms dedicated to this
 * inode and sets the FEK once.  After this call the transforms are
 * read-only and can be used concurrently from any context without
 * holding a lock (each caller uses its own aead_request / shash_desc).
 */
int cryptofs_inode_crypto_init(struct cryptofs_inode_info *iinfo, const u8 *fek)
{
	struct crypto_aead *tfm;
	struct crypto_shash *hmac_tfm;
	int err;

	if (iinfo->crypto_initialized)
		return 0;

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	err = crypto_aead_setauthsize(tfm, CRYPTOFS_TAG_SIZE);
	if (err) {
		crypto_free_aead(tfm);
		return err;
	}

	err = crypto_aead_setkey(tfm, fek, CRYPTOFS_KEY_SIZE);
	if (err) {
		crypto_free_aead(tfm);
		return err;
	}

	hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(hmac_tfm)) {
		crypto_free_aead(tfm);
		return PTR_ERR(hmac_tfm);
	}

	err = crypto_shash_setkey(hmac_tfm, fek, CRYPTOFS_KEY_SIZE);
	if (err) {
		crypto_free_aead(tfm);
		crypto_free_shash(hmac_tfm);
		return err;
	}

	iinfo->tfm = tfm;
	iinfo->hmac_tfm = hmac_tfm;
	/* Ensure stores to tfm/hmac_tfm are visible before the flag. */
	smp_wmb();
	iinfo->crypto_initialized = true;

	return 0;
}

/*
 * Free per-inode crypto transforms.
 */
void cryptofs_inode_crypto_free(struct cryptofs_inode_info *iinfo)
{
	if (iinfo->tfm) {
		crypto_free_aead(iinfo->tfm);
		iinfo->tfm = NULL;
	}
	if (iinfo->hmac_tfm) {
		crypto_free_shash(iinfo->hmac_tfm);
		iinfo->hmac_tfm = NULL;
	}
	iinfo->crypto_initialized = false;
}

/*
 * Derive a 12-byte nonce from the FEK, inode number, and extent index.
 *
 * nonce = HMAC-SHA256(FEK, inode_no || extent_idx) truncated to 12 bytes
 *
 * Uses the per-inode HMAC transform (key already set).  The stack-
 * allocated shash_desc provides per-call state, so no locking is needed.
 */
int cryptofs_derive_nonce(struct cryptofs_inode_info *iinfo,
			  u64 inode_no, u64 extent_idx, u8 *nonce)
{
	SHASH_DESC_ON_STACK(desc, iinfo->hmac_tfm);
	u8 hash[32]; /* SHA-256 output */
	__le64 data[2];
	int err;

	desc->tfm = iinfo->hmac_tfm;

	err = crypto_shash_init(desc);
	if (err)
		return err;

	/* Hash inode_no || extent_idx */
	data[0] = cpu_to_le64(inode_no);
	data[1] = cpu_to_le64(extent_idx);

	err = crypto_shash_update(desc, (u8 *)data, sizeof(data));
	if (err)
		return err;

	err = crypto_shash_final(desc, hash);
	if (err)
		return err;

	/* Truncate to 12 bytes for GCM nonce */
	memcpy(nonce, hash, CRYPTOFS_NONCE_SIZE);
	memzero_explicit(hash, sizeof(hash));

	return 0;
}

/*
 * Encrypt a single 4KB extent using AES-256-GCM.
 *
 * Uses the per-inode AEAD transform (key already set).  Each call
 * allocates its own aead_request, so concurrent calls on the same
 * inode are safe without any locking.
 *
 * Input:  plaintext (4096 bytes)
 * Output: ciphertext (4096 bytes), tag (16 bytes)
 */
int cryptofs_encrypt_extent(struct cryptofs_inode_info *iinfo,
			    u64 inode_no, u64 extent_idx,
			    const u8 *plaintext, u8 *ciphertext, u8 *tag)
{
	struct aead_request *req;
	struct scatterlist sg_src[1], sg_dst[1];
	u8 nonce[CRYPTOFS_NONCE_SIZE];
	u8 *src_buf;
	int err;
	DECLARE_CRYPTO_WAIT(wait);

	/* Derive the nonce for this extent */
	err = cryptofs_derive_nonce(iinfo, inode_no, extent_idx, nonce);
	if (err)
		return err;

	/* Allocate request (per-inode tfm, key already set) */
	req = aead_request_alloc(iinfo->tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	/*
	 * GCM encryption: input is plaintext, output is ciphertext + tag.
	 * We use a single buffer: [plaintext(4096)] for input,
	 * and [ciphertext(4096) + tag(16)] for output.
	 */
	src_buf = kmalloc(CRYPTOFS_EXTENT_SIZE + CRYPTOFS_TAG_SIZE, GFP_KERNEL);
	if (!src_buf) {
		aead_request_free(req);
		return -ENOMEM;
	}

	memcpy(src_buf, plaintext, CRYPTOFS_EXTENT_SIZE);

	sg_init_one(sg_src, src_buf, CRYPTOFS_EXTENT_SIZE);
	sg_init_one(sg_dst, src_buf, CRYPTOFS_EXTENT_SIZE + CRYPTOFS_TAG_SIZE);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, sg_src, sg_dst,
			       CRYPTOFS_EXTENT_SIZE, nonce);
	aead_request_set_ad(req, 0);

	err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	if (!err) {
		memcpy(ciphertext, src_buf, CRYPTOFS_EXTENT_SIZE);
		memcpy(tag, src_buf + CRYPTOFS_EXTENT_SIZE, CRYPTOFS_TAG_SIZE);
	}

	memzero_explicit(src_buf, CRYPTOFS_EXTENT_SIZE + CRYPTOFS_TAG_SIZE);
	kfree(src_buf);
	aead_request_free(req);
	return err;
}

/*
 * Decrypt a single 4KB extent using AES-256-GCM.
 *
 * Uses the per-inode AEAD transform (key already set).  Lock-free.
 *
 * Input:  ciphertext (4096 bytes), tag (16 bytes)
 * Output: plaintext (4096 bytes)
 *
 * Returns -EBADMSG if authentication fails (tampered data).
 */
int cryptofs_decrypt_extent(struct cryptofs_inode_info *iinfo,
			    u64 inode_no, u64 extent_idx,
			    const u8 *ciphertext, const u8 *tag, u8 *plaintext)
{
	struct aead_request *req;
	struct scatterlist sg_src[1], sg_dst[1];
	u8 nonce[CRYPTOFS_NONCE_SIZE];
	u8 *src_buf;
	int err;
	DECLARE_CRYPTO_WAIT(wait);

	/* Derive the nonce */
	err = cryptofs_derive_nonce(iinfo, inode_no, extent_idx, nonce);
	if (err)
		return err;

	/* Allocate request (per-inode tfm, key already set) */
	req = aead_request_alloc(iinfo->tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	/*
	 * GCM decryption: input is ciphertext + tag.
	 * Output is plaintext.
	 */
	src_buf = kmalloc(CRYPTOFS_EXTENT_SIZE + CRYPTOFS_TAG_SIZE, GFP_KERNEL);
	if (!src_buf) {
		aead_request_free(req);
		return -ENOMEM;
	}

	memcpy(src_buf, ciphertext, CRYPTOFS_EXTENT_SIZE);
	memcpy(src_buf + CRYPTOFS_EXTENT_SIZE, tag, CRYPTOFS_TAG_SIZE);

	sg_init_one(sg_src, src_buf, CRYPTOFS_EXTENT_SIZE + CRYPTOFS_TAG_SIZE);
	sg_init_one(sg_dst, plaintext, CRYPTOFS_EXTENT_SIZE);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, sg_src, sg_dst,
			       CRYPTOFS_EXTENT_SIZE + CRYPTOFS_TAG_SIZE, nonce);
	aead_request_set_ad(req, 0);

	err = crypto_wait_req(crypto_aead_decrypt(req), &wait);

	memzero_explicit(src_buf, CRYPTOFS_EXTENT_SIZE + CRYPTOFS_TAG_SIZE);
	kfree(src_buf);
	aead_request_free(req);
	return err;
}

/*
 * Generate a random 256-bit file encryption key.
 */
int cryptofs_generate_fek(u8 *fek)
{
	get_random_bytes(fek, CRYPTOFS_KEY_SIZE);
	return 0;
}

/*
 * Wrap (encrypt) a FEK with a master key using AES-256-GCM.
 *
 * Input:  master_key (32 bytes), fek (32 bytes)
 * Output: wrapped_fek (32 bytes ciphertext), nonce (12 bytes), tag (16 bytes)
 */
int cryptofs_wrap_fek(struct cryptofs_sb_info *sbi, const u8 *master_key,
		      const u8 *fek, u8 *wrapped_fek, u8 *nonce, u8 *tag)
{
	struct aead_request *req;
	struct scatterlist sg_src[1], sg_dst[1];
	u8 *buf;
	int err;
	DECLARE_CRYPTO_WAIT(wait);

	mutex_lock(&sbi->crypto_lock);

	/* Generate a random nonce for FEK wrapping */
	get_random_bytes(nonce, CRYPTOFS_NONCE_SIZE);

	/* Set the master key for this operation */
	err = crypto_aead_setkey(sbi->tfm, master_key, CRYPTOFS_KEY_SIZE);
	if (err)
		goto unlock;

	req = aead_request_alloc(sbi->tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto unlock;
	}

	buf = kmalloc(CRYPTOFS_KEY_SIZE + CRYPTOFS_TAG_SIZE, GFP_KERNEL);
	if (!buf) {
		aead_request_free(req);
		err = -ENOMEM;
		goto unlock;
	}

	memcpy(buf, fek, CRYPTOFS_KEY_SIZE);

	sg_init_one(sg_src, buf, CRYPTOFS_KEY_SIZE);
	sg_init_one(sg_dst, buf, CRYPTOFS_KEY_SIZE + CRYPTOFS_TAG_SIZE);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, sg_src, sg_dst,
			       CRYPTOFS_KEY_SIZE, nonce);
	aead_request_set_ad(req, 0);

	err = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	if (!err) {
		memcpy(wrapped_fek, buf, CRYPTOFS_KEY_SIZE);
		memcpy(tag, buf + CRYPTOFS_KEY_SIZE, CRYPTOFS_TAG_SIZE);
	}

	memzero_explicit(buf, CRYPTOFS_KEY_SIZE + CRYPTOFS_TAG_SIZE);
	kfree(buf);
	aead_request_free(req);
	mutex_unlock(&sbi->crypto_lock);
	return err;

unlock:
	mutex_unlock(&sbi->crypto_lock);
	return err;
}

/*
 * Unwrap (decrypt) a FEK using a master key.
 */
int cryptofs_unwrap_fek(struct cryptofs_sb_info *sbi, const u8 *master_key,
			const u8 *wrapped_fek, const u8 *nonce, const u8 *tag,
			u8 *fek)
{
	struct aead_request *req;
	struct scatterlist sg_src[1], sg_dst[1];
	u8 *buf;
	int err;
	DECLARE_CRYPTO_WAIT(wait);

	mutex_lock(&sbi->crypto_lock);

	/* Set the master key for this operation */
	err = crypto_aead_setkey(sbi->tfm, master_key, CRYPTOFS_KEY_SIZE);
	if (err)
		goto unlock;

	req = aead_request_alloc(sbi->tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto unlock;
	}

	buf = kmalloc(CRYPTOFS_KEY_SIZE + CRYPTOFS_TAG_SIZE, GFP_KERNEL);
	if (!buf) {
		aead_request_free(req);
		err = -ENOMEM;
		goto unlock;
	}

	memcpy(buf, wrapped_fek, CRYPTOFS_KEY_SIZE);
	memcpy(buf + CRYPTOFS_KEY_SIZE, tag, CRYPTOFS_TAG_SIZE);

	sg_init_one(sg_src, buf, CRYPTOFS_KEY_SIZE + CRYPTOFS_TAG_SIZE);
	sg_init_one(sg_dst, fek, CRYPTOFS_KEY_SIZE);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, sg_src, sg_dst,
			       CRYPTOFS_KEY_SIZE + CRYPTOFS_TAG_SIZE,
			       (u8 *)nonce);
	aead_request_set_ad(req, 0);

	err = crypto_wait_req(crypto_aead_decrypt(req), &wait);

	memzero_explicit(buf, CRYPTOFS_KEY_SIZE + CRYPTOFS_TAG_SIZE);
	kfree(buf);
	aead_request_free(req);
	mutex_unlock(&sbi->crypto_lock);
	return err;

unlock:
	mutex_unlock(&sbi->crypto_lock);
	return err;
}

/* ========== Key table management ========== */

int cryptofs_key_table_init(struct cryptofs_sb_info *sbi)
{
	INIT_LIST_HEAD(&sbi->key_table);
	init_rwsem(&sbi->key_table_lock);
	sbi->key_count = 0;
	return 0;
}

void cryptofs_key_table_free(struct cryptofs_sb_info *sbi)
{
	struct cryptofs_key_entry *entry, *tmp;

	down_write(&sbi->key_table_lock);
	list_for_each_entry_safe(entry, tmp, &sbi->key_table, list) {
		list_del(&entry->list);
		memzero_explicit(entry->key_data, CRYPTOFS_KEY_SIZE);
		kfree(entry);
	}
	sbi->key_count = 0;
	up_write(&sbi->key_table_lock);
}

int cryptofs_key_table_add(struct cryptofs_sb_info *sbi,
			   const u8 *key_id, const u8 *key_data)
{
	struct cryptofs_key_entry *entry;

	down_write(&sbi->key_table_lock);

	/* Check if key_id already exists; if so, replace it */
	list_for_each_entry(entry, &sbi->key_table, list) {
		if (memcmp(entry->key_id, key_id, CRYPTOFS_KEY_ID_SIZE) == 0) {
			memcpy(entry->key_data, key_data, CRYPTOFS_KEY_SIZE);
			up_write(&sbi->key_table_lock);
			pr_info("cryptofs: replaced key in key table\n");
			return 0;
		}
	}

	if (sbi->key_count >= CRYPTOFS_MAX_KEYS) {
		up_write(&sbi->key_table_lock);
		return -ENOSPC;
	}

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		up_write(&sbi->key_table_lock);
		return -ENOMEM;
	}

	memcpy(entry->key_id, key_id, CRYPTOFS_KEY_ID_SIZE);
	memcpy(entry->key_data, key_data, CRYPTOFS_KEY_SIZE);
	list_add_tail(&entry->list, &sbi->key_table);
	sbi->key_count++;
	up_write(&sbi->key_table_lock);

	pr_info("cryptofs: added key to key table (%d total)\n", sbi->key_count);
	return 0;
}

int cryptofs_key_table_del(struct cryptofs_sb_info *sbi, const u8 *key_id)
{
	struct cryptofs_key_entry *entry;

	down_write(&sbi->key_table_lock);
	list_for_each_entry(entry, &sbi->key_table, list) {
		if (memcmp(entry->key_id, key_id, CRYPTOFS_KEY_ID_SIZE) == 0) {
			list_del(&entry->list);
			sbi->key_count--;
			up_write(&sbi->key_table_lock);
			memzero_explicit(entry->key_data, CRYPTOFS_KEY_SIZE);
			kfree(entry);
			return 0;
		}
	}
	up_write(&sbi->key_table_lock);
	return -ENOENT;
}

/*
 * Look up a master key in the key table.
 * Must be called under key_table_lock (read or write).
 * Returns pointer to key_data or NULL.
 */
const u8 *cryptofs_key_lookup(struct cryptofs_sb_info *sbi, const u8 *key_id)
{
	struct cryptofs_key_entry *entry;

	list_for_each_entry(entry, &sbi->key_table, list) {
		if (memcmp(entry->key_id, key_id, CRYPTOFS_KEY_ID_SIZE) == 0)
			return entry->key_data;
	}
	return NULL;
}

/*
 * Resolve a master key by mode.
 *
 * TRANSPARENT: look up key_id in the kernel key table.
 * GUARDED: search the calling process's keyring for "cryptofs:<hex key_id>".
 *
 * On success, copies 32 bytes of key material into out_key.
 * Returns 0 on success, negative error otherwise.
 */
int cryptofs_resolve_key(struct cryptofs_sb_info *sbi, const u8 *key_id,
			 enum cryptofs_access_mode mode, u8 *out_key)
{
	if (mode == CRYPTOFS_MODE_TRANSPARENT) {
		const u8 *key_data;

		down_read(&sbi->key_table_lock);
		key_data = cryptofs_key_lookup(sbi, key_id);
		if (key_data) {
			memcpy(out_key, key_data, CRYPTOFS_KEY_SIZE);
			up_read(&sbi->key_table_lock);
			return 0;
		}
		up_read(&sbi->key_table_lock);
		return -ENOKEY;
	}

	if (mode == CRYPTOFS_MODE_GUARDED) {
		struct key *kr_key;
		const struct user_key_payload *payload;
		char desc[48]; /* "cryptofs:" + 32 hex chars + NUL */
		int i;

		/* Build keyring description: "cryptofs:<hex key_id>" */
		memcpy(desc, "cryptofs:", 9);
		for (i = 0; i < CRYPTOFS_KEY_ID_SIZE; i++)
			snprintf(desc + 9 + i * 2, 3, "%02x", key_id[i]);

		kr_key = request_key(&key_type_logon, desc, NULL);
		if (IS_ERR(kr_key))
			return PTR_ERR(kr_key);

		down_read(&kr_key->sem);
		payload = user_key_payload_locked(kr_key);
		if (!payload || payload->datalen < CRYPTOFS_KEY_SIZE) {
			up_read(&kr_key->sem);
			key_put(kr_key);
			return -ENOKEY;
		}
		memcpy(out_key, payload->data, CRYPTOFS_KEY_SIZE);
		up_read(&kr_key->sem);
		key_put(kr_key);
		return 0;
	}

	return -EINVAL;
}

/*
 * Read the file header from the lower file.
 */
int cryptofs_read_file_header(struct file *lower_file,
			      struct cryptofs_file_header *hdr)
{
	loff_t pos = 0;
	ssize_t nread;

	nread = kernel_read(lower_file, hdr, sizeof(*hdr), &pos);
	if (nread < (ssize_t)sizeof(*hdr))
		return (nread < 0) ? nread : -ENODATA;

	/* Validate magic */
	if (le64_to_cpu(hdr->magic) != CRYPTOFS_FILE_MAGIC)
		return -ENODATA;

	return 0;
}

/*
 * Write the file header to the lower file.
 */
int cryptofs_write_file_header(struct file *lower_file,
			       const struct cryptofs_file_header *hdr)
{
	loff_t pos = 0;
	ssize_t nwritten;

	nwritten = kernel_write(lower_file, hdr, sizeof(*hdr), &pos);
	if (nwritten < (ssize_t)sizeof(*hdr))
		return (nwritten < 0) ? nwritten : -EIO;

	return 0;
}

/*
 * Ensure the FEK is loaded for an inode.
 * Reads the file header from the lower file and unwraps the FEK.
 */
int cryptofs_ensure_fek(struct inode *inode)
{
	struct cryptofs_inode_info *iinfo = CRYPTOFS_I(inode);
	struct inode *lower_inode;
	struct file *lower_file;

	if (iinfo->fek_loaded)
		return 0;

	mutex_lock(&iinfo->fek_mutex);
	if (iinfo->fek_loaded) {
		mutex_unlock(&iinfo->fek_mutex);
		return 0;
	}

	/* We need to open the lower file to read the header */
	lower_inode = cryptofs_lower_inode(inode);
	if (!lower_inode || !S_ISREG(lower_inode->i_mode)) {
		mutex_unlock(&iinfo->fek_mutex);
		return -EINVAL;
	}

	/*
	 * Open the lower file temporarily to read the header.
	 * We use a dentry from the lower inode.
	 */
	lower_file = filp_open("/dev/null", O_RDONLY, 0); /* placeholder */
	if (IS_ERR(lower_file)) {
		/*
		 * Fallback: we'll load the FEK on the first file open
		 * via the file operations path.
		 */
		mutex_unlock(&iinfo->fek_mutex);
		return -ENODATA;
	}
	fput(lower_file);

	/*
	 * The FEK will be loaded when the file is actually opened
	 * through cryptofs_open() which has access to the lower file.
	 * Return -ENODATA to indicate "not loaded yet, but not an error."
	 */
	mutex_unlock(&iinfo->fek_mutex);
	return -ENODATA;
}
