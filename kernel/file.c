// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - file operations
 *
 * Implements read, write, seek, and other file operations with
 * transparent encryption/decryption. Authorized processes see
 * plaintext; unauthorized processes see raw ciphertext.
 */

#include "cryptofs.h"
#include <linux/splice.h>

/*
 * Open: open the corresponding file in the lower filesystem.
 */
static int cryptofs_open(struct inode *inode, struct file *file)
{
	struct cryptofs_file_info *file_info;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *lower_dentry;
	struct inode *lower_inode;
	struct super_block *sb = inode->i_sb;
	int lower_flags;
	int err = 0;

	/* Allocate our per-file info */
	file_info = kmalloc(sizeof(*file_info), GFP_KERNEL);
	if (!file_info)
		return -ENOMEM;

	/* Get lower path */
	cryptofs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = d_inode(lower_dentry);

	/*
	 * Open the lower file.  When the upper file is opened for writing
	 * (O_WRONLY), upgrade to O_RDWR so that the read-decrypt-modify-
	 * encrypt-write cycle in write_iter can read back existing extents.
	 * Strip creation flags — the lower file already exists.
	 */
	lower_flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_APPEND);
	if ((lower_flags & O_ACCMODE) == O_WRONLY)
		lower_flags = (lower_flags & ~O_ACCMODE) | O_RDWR;

	lower_file = dentry_open(&lower_path, lower_flags, current_cred());
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		kfree(file_info);
		goto out;
	}

	file_info->lower_file = lower_file;
	file->private_data = file_info;

	/*
	 * For regular files that already have data, try to load the FEK
	 * from the on-disk header.  This is needed when the inode was
	 * evicted and recreated since the last open.
	 */
	if (S_ISREG(inode->i_mode) && !CRYPTOFS_I(inode)->fek_loaded &&
	    i_size_read(lower_inode) >= CRYPTOFS_HEADER_SIZE) {
		struct cryptofs_inode_info *iinfo = CRYPTOFS_I(inode);

		mutex_lock(&iinfo->fek_mutex);
		if (!iinfo->fek_loaded) {
			struct cryptofs_file_header hdr;

			err = cryptofs_read_file_header(lower_file, &hdr);
			if (!err) {
				struct cryptofs_sb_info *sbi = CRYPTOFS_SB(sb);

				err = cryptofs_unwrap_fek(sbi,
						hdr.encrypted_fek,
						hdr.fek_nonce,
						hdr.encrypted_fek + CRYPTOFS_KEY_SIZE,
						iinfo->fek);
				if (!err) {
					err = cryptofs_inode_crypto_init(iinfo,
									iinfo->fek);
					if (!err) {
						iinfo->fek_loaded = true;
						inode->i_size = le64_to_cpu(hdr.file_size);
					}
				}
			}
			/*
			 * Non-fatal: the FEK will be generated on the
			 * first write if this is a new/empty file.
			 */
			if (err) {
				pr_debug("cryptofs: FEK load deferred for ino %lu: %d\n",
					 inode->i_ino, err);
				err = 0;
			}
		}
		mutex_unlock(&iinfo->fek_mutex);
	}

	cryptofs_audit_log(CRYPTOFS_AUDIT_OPEN, inode,
			   cryptofs_policy_check(CRYPTOFS_SB(sb), inode),
			   file->f_path.dentry->d_name.name);

out:
	cryptofs_put_lower_path(file->f_path.dentry, &lower_path);
	return err;
}

/*
 * Release: close the lower file.
 */
static int cryptofs_release(struct inode *inode, struct file *file)
{
	struct cryptofs_file_info *file_info = CRYPTOFS_F(file);

	if (file_info) {
		if (file_info->lower_file)
			fput(file_info->lower_file);
		kfree(file_info);
		file->private_data = NULL;
	}
	return 0;
}

/*
 * read_iter: encrypted read.
 *
 * For authorized processes: read ciphertext from lower FS,
 * decrypt each extent, return plaintext.
 * For unauthorized processes: return raw ciphertext.
 */
static ssize_t cryptofs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct cryptofs_sb_info *sbi = CRYPTOFS_SB(inode->i_sb);
	struct cryptofs_inode_info *iinfo = CRYPTOFS_I(inode);
	struct file *lower_file = cryptofs_lower_file(file);
	bool authorized;
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(iter);
	ssize_t total_read = 0;
	u8 *extent_buf = NULL;
	u8 *plain_buf = NULL;
	u8 tag[CRYPTOFS_TAG_SIZE];
	int err = 0;

	if (!count)
		return 0;

	/* Check if we have a valid FEK (file is encrypted) */
	if (!iinfo->fek_loaded) {
		/* File has no encryption header: pass through to lower */
		goto passthrough;
	}

	/* Check policy for the calling process */
	authorized = cryptofs_policy_check(sbi, inode);

	cryptofs_audit_log(CRYPTOFS_AUDIT_READ, inode, authorized,
			   file->f_path.dentry->d_name.name);

	if (!authorized) {
		/*
		 * Unauthorized: return raw ciphertext from lower file.
		 * Skip the header and return the encrypted extents as-is.
		 */
		struct kiocb lower_iocb;
		loff_t lower_pos;

		lower_pos = cryptofs_logical_to_lower(pos);
		init_sync_kiocb(&lower_iocb, lower_file);
		lower_iocb.ki_pos = lower_pos;

		err = vfs_iter_read(lower_file, iter, &lower_iocb.ki_pos, 0);
		if (err > 0)
			iocb->ki_pos = pos + err;
		return err;
	}

	/* Authorized: decrypt extent by extent */
	extent_buf = kmalloc(CRYPTOFS_EXTENT_DISK_SIZE, GFP_KERNEL);
	plain_buf = kmalloc(CRYPTOFS_EXTENT_SIZE, GFP_KERNEL);
	if (!extent_buf || !plain_buf) {
		err = -ENOMEM;
		goto out;
	}

	while (count > 0 && pos < inode->i_size) {
		u64 ext_idx = cryptofs_extent_index(pos);
		u64 ext_off = cryptofs_extent_offset(pos);
		size_t bytes_in_extent = min_t(size_t,
			CRYPTOFS_EXTENT_SIZE - ext_off,
			count);
		loff_t lower_ext_start;
		ssize_t nread;

		/* Clamp to file size */
		if (pos + bytes_in_extent > inode->i_size)
			bytes_in_extent = inode->i_size - pos;

		if (bytes_in_extent == 0)
			break;

		/* Read the encrypted extent + tag from the lower file */
		lower_ext_start = CRYPTOFS_HEADER_SIZE +
				  (ext_idx * CRYPTOFS_EXTENT_DISK_SIZE);

		nread = kernel_read(lower_file, extent_buf,
				    CRYPTOFS_EXTENT_DISK_SIZE,
				    &lower_ext_start);
		if (nread < CRYPTOFS_EXTENT_DISK_SIZE) {
			if (nread < 0)
				err = nread;
			else
				err = -EIO;
			break;
		}

		/* Separate ciphertext and auth tag */
		memcpy(tag, extent_buf + CRYPTOFS_EXTENT_SIZE,
		       CRYPTOFS_TAG_SIZE);

		/* Decrypt the extent (per-inode transform, lock-free) */
		err = cryptofs_decrypt_extent(iinfo, inode->i_ino, ext_idx,
					      extent_buf, tag, plain_buf);
		if (err) {
			pr_warn("cryptofs: decryption failed for inode %lu extent %llu: %d\n",
				inode->i_ino, ext_idx, err);
			break;
		}

		/* Copy the requested portion to the user buffer */
		if (copy_to_iter(plain_buf + ext_off, bytes_in_extent,
				 iter) != bytes_in_extent) {
			err = -EFAULT;
			break;
		}

		pos += bytes_in_extent;
		count -= bytes_in_extent;
		total_read += bytes_in_extent;
	}

out:
	kfree(extent_buf);
	kfree(plain_buf);

	if (total_read > 0) {
		iocb->ki_pos = pos;
		return total_read;
	}
	return err;

passthrough:
	/* No encryption on this file: pass through to lower */
	{
		struct kiocb lower_iocb;
		init_sync_kiocb(&lower_iocb, lower_file);
		lower_iocb.ki_pos = pos;
		err = vfs_iter_read(lower_file, iter, &lower_iocb.ki_pos, 0);
		if (err > 0)
			iocb->ki_pos = pos + err;
		return err;
	}
}

/*
 * write_iter: encrypted write.
 *
 * Authorized processes: encrypt plaintext and write to lower FS.
 * Unauthorized processes: write is BLOCKED (-EACCES).
 */
static ssize_t cryptofs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct cryptofs_sb_info *sbi = CRYPTOFS_SB(inode->i_sb);
	struct cryptofs_inode_info *iinfo = CRYPTOFS_I(inode);
	struct file *lower_file = cryptofs_lower_file(file);
	bool authorized;
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(iter);

	/* Handle O_APPEND: start writing at the end of file */
	if (iocb->ki_flags & IOCB_APPEND)
		pos = i_size_read(inode);
	ssize_t total_written = 0;
	u8 *plain_buf = NULL;
	u8 *cipher_buf = NULL;
	u8 *extent_buf = NULL;
	u8 tag[CRYPTOFS_TAG_SIZE];
	int err = 0;

	if (!count)
		return 0;

	/* Check policy */
	authorized = cryptofs_policy_check(sbi, inode);

	cryptofs_audit_log(CRYPTOFS_AUDIT_WRITE, inode, authorized,
			   file->f_path.dentry->d_name.name);

	if (!authorized) {
		/* Unauthorized writes are blocked to prevent corruption */
		return -EACCES;
	}

	/* Ensure FEK exists. If this is a new file, generate one. */
	if (!iinfo->fek_loaded) {
		mutex_lock(&iinfo->fek_mutex);
		if (!iinfo->fek_loaded) {
			struct cryptofs_file_header hdr;

			/* Generate a new FEK for this file */
			err = cryptofs_generate_fek(iinfo->fek);
			if (err) {
				mutex_unlock(&iinfo->fek_mutex);
				return err;
			}

			/* Write the file header with the wrapped FEK */
			memset(&hdr, 0, sizeof(hdr));
			hdr.magic = cpu_to_le64(CRYPTOFS_FILE_MAGIC);
			hdr.version = cpu_to_le32(CRYPTOFS_VERSION);
			hdr.flags = cpu_to_le32(CRYPTOFS_FLAG_ENCRYPTED);
			hdr.file_size = cpu_to_le64(0);

			err = cryptofs_wrap_fek(sbi, iinfo->fek,
						hdr.encrypted_fek,
						hdr.fek_nonce,
						hdr.encrypted_fek +
						    CRYPTOFS_KEY_SIZE);
			if (err) {
				mutex_unlock(&iinfo->fek_mutex);
				return err;
			}

			err = cryptofs_write_file_header(lower_file, &hdr);
			if (err) {
				mutex_unlock(&iinfo->fek_mutex);
				return err;
			}

			/* Init per-inode crypto (alloc transforms, set key) */
			err = cryptofs_inode_crypto_init(iinfo, iinfo->fek);
			if (err) {
				mutex_unlock(&iinfo->fek_mutex);
				return err;
			}

			iinfo->fek_loaded = true;
		}
		mutex_unlock(&iinfo->fek_mutex);
	}

	/* Allocate working buffers */
	plain_buf = kmalloc(CRYPTOFS_EXTENT_SIZE, GFP_KERNEL);
	cipher_buf = kmalloc(CRYPTOFS_EXTENT_SIZE, GFP_KERNEL);
	extent_buf = kmalloc(CRYPTOFS_EXTENT_DISK_SIZE, GFP_KERNEL);
	if (!plain_buf || !cipher_buf || !extent_buf) {
		err = -ENOMEM;
		goto out;
	}

	while (count > 0) {
		u64 ext_idx = cryptofs_extent_index(pos);
		u64 ext_off = cryptofs_extent_offset(pos);
		size_t bytes_in_extent = min_t(size_t,
			CRYPTOFS_EXTENT_SIZE - ext_off,
			count);
		loff_t lower_ext_start;
		ssize_t nwritten;

		/*
		 * If this is a partial extent write, we need to
		 * read-decrypt-modify-reencrypt.
		 */
		if (ext_off != 0 || bytes_in_extent < CRYPTOFS_EXTENT_SIZE) {
			/* Partial write: read existing extent first */
			lower_ext_start = CRYPTOFS_HEADER_SIZE +
					  (ext_idx * CRYPTOFS_EXTENT_DISK_SIZE);

			ssize_t nread = kernel_read(lower_file, extent_buf,
						    CRYPTOFS_EXTENT_DISK_SIZE,
						    &lower_ext_start);

			if (nread == CRYPTOFS_EXTENT_DISK_SIZE) {
				/* Existing extent: decrypt it */
				memcpy(tag, extent_buf + CRYPTOFS_EXTENT_SIZE,
				       CRYPTOFS_TAG_SIZE);
				err = cryptofs_decrypt_extent(iinfo,
							      inode->i_ino,
							      ext_idx,
							      extent_buf, tag,
							      plain_buf);
				if (err) {
					pr_warn("cryptofs: decrypt for partial write failed: %d\n", err);
					break;
				}
			} else {
				/* New extent or short read: zero-fill */
				memset(plain_buf, 0, CRYPTOFS_EXTENT_SIZE);
			}
		} else {
			memset(plain_buf, 0, CRYPTOFS_EXTENT_SIZE);
		}

		/* Copy user data into the plaintext buffer at the right offset */
		if (copy_from_iter(plain_buf + ext_off, bytes_in_extent,
				   iter) != bytes_in_extent) {
			err = -EFAULT;
			break;
		}

		/* Encrypt the entire extent (per-inode transform, lock-free) */
		err = cryptofs_encrypt_extent(iinfo, inode->i_ino,
					      ext_idx, plain_buf, cipher_buf,
					      tag);
		if (err) {
			pr_warn("cryptofs: encryption failed: %d\n", err);
			break;
		}

		/* Build extent + tag for writing */
		memcpy(extent_buf, cipher_buf, CRYPTOFS_EXTENT_SIZE);
		memcpy(extent_buf + CRYPTOFS_EXTENT_SIZE, tag,
		       CRYPTOFS_TAG_SIZE);

		/* Write to the lower file */
		lower_ext_start = CRYPTOFS_HEADER_SIZE +
				  (ext_idx * CRYPTOFS_EXTENT_DISK_SIZE);

		nwritten = kernel_write(lower_file, extent_buf,
					CRYPTOFS_EXTENT_DISK_SIZE,
					&lower_ext_start);
		if (nwritten != CRYPTOFS_EXTENT_DISK_SIZE) {
			err = (nwritten < 0) ? nwritten : -EIO;
			break;
		}

		pos += bytes_in_extent;
		count -= bytes_in_extent;
		total_written += bytes_in_extent;
	}

	/* Update the logical file size in the header if needed */
	if (total_written > 0 && pos > inode->i_size) {
		struct cryptofs_file_header hdr;

		inode->i_size = pos;

		/* Read, update, and rewrite header */
		err = cryptofs_read_file_header(lower_file, &hdr);
		if (!err) {
			hdr.file_size = cpu_to_le64(pos);
			cryptofs_write_file_header(lower_file, &hdr);
		}
		err = 0; /* Non-critical if header update fails */
	}

out:
	kfree(plain_buf);
	kfree(cipher_buf);
	kfree(extent_buf);

	if (total_written > 0) {
		iocb->ki_pos = pos;
		return total_written;
	}
	return err;
}

/*
 * llseek: adjust the file position.
 * Translate logical offset; the actual seeking is straightforward
 * since we track the logical file size in our inode.
 */
static loff_t cryptofs_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	loff_t retval;

	/* Use generic_file_llseek on the logical (plaintext) size */
	inode_lock(inode);
	retval = generic_file_llseek_size(file, offset, whence,
					  inode->i_sb->s_maxbytes,
					  i_size_read(inode));
	inode_unlock(inode);
	return retval;
}

/*
 * fsync: flush data to the lower filesystem.
 */
static int cryptofs_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	struct file *lower_file = cryptofs_lower_file(file);

	return vfs_fsync_range(lower_file, start, end, datasync);
}

/*
 * flush: called on each close of a file descriptor.
 */
static int cryptofs_flush(struct file *file, fl_owner_t id)
{
	struct file *lower_file = cryptofs_lower_file(file);

	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
		return lower_file->f_op->flush(lower_file, id);
	return 0;
}

/* Regular file operations */
const struct file_operations cryptofs_main_fops = {
	.llseek		= cryptofs_llseek,
	.read_iter	= cryptofs_read_iter,
	.write_iter	= cryptofs_write_iter,
	.splice_read	= copy_splice_read,
	.splice_write	= iter_file_splice_write,
	.open		= cryptofs_open,
	.release	= cryptofs_release,
	.fsync		= cryptofs_fsync,
	.flush		= cryptofs_flush,
};

/*
 * Directory file operations: pass through to lower filesystem.
 * Directories are not encrypted.
 */
static int cryptofs_readdir(struct file *file, struct dir_context *ctx)
{
	struct file *lower_file = cryptofs_lower_file(file);
	int err;

	err = iterate_dir(lower_file, ctx);
	file->f_pos = lower_file->f_pos;
	return err;
}

const struct file_operations cryptofs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= cryptofs_readdir,
	.open		= cryptofs_open,
	.release	= cryptofs_release,
	.fsync		= cryptofs_fsync,
};
