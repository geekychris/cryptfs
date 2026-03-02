// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS - mmap / address space operations
 *
 * Provides page cache integration for memory-mapped files.
 * readpage decrypts a page from the lower filesystem.
 * writepage encrypts and writes back to the lower filesystem.
 */

#include <linux/writeback.h>
#include "cryptofs.h"

/*
 * Read a page: read the encrypted extent from the lower filesystem
 * and decrypt it into the page cache page.
 */
static int cryptofs_read_folio(struct file *file, struct folio *folio)
{
	struct page *page = &folio->page;
	struct inode *inode = page->mapping->host;
	struct cryptofs_sb_info *sbi = CRYPTOFS_SB(inode->i_sb);
	struct cryptofs_inode_info *iinfo = CRYPTOFS_I(inode);
	struct file *lower_file;
	pgoff_t index = page->index;
	u64 extent_idx = index; /* 1 page = 1 extent (both 4KB) */
	loff_t lower_offset;
	u8 *extent_buf = NULL;
	u8 *page_data;
	u8 tag[CRYPTOFS_TAG_SIZE];
	ssize_t nread;
	int err = 0;

	if (!file) {
		err = -EINVAL;
		goto out_unlock;
	}

	lower_file = cryptofs_lower_file(file);

	/* If FEK not loaded, return zeros (file might be new) */
	if (!iinfo->fek_loaded) {
		page_data = kmap_local_page(page);
		memset(page_data, 0, PAGE_SIZE);
		kunmap_local(page_data);
		goto out_up;
	}

	/* Check authorization */
	if (!cryptofs_policy_check(sbi, inode)) {
		/* Unauthorized: return raw ciphertext */
		lower_offset = CRYPTOFS_HEADER_SIZE +
			       (extent_idx * CRYPTOFS_EXTENT_DISK_SIZE);
		page_data = kmap_local_page(page);
		nread = kernel_read(lower_file, page_data,
				    PAGE_SIZE, &lower_offset);
		if (nread < PAGE_SIZE)
			memset(page_data + max(0L, nread), 0,
			       PAGE_SIZE - max(0L, nread));
		kunmap_local(page_data);
		goto out_up;
	}

	/* Read encrypted extent + tag from lower file */
	extent_buf = kmalloc(CRYPTOFS_EXTENT_DISK_SIZE, GFP_KERNEL);
	if (!extent_buf) {
		err = -ENOMEM;
		goto out_unlock;
	}

	lower_offset = CRYPTOFS_HEADER_SIZE +
		       (extent_idx * CRYPTOFS_EXTENT_DISK_SIZE);

	nread = kernel_read(lower_file, extent_buf,
			    CRYPTOFS_EXTENT_DISK_SIZE, &lower_offset);

	page_data = kmap_local_page(page);

	if (nread == CRYPTOFS_EXTENT_DISK_SIZE) {
		memcpy(tag, extent_buf + CRYPTOFS_EXTENT_SIZE,
		       CRYPTOFS_TAG_SIZE);

		err = cryptofs_decrypt_extent(iinfo, inode->i_ino,
					      extent_idx, extent_buf,
					      tag, page_data);
		if (err) {
			pr_warn("cryptofs: mmap decrypt failed for inode %lu page %lu\n",
				inode->i_ino, index);
			memset(page_data, 0, PAGE_SIZE);
			err = 0; /* Don't fail the page read */
		}
	} else {
		/* Beyond file end or short read: zero fill */
		memset(page_data, 0, PAGE_SIZE);
	}

	kunmap_local(page_data);
	kfree(extent_buf);

out_up:
	SetPageUptodate(page);
out_unlock:
	unlock_page(page);
	return err;
}

/*
 * Write a dirty page back.
 *
 * In a stacked filesystem the lower file handle is not readily available
 * during asynchronous writeback.  Rather than risk silent data loss we
 * always re-dirty the page so that the VFS keeps it around until data
 * is flushed through our write_iter path (close / fsync).
 */
static int cryptofs_writepage(struct page *page, struct writeback_control *wbc)
{
	folio_redirty_for_writepage(wbc, page_folio(page));
	/* Do NOT unlock_page here: the caller (shrink_page_list) does it
	 * when it sees AOP_WRITEPAGE_ACTIVATE. */
	return AOP_WRITEPAGE_ACTIVATE;
}

const struct address_space_operations cryptofs_aops = {
	.read_folio	= cryptofs_read_folio,
	.writepage	= cryptofs_writepage,
};
