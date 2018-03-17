/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * SFS is a small filesystem designed for saving limited size files in
 * page based flash such as that often found in a SoC.  It's best
 * suited for applications that write up to a hundred small files of a
 * similar size which are also similar to the flash page size.
 *
 * The filesystem is made of a single virtual root directory that
 * holds one file per block.  A block is a fixed number of flash pages
 * and includes a header, filename, and the file data.  The whole of
 * the file must fit in one block.
 *
 * The filesystem is implemented as a hash table with a fixed number
 * of buckets, open addressing, and linear probing.  The filename is
 * hashed to a block which helps with wear leveling and reduces the
 * best case lookup time.  If a file is overwritten, then the
 * filesystem picks the next free block to reduce wear.  The
 * worst case lookup involves reading the header of each block.
 *
 * The filesystem is power safe.  Note that overwriting a file
 * involves erasing the old version then creating the new.
 */

#define SYS_LOG_LEVEL 3
#define SYS_LOG_DOMAIN "sfs"
#include <logging/sys_log.h>

#include <crc8.h>
#include <device.h>
#include <flash.h>
#include <init.h>
#include <string.h>
#include <zephyr.h>

#include "sfs.h"

/* Size of a block which also limits the largest file size */
#define SFS_BLOCK_SIZE 512

#define SFS_NUM_BLOCKS (FLASH_AREA_SFS_SIZE / SFS_BLOCK_SIZE)
#define SFS_OFFSET FLASH_AREA_SFS_OFFSET
#define SFS_MAGIC 153

#define SFS_HEADER_LEN (offsetof(struct sfs_header, data))

struct sfs_header {
	u8_t magic;
	u8_t name[MAX_FILE_NAME + 1];
	u16_t size;
	u8_t data_crc;
	u8_t crc;
	u8_t data[0];
};

struct sfs_data {
	struct device *dev;
	u16_t write_size;
	u16_t header_capacity;
};

static struct sfs_data data;

/* Hash a string to a block number using the djb2 algorithm.  This is
 * used to smear the files across the flash, and also helps the best
 * case lookup time by putting the file at a predictable place.
 */
static sfs_block sfs_hash(const char *name)
{
	u32_t hash = 5381;

	for (; *name != '\0'; name++) {
		hash = hash * 33 + *name;
	}

	return hash % SFS_NUM_BLOCKS;
}

/* Safely copy a filename to a buffer */
static void sfs_copy_name(char *dst, const char *src)
{
	strncpy(dst, src, MAX_FILE_NAME);
	dst[MAX_FILE_NAME] = '\0';
}

/* Convert a block number to a flash byte offset */
static off_t sfs_to_offset(sfs_block block)
{
	return SFS_OFFSET + block * SFS_BLOCK_SIZE;
}

/* Returns true if the block number is valid, i.e. within the flash
 * range.
 */
static bool sfs_valid_block(sfs_block block)
{
	return block >= 0 && block < SFS_NUM_BLOCKS;
}

/* Returns the next block number, wrapping at the end of flash.  Used
 * in iteration.
 */
static sfs_block sfs_next(sfs_block block)
{
	block++;

	if (block < 0) {
		return 0;
	}
	if (block >= SFS_NUM_BLOCKS) {
		return block - SFS_NUM_BLOCKS;
	}
	return block;
}

/* Reads and validates a block header */
static int sfs_read_header(sfs_block block, struct sfs_header *hdr)
{
	int err;
	u8_t crc;

	SYS_LOG_DBG("block=%d", block);

	if (!sfs_valid_block(block)) {
		return -EINVAL;
	}

	err = flash_read(data.dev, sfs_to_offset(block), hdr, sizeof(*hdr));
	if (err != 0) {
		SYS_LOG_INF("bad read err=%d", err);
		return err;
	}

	if (hdr->magic != SFS_MAGIC) {
		SYS_LOG_DBG("bad magic=%d", hdr->magic);
		return -EIO;
	}

	crc = crc8_ccitt(0, hdr, offsetof(struct sfs_header, data));
	if (crc != 0) {
		SYS_LOG_INF("bad crc=%d", crc);
		return -EILSEQ;
	}

	return 0;
}

/* Scans the flash to find the block containing the given path.
 * If a block exists, fills in `hdr` and returns the block number.
 */
static sfs_block sfs_find(const char *path, struct sfs_header *hdr)
{
	sfs_block block = sfs_hash(path);
	sfs_block end = block;

	SYS_LOG_DBG("path=%s block=%d end=%d", path, block, end);

	do {
		int err = sfs_read_header(block, hdr);

		if (err == 0 &&
		    strncmp(path, hdr->name, MAX_FILE_NAME) == 0) {
			return block;
		}
		block = sfs_next(block);
	} while (block != end);

	return -ENOENT;
}

/* Erases the whole of the block */
int sfs_erase(sfs_block block)
{
	return flash_erase(data.dev, sfs_to_offset(block), SFS_BLOCK_SIZE);
}

/* Writes a file to flash */
ssize_t sfs_write(struct sfs_file *zfp, const void *ptr, size_t size)
{
	sfs_block block;
	sfs_block end;
	int err;
	u8_t buf[data.write_size];
	struct sfs_header *hdr = (struct sfs_header *)buf;
	off_t at;
	bool found = false;

	SYS_LOG_DBG("");

	if (zfp->block != -1) {
		SYS_LOG_ERR("already read or written");
		return -EINVAL;
	}

	/* Erase any existing file */
	block = sfs_find(zfp->name, hdr);
	if (block >= 0) {
		err = sfs_erase(block);
		if (err != 0) {
			SYS_LOG_ERR("erase old block err=%d", err);
			return err;
		}
		/* Reduce the wear by scanning from the next block. */
		block = sfs_next(block);
	} else {
		/* Pick the hashed filename as the first block to scan
		 * from.
		 */
		block = sfs_hash(zfp->name);
	}

	/* Scan and find a free block */
	end = block;
	do {
		if (sfs_read_header(block, hdr) != 0) {
			found = true;
			break;
		}
		block = sfs_next(block);
	} while (block != end);

	if (!found) {
		return -ENOSPC;
	}

	err = sfs_erase(block);
	if (err != 0) {
		SYS_LOG_ERR("erase new block err=%d", err);
		return err;
	}

	/* Write the trailing blocks */
	for (at = data.header_capacity; at < size; at += sizeof(buf)) {
		size_t remain = min(sizeof(buf), size - at);

		memcpy(buf, ptr + at, remain);
		err = flash_write(data.dev,
				  sfs_to_offset(block) + at -
				  data.header_capacity + data.write_size,
				  buf, sizeof(buf));
		if (err != 0) {
			SYS_LOG_ERR("data write err=%d", err);
			return err;
		}
	}

	/* Fill out the header */
	hdr->magic = SFS_MAGIC;
	hdr->size = size;
	sfs_copy_name(hdr->name, zfp->name);
	hdr->data_crc = crc8_ccitt(0, ptr, size);
	hdr->crc = crc8_ccitt(0, hdr, offsetof(struct sfs_header, crc));
	hdr->data_crc = crc8_ccitt(0, ptr, size);

	/* Copy the first part of the data */
	memcpy(hdr->data, ptr, min(size, data.header_capacity));

	/* Write the header */
	err = flash_write(data.dev, sfs_to_offset(block), buf, sizeof(buf));
	if (err != 0) {
		SYS_LOG_ERR("header write err=%d", err);
		return err;
	}

	return size;
}

/* Check if a file exists */
int sfs_stat(const char *path, struct sfs_dirent *entry)
{
	struct sfs_header hdr;
	sfs_block block;

	block = sfs_find(path, &hdr);
	if (block < 0) {
		return block;
	}

	entry->type = FS_DIR_ENTRY_FILE;
	sfs_copy_name(entry->name, hdr.name);
	entry->size = hdr.size;

	return 0;
}

/* Read part of a file.  Supports reading parts of the file at a time
 * and supports sfs_seek to rewind after the first read has been done.
 */
ssize_t sfs_read(struct sfs_file *zfp, void *ptr, size_t size)
{
	int remain;
	int read;
	int err;

	SYS_LOG_DBG("size=%d", size);

	if (zfp->block < 0) {
		struct sfs_header hdr;

		err = sfs_find(zfp->name, &hdr);

		if (err < 0) {
			return err;
		}
		zfp->block = err;
		zfp->size = hdr.size;
	}

	remain = zfp->size - zfp->offset;
	read = min(remain, size);

	if (read > 0) {
		err = flash_read(data.dev,
				 sfs_to_offset(zfp->block) +
					 offsetof(struct sfs_header, data) +
					 zfp->offset,
				 ptr, read);
		if (err != 0) {
			return err;
		}
		zfp->offset += read;
	}

	return read;
}

/* Open a directory for scanning */
int sfs_opendir(struct sfs_dir *zdp, const char *path)
{
	if (path == NULL || strcmp(path, "/") != 0) {
		return -ENOENT;
	}

	zdp->block = 0;
	return 0;
}

int sfs_closedir(struct sfs_dir *zdp)
{
	SYS_LOG_DBG("");

	/* Nothing to do */
	return 0;
}

/* Read the next item in the directory */
int sfs_readdir(struct sfs_dir *zdp, struct sfs_dirent *entry)
{
	struct sfs_header hdr;

	SYS_LOG_DBG("");

	for (; zdp->block < SFS_NUM_BLOCKS &&
	       sfs_read_header(zdp->block, &hdr) != 0;
	     zdp->block++) {
	}

	if (!sfs_valid_block(zdp->block)) {
		entry->name[0] = '\0';
		return 0;
	}

	entry->type = FS_DIR_ENTRY_FILE;
	strcpy(entry->name, hdr.name);
	entry->size = hdr.size;
	zdp->block++;

	return 0;
}

int sfs_mkdir(const char *path)
{
	SYS_LOG_DBG("");

	return -ENOTSUP;
}

int sfs_truncate(struct sfs_file *zfp, off_t length)
{
	SYS_LOG_DBG("");

	return -ENOTSUP;
}

int sfs_open(struct sfs_file *zfp, const char *filename)
{
	SYS_LOG_DBG("name=%s", filename);

	zfp->block = -1;
	zfp->offset = 0;
	zfp->size = -1;

	if (filename == NULL || filename[0] != '/') {
		return -ENOENT;
	}

	/* Save the filename for later as we don't know if this is a
	 * read or write.
	 */
	sfs_copy_name(zfp->name, filename);

	return 0;
}

int sfs_close(struct sfs_file *zfp)
{
	SYS_LOG_DBG("");

	/* Nothing to do */
	return 0;
}

int sfs_unlink(const char *path)
{
	struct sfs_header hdr;
	sfs_block block = sfs_find(path, &hdr);

	SYS_LOG_DBG("path=%s", path);

	if (block < 0) {
		return -ENOENT;
	}
	return sfs_erase(block);
}

/* Seek within a file.  Some functionality only works once the file
 * has initially been read.
 */
int sfs_seek(struct sfs_file *zfp, off_t offset, int whence)
{
	int target = -1;

	SYS_LOG_DBG("offset=%d whence=%d", offset, whence);

	if (zfp->size < 0) {
		/* Don't know the mode of the file yet.  Assume that
		 * it's a read.
		 */
		switch (whence) {
		case FS_SEEK_SET:
		case FS_SEEK_CUR:
			zfp->offset = whence;
			break;
		case FS_SEEK_END:
			zfp->offset = 0;
			break;
		default:
			return -EINVAL;
		}
		return 0;
	}

	switch (whence) {
	case FS_SEEK_SET:
		target = whence;
		break;
	case FS_SEEK_CUR:
		target = zfp->offset + whence;
		break;
	case FS_SEEK_END:
		target = zfp->size - whence;
		break;
	default:
		return -EINVAL;
	}
	if (target < 0 || target > zfp->size) {
		return -EINVAL;
	}
	zfp->offset = target;

	return 0;
}

static int sfs_init(struct device *dev)
{
	size_t write_size;
	int blocks;

	data.dev = device_get_binding(FLASH_DEV_NAME);
	if (data.dev == NULL) {
		return -EINVAL;
	}

	/* Calculate the size of the header in write blocks and how
	 * much will be left for data.
	 */
	write_size = flash_get_write_block_size(data.dev);
	blocks = (SFS_HEADER_LEN + write_size - 1) / write_size;

	data.write_size = write_size;
	data.header_capacity = blocks * write_size - SFS_HEADER_LEN;

	return 0;
}

SYS_INIT(sfs_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
