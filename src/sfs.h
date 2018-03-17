/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _FS_SFS_H_
#define _FS_SFS_H_

#include <sys/types.h>
#include <fs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_FILE_NAME 12

typedef s16_t sfs_block;

struct sfs_file {
	sfs_block block;
	s16_t offset;
	s16_t size;
	u8_t name[MAX_FILE_NAME+1];
};

struct sfs_dir {
	s16_t block;
};

struct sfs_dirent {
	enum fs_dir_entry_type type;
	char name[MAX_FILE_NAME + 1];
	size_t size;
};

int sfs_open(struct sfs_file *zfp, const char *file_name);
int sfs_close(struct sfs_file *zfp);
int sfs_unlink(const char *path);
ssize_t sfs_read(struct sfs_file *zfp, void *ptr, size_t size);
ssize_t sfs_write(struct sfs_file *zfp, const void *ptr, size_t size);
int sfs_opendir(struct sfs_dir *zdp, const char *path);
int sfs_readdir(struct sfs_dir *zdp, struct sfs_dirent *entry);
int sfs_closedir(struct sfs_dir *zdp);
int sfs_stat(const char *path, struct sfs_dirent *entry);

#ifdef __cplusplus
}
#endif

#endif
