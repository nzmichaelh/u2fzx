/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _FS_SFS_H_
#define _FS_SFS_H_

#include <fs.h>
#include <zephyr/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_FILE_NAME 12

typedef s16_t sfs_block;

struct sfs_file {
	sfs_block block;
	s16_t offset;
	s16_t size;
	u8_t name[MAX_FILE_NAME + 1];
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
