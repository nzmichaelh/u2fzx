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

#pragma once

#include <errno.h>
#include <string.h>

#include <zephyr/types.h>

#include "sfs.h"
#include "ugsl.h"

#define ERROR(_code)                                                         \
	{                                                                    \
		.code = static_cast<s16_t>(_code)                            \
	}

struct error {
	error() : code(0) {}
	error(int status) : code(status) {}

	explicit operator bool() const { return code != 0; }

	s16_t code;

	struct proxy {
		s16_t code;
	};

	error(proxy p) : code(p.code) {}

	static constexpr struct proxy ok = ERROR(0);
	static constexpr struct proxy io = ERROR(-EIO);
	static constexpr struct proxy noent = ERROR(-ENOENT);
	static constexpr struct proxy nomem = ERROR(-ENOMEM);
	static constexpr struct proxy inval = ERROR(-EINVAL);
	static constexpr struct proxy exist = ERROR(-EEXIST);
	static constexpr struct proxy perm = ERROR(-EPERM);
	static constexpr struct proxy nospc = ERROR(-ENOSPC);
};

struct string {
	string(const char *p) : p_{(const u8_t *)p} {}
	string(const u8_t *p) : p_{p} {}

	const char *c_str() const { return (const char *)p_; }

      private:
	const u8_t *p_;
};

void u2f_took(const char *msg, int *start);
void u2f_dump_hex(const char *msg, const u8_t *buf, int len);
void u2f_dump_hex(const char *msg, const gsl::span<u8_t> &s);

template <typename T> error u2f_write_file(string fname, const T &pc)
{
	struct sfs_file fp;
	int err;

	err = sfs_open(&fp, fname.c_str());
	if (err != 0) {
		return ERROR(err);
	}

	err = sfs_write(&fp, pc.cbegin(), pc.size());
	if (err < 0) {
		return ERROR(err);
	}
	if (err != (int)pc.size()) {
		return error::nospc;
	}

	return ERROR(sfs_close(&fp));
}

template <typename T> int u2f_read_file(string fname, T &buf)
{
	struct sfs_dirent entry;
	struct sfs_file fp;

	auto err = sfs_stat(fname.c_str(), &entry);
	if (err != 0) {
		return err;
	}

	err = sfs_open(&fp, fname.c_str());
	if (err != 0) {
		return err;
	}

	err = sfs_read(&fp, buf.begin(), buf.size());
	sfs_close(&fp);

	return err;
}
