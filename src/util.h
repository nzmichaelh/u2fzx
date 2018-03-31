#pragma once

#include <errno.h>
#include <string.h>

#include <zephyr/types.h>

#include "sfs.h"
#include "ugtl.h"

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

struct slice : gtl::span<u8_t> {
	slice(const u8_t *p, size_t len) : span<u8_t>()
	{
		p_ = (u8_t *)p;
		size_ = len;
	}

	slice get_p(ptrdiff_t offset, size_t len) const
	{
		if (offset < 0 || len < 0) {
			return {nullptr, 0};
		}
		if (offset + len > this->size()) {
			return {nullptr, 0};
		}
		return {cbegin() + offset, len};
	}

	int get_u8(ptrdiff_t offset) const;

	const char *str() const { return (const char *)cbegin(); }
};

struct str_slice : public slice {
	str_slice(const char *msg) : slice((u8_t *)msg, strlen(msg)) {}
};

template <int N> struct fixed_slice : public slice {
	fixed_slice() : slice(buf_, N) {}

      private:
	u8_t buf_[N];
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
void u2f_dump_hex(const char *msg, const slice &s);

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
