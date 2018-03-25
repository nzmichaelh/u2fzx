#pragma once

#include <errno.h>
#include <string.h>

#include <zephyr/types.h>

struct slice {
	u8_t *p;
	size_t len;

	slice get_p(ptrdiff_t offset, size_t len) const;
	int get_u8(ptrdiff_t offset) const;

	explicit operator bool() const { return len > 0; }
	const char *str() const { return (const char *)p; }

	const u8_t *cbegin() const { return p; }
	const u8_t *cend() const { return p + len; }
};

struct str_slice : public slice {
	str_slice(const char *msg)
	{
		p = (u8_t *)msg;
		len = strlen(msg);
	}
};

template <int N> struct fixed_slice : public slice {
	static const int size = N;

	fixed_slice()
	{
		p = buf_;
		len = N;
	}

      private:
	u8_t buf_[N];
};
