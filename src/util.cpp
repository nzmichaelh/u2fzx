#include "util.h"

slice slice::get_p(ptrdiff_t offset, size_t len) const
{
	if (offset < 0 || len < 0) {
		return {nullptr};
	}
	if (offset + len > this->len) {
		return {nullptr};
	}
	return {.p = p + offset, .len = len};
}

int slice::get_u8(ptrdiff_t offset) const
{
	auto s = get_p(offset, 1);

	if (!s) {
		return -EINVAL;
	}
	return s.p[0];
}
