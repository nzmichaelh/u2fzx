/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <errno.h>
#include <zephyr/types.h>

#define ERROR(_code) { .code = static_cast<s16_t>(_code) }

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
};
