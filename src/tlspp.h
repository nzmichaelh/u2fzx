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

/*
 * Tiny wrappers around mbedtls to make it type safe and ensure that
 * memory is released.
 */

#pragma once

#include "util.h"
#include <zephyr/types.h>

#include <array>

extern "C" {
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>
}

struct sha256 {
	using digest = std::array<u8_t, 32>;

	sha256()
	{
		mbedtls_sha256_init(&sha_);
		mbedtls_sha256_starts_ret(&sha_, 0);
	}
	~sha256() { mbedtls_sha256_free(&sha_); }

	template <typename T> sha256& update(const T &sp, size_t skip = 0);
	template <typename T> sha256& update_be(const T ch);

	digest final() {
		digest di;
		mbedtls_sha256_finish_ret(&sha_, di.begin());
		return di;
	}

      private:
	mbedtls_sha256_context sha_;
};

template <typename T> sha256& sha256::update(const T &sp, size_t skip)
{
	if (!sp.empty() && skip < sp.size()) {
		mbedtls_sha256_update_ret(&sha_, (u8_t *)sp.cbegin() + skip,
					  sp.size() - skip);
	}
	return *this;
}

template <typename T> sha256& sha256::update_be(const T ch)
{
	u8_t buf[sizeof(ch)];
	u32_t v = ch;

	for (int i = sizeof(ch) - 1; i >= 0; i--) {
		buf[i] = static_cast<u8_t>(v);
		v >>= 8;
	}

	mbedtls_sha256_update(&sha_, buf, sizeof(buf));
	return *this;
}

struct mpi {
	mbedtls_mpi w;

	mpi() { mbedtls_mpi_init(&w); }
	~mpi() { mbedtls_mpi_free(&w); }
};

struct ecp_group {
	mbedtls_ecp_group w;

	ecp_group() { mbedtls_ecp_group_init(&w); }
	~ecp_group() { mbedtls_ecp_group_free(&w); }
};

struct ecdsa_context {
	mbedtls_ecdsa_context w;

	ecdsa_context() { mbedtls_ecdsa_init(&w); }
	~ecdsa_context() { mbedtls_ecdsa_free(&w); }
};
