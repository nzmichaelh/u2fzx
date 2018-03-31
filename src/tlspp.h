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

	template <typename T> void update_it(const T &sp, size_t drop = 0);
	template <typename T> void update(T ch);

	void sum(digest &di) { mbedtls_sha256_finish_ret(&sha_, di.begin()); }

      private:
	mbedtls_sha256_context sha_;
};

template <typename T> void sha256::update_it(const T &sp, size_t drop)
{
	if (!sp.empty() && drop < sp.size()) {
		mbedtls_sha256_update_ret(&sha_, (u8_t *)sp.cbegin() + drop,
					  sp.size() - drop);
	}
}

template <typename T> void sha256::update(T ch)
{
	u8_t buf[sizeof(ch)];

	for (int i = sizeof(ch) - 1; i >= 0; i--) {
		buf[i] = static_cast<u8_t>(ch);
		ch >>= 8;
	}

	mbedtls_sha256_update(&sha_, buf, sizeof(buf));
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
