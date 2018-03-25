#pragma once

extern "C" {
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
}

#include "error.h"
#include "util.h"

struct sha256 {
	using digest = fixed_slice<32>;

	sha256() {
		mbedtls_sha256_init(&sha_);
		mbedtls_sha256_starts_ret(&sha_, 0);
	}
	~sha256() { mbedtls_sha256_free(&sha_); }

	void update(const slice &sl, size_t drop = 0);
	template <int N>
	void update(const fixed_slice<N> &sl, size_t drop = 0)
	{
		update(static_cast<const slice &>(sl), drop);
	}
	template <typename T> void update(T ch);

	void sum(slice &sl);

      private:
	mbedtls_sha256_context sha_;
};

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

error u2f_base64url(const slice &src, slice &dest);
error u2f_rng(slice &dest);
error u2f_crypto_init();

int u2f_mbedtls_rng(void *ctx, u8_t *buf, size_t len);
