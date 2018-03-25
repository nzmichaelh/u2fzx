#pragma once

#include <tinycrypt/sha256.h>

#include "error.h"
#include "util.h"

struct sha256 {
	using digest = fixed_slice<TC_SHA256_DIGEST_SIZE>;

	int init();

	void update(const slice &sl, size_t drop=0);
	template <int N> void update(const fixed_slice<N> &sl, size_t drop=0)
	{
		update(static_cast<const slice &>(sl), drop);
	}
	template <typename T> void update(T ch);

	void sum(slice &sl);

      private:
	struct tc_sha256_state_struct sha_;
};

template <typename T> void sha256::update(T ch)
{
	u8_t buf[sizeof(ch)];

	for (int i = sizeof(ch) - 1; i >= 0; i--) {
		buf[i] = static_cast<u8_t>(ch);
		ch >>= 8;
	}

	tc_sha256_update(&sha_, buf, sizeof(buf));
}

error u2f_base64url(const slice &src, slice &dest);
error u2f_rng(slice& dest);
error u2f_crypto_init();

int u2f_mbedtls_rng(void *ctx, u8_t* buf, size_t len);
