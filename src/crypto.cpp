/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_LEVEL 4
#define SYS_LOG_DOMAIN "crypto"
#include <logging/sys_log.h>

#include "crypto.h"
#include "sfs.h"
#include "util.h"

#include <algorithm>

#define U2F_SEED "/seed"

extern "C" {
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>
}

struct crypto {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
};

static crypto crypto;

size_t u2f_base64url(const gsl::span<u8_t> src, gsl::span<char> dest)
{
	static const char alphabet[] = "ABCDEFGHIJKLMNOP"
				       "QRSTUVWXYZabcdef"
				       "ghijklmnopqrstuv"
				       "wxyz0123456789-_";
	size_t out = src.size() * 4 / 3;

	if ((src.size() % 3) != 0 || dest.size() != out) {
		return 0;
	}

	char *p = dest.begin();
	for (size_t i = 0; i < src.size(); i += 3) {
		const auto s = src.cbegin();
		u32_t acc = (s[i + 2] << 16) | (s[i + 1] << 8) | (s[i + 0]);

		for (size_t j = 0; j < 4; j++) {
			*p++ = alphabet[acc % 64];
			acc >>= 6;
		}
	}

	return p - dest.begin();
}

int u2f_mbedtls_rng(void *ctx, u8_t *buf, size_t len)
{
	return mbedtls_ctr_drbg_random(&crypto.ctr_drbg, buf, len);
}

error u2f_rng(gsl::span<u8_t> dest)
{
	return error(u2f_mbedtls_rng(nullptr, dest.begin(), dest.size()));
}

int mbedtls_platform_std_nv_seed_read(u8_t *buf, size_t len)
{
	struct sfs_file fp;

	SYS_LOG_DBG("len=%d", len);

	std::fill(buf, buf + len, 0x55);

	auto err = sfs_open(&fp, U2F_SEED);
	if (err != 0) {
		SYS_LOG_DBG("open");
		return 0;
	}

	auto got = sfs_read(&fp, buf, len);
	if (got < 0) {
		SYS_LOG_DBG("read");
		return 0;
	}
	if ((size_t)got != len) {
		SYS_LOG_DBG("short");
		return 0;
	}
	return 0;
}

int mbedtls_platform_std_nv_seed_write(u8_t *buf, size_t len)
{
	struct sfs_file fp;
	int err;

	SYS_LOG_DBG("len=%d", len);

	err = sfs_open(&fp, U2F_SEED);
	if (err != 0) {
		SYS_LOG_DBG("open");
		return err;
	}

	auto wrote = sfs_write(&fp, buf, len);
	if (wrote < 0) {
		SYS_LOG_DBG("write");
		return wrote;
	}
	if ((size_t)wrote != len) {
		SYS_LOG_DBG("short");
		return -EIO;
	}
	return 0;
}

error u2f_crypto_init()
{
	mbedtls_entropy_init(&crypto.entropy);
	mbedtls_ctr_drbg_init(&crypto.ctr_drbg);

	auto custom = u2f_crypto_custom();
	return error(mbedtls_ctr_drbg_seed(&crypto.ctr_drbg,
					   mbedtls_entropy_func,
					   &crypto.entropy,
					   (u8_t*)custom.data(), custom.size()*sizeof(custom.data()[0])));
}

void *stderr;

extern "C" void u2f_fprintf(void *ignore, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintk(fmt, ap);
	va_end(ap);
}
