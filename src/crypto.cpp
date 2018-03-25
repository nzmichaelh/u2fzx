#define SYS_LOG_LEVEL 4
#define SYS_LOG_DOMAIN "crypto"
#include <logging/sys_log.h>

#include "crypto.h"
#include "sfs.h"

extern "C" {
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
}

#define U2F_SEED "/seed"

struct crypto {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
};

static crypto crypto;

int sha256::init() { return tc_sha256_init(&sha_); }

void sha256::update(const slice &sl, size_t drop)
{
	if (sl && drop < sl.len) {
		tc_sha256_update(&sha_, sl.p + drop, sl.len - drop);
	}
}

void sha256::sum(slice &sl) { tc_sha256_final(sl.p, &sha_); }

int u2f_mbedtls_rng(void *ctx, u8_t* buf, size_t len)
{
	SYS_LOG_DBG("len=%d", len);

	return mbedtls_ctr_drbg_random(&crypto.ctr_drbg, buf, len);
}

error u2f_rng(slice& dest)
{
	SYS_LOG_DBG("");

	return error(u2f_mbedtls_rng(nullptr, dest.p, dest.len));
}

int mbedtls_platform_std_nv_seed_read(u8_t *buf, size_t len)
{
	struct sfs_file fp;
	int err;

	SYS_LOG_DBG("len=%d", len);

	err = sfs_open(&fp, U2F_SEED);
	if (err != 0) {
		SYS_LOG_DBG("open");
		return err;
	}

	auto got = sfs_read(&fp, buf, len);
	if (got < 0) {
		SYS_LOG_DBG("read");
		return got;
	}
	if ((size_t)got != len) {
		SYS_LOG_DBG("short");
		return -EIO;
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

	return error(mbedtls_ctr_drbg_seed(
			     &crypto.ctr_drbg,
			     mbedtls_entropy_func, &crypto.entropy,
			     NULL, 0));
}
