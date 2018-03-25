/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <device.h>
#include <init.h>
#include <misc/byteorder.h>
#include <net/buf.h>
#include <string.h>
#include <zephyr.h>

#include <tinycrypt/constants.h>
#include <tinycrypt/hmac_prng.h>
#include <tinycrypt/ecc_platform_specific.h>

extern "C" {
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
}

#include "prng.h"

struct prng_data {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	u32_t personalization[6];
};

static struct prng_data data;

static int prng_init(struct device *dev)
{
	int err;

	prng_board_init();

	mbedtls_entropy_init(&data.entropy);

	err = mbedtls_ctr_drbg_seed(
		&data.ctr_drbg,
		mbedtls_entropy_func,
		&data.entropy,
		(const unsigned char *)data.personalization,
		sizeof(data.personalization));

	if (err != 0) {
		return err;
	}

	return 0;
}

SYS_INIT(prng_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
