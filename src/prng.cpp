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

#include "prng.h"

struct prng_data {
	struct tc_hmac_prng_struct prng;
	u32_t entropy[17];
	u8_t at;
};

static struct prng_data data;

void prng_add_entropy(u32_t ch)
{
	data.entropy[data.at++] = ch;
	if (data.at >= ARRAY_SIZE(data.entropy)) {
		data.at = 0;
	}
}

int default_CSPRNG(u8_t *buf, unsigned int len)
{
	int err;

	for (;;) {
		err = tc_hmac_prng_generate(buf, len, &data.prng);

		switch (err) {
		case TC_CRYPTO_SUCCESS:
			return err;
		case TC_HMAC_PRNG_RESEED_REQ:
			prng_feed();
			err = tc_hmac_prng_reseed(
				&data.prng, (u8_t *)data.entropy,
				sizeof(data.entropy), NULL, 0);
			if (err != TC_CRYPTO_SUCCESS) {
				return err;
			}
			break;
		default:
			return TC_CRYPTO_FAIL;
		}
	}
}

static int prng_init(struct device *dev)
{
	int err;

	prng_board_init();

	err = tc_hmac_prng_init(&data.prng, (u8_t *)data.entropy,
				sizeof(data.entropy));
	if (err != TC_CRYPTO_SUCCESS) {
		return -ENOMEM;
	}
	return 0;
}

SYS_INIT(prng_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
