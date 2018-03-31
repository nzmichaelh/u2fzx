/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_LEVEL 4
#define SYS_LOG_DOMAIN "main"
#include <logging/sys_log.h>

#include "crypto.h"
#include <zephyr.h>

void hid_run();

void main(void)
{
	/* The crypto init overwrites the seed.  Wait a little for the
	 * power to stabalise to reduce the change of losing the
	 * seed.
	 */
	k_sleep(K_MSEC(670));

	auto err = u2f_crypto_init();
	if (err) {
		SYS_LOG_ERR("crypto=%d", err.code);
	}

	SYS_LOG_DBG("Starting application");

	for (;;) {
		hid_run();
	}
}
