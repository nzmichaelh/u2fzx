/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_LEVEL 4
#define SYS_LOG_DOMAIN "main"
#include <logging/sys_log.h>

#include <zephyr.h>

void hid_run();

void main(void)
{
	SYS_LOG_DBG("Starting application");

	for (;;) {
		hid_run();
	}
}
