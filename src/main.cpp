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

#define SYS_LOG_LEVEL 4
#define SYS_LOG_DOMAIN "main"
#include <logging/sys_log.h>

#include "crypto.h"
#include "ui.h"

#include <zephyr.h>

void hid_run();

void main(void)
{
	ui_wink(ui_code::STARTUP);

	/* The crypto init overwrites the seed.  Wait a little for the
	 * power to stabalise to reduce the change of losing the
	 * seed.
	 */
	k_sleep(K_MSEC(2670));

	auto err = u2f_crypto_init();
	if (err) {
		SYS_LOG_ERR("crypto=%d", err.code);
	}

	SYS_LOG_DBG("Starting application");
	ui_wink(ui_code::RUN);

	for (;;) {
		hid_run();
	}
}
