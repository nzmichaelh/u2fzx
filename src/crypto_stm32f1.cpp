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

#include <string.h>
#include <zephyr.h>

#include "crypto.h"
#include <arch/arm/cortex_m/cmsis.h>

extern "C" {
#include <mbedtls/entropy.h>
}

std::array<u32_t, 6> u2f_crypto_custom()
{
	std::array<u32_t, 6> c;

	std::fill(c.begin(), c.end(), 0);

	return c;
}

u32_t mbedtls_timing_hardclock() {
	printk("mbedtls_timing_hardclock\n");

	return SysTick->VAL;
}
