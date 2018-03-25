/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr.h>

#include <arch/arm/cortex_m/cmsis.h>
#include "prng.h"

extern "C" {
#include <mbedtls/entropy.h>
}

#define SERIAL_0 0x0080A00C
#define SERIAL_1 0x0080A040
#define SERIAL_2 0x0080A044
#define SERIAL_3 0x0080A048

void prng_feed() {}
void prng_board_init() {}

#if 0
void prng_feed(void)
{
	prng_add_entropy(SysTick->VAL);
	prng_add_entropy(k_uptime_get_32());
}

void prng_board_init()
{
	prng_add_entropy(*(u32_t *)SERIAL_0);
	prng_add_entropy(*(u32_t *)SERIAL_1);
	prng_add_entropy(*(u32_t *)SERIAL_2);
	prng_add_entropy(*(u32_t *)SERIAL_3);

	prng_feed();
}
#endif

u32_t mbedtls_timing_hardclock()
{
	return SysTick->VAL;
}
