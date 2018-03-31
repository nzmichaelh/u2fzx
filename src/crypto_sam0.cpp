/*
 * Copyright (c) 2018 Google LLC.
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

#define SERIAL_0 0x0080A00C
#define SERIAL_1 0x0080A040
#define SERIAL_2 0x0080A044
#define SERIAL_3 0x0080A048

std::array<u32_t, 6> u2f_crypto_custom()
{
	std::array<u32_t, 6> c;

	std::fill(c.begin(), c.end(), 0);
	c[0] = *(u32_t *)SERIAL_0;
	c[1] = *(u32_t *)SERIAL_1;
	c[2] = *(u32_t *)SERIAL_2;
	c[3] = *(u32_t *)SERIAL_3;

	return c;
}

u32_t mbedtls_timing_hardclock() {
	printk("mbedtls_timing_hardclock\n");

	return SysTick->VAL;
}
