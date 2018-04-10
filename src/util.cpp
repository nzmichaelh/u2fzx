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
#define SYS_LOG_DOMAIN "u2f"
#include <logging/sys_log.h>

#include <misc/__assert.h>
#include <misc/byteorder.h>
#include <net/buf.h>
#include <string.h>
#include <zephyr.h>

#include "util.h"

#include "sfs.h"

void u2f_took(const char *msg, int *start)
{
	u32_t now = k_uptime_get_32();
	s32_t took = now - *start;
	*start = now;

	printk("%d (+%d) %s\n", now, took, msg);
}

void u2f_dump_hex(const char *msg, const u8_t *buf, int len)
{
	printk("%u %s(%d): ", k_uptime_get_32(), msg, len);
	for (int i = 0; i < len; i++) {
		printk(" %x", buf[i]);
	}
	printk("\n");
}

void u2f_dump_hex(const char *msg, const gsl::span<u8_t> &s)
{
	u2f_dump_hex(msg, s.cbegin(), s.size());
}
