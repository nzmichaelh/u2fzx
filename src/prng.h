/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <sys/types.h>

void prng_add_entropy(u32_t ch);
void prng_feed();
void prng_board_init();
