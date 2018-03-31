/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "util.h"

#include <array>

int u2f_mbedtls_rng(void *ctx, u8_t *buf, size_t len);

error u2f_base64url(const gsl::span<u8_t> src, gsl::span<char> dest);
error u2f_rng(gsl::span<u8_t> dest);
std::array<u32_t, 6> u2f_crypto_custom();

error u2f_crypto_init();
