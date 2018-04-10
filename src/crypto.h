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

#pragma once

#include "util.h"

#include <array>

int u2f_mbedtls_rng(void *ctx, u8_t *buf, size_t len);

size_t u2f_base64url(const gsl::span<u8_t> src, gsl::span<char> dest);
error u2f_rng(gsl::span<u8_t> dest);
std::array<u32_t, 6> u2f_crypto_custom();

error u2f_crypto_init();
