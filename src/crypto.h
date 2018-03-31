#pragma once

#include "util.h"

error u2f_rng(gtl::span<u8_t> dest);
error u2f_crypto_init();

int u2f_mbedtls_rng(void *ctx, u8_t *buf, size_t len);
error u2f_base64url(const gtl::span<u8_t> src, gtl::span<char> dest);
