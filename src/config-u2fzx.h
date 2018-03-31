/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

extern void *stderr;
void u2f_fprintf(void *, const char *, ...);

/* System support */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_EXIT_ALT
#define MBEDTLS_NO_PLATFORM_ENTROPY
//#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#define MBEDTLS_PLATFORM_PRINTF_ALT
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_TIMING_C
#define MBEDTLS_TIMING_ALT
#define MBEDTLS_ENTROPY_NV_SEED
#define MBEDTLS_MEMORY_DEBUG
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_PLATFORM_FPRINTF_MACRO u2f_fprintf

/* mbed TLS feature support */
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM

/* mbed TLS modules */
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
//#define MBEDTLS_CCM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
//#define MBEDTLS_CMAC_C
//#define MBEDTLS_ECJPAKE_C
#define MBEDTLS_ECP_C
//#define MBEDTLS_HMAC_DRBG_C
//#define MBEDTLS_MD_C
//#define MBEDTLS_OID_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_ECDSA_C

/* Save RAM at the expense of ROM */
#define MBEDTLS_AES_ROM_TABLES

/* Save RAM by adjusting to our exact needs */
#define MBEDTLS_ECP_MAX_BITS 256
#define MBEDTLS_MPI_MAX_SIZE 32 // 256 bits is 32 bytes

unsigned int mbedtls_timing_hardclock(void);
int mbedtls_platform_std_nv_seed_read(unsigned char *buf,
				      unsigned int buf_len);
int mbedtls_platform_std_nv_seed_write(unsigned char *buf,
				       unsigned int buf_len);

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
