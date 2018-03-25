/*
 *  Minimal configuration for using TLS as part of Thread
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * Minimal configuration for using TLS a part of Thread
 * http://threadgroup.org/
 *
 * Distinguishing features:
 * - no RSA or classic DH, fully based on ECC
 * - no X.509
 * - support for experimental EC J-PAKE key exchange
 *
 * See README.txt for usage instructions.
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
#define MBEDTLS_ECP_MAX_BITS             256
#define MBEDTLS_MPI_MAX_SIZE              32 // 256 bits is 32 bytes

unsigned int mbedtls_timing_hardclock(void);
int mbedtls_platform_std_nv_seed_read(unsigned char *buf, unsigned int buf_len);
int mbedtls_platform_std_nv_seed_write(unsigned char *buf, unsigned int buf_len);

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
