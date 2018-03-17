/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_LEVEL 4
#define SYS_LOG_DOMAIN "u2f"
#include <logging/sys_log.h>

#include <misc/byteorder.h>
#include <net/buf.h>
#include <string.h>
#include <zephyr.h>

#include <mbedtls/base64.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/ecc_dsa.h>
#include <tinycrypt/ecc_platform_specific.h>
#include <tinycrypt/sha256.h>

#include "sfs.h"

#define U2F_EC_FMT_UNCOMPRESSED 0x04

#define U2F_EC_POINT_SIZE 32
#define U2F_EC_PUBKEY_SIZE 65
#define U2F_APDU_SIZE 7
#define U2F_CHALLENGE_SIZE 32
#define U2F_APPLICATION_SIZE 32
#define U2F_KEY_HANDLE_ID_SIZE 8
#define U2F_KEY_HANDLE_KEY_SIZE 36
#define U2F_KEY_HANDLE_SIZE (U2F_KEY_HANDLE_KEY_SIZE + U2F_KEY_HANDLE_ID_SIZE)
#define U2F_REGISTER_REQUEST_SIZE (U2F_CHALLENGE_SIZE + U2F_APPLICATION_SIZE)
#define U2F_MAX_REQUEST_PAYLOAD                                              \
	(1 + U2F_CHALLENGE_SIZE + U2F_APPLICATION_SIZE + 1 +                 \
	 U2F_KEY_HANDLE_SIZE)

/* U2F native commands */
#define U2F_REGISTER 0x01
#define U2F_AUTHENTICATE 0x02
#define U2F_VERSION 0x03
#define U2F_VENDOR_FIRST 0xc0
#define U2F_VENDOR_LAST 0xff

#define U2F_ERASE 0xc1
#define U2F_SET_CERTIFICATE 0xc2
#define U2F_SET_PRIVATE_KEY 0xc3

/* U2F_CMD_REGISTER command defines */
#define U2F_REGISTER_ID 0x05
#define U2F_REGISTER_HASH_ID 0x00

/* U2F Authenticate */
#define U2F_AUTHENTICATE_CHECK 0x7
#define U2F_AUTHENTICATE_SIGN 0x3

/* Command status responses */
#define U2F_SW_NO_ERROR 0x9000
#define U2F_SW_WRONG_DATA 0x6984
#define U2F_SW_CONDITIONS_NOT_SATISFIED 0x6985
#define U2F_SW_INS_NOT_SUPPORTED 0x6d00
#define U2F_SW_WRONG_LENGTH 0x6700
#define U2F_SW_CLASS_NOT_SUPPORTED 0x6E00
#define U2F_SW_WRONG_PAYLOAD 0x6a80
#define U2F_SW_INSUFFICIENT_MEMORY 0x9210

#define U2F_PRIVATE_KEY_NAME "/attest.pk"
#define U2F_CERTIFICATE_NAME "/attest.der"

struct slice {
	const u8_t *p;
	int len;
};

static u16_t u2f_map_err(int err)
{
	switch (err) {
	case 0:
		return U2F_SW_NO_ERROR;
	case -EINVAL:
		return U2F_SW_WRONG_DATA;
	case -EPERM:
		return U2F_SW_CONDITIONS_NOT_SATISFIED;
	case -ENOENT:
		return U2F_SW_INS_NOT_SUPPORTED;
	case -ENOMEM:
		return U2F_SW_INSUFFICIENT_MEMORY;
	default:
		SYS_LOG_DBG("err=%d", err);
		return U2F_SW_WRONG_DATA;
	}
}

const u8_t *get_p(struct slice *s, int offset, int len)
{
	if (offset < 0 || len < 0) {
		return NULL;
	}
	if (offset + len > s->len) {
		return NULL;
	}
	return s->p + offset;
}

int get_u8(struct slice *s, int offset)
{
	const u8_t *p = get_p(s, offset, 1);

	if (p == NULL) {
		return -EINVAL;
	}
	return *p;
}

void dump_hex(const char *msg, const u8_t *buf, int len)
{
	printk("%s(%d): ", msg, len);
	for (int i = 0; i < len; i++) {
		printk(" %x", buf[i]);
	}
	printk("\n");
}

static int net_buf_add_varint(struct net_buf *resp, const u8_t *buf, int len)
{
	net_buf_add_u8(resp, 0x02);

	if ((buf[0] & 0x80) != 0) {
		net_buf_add_le16(resp, len + 1);
		net_buf_add_mem(resp, buf, len);

		return len + 1 + 2;
	}

	net_buf_add_u8(resp, len);
	net_buf_add_mem(resp, buf, len);

	return len + 1 + 1;
}

static void net_buf_add_x962(struct net_buf *resp, const u8_t *signature)
{
	/* Encode the signature in X9.62 format */
	net_buf_add_u8(resp, 0x30);
	u8_t *len = net_buf_add(resp, 1);

	*len = 0;

	*len += net_buf_add_varint(resp, &signature[0], 32);
	*len += net_buf_add_varint(resp, &signature[32], 32);
}

static int u2f_write_file(const char *fname, struct slice *pc)
{
	struct sfs_file fp;
	int err;

	err = sfs_open(&fp, fname);
	if (err != 0) {
		SYS_LOG_ERR("sfs_open err=%d", err);
		return err;
	}

	err = sfs_write(&fp, pc->p, pc->len);
	if (err != pc->len) {
		SYS_LOG_ERR("sfs_write err=%d", err);
		return err;
	}

	err = sfs_close(&fp);
	if (err != 0) {
		SYS_LOG_ERR("sfs_close err=%d", err);
		return err;
	}

	return 0;
}

static int u2f_read_file(const char *fname, u8_t *buf, int len)
{
	struct sfs_dirent entry;
	struct sfs_file fp;
	int err;

	err = sfs_stat(fname, &entry);
	if (err != 0) {
		SYS_LOG_ERR("sfs_stat");
		return err;
	}

	err = sfs_open(&fp, fname);
	if (err != 0) {
		SYS_LOG_ERR("sfs_open");
		return err;
	}

	err = sfs_read(&fp, buf, len);
	sfs_close(&fp);

	return err;
}

static int u2f_write_private(const u8_t *private, u8_t *handle)
{
	struct slice s = {
		.p = private, .len = 32,
	};

	for (;;) {
		u8_t key[6];
		struct sfs_dirent entry;
		int err;
		size_t olen;

		handle[0] = '/';

		/* Create a handle */
		if (default_CSPRNG(key, sizeof(key)) != TC_CRYPTO_SUCCESS) {
			SYS_LOG_ERR("default_CSPRNG");
			return -EIO;
		}

		/* Make the handle printable */
		err = mbedtls_base64_encode(handle + 1, 8 + 1, &olen, key,
					    sizeof(key));
		if (err != 0) {
			SYS_LOG_ERR("base64_encode err=%d", err);
			return -ENOMEM;
		}

		strcat(handle, ".pk");

		if (sfs_stat(handle, &entry) == 0) {
			/* Handle already exists, try again. */
			continue;
		}

		err = u2f_write_file(handle, &s);
		if (err != 0) {
			SYS_LOG_ERR("err=%d", err);
			return err;
		}

		return 0;
	}
	while (true)
		;
}

static int u2f_authenticate(int p1, struct slice *pc, int le,
			    struct net_buf *resp)
{
	const u8_t *chal = get_p(pc, 0, 32);
	const u8_t *app = get_p(pc, 32, 32);
	int l = get_u8(pc, 64);
	const u8_t *handle = get_p(pc, 65, l);
	u8_t fname[MAX_FILE_NAME + 1];
	int err;

	SYS_LOG_DBG("chal=%p app=%p l=%d handle=%p", chal, app, l, handle);

	if (chal == NULL || app == NULL || l < 0 || handle == NULL) {
		return -EINVAL;
	}

	dump_hex("chal", chal, 32);
	dump_hex("app", app, 32);
	dump_hex("handle", handle, l);

	if (l != MAX_FILE_NAME) {
		return -EINVAL;
	}
	memcpy(fname, handle, l);
	fname[sizeof(fname) - 1] = '\0';

	/* Fetch the private key */
	u8_t private[32];

	err = u2f_read_file(fname, private, sizeof(private));
	if (err != sizeof(private)) {
		return -EINVAL;
	}

	dump_hex("private", private, sizeof(private));

	/* Add user presence */
	net_buf_add_u8(resp, 1);

	/* Add the press counter */
	net_buf_add_be32(resp, 0x01010101);

	/* Generate the digest */
	struct tc_sha256_state_struct sha;

	if (tc_sha256_init(&sha) != TC_CRYPTO_SUCCESS) {
		SYS_LOG_ERR("tc_sha256_init");
		return -ENOMEM;
	}

	tc_sha256_update(&sha, app, 32);

	u8_t ch = 1;

	tc_sha256_update(&sha, &ch, sizeof(ch));

	u8_t w[sizeof(u32_t)];
	sys_put_be32(1, w);

	tc_sha256_update(&sha, w, sizeof(w));
	tc_sha256_update(&sha, chal, 32);

	u8_t digest[TC_SHA256_DIGEST_SIZE];

	tc_sha256_final(digest, &sha);

	/* Generate the signature */
	u8_t signature[64];

	if (uECC_sign(private, digest, sizeof(digest), signature,
		      uECC_secp256r1()) != TC_CRYPTO_SUCCESS) {
		SYS_LOG_ERR("uECC_sign");
		return -ENOMEM;
	}

	net_buf_add_x962(resp, signature);

	return 0;
}

static int u2f_register(int p1, struct slice *pc, int le,
			struct net_buf *resp)
{
	const u8_t *chal = get_p(pc, 0, 32);
	const u8_t *app = get_p(pc, 32, 32);
	u8_t private[32];
	u8_t ch;
	int err;

	if (pc->len != 64) {
		SYS_LOG_ERR("lc=%d", pc->len);
		return -EINVAL;
	}

	/* Add the header */
	net_buf_add_u8(resp, 0x05);

	/* Reserve space for the public key */
	net_buf_add_u8(resp, U2F_EC_FMT_UNCOMPRESSED);
	u8_t *public = net_buf_add(resp, 64);

	/* Generate a new public/private key pair */
	if (uECC_make_key(public, private, uECC_secp256r1()) !=
	    TC_CRYPTO_SUCCESS) {
		SYS_LOG_ERR("uECC_make_key");
		return -ENOMEM;
	}

	u8_t handle[MAX_FILE_NAME + 1];

	err = u2f_write_private(private, handle);
	if (err != 0) {
		SYS_LOG_ERR("write_private");
		return err;
	}

	net_buf_add_u8(resp, sizeof(handle) - 1);
	net_buf_add_mem(resp, handle, sizeof(handle) - 1);

	/* Add the attestation certificate */
	err = u2f_read_file(U2F_CERTIFICATE_NAME, net_buf_tail(resp),
			    net_buf_tailroom(resp));
	if (err < 0) {
		return err;
	}
	if (err == 0) {
		return -EINVAL;
	}
	net_buf_add(resp, err);

	/* Generate the digest */
	struct tc_sha256_state_struct sha;

	if (tc_sha256_init(&sha) != TC_CRYPTO_SUCCESS) {
		SYS_LOG_ERR("tc_sha256_init");
		return -ENOMEM;
	}

	ch = 0;
	tc_sha256_update(&sha, &ch, sizeof(ch));
	tc_sha256_update(&sha, app, 32);
	tc_sha256_update(&sha, chal, 32);
	tc_sha256_update(&sha, handle, sizeof(handle) - 1);
	ch = U2F_EC_FMT_UNCOMPRESSED;
	tc_sha256_update(&sha, &ch, sizeof(ch));
	tc_sha256_update(&sha, public, 64);

	u8_t digest[TC_SHA256_DIGEST_SIZE];

	tc_sha256_final(digest, &sha);

	/* Generate the signature */
	u8_t signature[64];
	u8_t key[32];

	err = u2f_read_file(U2F_PRIVATE_KEY_NAME, key, sizeof(key));
	if (err < 0) {
		return err;
	}
	if (err != sizeof(key)) {
		return -EINVAL;
	}
	if (uECC_sign(key, digest, sizeof(digest), signature,
		      uECC_secp256r1()) != TC_CRYPTO_SUCCESS) {
		SYS_LOG_ERR("uECC_sign");
		return -ENOMEM;
	}

	net_buf_add_x962(resp, signature);

	return 0;
}

static int u2f_version(int p1, struct slice *pc, int le, struct net_buf *resp)
{
	net_buf_add_mem(resp, "U2F_V2", 6);

	return 0;
}

static int u2f_write_once(const char *fname, struct slice *pc)
{
	struct sfs_dirent entry;

	if (sfs_stat(fname, &entry) == 0) {
		SYS_LOG_ERR("%s exists", fname);
		return -EEXIST;
	}

	return u2f_write_file(fname, pc);
}

static int u2f_set_private_key(struct slice *pc)
{
	if (pc->len != 32) {
		return -EINVAL;
	}

	return u2f_write_once(U2F_PRIVATE_KEY_NAME, pc);
}

static int u2f_set_certificate(struct slice *pc)
{
	return u2f_write_once(U2F_CERTIFICATE_NAME, pc);
}

static int u2f_erase(void)
{
	struct sfs_dir dir;
	int err;

	err = sfs_opendir(&dir, "/");
	if (err != 0) {
		return err;
	}

	for (;;) {
		struct sfs_dirent ent;

		err = sfs_readdir(&dir, &ent);
		SYS_LOG_DBG("err=%d name=%s", err, ent.name);

		if (err != 0) {
			goto err;
		}

		if (ent.name[0] == '\0') {
			return sfs_closedir(&dir);
		}

		err = sfs_unlink(ent.name);
		if (err != 0) {
			goto err;
		}
	}

err:
	sfs_closedir(&dir);
	return err;
}

int u2f_dispatch(struct net_buf *req, struct net_buf *resp)
{
	u8_t cla;
	u8_t ins;
	u8_t p1;
	u8_t p2;
	struct slice pc;
	u16_t le = 0;
	int err;

	SYS_LOG_DBG("");

	dump_hex("<<", req->data, req->len);

	cla = net_buf_pull_u8(req);
	if (cla != 0) {
		SYS_LOG_ERR("bad cla");
		return -EINVAL;
	}

	ins = net_buf_pull_u8(req);
	p1 = net_buf_pull_u8(req);
	p2 = net_buf_pull_u8(req);

	if (net_buf_pull_u8(req) != 0) {
		SYS_LOG_ERR("Bad lc header");
		return -EINVAL;
	}

	pc.len = net_buf_pull_be16(req);
	pc.p = req->data;
	req->data += pc.len;
	req->len -= pc.len;

	if (req->len > 0) {
		le = net_buf_pull_be16(req);
	}

	SYS_LOG_DBG("ins=%d p1=%d p2=%d lc=%d le=%d", ins, p1, p2, pc.len,
		    le);
	switch (ins) {
	case U2F_REGISTER:
		err = u2f_register(p1, &pc, le, resp);
		break;
	case U2F_AUTHENTICATE:
		err = u2f_authenticate(p1, &pc, le, resp);
		break;
	case U2F_VERSION:
		err = u2f_version(p1, &pc, le, resp);
		break;
	case U2F_SET_PRIVATE_KEY:
		err = u2f_set_private_key(&pc);
		break;
	case U2F_SET_CERTIFICATE:
		err = u2f_set_certificate(&pc);
		break;
	case U2F_ERASE:
		err = u2f_erase();
		break;
	default:
		SYS_LOG_ERR("ins=%d not supported", ins);
		err = -ENOENT;
		break;
	}

	SYS_LOG_DBG("err=%d", err);
	net_buf_add_be16(resp, u2f_map_err(err));

	return 0;
}
