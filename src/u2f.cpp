/*
 * Copyright (c) 2018 Google LLC.
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

#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/asn1.h>

#include "error.h"
#include "sfs.h"
#include "stdish.h"
#include "ui.h"
#include "util.h"
#include "crypto.h"

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
#define U2F_VENDOR_JUJU 0xc9

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

struct u2f_data {
};

using u2f_key = fixed_slice<32>;
using u2f_filename = fixed_slice<MAX_FILE_NAME + 1>;
using u2f_handle = fixed_slice<8>;

error u2f_base64url(const slice &src, slice &dest)
{
	static const char alphabet[] = "ABCDEFGHIJKLMNOP"
				       "QRSTUVWXYZabcdef"
				       "ghijklmnopqrstuv"
				       "wxyz0123456789-_";
	size_t out = src.len * 4 / 3;

	if ((src.len % 3) != 0 || dest.len != out) {
		return error::inval;
	}

	u8_t *p = dest.p;
	for (size_t i = 0; i < src.len; i += 3) {
		u32_t acc = (src.p[i + 2] << 16) | (src.p[i + 1] << 8) |
			    (src.p[i + 0]);

		for (size_t j = 0; j < 4; j++) {
			*p++ = alphabet[acc % 64];
			acc >>= 6;
		}
	}

	return error::ok;
}

extern "C" void u2f_took(const char *msg, int* start)
{
	u32_t now = k_uptime_get_32();
	s32_t took = now - *start;
	*start = now;

	printk("%d (+%d) %s\n", now, took, msg);
}

static u16_t u2f_map_err(error err)
{
	switch (err.code) {
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
		return U2F_SW_WRONG_DATA;
	}
}

static void u2f_make_filename(const slice &handle, u2f_filename &fname)
{
	u8_t *p = fname.p;
	*p++ = '/';
	std::copy(handle.cbegin(), handle.cend(), p);
	p += handle.len - 1;
	*p++ = '.';
	*p++ = 'p';
	*p++ = 'k';
	*p++ = '\0';
}

void dump_hex(const char *msg, const u8_t *buf, int len)
{
	printk("%u %s(%d): ", k_uptime_get_32(), msg, len);
	for (int i = 0; i < len; i++) {
		printk(" %x", buf[i]);
	}
	printk("\n");
}

void dump_hex(const char *msg, const slice &s) { dump_hex(msg, s.p, s.len); }

static int net_buf_add_der(struct net_buf *resp, const slice &sl)
{
	bool pad = (sl.get_u8(0) & 0x80) != 0;
	int len = sl.len;

	if (pad) {
		len++;
	}

	net_buf_add_u8(resp, MBEDTLS_ASN1_INTEGER);
	net_buf_add_u8(resp, len);
	if (pad) {
		net_buf_add_u8(resp, 0);
	}
	net_buf_add_mem(resp, sl.p, sl.len);

	return len + 1 + 1;
}

static int net_buf_add_varint(struct net_buf *resp, const mbedtls_mpi& m)
{
	fixed_slice<32> sl;
	if (mbedtls_mpi_write_binary(&m, sl.p, sl.len) != 0) {
		SYS_LOG_ERR("write_binary size=%d", mbedtls_mpi_size(&m));
		return 0;
	}

	return net_buf_add_der(resp, sl);
}

static void net_buf_add_x962(struct net_buf *resp, const mbedtls_mpi& r, const mbedtls_mpi s)
{
	/* Encode the signature in X9.62 format */
	net_buf_add_u8(resp, MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
	u8_t *len = (u8_t *)net_buf_add(resp, 1);

	*len = 0;

	*len += net_buf_add_varint(resp, r);
	*len += net_buf_add_varint(resp, s);
}

static error u2f_write_file(const slice &fname, const slice &pc)
{
	struct sfs_file fp;
	int err;

	SYS_LOG_DBG("fname=%s", fname.str());

	err = sfs_open(&fp, fname.str());
	if (err != 0) {
		SYS_LOG_ERR("sfs_open err=%d", err);
		return ERROR(err);
	}

	err = sfs_write(&fp, pc.p, pc.len);
	if (err != (int)pc.len) {
		SYS_LOG_ERR("sfs_write err=%d", err);
		return ERROR(err);
	}

	err = sfs_close(&fp);
	if (err != 0) {
		SYS_LOG_ERR("sfs_close err=%d", err);
		return ERROR(err);
	}

	return error::ok;
}

static int u2f_read_file(const slice &fname, slice &buf)
{
	struct sfs_dirent entry;
	struct sfs_file fp;
	int status;

	SYS_LOG_DBG("fname=%s", fname.str());

	status = sfs_stat(fname.str(), &entry);
	if (status != 0) {
		SYS_LOG_ERR("sfs_stat");
		return status;
	}

	status = sfs_open(&fp, (char *)fname.p);
	if (status != 0) {
		SYS_LOG_ERR("sfs_open");
		return status;
	}

	status = sfs_read(&fp, buf.p, buf.len);
	sfs_close(&fp);

	return status;
}

static error u2f_read_key(const slice &fname, mpi &key)
{
	fixed_slice<32> buf;

	auto read = u2f_read_file(fname, buf);
	if (read < 0) {
		return ERROR(read);
	}
	if (read != (int)buf.len) {
		return error::inval;
	}

	if (mbedtls_mpi_read_binary(&key.w, buf.p, buf.len)) {
		SYS_LOG_ERR("read key");
		return error::nomem;
	}
	return error::ok;
}

static error u2f_write_private(mbedtls_mpi &priv, slice &handle)
{
	for (;;) {
		struct sfs_dirent entry;
		fixed_slice<6> raw;
		error err;

		/* Create a handle */
		err = u2f_rng(raw);
		if (err) {
			SYS_LOG_ERR("make handle");
			return err;
		}

		/* Make the handle printable */
		err = u2f_base64url(raw, handle);
		if (err) {
			SYS_LOG_ERR("base64_encode err=%d", err.code);
			return error::nomem;
		}

		u2f_filename fname;

		u2f_make_filename(handle, fname);

		if (sfs_stat((char *)fname.p, &entry) == 0) {
			/* Handle already exists, try again. */
			continue;
		}

		u2f_key key;
		if (mbedtls_mpi_write_binary(&priv, key.p, key.len) != 0) {
			SYS_LOG_ERR("write_binary len=%d", mbedtls_mpi_size(&priv));
			return error::nomem;
		}

		err = u2f_write_file(fname, key);
		if (err) {
			return err;
		}

		return error::ok;
	}
	while (true)
		;
}

static error u2f_authenticate(int p1, const struct slice &pc, int le,
			      struct net_buf *resp)
{
	auto chal = pc.get_p(0, 32);
	auto app = pc.get_p(32, 32);
	int l = pc.get_u8(64);
	auto handle = pc.get_p(65, l);

	SYS_LOG_DBG("chal=%p app=%p l=%d handle=%p", chal.p, app.p, l,
		    handle.p);

	if (!chal || !app || l != u2f_handle::size || !handle) {
		return error::inval;
	}

	if (p1 != U2F_AUTHENTICATE_SIGN) {
		return error::inval;
	}

	if (!ui_user_present()) {
		SYS_LOG_INF("user not present");
		return error::perm;
	}

	u2f_filename fname;

	u2f_make_filename(handle, fname);

	/* Add user presence */
	net_buf_add_u8(resp, 1);

	/* Add the press counter */
	net_buf_add_be32(resp, 1);

	/* Generate the digest */
	sha256 sha;
	sha.update(app);
	sha.update<u8_t>(1);
	sha.update<u32_t>(1);
	sha.update(chal);

	sha256::digest digest;

	sha.sum(digest);

	/* Generate the signature */
	mpi r, s, d;

	/* Fetch the private key */
	if (u2f_read_key(fname, d)) {
		SYS_LOG_ERR("read d");
		return error::inval;
	}

	ecp_group grp;

	if (mbedtls_ecp_group_load(&grp.w, MBEDTLS_ECP_DP_SECP256R1)) {
		SYS_LOG_ERR("group_load");
		return error::nomem;
	}
	if (mbedtls_ecdsa_sign(&grp.w, &r.w, &s.w,
			       &d.w, digest.p, digest.len,
			       u2f_mbedtls_rng, nullptr)) {
		SYS_LOG_ERR("sign");
		return error::nomem;
	}

	net_buf_add_x962(resp, r.w, s.w);

	return error::ok;
}

static error u2f_register(int p1, const struct slice &pc, int le,
			  struct net_buf *resp)
{
	auto chal = pc.get_p(0, 32);
	auto app = pc.get_p(32, 32);
	error err;
	int now = 0;
	size_t len;

	u2f_took("start", &now);
	if (!chal || !app) {
		return error::inval;
	}

	#if 0
	if (!ui_user_present()) {
		return error::perm;
	}
	#endif

	/* Add the header */
	net_buf_add_u8(resp, U2F_REGISTER_ID);

	/* Reserve space for the public key */
	slice pub = {
		.p = (u8_t *)net_buf_add(resp, 65),
		.len = 65,
	};

	u2f_took("pre-generate key", &now);

	ecdsa_context ctx;

	/* Generate a new public/private key pair */
	int status = mbedtls_ecdsa_genkey(&ctx.w, MBEDTLS_ECP_DP_SECP256R1, u2f_mbedtls_rng, nullptr);
	if (status != 0) {
		SYS_LOG_ERR("uECC_make_key s=%d", status);
		return error::nomem;
	}
	status = mbedtls_ecp_point_write_binary(&ctx.w.grp, &ctx.w.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len, pub.p, pub.len);
	if (status != 0) {
		SYS_LOG_ERR("write_binary s=%d", status);
		return error::nomem;
	}
	if (len != pub.len) {
		SYS_LOG_ERR("write_binary short %d != %d", len, pub.len);
		return error::nomem;
	}

	u2f_took("generate key", &now);

	u2f_handle handle;

	err = u2f_write_private(ctx.w.d, handle);
	if (err) {
		SYS_LOG_ERR("write_private");
		return err;
	}
	u2f_took("write key", &now);

	net_buf_add_u8(resp, handle.len);
	net_buf_add_mem(resp, handle.p, handle.len);

	/* Add the attestation certificate */
	slice tail = {
		.p = net_buf_tail(resp),
		.len = net_buf_tailroom(resp),
	};
	auto read = u2f_read_file(str_slice(U2F_CERTIFICATE_NAME), tail);
	if (read < 0) {
		return ERROR(read);
	}
	if (read == 0) {
		return error::inval;
	}

	net_buf_add(resp, read);
	u2f_took("read attest", &now);

	/* Generate the digest */
	sha256 sha;
	sha.update<u8_t>(U2F_REGISTER_HASH_ID);
	sha.update(app);
	sha.update(chal);
	sha.update(handle);
	sha.update<u8_t>(U2F_EC_FMT_UNCOMPRESSED);
	sha.update(pub, 1);

	sha256::digest digest;

	sha.sum(digest);
	u2f_took("sha", &now);

	/* Generate the signature */
	mpi r, s, a;

	if (u2f_read_key(str_slice(U2F_PRIVATE_KEY_NAME), a)) {
		return error::inval;
	}

	if (mbedtls_ecdsa_sign(&ctx.w.grp, &r.w, &s.w, &a.w, digest.p, digest.len, u2f_mbedtls_rng, nullptr) != 0) {
		SYS_LOG_ERR("ecdsa_sign");
		return error::nomem;
	}
	u2f_took("sign", &now);

	net_buf_add_x962(resp, r.w, s.w); //signature);

	return error::ok;
}

static error u2f_version(int p1, const slice &pc, int le,
			 struct net_buf *resp)
{
	net_buf_add_mem(resp, "U2F_V2", 6);

	return error::ok;
}

static error u2f_write_once(const slice &fname, const struct slice &pc)
{
	struct sfs_dirent entry;

	if (sfs_stat(fname.str(), &entry) == 0) {
		SYS_LOG_ERR("%s exists", fname.str());
		return error::exist;
	}

	return u2f_write_file(fname, pc);
}

static error u2f_set_private_key(const struct slice &pc)
{
	if (pc.len != 32) {
		return error::inval;
	}

	return u2f_write_once(str_slice(U2F_PRIVATE_KEY_NAME), pc);
}

static error u2f_set_certificate(const struct slice &pc)
{
	return u2f_write_once(str_slice(U2F_CERTIFICATE_NAME), pc);
}

static error u2f_erase(void)
{
	struct sfs_dir dir;
	int status;

	status = sfs_opendir(&dir, "/");
	if (status != 0) {
		return ERROR(status);
	}

	for (;;) {
		struct sfs_dirent ent;

		status = sfs_readdir(&dir, &ent);
		if (status != 0) {
			goto err;
		}

		if (ent.name[0] == '\0') {
			return ERROR(sfs_closedir(&dir));
		}

		status = sfs_unlink(ent.name);
		if (status != 0) {
			goto err;
		}
	}

err:
	sfs_closedir(&dir);
	return ERROR(status);
}

static error u2f_vendor(u8_t p1, u8_t p2, struct slice &pc)
{
	switch (p1) {
	case U2F_SET_PRIVATE_KEY:
		return u2f_set_private_key(pc);
	case U2F_SET_CERTIFICATE:
		return u2f_set_certificate(pc);
	case U2F_ERASE:
		return u2f_erase();
	default:
		return error::noent;
	}
}

error u2f_dispatch(struct net_buf *req, struct net_buf *resp)
{
	u16_t le = 0;
	error err;

	dump_hex("<<", req->data, req->len);

	auto cla = net_buf_pull_u8(req);
	if (cla != 0) {
		SYS_LOG_ERR("bad cla");
		return error::inval;
	}

	auto ins = net_buf_pull_u8(req);
	auto p1 = net_buf_pull_u8(req);
	auto p2 = net_buf_pull_u8(req);

	if (net_buf_pull_u8(req) != 0) {
		SYS_LOG_ERR("Bad lc header");
		return error::inval;
	}

	struct slice pc = {
		.p = nullptr,
		.len = net_buf_pull_be16(req),
	};
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
		err = u2f_register(p1, pc, le, resp);
		break;
	case U2F_AUTHENTICATE:
		err = u2f_authenticate(p1, pc, le, resp);
		break;
	case U2F_VERSION:
		err = u2f_version(p1, pc, le, resp);
		break;
	case U2F_VENDOR_JUJU:
		err = u2f_vendor(p1, p2, pc);
		break;
	default:
		SYS_LOG_ERR("ins=%d not supported", ins);
		err = error::noent;
		break;
	}

	mbedtls_memory_buffer_alloc_status();

	size_t max_used, max_blocks;
	mbedtls_memory_buffer_alloc_max_get(&max_used, &max_blocks);

	SYS_LOG_DBG("used=%d blocks=%d", max_used, max_blocks);

	if (err) {
		SYS_LOG_ERR("err=%d", err.code);
	}

	net_buf_add_be16(resp, u2f_map_err(err));

	return error::ok;
}
