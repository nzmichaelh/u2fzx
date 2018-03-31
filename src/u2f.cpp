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

#include <mbedtls/asn1.h>
#include <mbedtls/memory_buffer_alloc.h>

#include "crypto.h"
#include "tlspp.h"
#include "ugtl.h"
#include "ui.h"
#include "util.h"

#define U2F_EC_FMT_UNCOMPRESSED 0x04

/* U2F native commands */
#define U2F_REGISTER 0x01
#define U2F_AUTHENTICATE 0x02
#define U2F_VERSION 0x03
#define U2F_VENDOR_FIRST 0xc0
#define U2F_VENDOR_LAST 0xff
#define U2F_VENDOR_JUJU 0xc9

/* U2F_CMD_REGISTER command defines */
#define U2F_REGISTER_ID 0x05
#define U2F_REGISTER_HASH_ID 0x00

/* U2F Authenticate */
#define U2F_AUTHENTICATE_CHECK 0x7
#define U2F_AUTHENTICATE_SIGN 0x3

/* U2F Vendor Juju */
#define U2F_ERASE 0xc1
#define U2F_SET_CERTIFICATE 0xc2
#define U2F_SET_PRIVATE_KEY 0xc3

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

using u2f_key = std::array<u8_t, 32>;
using u2f_filename = std::array<u8_t, MAX_FILE_NAME + 1>;
using u2f_handle = std::array<char, 8>;

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

static void u2f_make_filename(gtl::span<char> handle, u2f_filename &fname)
{
	auto *p = fname.begin();
	*p++ = '/';
	std::copy(handle.cbegin(), handle.cend(), p);
	p += handle.size() - 1;
	*p++ = '.';
	*p++ = 'k';
	*p++ = '\0';
}

static size_t net_buf_add_der(struct net_buf *resp, gtl::span<u8_t> sp)
{
	bool pad = (sp.at(0) & 0x80) != 0;
	auto len = sp.size();

	if (pad) {
		len++;
	}

	net_buf_add_u8(resp, MBEDTLS_ASN1_INTEGER);
	net_buf_add_u8(resp, len);
	if (pad) {
		net_buf_add_u8(resp, 0);
	}
	net_buf_add_mem(resp, sp.cbegin(), sp.size());

	return len + 1 + 1;
}

static int net_buf_add_varint(struct net_buf *resp, const mbedtls_mpi &m)
{
	u2f_key sl;
	if (mbedtls_mpi_write_binary(&m, sl.begin(), sl.size()) != 0) {
		SYS_LOG_ERR("write_binary size=%d", mbedtls_mpi_size(&m));
		return 0;
	}

	return net_buf_add_der(resp, gtl::span<u8_t>(sl));
}

static void net_buf_add_x962(struct net_buf *resp, const mbedtls_mpi &r,
			     const mbedtls_mpi s)
{
	/* Encode the signature in X9.62 format */
	net_buf_add_u8(resp,
		       MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
	u8_t *len = (u8_t *)net_buf_add(resp, 1);

	*len = 0;

	*len += net_buf_add_varint(resp, r);
	*len += net_buf_add_varint(resp, s);
}

static error u2f_read_key(string fname, mpi &key)
{
	u2f_key buf;

	auto read = u2f_read_file(fname, buf);
	if (read < 0) {
		return ERROR(read);
	}
	if (read != (int)buf.size()) {
		return error::inval;
	}

	if (mbedtls_mpi_read_binary(&key.w, buf.begin(), buf.size())) {
		SYS_LOG_ERR("read key");
		return error::nomem;
	}
	return error::ok;
}

static error u2f_write_private(mbedtls_mpi &priv, gtl::span<char> handle)
{
	for (;;) {
		struct sfs_dirent entry;
		std::array<u8_t, 6> raw;
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

		if (sfs_stat((char *)fname.begin(), &entry) == 0) {
			/* Handle already exists, try again. */
			continue;
		}

		u2f_key key;
		if (mbedtls_mpi_write_binary(&priv, key.begin(),
					     key.size()) != 0) {
			SYS_LOG_ERR("write_binary len=%d",
				    mbedtls_mpi_size(&priv));
			return error::nomem;
		}

		err = u2f_write_file(fname.cbegin(), key);
		if (err) {
			SYS_LOG_ERR("write_file err=%d", err.code);
			return err;
		}

		return error::ok;
	}
}

static error u2f_authenticate(int p1, const struct slice &pc, int le,
			      struct net_buf *resp)
{
	auto chal = pc.get_p(0, 32);
	auto app = pc.get_p(32, 32);
	int l = pc.get_u8(64);
	auto handle = pc.get_p(65, l).cast<char>();

	SYS_LOG_DBG("chal=%p app=%p l=%d handle=%p", chal.cbegin(),
		    app.cbegin(), l, handle.cbegin());

	if (!chal || !app || l != (int)handle.size() || !handle) {
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
	sha.update_it(app);
	sha.update<u8_t>(1);
	sha.update<u32_t>(1);
	sha.update_it(chal);

	sha256::digest digest;

	sha.sum(digest);

	/* Generate the signature */
	mpi r, s, d;

	/* Fetch the private key */
	if (u2f_read_key(fname.begin(), d)) {
		SYS_LOG_ERR("read d");
		return error::inval;
	}

	ecp_group grp;

	if (mbedtls_ecp_group_load(&grp.w, MBEDTLS_ECP_DP_SECP256R1)) {
		SYS_LOG_ERR("group_load");
		return error::nomem;
	}
	if (mbedtls_ecdsa_sign(&grp.w, &r.w, &s.w, &d.w, digest.begin(),
			       digest.size(), u2f_mbedtls_rng, nullptr)) {
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
	int status = mbedtls_ecdsa_genkey(&ctx.w, MBEDTLS_ECP_DP_SECP256R1,
					  u2f_mbedtls_rng, nullptr);
	if (status != 0) {
		SYS_LOG_ERR("uECC_make_key s=%d", status);
		return error::nomem;
	}
	status = mbedtls_ecp_point_write_binary(
		&ctx.w.grp, &ctx.w.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len,
		pub.begin(), pub.size());
	if (status != 0) {
		SYS_LOG_ERR("write_binary s=%d", status);
		return error::nomem;
	}
	if (len != pub.size()) {
		SYS_LOG_ERR("write_binary short %d != %d", len, pub.size());
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

	net_buf_add_u8(resp, handle.size());
	net_buf_add_mem(resp, handle.cbegin(), handle.size());

	/* Add the attestation certificate */
	slice tail = {
		.p = net_buf_tail(resp),
		.len = net_buf_tailroom(resp),
	};
	auto read = u2f_read_file((const u8_t *)U2F_CERTIFICATE_NAME, tail);
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
	sha.update_it(app);
	sha.update_it(chal);
	sha.update_it(handle);
	sha.update<u8_t>(U2F_EC_FMT_UNCOMPRESSED);
	sha.update_it(pub, 1);

	sha256::digest digest;

	sha.sum(digest);
	u2f_took("sha", &now);

	/* Generate the signature */
	mpi r, s, a;

	if (u2f_read_key((const u8_t *)U2F_PRIVATE_KEY_NAME, a)) {
		return error::inval;
	}

	if (mbedtls_ecdsa_sign(&ctx.w.grp, &r.w, &s.w, &a.w, digest.begin(),
			       digest.size(), u2f_mbedtls_rng,
			       nullptr) != 0) {
		SYS_LOG_ERR("ecdsa_sign");
		return error::nomem;
	}
	u2f_took("sign", &now);

	net_buf_add_x962(resp, r.w, s.w); // signature);

	return error::ok;
}

static error u2f_version(int p1, const slice &pc, int le,
			 struct net_buf *resp)
{
	net_buf_add_mem(resp, "U2F_V2", 6);

	return error::ok;
}

static error u2f_write_once(string fname, const struct slice &pc)
{
	struct sfs_dirent entry;

	if (sfs_stat(fname.c_str(), &entry) == 0) {
		SYS_LOG_ERR("%s exists", fname.c_str());
		return error::exist;
	}

	return u2f_write_file(fname, pc);
}

static error u2f_set_private_key(const struct slice &pc)
{
	if (pc.size() != 32) {
		return error::inval;
	}

	return u2f_write_once((const u8_t *)U2F_PRIVATE_KEY_NAME, pc);
}

static error u2f_set_certificate(const struct slice &pc)
{
	return u2f_write_once((const u8_t *)U2F_CERTIFICATE_NAME, pc);
}

static error u2f_erase(void)
{
	struct sfs_dir dir;
	int status;

	status = sfs_opendir(&dir, "/");
	if (status != 0) {
		return ERROR(status);
	}
	auto _ = gtl::finally([&dir] { sfs_closedir(&dir); });

	for (;;) {
		struct sfs_dirent ent;

		status = sfs_readdir(&dir, &ent);
		if (status != 0) {
			return ERROR(status);
		}

		if (ent.name[0] == '\0') {
			return ERROR(sfs_closedir(&dir));
		}

		status = sfs_unlink(ent.name);
		if (status != 0) {
			return ERROR(status);
		}
	}
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

	u2f_dump_hex("<<", req->data, req->len);

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

	auto len = net_buf_pull_be16(req);
	slice pc{req->data, len};

	req->data += len;
	req->len -= len;

	if (req->len > 0) {
		le = net_buf_pull_be16(req);
	}

	SYS_LOG_DBG("ins=%d p1=%d p2=%d lc=%d le=%d", ins, p1, p2, pc.size(),
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
