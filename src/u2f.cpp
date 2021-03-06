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

#include <optional>

#include <misc/__assert.h>
#include <misc/byteorder.h>
#include <net/buf.h>
#include <string.h>
#include <zephyr.h>

#include <mbedtls/asn1.h>
#include <mbedtls/memory_buffer_alloc.h>

#include "crypto.h"
#include "tlspp.h"
#include "ugsl.h"
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
#define U2F_SET_SEED 0xc4

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
#define U2F_SEED_NAME "/seed"

using u2f_key = std::array<u8_t, 32>;
using u2f_filename = std::array<char, MAX_FILE_NAME + 1>;
using u2f_handle = std::array<u8_t, 6>;

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

static ui_code u2f_map_err_wink(error err)
{
	switch (err.code) {
	case 0:
		/* Fallthrough */
	case -EPERM:
		return ui_code::INVALID;
	case -EINVAL:
		return ui_code::ERROR_INVAL;
	case -ENOENT:
		return ui_code::ERROR_NOENT;
	case -ENOMEM:
		return ui_code::ERROR_NOMEM;
	default:
		return ui_code::ERROR;
	}
}

static u2f_filename u2f_make_filename(const gsl::span<u8_t> handle)
{
	u2f_filename fname;

	auto *p = fname.begin();
	*p++ = '/';
	/* Make the handle printable */
	p += u2f_base64url(handle, {p, (size_t)(fname.end() - p)});
	*p++ = '.';
	*p++ = 'k';
	*p++ = '\0';

	SYS_LOG_DBG("'%s'", fname.data());

	return fname;
}

/* Add a key as a ASN.1 integer to the response */
static size_t net_buf_add_integer(struct net_buf *resp, const mpi &m)
{
	u2f_key sl;
	if (mbedtls_mpi_write_binary(&m.w, sl.begin(), sl.size()) != 0) {
		SYS_LOG_ERR("write_binary size=%d", mbedtls_mpi_size(&m.w));
		return 0;
	}

	bool leading_zero = (sl[0] & 0x80) != 0;
	auto len = sl.size();

	if (leading_zero) {
		len++;
	}

	net_buf_add_u8(resp, MBEDTLS_ASN1_INTEGER);
	net_buf_add_u8(resp, len);
	if (leading_zero) {
		net_buf_add_u8(resp, 0);
	}
	net_buf_add_mem(resp, sl.cbegin(), sl.size());

	return len + 1 + 1;
}

/* Add a key pair as a X9.64 pair to the response */
static void net_buf_add_x962(struct net_buf *resp, const mpi &r, const mpi &s)
{
	/* Encode the signature in X9.62 format */
	net_buf_add_u8(resp,
		       MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED);
	u8_t *len = (u8_t *)net_buf_add(resp, 1);

	*len = 0;
	*len += net_buf_add_integer(resp, r);
	*len += net_buf_add_integer(resp, s);
}

static error u2f_read_key(const string fname, mpi &key)
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

static std::optional<u2f_handle> u2f_write_private(const mbedtls_mpi &priv)
{
	for (auto tries = 0; tries < 10; tries++) {
		struct sfs_dirent entry;

		/* Create a handle */
		u2f_handle handle;

		auto err = u2f_rng(handle);
		if (err) {
			SYS_LOG_ERR("make handle");
			return {};
		}

		u2f_filename fname = u2f_make_filename(handle);

		if (sfs_stat(fname.begin(), &entry) == 0) {
			/* Handle already exists, try again. */
			continue;
		}

		u2f_key key;
		if (mbedtls_mpi_write_binary(&priv, key.begin(),
					     key.size()) != 0) {
			return {};
		}

		err = u2f_write_file(fname.cbegin(), key);
		if (err) {
			SYS_LOG_ERR("write_file err=%d", err.code);
			return {};
		}

		return handle;
	}
	return {};
}

static error u2f_authenticate(int p1, const gsl::span<u8_t> &pc, int le,
			      struct net_buf *resp)
{
	auto chal = pc.subspan(0, 32);
	auto app = pc.subspan(32, 32);
	auto ls = pc.subspan(64, 1);

	if (chal.empty() || app.empty() || ls.empty()) {
		return error::inval;
	}

	auto l = ls.at(0);
	auto handle = pc.subspan(65, l);
	if (handle.empty()) {
		return error::inval;
	}

	SYS_LOG_DBG("chal=%p app=%p l=%d handle=%p:%d", chal.cbegin(),
		    app.cbegin(), l, handle.cbegin(), handle.size());


	if (p1 != U2F_AUTHENTICATE_SIGN) {
		return error::inval;
	}

	if (!ui_user_present(ui_code::AUTHENTICATE)) {
		SYS_LOG_INF("user not present");
		return error::perm;
	}

	/* Add user presence */
	net_buf_add_u8(resp, 1);

	/* Add the press counter */
	net_buf_add_be32(resp, 1);

	/* Generate the digest */
	auto digest = sha256().update(app)
			      .update_be<u8_t>(1)
			      .update_be<u32_t>(1)
			      .update(chal)
			      .final();

	/* Generate the signature */
	mpi r, s, d;

	auto fname = u2f_make_filename(handle);
	/* Fetch the private key */
	if (u2f_read_key(fname.begin(), d)) {
		SYS_LOG_ERR("read d fname=%s", fname.data());
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

	net_buf_add_x962(resp, r, s);

	return error::ok;
}

static error u2f_register(int p1, const struct gsl::span<u8_t> &pc, int le,
			  struct net_buf *resp)
{
	auto chal = pc.subspan(0, 32);
	auto app = pc.subspan(32, 32);
	error err;
	int now = 0;
	size_t len;

	u2f_took("start", &now);
	if (chal.empty() || app.empty()) {
		return error::inval;
	}

	if (!ui_user_present(ui_code::REGISTER)) {
		return error::perm;
	}

	/* Add the header */
	net_buf_add_u8(resp, U2F_REGISTER_ID);

	/* Reserve space for the public key */
	gsl::span<u8_t> pub{(u8_t *)net_buf_add(resp, 65), 65};

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

	auto handle = u2f_write_private(ctx.w.d);
	if (!handle) {
		SYS_LOG_ERR("write_private");
		return err;
	}
	u2f_took("write key", &now);

	net_buf_add_u8(resp, handle->size());
	net_buf_add_mem(resp, handle->cbegin(), handle->size());

	/* Add the attestation certificate */
	gsl::span<u8_t> tail{net_buf_tail(resp), net_buf_tailroom(resp)};

	auto read = u2f_read_file(U2F_CERTIFICATE_NAME, tail);
	if (read < 0) {
		return ERROR(read);
	}
	if (read == 0) {
		return error::inval;
	}

	net_buf_add(resp, read);
	u2f_took("read attest", &now);

	/* Generate the digest */
	auto digest = sha256().update_be<u8_t>(U2F_REGISTER_HASH_ID)
			      .update(app)
			      .update(chal)
			      .update(*handle)
			      .update_be<u8_t>(U2F_EC_FMT_UNCOMPRESSED)
			      .update(pub, 1)
			      .final();

	u2f_took("sha", &now);

	/* Generate the signature */
	mpi r, s, a;

	if (u2f_read_key(U2F_PRIVATE_KEY_NAME, a)) {
		return error::inval;
	}

	if (mbedtls_ecdsa_sign(&ctx.w.grp, &r.w, &s.w, &a.w, digest.begin(),
			       digest.size(), u2f_mbedtls_rng,
			       nullptr) != 0) {
		SYS_LOG_ERR("ecdsa_sign");
		return error::nomem;
	}
	u2f_took("sign", &now);

	net_buf_add_x962(resp, r, s);

	return error::ok;
}

static error u2f_version(int p1, const gsl::span<u8_t> &pc, int le,
			 struct net_buf *resp)
{
	net_buf_add_mem(resp, "U2F_V2", 6);

	return error::ok;
}

static error u2f_write_once(string fname, const gsl::span<u8_t> &pc)
{
	struct sfs_dirent entry;

	if (sfs_stat(fname.c_str(), &entry) == 0) {
		SYS_LOG_ERR("%s exists", fname.c_str());
		return error::exist;
	}

	return u2f_write_file(fname, pc);
}

static error u2f_set_private_key(const gsl::span<u8_t> &pc)
{
	if (pc.size() != 32) {
		return error::inval;
	}
	return u2f_write_once(U2F_PRIVATE_KEY_NAME, pc);
}

static error u2f_set_certificate(const gsl::span<u8_t> &pc)
{
	return u2f_write_once(U2F_CERTIFICATE_NAME, pc);
}

static error u2f_set_seed(const gsl::span<u8_t> &pc)
{
	if (pc.size() < 32) {
		return error::inval;
	}
	return u2f_write_once(U2F_SEED_NAME, pc);
}

static error u2f_erase(void)
{
	struct sfs_dir dir;
	int status;

	status = sfs_opendir(&dir, "/");
	if (status != 0) {
		return ERROR(status);
	}
	auto _ = gsl::finally([&dir] { sfs_closedir(&dir); });

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

static error u2f_vendor(u8_t p1, u8_t p2, const gsl::span<u8_t> &pc)
{
	switch (p1) {
	case U2F_SET_PRIVATE_KEY:
		return u2f_set_private_key(pc);
	case U2F_SET_CERTIFICATE:
		return u2f_set_certificate(pc);
	case U2F_SET_SEED:
		return u2f_set_seed(pc);
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
	gsl::span<u8_t> pc{req->data, len};

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

#ifdef MBEDTLS_MEMORY_DEBUG
	mbedtls_memory_buffer_alloc_status();

	size_t max_used, max_blocks;
	mbedtls_memory_buffer_alloc_max_get(&max_used, &max_blocks);

	SYS_LOG_DBG("used=%d blocks=%d", max_used, max_blocks);
#endif

	if (err) {
		SYS_LOG_ERR("err=%d", err.code);
		ui_wink(u2f_map_err_wink(err));
	}

	net_buf_add_be16(resp, u2f_map_err(err));

	return error::ok;
}
