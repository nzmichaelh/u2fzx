/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_LEVEL 4
#define SYS_LOG_DOMAIN "hid"
#include <logging/sys_log.h>

#include <device.h>
#include <init.h>
#include <misc/byteorder.h>
#include <net/buf.h>
#include <string.h>
#include <zephyr.h>

#include <usb/class/usb_hid.h>
#include <usb/usb_device.h>

#include "error.h"
#include "prng.h"
#include "stdish.h"
#include "ui.h"

#define TYPE_MASK 0x80
#define TYPE_INIT 0x80
#define TYPE_CONT 0x00

enum class u2fhid_cmd : u8_t {
	PING = TYPE_INIT | 0x01,
	MSG = TYPE_INIT | 0x03,
	LOCK = TYPE_INIT | 0x04,
	INIT = TYPE_INIT | 0x06,
	WINK = TYPE_INIT | 0x08,
	ERROR = TYPE_INIT | 0x3f,
};

enum class u2fhid_err : u8_t {
	/* No error */
	NONE = 0x00,
	/* Invalid command */
	INVALID_CMD = 0x01,
	/* Invalid parameter */
	INVALID_PAR = 0x02,
	/* Invalid message length */
	INVALID_LEN = 0x03,
	/* Invalid message sequencing */
	INVALID_SEQ = 0x04,
	/* Message has timed out */
	MSG_TIMEOUT = 0x05,
	/* Channel busy */
	CHANNEL_BUSY = 0x06,
	/* Command requires channel lock */
	LOCK_REQUIRED = 0x0a,
	/* Command not allowed on this cid */
	INVALID_CID = 0x0b,
	/* Other unspecified error */
	OTHER = 0x7f,
};

#define CAPABILITY_WINK 0x01
#define CAPABILITY_LOCK 0x02

#define U2FHID_BROADCAST 0xffffffff

#define U2FHID_PACKET_SIZE 64
#define U2FHID_INIT_PAYLOAD_SIZE (U2FHID_PACKET_SIZE - 7)
#define U2FHID_CONT_PAYLOAD_SIZE (U2FHID_PACKET_SIZE - 5)
#define U2FHID_MAX_PAYLOAD_SIZE (7609)

extern struct net_buf_pool hid_msg_pool;
extern struct net_buf_pool hid_rx_pool;

void dump_hex(const char *msg, const u8_t *buf, int len);
error u2f_dispatch(struct net_buf *req, struct net_buf *resp);

struct u2f_init_hdr {
	u32_t cid;
	u2fhid_cmd cmd;
	u8_t bcnt[2];
	u8_t payload[1];
};
BUILD_ASSERT(sizeof(struct u2f_init_hdr) == 8);

struct u2f_init_pkt {
	u32_t cid;
	u2fhid_cmd cmd;
	u8_t bcnt[2];
	u8_t payload[U2FHID_INIT_PAYLOAD_SIZE];
};
BUILD_ASSERT(sizeof(struct u2f_init_pkt) == U2FHID_PACKET_SIZE);

struct u2f_cont_pkt {
	u32_t cid;
	u8_t seq;
	u8_t payload[U2FHID_CONT_PAYLOAD_SIZE];
};
BUILD_ASSERT(sizeof(struct u2f_cont_pkt) == U2FHID_PACKET_SIZE);

struct hid_data {
	u32_t next_channel;
	u32_t cid;

	struct k_fifo rx_q;
	struct k_sem tx_sem;
};

static struct hid_data data;

/* Some HID sample Report Descriptor */
static const u8_t hid_report_desc[] = {
	0x06, 0xd0,
	0xf1,       /* USAGE_PAGE (FIDO Alliance) */
	0x09, 0x01, /* USAGE (Keyboard) */
	0xa1, 0x01, /* COLLECTION (Application) */

	0x09, 0x20, /* USAGE (Input Report Data) */
	0x15, 0x00, /* LOGICAL_MINIMUM (0) */
	0x26, 0xff,
	0x00,			  /* LOGICAL_MAXIMUM (255) */
	0x75, 0x08,		  /* REPORT_SIZE (8) */
	0x95, U2FHID_PACKET_SIZE, /* REPORT_COUNT (64) */
	0x81, 0x02,		  /* INPUT (Data,Var,Abs) */
	0x09, 0x21,		  /* USAGE(Output Report Data) */
	0x15, 0x00,		  /* LOGICAL_MINIMUM (0) */
	0x26, 0xff,
	0x00,			  /* LOGICAL_MAXIMUM (255) */
	0x75, 0x08,		  /* REPORT_SIZE (8) */
	0x95, U2FHID_PACKET_SIZE, /* REPORT_COUNT (64) */
	0x91, 0x02,		  /* OUTPUT (Data,Var,Abs) */

	0xc0, /* END_COLLECTION */
};

static error hid_handle_init(struct net_buf *req, struct net_buf *resp)
{
	net_buf_add_mem(resp, req->data, 8);
	net_buf_pull(req, 8);
	net_buf_add_be32(resp, ++data.next_channel);
	net_buf_add_u8(resp, 2);
	net_buf_add_u8(resp, 0);
	net_buf_add_u8(resp, 1);
	net_buf_add_u8(resp, 0);
	net_buf_add_u8(resp, CAPABILITY_WINK);

	return error::ok;
}

static net_buf *hid_rx_pkt(u8_t type, int min_size, int timeout)
{
	auto rx = net_buf_get(&data.rx_q, timeout);
	autounref rx1{rx};

	if (rx == nullptr) {
		return nullptr;
	}
	dump_hex("<<", rx->data, rx->len);

	if (rx->len < min_size) {
		return nullptr;
	}

	auto hdr = (u2f_init_hdr *)rx->data;
	if ((static_cast<u8_t>(hdr->cmd) & TYPE_MASK) != type) {
		return nullptr;
	}

	net_buf_ref(rx);

	return rx;
}

static net_buf *hid_rx(u32_t &cid, u2fhid_cmd &cmd)
{
	auto rx = hid_rx_pkt(TYPE_INIT, sizeof(u2f_init_hdr), K_FOREVER);
	autounref rx1{rx};

	if (rx == nullptr) {
		return nullptr;
	}

	auto hdr = (u2f_init_pkt *)rx->data;
	cid = hdr->cid;
	cmd = hdr->cmd;

	auto req = net_buf_alloc(&hid_msg_pool, K_NO_WAIT);
	autounref req1{req};

	if (req == nullptr) {
		/* No buffers */
		SYS_LOG_ERR("unable to make a req buffer");
		return nullptr;
	}

	auto bcnt = sys_get_be16(hdr->bcnt);
	if (bcnt > req->size) {
		SYS_LOG_ERR("bcnt=%d is too big for buf %d", bcnt, req->size);
		return nullptr;
	}

	size_t remain = bcnt;
	/* Take everything from the first packet */
	size_t take = min(remain, rx->len - offsetof(u2f_init_pkt, payload));
	net_buf_add_mem(req, hdr->payload, take);
	remain -= take;

	SYS_LOG_DBG("took %d of bcnt=%d from 1st packet", take, bcnt);

	for (u8_t seq = 0; remain > 0; seq++) {
		auto crx =
			hid_rx_pkt(TYPE_CONT, offsetof(u2f_cont_pkt, payload),
				   K_SECONDS(1));
		autounref crx1{crx};

		if (crx == nullptr) {
			SYS_LOG_WRN("timeout while waiting for cont packet");
			return nullptr;
		}

		auto cont = (u2f_cont_pkt *)crx->data;
		if (cont->seq != seq) {
			SYS_LOG_WRN("got seq=%d expect %d on cont packet",
				    cont->seq, seq);
			return nullptr;
		}

		take = min(remain,
			   crx->len - offsetof(u2f_cont_pkt, payload));
		net_buf_add_mem(req, cont->payload, take);
		SYS_LOG_DBG("took %d of remain=%d from seq=%d", take, remain,
			    seq);

		remain -= take;
	}

	net_buf_ref(req);
	return req;
}

static u2fhid_err hid_map_error(error err)
{
	switch (err.code) {
	case 0:
	case -ENOENT:
		return u2fhid_err::INVALID_CMD;
	default:
		SYS_LOG_ERR("unmapped error code=%d", err.code);
		return u2fhid_err::OTHER;
	}
}

static error hid_tx_pkt(const u8_t *buf, int len)
{
	prng_feed();

//	dump_hex(">>", buf, len);

	for (int retry = 0; retry < 10; retry++) {
		u32_t wrote = 0;
		error err = ERROR(
			usb_write(CONFIG_HID_INT_EP_ADDR, buf, len, &wrote));

		switch (err.code) {
		case 0:
			return err;
		case -EAGAIN:
			k_sem_take(&data.tx_sem, K_MSEC(100));
			break;
		default:
			SYS_LOG_ERR("err=%d", err.code);
			return err;
		}
	}

	SYS_LOG_ERR("timeout");
	return error::io;
}

static void hid_tx(u32_t cid, u2fhid_cmd cmd, net_buf *resp)
{
	u32_t start = k_uptime_get_32();

	size_t bcnt = resp->len;
	const u8_t *p = resp->data;

	{
		u2f_init_pkt init = {
			.cid = cid,
			.cmd = cmd,
		};

		sys_put_be16(bcnt, init.bcnt);

		size_t take = min(sizeof(init.payload), bcnt);
		std::copy(p, p + take, init.payload);

		SYS_LOG_DBG("writing %d of %d in 1st packet", take, bcnt);

		if (hid_tx_pkt((u8_t *)&init, sizeof(init))) {
			return;
		}
		bcnt -= take;
		p += take;
	}

	for (u8_t seq = 0; bcnt > 0; seq++) {
		u2f_cont_pkt cont = {
			.cid = cid,
			.seq = seq,
		};

		int take = min(sizeof(cont.payload), bcnt);
		std::copy(p, p + take, cont.payload);

		if (hid_tx_pkt((u8_t *)&cont, sizeof(cont))) {
			return;
		}

		bcnt -= take;
		p += take;
	}

	SYS_LOG_DBG("tx in %d", (int)(k_uptime_get_32() - start));
}

void hid_run()
{
	for (;;) {
		// Receive a packet and ensure it's released later.
		u32_t cid = 0;
		u2fhid_cmd cmd = u2fhid_cmd::ERROR;

		auto req = hid_rx(cid, cmd);
		autounref unref1{req};

		if (req == nullptr) {
			continue;
		}

		// Allocate the response buf.
		auto resp = net_buf_alloc(&hid_msg_pool, K_NO_WAIT);
		autounref resp1{resp};

		if (resp == nullptr) {
			continue;
		}

		error err;

		switch (cmd) {
		case u2fhid_cmd::INIT:
			err = hid_handle_init(req, resp);
			break;
		case u2fhid_cmd::MSG:
			err = u2f_dispatch(req, resp);
			break;
		case u2fhid_cmd::WINK:
			ui_wink();
			err = error::ok;
			break;
		default:
			err = ERROR(-ENOENT);
			break;
		}

		if (err) {
			net_buf_reset(resp);
			net_buf_add_u8(resp,
				       static_cast<u8_t>(hid_map_error(err)));
			hid_tx(cid, u2fhid_cmd::ERROR, resp);
		} else {
			hid_tx(cid, cmd, resp);
		}
	}
}

static int hid_set_report_cb(struct usb_setup_packet *setup, s32_t *plen,
			     u8_t **pdata)
{
	size_t len = *plen;

	prng_feed();

	auto buf = net_buf_alloc(&hid_rx_pool, K_NO_WAIT);
	if (buf == nullptr) {
		return -ENOMEM;
	}
	if (len > net_buf_tailroom(buf)) {
		net_buf_unref(buf);
		return -ENOMEM;
	}

	net_buf_add_mem(buf, *pdata, len);
	net_buf_put(&data.rx_q, buf);

	return 0;
}

static int hid_get_report_cb(struct usb_setup_packet *setup, s32_t *len,
			     u8_t **data)
{
	SYS_LOG_DBG("Get report callback");
	return 0;
}

static void hid_int_in_ready(void)
{
	k_sem_give(&data.tx_sem);
}

static struct hid_ops ops = {
	.get_report = hid_get_report_cb,
	.get_idle = nullptr,
	.get_protocol = nullptr,
	.set_report = hid_set_report_cb,
	.set_idle = nullptr,
	.int_in_ready = hid_int_in_ready,
};

static int hid_init(struct device *dev)
{
	k_fifo_init(&data.rx_q);
	k_sem_init(&data.tx_sem, 1, 2);

	usb_hid_register_device(hid_report_desc, sizeof(hid_report_desc),
				&ops);
	return usb_hid_init();
}

SYS_INIT(hid_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
