/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_LEVEL 4
#define SYS_LOG_DOMAIN "hid"
#include <logging/sys_log.h>

#include <misc/byteorder.h>
#include <net/buf.h>
#include <string.h>
#include <zephyr.h>
#include <device.h>
#include <init.h>

#include <usb/usb_device.h>
#include <usb/class/usb_hid.h>

#include "prng.h"

#define TYPE_MASK 0x80
#define TYPE_INIT 0x80
#define TYPE_CONT 0x00

#define U2FHID_PING (TYPE_INIT | 0x01)
#define U2FHID_MSG (TYPE_INIT | 0x03)
#define U2FHID_LOCK (TYPE_INIT | 0x04)
#define U2FHID_INIT (TYPE_INIT | 0x06)
#define U2FHID_WINK (TYPE_INIT | 0x08)
#define U2FHID_ERROR (TYPE_INIT | 0x3f)

#define CAPABILITY_WINK 0x01
#define CAPABILITY_LOCK 0x02

#define U2FHID_BROADCAST 0xffffffff

#define U2FHID_PACKET_SIZE 64
#define U2FHID_INIT_PAYLOAD_SIZE (U2FHID_PACKET_SIZE - 7)
#define U2FHID_CONT_PAYLOAD_SIZE (U2FHID_PACKET_SIZE - 5)
#define U2FHID_MAX_PAYLOAD_SIZE (7609)

void dump_hex(const char *msg, const u8_t *buf, int len);
int u2f_dispatch(struct net_buf *req, struct net_buf *resp);

struct u2f_init_hdr {
	u32_t cid;
	u8_t cmd;
	u8_t bcnt[2];
	u8_t payload[1];
};
BUILD_ASSERT(sizeof(struct u2f_init_hdr) == 8);

struct u2f_init_pkt {
	u32_t cid;
	u8_t cmd;
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

	struct net_buf *rx;
	u32_t rx_cid;
	u8_t rx_cmd;
	u16_t rx_want;
	u8_t rx_seq;
	struct k_work rx_work;
	struct k_fifo rx_q;

	struct k_fifo tx_q;
	struct k_work tx_work;

	struct net_buf *tx;
	int tx_seq;
};

static struct hid_data data;

NET_BUF_POOL_DEFINE(hid_msg_pool, 4, 700, 0, NULL);

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

static void hid_tx(struct k_work *work)
{
	int err;
	u32_t wrote;
	int at;
	int stride;

	if (data.tx == NULL) {
		data.tx = net_buf_get(&data.tx_q, K_NO_WAIT);
		data.tx_seq = -1;
	}
	if (data.tx == NULL) {
		SYS_LOG_DBG("done");
		return;
	}

	if (data.tx_seq < 0) {
		at = 0;
		stride = U2FHID_PACKET_SIZE;
		err = usb_write(CONFIG_HID_INT_EP_ADDR, data.tx->data,
				U2FHID_PACKET_SIZE, &wrote);
	} else {
		struct u2f_cont_pkt pkt = {
			.cid = *(u32_t *)(data.tx->data), .seq = data.tx_seq,
		};

		at = U2FHID_PACKET_SIZE +
		     (data.tx_seq * U2FHID_CONT_PAYLOAD_SIZE);
		stride = U2FHID_CONT_PAYLOAD_SIZE;
		memcpy(pkt.payload, data.tx->data + at, stride);
		err = usb_write(CONFIG_HID_INT_EP_ADDR, (u8_t *)&pkt,
				sizeof(pkt), &wrote);
	}

	if (err == 0) {
		prng_feed();

		data.tx_seq++;
		if (at + stride >= data.tx->len) {
			net_buf_unref(data.tx);
			data.tx = NULL;
		}
	}

	k_work_submit(&data.tx_work);
}

static int hid_handle_init(struct net_buf *req, struct net_buf *resp)
{
	SYS_LOG_DBG("");

	net_buf_add_mem(resp, req->data, 8);
	net_buf_pull(req, 8);
	net_buf_add_be32(resp, ++data.next_channel);
	net_buf_add_u8(resp, 2);
	net_buf_add_u8(resp, 0);
	net_buf_add_u8(resp, 1);
	net_buf_add_u8(resp, 0);
	net_buf_add_u8(resp, CAPABILITY_WINK);

	return 0;
}

static void hid_rx(struct k_work *work)
{
	struct net_buf *req;
	struct net_buf *resp = NULL;
	struct u2f_init_hdr *hdr;
	u8_t *bcnt;
	int err = 0;

	SYS_LOG_DBG("");

	req = k_fifo_get(&data.rx_q, K_NO_WAIT);
	if (req == NULL) {
		goto done;
	}

	dump_hex("<<", req->data, req->len);

	hdr = (struct u2f_init_hdr *)req->data;
	net_buf_pull(req, offsetof(struct u2f_init_hdr, payload));

	SYS_LOG_DBG("cid=%x cmd=%x", hdr->cid, hdr->cmd);

	resp = net_buf_alloc(&hid_msg_pool, K_NO_WAIT);
	if (resp == NULL) {
		err = -ENOMEM;
		goto done;
	}

	net_buf_add_mem(resp, &hdr->cid, sizeof(hdr->cid));
	net_buf_add_u8(resp, hdr->cmd);
	bcnt = net_buf_add(resp, 2);

	switch (hdr->cmd) {
	case U2FHID_INIT:
		err = hid_handle_init(req, resp);
		break;
	case U2FHID_MSG:
		err = u2f_dispatch(req, resp);
		break;
	default:
		err = -EINVAL;
	}

	if (err != 0) {
		goto done;
	}

	sys_put_be16(resp->len - 4 - 1 - 2, bcnt);

	dump_hex(">>", resp->data, resp->len);
	net_buf_ref(resp);
	net_buf_put(&data.tx_q, resp);
	k_work_submit(&data.tx_work);

done:
	if (resp != NULL) {
		net_buf_unref(resp);
	}
	if (req != NULL) {
		net_buf_unref(req);
	}
	if (!k_fifo_is_empty(&data.rx_q)) {
		k_work_submit(work);
	}
}

static int hid_set_report_cb(struct usb_setup_packet *setup, s32_t *plen,
			     u8_t **pdata)
{
	struct u2f_init_pkt *pkt = (struct u2f_init_pkt *)*pdata;
	int len = *plen;

	prng_feed();

	if (len < offsetof(struct u2f_cont_pkt, payload)) {
		return -EINVAL;
	}
	if ((pkt->cmd & TYPE_INIT) != 0) {
		u16_t bcnt;

		if (len < offsetof(struct u2f_init_pkt, payload)) {
			SYS_LOG_ERR("init packet too short");
			return -EINVAL;
		}
		bcnt = sys_get_be16(pkt->bcnt);
		if (bcnt > U2FHID_MAX_PAYLOAD_SIZE) {
			SYS_LOG_ERR("bcnt too big");
			return -EINVAL;
		}

		SYS_LOG_DBG("cmd=%x bcnt=%d", pkt->cmd, bcnt);
		if (data.rx != NULL) {
			net_buf_unref(data.rx);
			data.rx = NULL;
		}

		data.rx = net_buf_alloc(&hid_msg_pool, K_NO_WAIT);
		if (data.rx == NULL) {
			SYS_LOG_ERR("No memory");
			return -ENOMEM;
		}

		data.rx_cid = pkt->cid;
		data.rx_want = bcnt + offsetof(struct u2f_init_pkt, payload);
		data.rx_seq = 0;

		net_buf_add_mem(data.rx, (u8_t *)pkt, len);
	} else {
		struct u2f_cont_pkt *cont = (struct u2f_cont_pkt *)*pdata;

		if (data.rx == NULL) {
			SYS_LOG_ERR("no rx buf");
			return -EINVAL;
		}
		if (cont->cid != data.rx_cid) {
			SYS_LOG_ERR("cid changed");
			return -EINVAL;
		}
		if (cont->seq != data.rx_seq) {
			SYS_LOG_ERR("seq out of order");
			return -EINVAL;
		}
		data.rx_seq = cont->seq + 1;
		SYS_LOG_DBG("seq=%x", cont->seq);

		net_buf_add_mem(data.rx, cont->payload, len - 5);
	}

	if (data.rx != NULL && data.rx->len >= data.rx_want) {
		SYS_LOG_DBG("dispatch");
		net_buf_put(&data.rx_q, data.rx);
		data.rx = NULL;
		k_work_submit(&data.rx_work);
	}

	return 0;
}

static int hid_get_report_cb(struct usb_setup_packet *setup, s32_t *len,
			     u8_t **data)
{
	SYS_LOG_DBG("Get report callback");
	return 0;
}

static struct hid_ops ops = {
	.get_report = hid_get_report_cb,
	.set_report = hid_set_report_cb,
};

static int hid_init(struct device *dev)
{
	k_fifo_init(&data.rx_q);
	k_fifo_init(&data.tx_q);
	k_work_init(&data.tx_work, hid_tx);
	k_work_init(&data.rx_work, hid_rx);

	usb_hid_register_device(hid_report_desc, sizeof(hid_report_desc),
				&ops);
	return usb_hid_init();
}

SYS_INIT(hid_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
