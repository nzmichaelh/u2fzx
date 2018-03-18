/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <net/buf.h>

NET_BUF_POOL_DEFINE(hid_rx_pool, 1024/64, 64, 0, NULL);
NET_BUF_POOL_DEFINE(hid_msg_pool, 4, 700, 0, NULL);
