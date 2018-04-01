/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <net/buf.h>
#include <kernel.h>

void ui_thread(void *p1, void *p2, void *p3);

NET_BUF_POOL_DEFINE(hid_rx_pool, 1024/64, 64, 0, NULL);
NET_BUF_POOL_DEFINE(hid_msg_pool, 2, 700, 0, NULL);

K_THREAD_DEFINE(ui, 512, ui_thread, NULL, NULL, NULL, K_HIGHEST_THREAD_PRIO, 0, 0);
