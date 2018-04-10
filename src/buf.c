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

#include <net/buf.h>
#include <kernel.h>

void ui_thread(void *p1, void *p2, void *p3);

NET_BUF_POOL_DEFINE(hid_rx_pool, 1024/64, 64, 0, NULL);
NET_BUF_POOL_DEFINE(hid_msg_pool, 2, 700, 0, NULL);

K_THREAD_DEFINE(ui, 512, ui_thread, NULL, NULL, NULL, K_HIGHEST_THREAD_PRIO, 0, 0);
