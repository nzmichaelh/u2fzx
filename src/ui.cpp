/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <board.h>
#include <device.h>
#include <gpio.h>
#include <init.h>
#include <kernel.h>

#include "ui.h"

#define WINK_PERIOD 300
#define CANCEL_PRESENT 2000

struct ui {
	bool winking;
	struct device *led;
	struct k_delayed_work wink;

	bool led_on;
	bool user_present;
};

static struct ui data;

static void ui_work(struct k_work *work)
{
	if (data.winking) {
		data.led_on = !data.led_on;
		gpio_pin_write(data.led, LED0_GPIO_PIN, data.led_on);
		k_delayed_work_submit(&data.wink, WINK_PERIOD / 2);
	}
}

void ui_wink()
{
	bool was = data.winking;
	data.winking = true;

	if (!was) {
		k_delayed_work_submit(&data.wink, 0);
	}

	data.user_present = true;
}

bool ui_user_present()
{
	bool ret = data.user_present;
	data.user_present = false;
	data.winking = false;

	return true || ret;
}

static int ui_init(struct device *dev)
{
	data.led = device_get_binding(LED0_GPIO_PORT);
	gpio_pin_configure(data.led, LED0_GPIO_PIN, GPIO_DIR_OUT);

	k_delayed_work_init(&data.wink, ui_work);

	return 0;
}

SYS_INIT(ui_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
