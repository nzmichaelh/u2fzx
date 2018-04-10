/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_LEVEL 4
#define SYS_LOG_DOMAIN "ui"
#include <logging/sys_log.h>

#include <array>

#include <board.h>
#include <device.h>
#include <gpio.h>
#include <init.h>
#include <kernel.h>
#include <led_strip.h>

#include "ui.h"

#define WINK_PERIOD 300
#define CANCEL_PRESENT 2000

struct ui {
	k_sem sem;

	ui_code last_check;

	volatile u16_t winking;
	volatile ui_code user_present;
};

struct ui_seq {
	void set(u16_t reload)
	{
		if (reload != reload_) {
			reload_ = reload;
			v_ = 0;
		}
	}
	void tick()
	{
		v_ >>= 1;
		if (v_ <= 1) {
			v_ = reload_;
		}
	}

	bool on() const { return (v_ & 1) != 0; }
	bool idle() const { return reload_ == 0; }

      private:
	u16_t v_ = 0;
	u16_t reload_ = 0;
};

struct ui_led {
	struct device *dev;
	int pin;
	bool invert;
};

static const u16_t patterns[][3] = {
	/* INVALID */
	{0, 1},
	/* AUTO */
	{0, 1},
	/* STARTUP */
	{0b1100, 0b1010, 0b1001},
	/* RUN */
	{0},
	/* ERROR */
	{0, 0b100000000001},
	/* ERROR_INVAL */
	{0, 0b100000000101},
	/* ERROR_NOENT */
	{0, 0b100001010101},
	/* ERROR_NOMEM */
	{0, 0b100101010101},
	/* FAULT */
	{0, 0b11},
	/* REGISTER */
	{0b11110},
	/* AUTHENTICATE */
	{0b110},
};
BUILD_ASSERT(ARRAY_SIZE(patterns) == (int)ui_code::AUTHENTICATE + 1);

static struct ui data;

extern "C" void ui_thread(void *p1, void *p2, void *p3)
{
	ui_code code = ui_code::INVALID;
	int blinks = 0;

	ui_seq seq[3];
	std::array<ui_led, 3> leds{};

#ifdef LED0_GPIO_PORT
	leds[0] = {
		.dev = device_get_binding(LED0_GPIO_PORT),
		.pin = LED0_GPIO_PIN,
	};
#endif
#ifdef LED1_GPIO_PORT
	leds[1] = {
		.dev = device_get_binding(LED1_GPIO_PORT),
		.pin = LED1_GPIO_PIN,
		.invert = true,
	};
#endif
#ifdef LED2_GPIO_PORT
	leds[2] = {
		.dev = device_get_binding(LED2_GPIO_PORT),
		.pin = LED2_GPIO_PIN,
		.invert = true,
	};
#endif

	for (auto &led : leds) {
		if (led.dev == nullptr) {
			continue;
		}
		gpio_pin_configure(led.dev, led.pin, GPIO_DIR_OUT);
	}

	struct device *strip = nullptr;
#ifdef CONFIG_APA102_STRIP_NAME
	strip = device_get_binding(CONFIG_APA102_STRIP_NAME);
#endif

	for (;;) {
		auto winking = data.winking;
		auto next = (ui_code)(find_msb_set(winking) - 1);

		if (next != code) {
			code = next;
			auto &pattern = patterns[(int)code];
			for (auto i = 0U; i < ARRAY_SIZE(pattern); i++) {
				seq[i].set(pattern[i]);
			}
			blinks = 0;
		}

		for (auto i = 0U; i < leds.size(); i++) {
			auto &led = leds[i];
			if (led.dev == nullptr) {
				continue;
			}
			gpio_pin_write(led.dev, led.pin,
				       seq[i].on() ^ led.invert);
		}
		if (strip != nullptr) {
			struct led_rgb rgb = {
#ifdef CONFIG_LED_STRIP_RGB_SCRATCH
				.scratch = 0,
#endif
				.r = (u8_t)(seq[1].on() ? 255 : 0),
				.g = (u8_t)(seq[0].on() ? 255 : 0),
				.b = (u8_t)(seq[2].on() ? 255 : 0),
			};
			led_strip_update_rgb(strip, &rgb, 1);
		}

		if (++blinks == 3000 / 200) {
			data.user_present = code;
		}
		for (auto &s : seq) {
			s.tick();
		}

		if (code == ui_code::RUN) {
			k_sem_take(&data.sem, K_FOREVER);
		} else {
			k_sleep(K_MSEC(200));
		}
	}
}

void ui_wink(ui_code code)
{
	if (code == ui_code::AUTO) {
		code = data.last_check;
	}

	data.winking |= 1 << (int)code;
	k_sem_give(&data.sem);
}

bool ui_user_present(ui_code code)
{
	auto ret = data.user_present;
	data.last_check = code;

	if (ret != code) {
		return false;
	}
	data.user_present = ui_code::INVALID;
	data.winking &= ~(1 << (int)code);

	return true;
}

static int ui_init(struct device *dev)
{
	k_sem_init(&data.sem, 1, 1);
	return 0;
}

SYS_INIT(ui_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);
