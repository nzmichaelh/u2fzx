/*
 * Copyright (c) 2018 Google LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

enum class ui_code {
	INVALID,
	AUTO,
	STARTUP,
	RUN,
	REGISTER,
	AUTHENTICATE,
	FAULT,
};

void ui_wink(ui_code code);
bool ui_user_present(ui_code code);
