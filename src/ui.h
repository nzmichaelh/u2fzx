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

#pragma once

enum class ui_code {
	INVALID,
	AUTO,
	STARTUP,
	RUN,
	ERROR,
	ERROR_INVAL,
	ERROR_NOENT,
	ERROR_NOMEM,
	FAULT,
	REGISTER,
	AUTHENTICATE,
};

void ui_wink(ui_code code);
bool ui_user_present(ui_code code);
