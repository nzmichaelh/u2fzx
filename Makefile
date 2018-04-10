# Helper Makefile that can fetch Zephyr, the SDK, and build using
# CMake.
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

DTS = $(wildcard *.overlay)
BOARDS = $(DTS:%.overlay=%)

GCC_ARM_EMBEDDED = https://developer.arm.com/-/media/Files/downloads/gnu-rm/7-2017q4/gcc-arm-none-eabi-7-2017-q4-major-linux.tar.bz2
ZEPHYR_SDK = https://github.com/zephyrproject-rtos/meta-zephyr-sdk/releases/download/0.9.2/zephyr-sdk-0.9.2-setup.run

all: build

build: $(BOARDS:%=%.build)

%.build:
	mkdir -p build/$*
	cd build/$* && cmake ../.. -GNinja -DBOARD=$*
	ninja -C build/$*

clean:
	rm -fr build

build-with-deps: build-deps
	ZEPHYR_TOOLCHAIN_VARIANT=gccarmemb \
	GCCARMEMB_TOOLCHAIN_PATH=$(PWD)/third_party/gcc-arm-embedded \
	ZEPHYR_SDK_INSTALL_DIR=$(PWD)/third_party/zephyr-sdk \
	ZEPHYR_BASE=$(PWD)/third_party/zephyr \
	$(MAKE) build

build-deps: \
	third_party/gcc-arm-embedded \
	third_party/zephyr-sdk \
	third_party/zephyr/Makefile

third_party/gcc-arm-embedded:
	mkdir -p $@
	cd $@ && wget -c $(GCC_ARM_EMBEDDED)
	cd $@ && tar xaf $(notdir $(GCC_ARM_EMBEDDED)) --strip-components=1

third_party/zephyr-sdk:
	mkdir -p $@
	cd $@ && wget -c $(ZEPHYR_SDK)
	cd $@ && bash $(notdir $(ZEPHYR_SDK)) -- -y -d $$(pwd)
