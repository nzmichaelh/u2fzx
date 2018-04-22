# u2fzx - a U2F hardware token.

mlhx@google.com / michaelh@juju.nz

u2fzx is a open source two-factor authentication token.  It implements
the FIDO U2F protocol and has been tested with Chrome, Google
accounts, and Github and should be compatible with any other site or
browser that supports U2F over USB.

TODO: u2fzx is under development.  The Trinket version is the
further est along but still needs button support.  The Blackpill port
is started but doesn't support USB yet.

u2fzx uses the Zephyr RTOS and mbed TLS, has been tested on the
Adafruit Trinket M0 and generic Blackpill STM32 boards, and should be
straight forward to port to other Zephyr supported boards.

The Blackpill is available for ~$2 USD which makes a cheap and
cheerful way of making your account more secure.

## Building and flashing

    make build-with-deps
	ninja -C build/arduino_zero flash

## Setting up

Before it can be used, the token must be loaded with an attestation
keypair and random seed.  To do this, run:

    cd tools
	make attest
	python3 u2fzx.py

Note that this will also erase the token and any existing
registrations.

## Using

TODO

## Security overview

TODO

## License

Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Disclaimer

This is not an official Google product.
