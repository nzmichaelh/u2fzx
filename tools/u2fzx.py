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

import ecdsa
import secrets

from u2flib_host import u2f
from u2flib_host import constants

U2F_VENDOR_JUJU = 0xc9
INS_ERASE = 0xC1
INS_SET_CERTIFICATE = 0xC2
INS_SET_PRIVATE_KEY = 0xC3
INS_SET_SEED = 0xC4

def main():
    with u2f.list_devices()[0] as dev:
        dev.send_apdu(U2F_VENDOR_JUJU, INS_ERASE)

        with open('key.pem') as f:
            key = ecdsa.SigningKey.from_pem(f.read())
            dev.send_apdu(U2F_VENDOR_JUJU, INS_SET_PRIVATE_KEY, data=key.to_string())

        with open('cert.der', 'rb') as f:
            dev.send_apdu(U2F_VENDOR_JUJU, INS_SET_CERTIFICATE, data=f.read())

        dev.send_apdu(U2F_VENDOR_JUJU, INS_SET_SEED, data=secrets.token_bytes(256))

if __name__ == '__main__':
    main()
