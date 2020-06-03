ctr-cryptotool: 3DS tool for AES crypto. This includes a software implementation of the 3DS AES engine key-generator.

Build with `gcc ctr-cryptotool.c -lcrypto -o ctr-cryptotool` (requires libcrypto, part of openssl)

ctrclient.* and utils.* are based on the code from {neimod/ctr repo}/ctr/ramtracer/ctrclient. When ctrclient apps are built with CTRCLIENT={path to this ctr-cryptotool directory}, this allows the app to use the ctrclient API for doing local AES crypto using the sw implementation of the key-generator(and regular normal-keys too). When the required keys are not all set, this will fallback to sending network commands for crypto. When building ctrclient apps with this, add this make command-line option: "LIBS=-lcrypto".

This also requires a config file @ "$HOME/.3ds/aeskeyslots_keys", each text line has the following structure: {hex value for the keyslot} {key params}. Where key params can be any of the following: "normalkey=hex", "keyX=hex", or "keyY=hex". If this file doesn't exist or no keys are set here, then local crypto will not be used except when regular normal-keys are set via the ctrclient API. See source for more details for config handling.

Credits:
* Some of the key-generator code is based on DSi key-generator code from booto.

