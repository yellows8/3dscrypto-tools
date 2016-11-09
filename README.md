These are tools for Nintendo 3DS crypto, using the ctrclient API(see Makefiles). None of these run on an actual 3DS(unlike other already publicly available repo(s)). Unless you want to do network-only crypto with the original ctrclient.c(see Makefiles), you should check the ctr-cryptotool directory. If it uses network-crypto at some point(like when all of the keydata for a keyslot isn't setup for ctr-cryptotool), you would need a network crypto-server(normally running directly on a 3DS), which is not included with this repo.

* ctr-titletool: Download and/or decrypt CDN titles / tickets.
* ctr-ncchtool: Decrypt NCCH.
* ctr-nandcrypt: Generate NAND xorpads.
* ctr-savetool: General saveimage-related crypto tool.
* bosstool: SpotPass container crypto tool.
* ctr-new3dsfirmtool: Decrypt the ARM9 section from New3DS FIRM.

Credits:
* utils.c/utils.h and types.h are from ctrtool. tmd.h and ncch.h are based on the headers from ctrtool.
* ctrclient API: see the Makefiles/ctr-cryptotool README regarding the original.

