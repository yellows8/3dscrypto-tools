#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "ctrclient.h"
#include "types.h"
#include "utils.h"

int use_server = 1;
int dbsave_type = 0;

unsigned char hashdata_v60[0x40] = {/*REMOVED*/};

void aes_blockrotate(u8 *blk)
{
	int i, carry = 0;

	carry = blk[0] & 0x80;
	for(i=0; i<15; i++)
	{
		blk[i] = (blk[i]<<1) | (blk[i+1]>>7);
	}

	blk[15] <<= 1;
	if(carry)blk[15] ^= 0x87;
}

int aes_calcmac(ctrclient *client, u8 *outmac, u8 *buf, u32 size)
{
	u32 bufpos = 0, blki = 0;
	u8 cbcmac[16];
	u8 block[16];
	u8 iv[16];

	memset(cbcmac, 0, 16);
	memset(block, 0, 16);
	memset(iv, 0, 16);

	if(!ctrclient_aes_set_iv(client, iv))
			return 1;
	if(!ctrclient_aes_cbc_encrypt(client, block, 16))
		return 1;

	while(bufpos < size)
	{
		for(blki=0; blki<16; blki++)
		{
			cbcmac[blki] ^= buf[bufpos];

			bufpos++;
			if(blki<15 && bufpos==size)break;
		}

		if(bufpos < size)
		{
			if(!ctrclient_aes_set_iv(client, iv))
				return 1;
			if(!ctrclient_aes_cbc_encrypt(client, cbcmac, 16))
				return 1;
		}
	}

	aes_blockrotate(block);

	if(blki<16)
	{
		cbcmac[blki] ^= 0x80;
		aes_blockrotate(block);
	}

	for(blki=0; blki<16; blki++)block[blki] ^= cbcmac[blki];

	if(!ctrclient_aes_set_iv(client, iv))
		return 1;
	if(!ctrclient_aes_cbc_encrypt(client, block, 16))
		return 1;

	memcpy(outmac, block, 16);

	return 0;
}

void savegame_genhash(u8 *outhash, u8 *buffer, u32 bufsz, char *savetype, u8 *hashblock, u32 blocksz)
{
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, (u8*)savetype, 8);//savetype length is always 8

	if(hashblock)SHA256_Update(&ctx, hashblock, blocksz);

	SHA256_Update(&ctx, buffer, bufsz);
	SHA256_Final(outhash, &ctx);
}

int nandsave_genmac(ctrclient *client, u8 *header, u8 *outmac, unsigned long long saveID)
{
	int i;
	u8 calchash[0x20];
	u8 hashblk[8];

	memset(calchash, 0, 0x20);
	memset(hashblk, 0, 8);
	memcpy(hashblk, &saveID, 8);
	savegame_genhash(calchash, header, 0x100, "CTR-SYS0", hashblk, 8);

	printf("Generated hash for the MAC:\n");
	for(i=0; i<0x20; i++)printf("%02x", calchash[i]);

	if(use_server==0)return 1;

	if(!ctrclient_aes_select_key(client, 0x30))
		return 1;
	return aes_calcmac(client, outmac, calchash, 0x20);
}

int extdata_genmac(ctrclient *client, u8 *header, u8 *outmac, unsigned long long saveID, unsigned long long imageID)
{
	int i;
	u8 exthash[0x20];
	u8 hashblk[0x14];

	memset(exthash, 0, 0x20);
	memset(hashblk, 0, 0x14);

	memcpy(&hashblk[0], &saveID, 8);
	hashblk[0x8] = 1;//non-Quota.dat
	memcpy(&hashblk[0xc], &imageID, 8);

	savegame_genhash(exthash, header, 0x100, "CTR-EXT0", hashblk, 0x14);

	printf("Generated hash for the MAC:\n");
	for(i=0; i<0x20; i++)printf("%02x", exthash[i]);
	printf("\n");

	if(use_server==0)return 1;

	if(!ctrclient_aes_select_key(client, 0x30))
		return 1;
	return aes_calcmac(client, outmac, exthash, 0x20);
}

int sdsave_genmac(ctrclient *client, u8 *header, u8 *outmac, unsigned long long saveID)
{
	int i;
	u8 savhash[0x20];
	u8 ctrsignhash[0x20];

	memset(savhash, 0, 0x20);
	memset(ctrsignhash, 0, 0x20);

	savegame_genhash(savhash, header, 0x100, "CTR-SAV0", NULL, 0);
	savegame_genhash(ctrsignhash, savhash, 0x20, "CTR-SIGN", (unsigned char*)&saveID, 8);

	printf("Generated hash for the MAC:\n");
	for(i=0; i<0x20; i++)printf("%02x", ctrsignhash[i]);
	printf("\n");

	if(use_server==0)return 1;

	if(!ctrclient_aes_select_key(client, 0x30))
		return 1;
	return aes_calcmac(client, outmac, ctrsignhash, 0x20);
}

int gamecardsave_genmac(ctrclient *client, u8 *header, u8 *outmac)
{
	int i;
	u8 savhash[0x20];
	u8 norhash[0x20];

	memset(savhash, 0, 0x20);
	memset(norhash, 0, 0x20);

	savegame_genhash(savhash, header, 0x100, "CTR-SAV0", NULL, 0);
	savegame_genhash(norhash, savhash, 0x20, "CTR-NOR0", NULL, 0);

	printf("Generated hash for the MAC:\n");
	for(i=0; i<0x20; i++)printf("%02x", norhash[i]);
	printf("\n");

	if(use_server==0)return 1;

	if(!ctrclient_aes_select_key(client, 0x33))
		return 1;
	return aes_calcmac(client, outmac, norhash, 0x20);
}

int dbsave_genmac(ctrclient *client, u8 *header, u8 *outmac, u32 saveID)
{
	int i, keyslot;
	u8 dbhash[0x20];

	memset(dbhash, 0, 0x20);

	savegame_genhash(dbhash, header, 0x100, "CTR-9DB0", (unsigned char*)&saveID, 4);

	printf("Generated hash for the MAC:\n");
	for(i=0; i<0x20; i++)printf("%02x", dbhash[i]);
	printf("\n");

	if(use_server==0)return 1;

	if(dbsave_type==0)
	{
		keyslot = 0x30;
	}
	else
	{
		keyslot = 0x0b;
	}

	if(!ctrclient_aes_select_key(client, keyslot))
		return 1;

	return aes_calcmac(client, outmac, dbhash, 0x20);
}

int gensavemac(ctrclient *client, int savetype, u8 *buffer, unsigned long long saveID, unsigned long long imageID, int *updatemac)
{
	int i;
	u8 *header;
	u8 outmac[0x10];

	header = &buffer[0x100];

	if(savetype==0)
	{
		printf("Generating gamecard MAC...\n");
		if (gamecardsave_genmac(client, header, outmac) != 0)
			return 1;
	}
	else if(savetype==1)
	{
		printf("Generating NAND save MAC...\n");
		if (nandsave_genmac(client, header, outmac, saveID) != 0)
			return 1;
	}
	else if(savetype==2)
	{
		printf("Generating extdata MAC...\n");
		if (extdata_genmac(client, header, outmac, saveID, imageID) != 0)
			return 1;
	}
	else if(savetype==3)
	{
		printf("Generating SD save MAC...\n");
		if (sdsave_genmac(client, header, outmac, saveID) != 0)
			return 1;
	}
	else if(savetype==4)
	{
		printf("Generating DB save MAC...\n");
		if (dbsave_genmac(client, header, outmac, (u32)saveID) != 0)
			return 1;
	}

	printf("Calculated MAC: ");
	for(i=0; i<0x10; i++)printf("%02x", outmac[i]);
	printf("\n");
	printf("Savegame MAC: ");
	for(i=0; i<0x10; i++)printf("%02x", buffer[i]);
	printf("\n");
	if(memcmp(outmac, buffer, 0x10)==0)
	{
		printf("VALID!\n");
	}
	else
	{
		if(updatemac)*updatemac = 1;
		memcpy(buffer, outmac, 0x10);
		printf("INVALID!\n");
	}

	return 0;
}

int save_genxorpad(ctrclient *client, unsigned int keyslot, unsigned char *ctr, unsigned int xorpad_size, char *xorpad_path)
{
	FILE *f;
	unsigned char *xorpad_buf;
	unsigned int tmpsize;

	xorpad_buf = (unsigned char*)malloc(xorpad_size);
	if(xorpad_buf == NULL)
	{
		printf("Failed to allocate xorpad buf size %x.\n", xorpad_size);
		return 3;
	}
	memset(xorpad_buf, 0, xorpad_size);

	if(!ctrclient_aes_select_key(client, keyslot))
		return 1;
	if(!ctrclient_aes_set_ctr(client, ctr))
		return 1;
	if(!ctrclient_aes_ctr_crypt(client, xorpad_buf, xorpad_size))
		return 1;

	tmpsize = xorpad_size;
	if(tmpsize>0x200)tmpsize = 0x200;

	printf("Generated xorpad:\n");
	hexdump(xorpad_buf, tmpsize);

	if(xorpad_path[0])
	{
		printf("Writing xorpad file...\n");
		f = fopen(xorpad_path, "r+");
		if(f==NULL)
		{
			f = fopen(xorpad_path, "w");
			if(f==NULL)
			{
				printf("Failed to open output xorpad file: %s\n", xorpad_path);
				return 2;
			}
		}

		fwrite(xorpad_buf, 1, xorpad_size, f);
		fclose(f);
	}

	return 0;
}

void rsa_genmsg(unsigned char *message, unsigned char *sha256_hash)
{
	memset(message, 0xff, 0x100);
	message[0] = 0;
	message[1] = 1;

	message = &message[0x100-0x34];
	*message++ = 0;

	*message++ = 0x30;
	*message++ = 0x31;
	*message++ = 0x30;
	*message++ = 0x0d;
	*message++ = 0x06;
	*message++ = 0x09;
	*message++ = 0x60;
	*message++ = 0x86;
	*message++ = 0x48;
	*message++ = 0x01;
	*message++ = 0x65;
	*message++ = 0x03;
	*message++ = 0x04;
	*message++ = 0x02;
	*message++ = 0x01;
	*message++ = 0x05;
	*message++ = 0x00;
	*message++ = 0x04;
	*message++ = 0x20;
	memcpy(message, sha256_hash, 0x20);
}

int init_v60_keys(ctrclient *client, unsigned char *modulo, unsigned char *exponent)
{
	int i=0;
	RSA *rsactx = NULL;
	unsigned char hash[0x20];
	unsigned char message[0x100];
	unsigned char signature[0x100];
	unsigned char tmp[0x20];

	memset(hash, 0, 0x20);
	memset(message, 0, 0x100);
	memset(signature, 0, 0x100);
	memset(tmp, 0, 0x20);
	SHA256(hashdata_v60, 0x40, hash);

	rsactx = RSA_new();
	if(rsactx==NULL)
	{
		printf("OpenSSL RSA_new() failed.\n");
		return 2;
	}

	rsactx->n = BN_bin2bn(modulo, 0x100, NULL);
	rsactx->e = BN_bin2bn(exponent, 0x100, NULL);
	rsactx->d = BN_bin2bn(exponent, 0x100, NULL);

	if(rsactx->n==NULL || rsactx->e==NULL || rsactx->d==NULL)
	{
		printf("OpenSSL BN_bin2bn() failed.\n");
		RSA_free(rsactx);
		return 3;
	}

	//printf("Hash which will be signed:\n");
	//hexdump(hash, 0x20);

	rsa_genmsg(message, hash);

	//printf("RSA message:\n");
	//hexdump(message, 0x100);

	if(RSA_public_encrypt(RSA_size(rsactx), message, signature, rsactx, RSA_NO_PADDING)==-1)
	{
		ERR_load_crypto_strings();
		printf("OpenSSL RSA_public_encrypt failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		RSA_free(rsactx);
		return 4;
	}

	RSA_free(rsactx);

	//printf("Output signature:\n");
	//hexdump(signature, 0x100);

	SHA256(signature, 0x100, hash);

	printf("Calculated keyY for keyslot 0x2f(for savedata keyY calculation): ");
	for(i=0; i<0x10; i++)printf("%02x", hash[i]);
	printf("\n");
	printf("Calculated keyX for keyslot 0x25(for v7.0 NCCH crypto, won't be written to hw): ");
	for(i=0; i<0x10; i++)printf("%02x", hash[i+0x10]);
	printf("\n");

	printf("Setting keyY for keyslot 0x2f...\n");
	if(!ctrclient_aes_set_ykey(client, 0x2f, hash))return 1;//The ctrclient AES protocol doesn't support setting the keyX, therefore the keyX for keyslot 0x25 can't be set here.

	printf("Encrypting an all-zero block with AES-CTR with keyslot 0x2f...\n");
	if(!ctrclient_aes_select_key(client, 0x2f))return 1;
	if(!ctrclient_aes_set_ctr(client, tmp))return 1;
	if(!ctrclient_aes_ctr_crypt(client, &tmp[0x10], 0x10))return 1;

	printf("Encrypted output:\n");
	hexdump(&tmp[0x10], 0x10);

	return 0;
}

int main(int argc, char *argv[])
{
	ctrclient client;
	char serveradr[256];

	unsigned char buffer[0x200];
	unsigned char outbuf[0x30];
	unsigned char keyY[16];
	unsigned char iv[16];
	unsigned char ctr[16];
	unsigned char hashblock[0x70];
	unsigned char hash[32];
	unsigned char accessdesc_sig[8];
	unsigned char exefscode_hash[0x20];

	char insave_path[256];
	char ncch_path[256];
	char xorpad_path[256];
	unsigned short imgpath[256];

	unsigned int tmp=0;
	unsigned int imgpath_len = 0;
	int argi;
	int i;
	int romid_set = 0, accessdescsig_set = 0, codehash_set = 0, keyY_set = 0, rawkeyY_set = 0, rsaexponent_set = 0;
	int keytype = 0;
	int savetype = 0;
	int genmac = 0, updatemac = 0, writemac = 0;
	int decrypt_blocks = 0, generate_xorpad = 0;
	unsigned int xorpad_size = 0x200;
	unsigned long long saveID = 0, imageID = 0;
	unsigned char *rsamodulo_v60 = NULL;
	unsigned int rsamodulo_v60_size = 0x100;
	unsigned char rsaexponent[0x100];
	FILE *f;

	struct stat filestats;

	memset(serveradr, 0, 256);

	memset(buffer, 0, sizeof(buffer));
	memset(keyY, 0, 0x10);
	memset(iv, 0, 0x10);
	memset(ctr, 0, 0x10);
	memset(hashblock, 0, 0x70);
	memset(hash, 0, 32);
	memset(accessdesc_sig, 0, 8);

	memset(insave_path, 0, 256);
	memset(ncch_path, 0, 256);
	memset(xorpad_path, 0, 256);
	memset(imgpath, 0, 256 * 2);

	memset(rsaexponent, 0, 0x100);

	if(argc==1)
	{
		printf("ctr-savetool by yellows8\n");
		printf("Tool for generating a Nintendo 3DS savegame MAC and xorpad.\n");
		printf("Usage:\n");
		printf("--serveradr=<addr> Use the specified server address instead of the default address.\n");
		printf("--useserver=<val> This specified whether to use the server. When this is zero, the hashes and keyY are generated, without using the server for the MAC/xorpad generation.\n");
		printf("\n");

		printf("--insave=<path> Input savegame, required when using options --genmac or --decblocks.\n");
		printf("--ncch=<path> NCCH to load the 8-byte cleartext accessdesc signature from, for the keyY.\n");
		printf("--genxorpad=<path> Generate the save xorpad, and optionally write the xorpad to <path>.\n");
		printf("--xorpadsize=<hex-size> Size of the xorpad to generate, when --genxorpad was specified.\n");
		printf("--saveid=<hex> SaveID, required for non-gamecard savegames(also required for gamecard v6.0 save crypto).\n");
		printf("--imgid=<hex> ImageID, used for extdata when generating the MAC.\n");
		printf("\n");		

		printf("--genmac Generate the MAC.\n");
		printf("--writemac Write the calculated MAC to the save, when the save MAC and generated MAC don't match.\n");
		printf("--decblocks Decrypt the second and third AES blocks from the input savegame with AES-CBC IV=0, for retrieving the CTR used for each block.\n");
		printf("--gamecard Process a gamecard savegame, this is the default save-type.\n");
		printf("--nandsave Process a NAND savegame, only MAC generation is supported for this.\n");
		printf("--extdata Process an extdata image, MAC generation is not supported for Quota.dat.\n");
		printf("--sdsave Process a SD /title savegame.\n");
		printf("--dbsave=<sd|nand> Process a DB /dbs extdata image.\n");
		printf("\n");

		printf("--accessdescsig=<hex> 8-byte cleartext accessdesc signature, for the keyY.\n");
		printf("--romid=<hex> Specify the 4-byte/8-byte ID stored at keyY+8, or the 0x10-byte romID used for generating the keyY.\n");
		printf("--keyY=<hex> Raw keyY to use for the savegame.\n");
		printf("--CTR=<hex> Raw CTR to use for the savegame.\n");
		printf("--imgpath=<path> SD card path to generate the CTR from.\n");
		printf("--exefscodehash=<hex> Hash of the ExeFS .code from the main CXI ExeFS header, for the v6.0 save crypto.\n");
		printf("--genv60keys=<rsamodulopath> Calculate the v6.0/v7.0 keys for savedata keyY generation and NCCH crypto. If the input file is larger than 0x100-bytes, this will then calculate the keys using the modulus loaded from each byte in the input file.\n");
		printf("--rsaexponent=<big-endian hex u32 exponent> Sets the RSA exponent used for the above v6.0+ key generation. The value of this parameter can also be <@filepath>, to load the exponent from a file.\n");
	}

	for(argi=1; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--serveradr=", 12)==0)strncpy(serveradr, &argv[argi][12], 255);
		if(strncmp(argv[argi], "--useserver=", 12)==0)
		{
			sscanf(&argv[argi][12], "%d", &use_server);
		}

		if(strncmp(argv[argi], "--insave=", 9)==0)strncpy(insave_path, &argv[argi][9], 255);
		if(strncmp(argv[argi], "--ncch=", 7)==0)strncpy(ncch_path, &argv[argi][7], 255);
		if(strncmp(argv[argi], "--genxorpad", 11)==0)
		{
			generate_xorpad = 1;
			if(strlen(argv[argi])>=12)strncpy(xorpad_path, &argv[argi][12], 255);
		}

		if(strncmp(argv[argi], "--xorpadsize=", 13)==0)
		{
			sscanf(&argv[argi][13], "%x", &xorpad_size);
		}

		if(strncmp(argv[argi], "--saveid=", 9)==0)
		{
			sscanf(&argv[argi][9], "%llx", &saveID);
		}

		if(strncmp(argv[argi], "--imgid=", 8)==0)
		{
			sscanf(&argv[argi][8], "%llx", &imageID);
		}

		if(strncmp(argv[argi], "--genmac", 8)==0)genmac = 1;
		if(strncmp(argv[argi], "--writemac", 10)==0)writemac = 1;
		if(strncmp(argv[argi], "--decblocks", 11)==0)decrypt_blocks = 1;
		if(strncmp(argv[argi], "--gamecard", 10)==0)savetype = 0;
		if(strncmp(argv[argi], "--nandsave", 10)==0)savetype = 1;
		if(strncmp(argv[argi], "--extdata", 9)==0)savetype = 2;
		if(strncmp(argv[argi], "--sdsave", 10)==0)savetype = 3;
		if(strncmp(argv[argi], "--dbsave=", 9)==0)
		{
			savetype = 4;
			if(strncmp(&argv[argi][9], "sd", 2)==0)
			{
				dbsave_type = 0;
			}
			else if(strncmp(&argv[argi][9], "nand", 4)==0)
			{
				dbsave_type = 1;
			}
			else
			{
				printf("Value for --dbsave option is invalid.\n");
			}
		}

		if(strncmp(argv[argi], "--accessdescsig=", 16)==0)
		{
			if(strlen(argv[argi])!=32)
			{
				printf("Accessdesc signature input is invalid.\n");
			}
			else
			{
				for(i=0; i<8; i++)
				{
					sscanf(&argv[argi][16 + i*2], "%02x", &tmp);
					accessdesc_sig[i] = tmp;
				}
				accessdescsig_set = 1;
			}
		}

		if(strncmp(argv[argi], "--romid=", 8)==0)
		{
			if(strlen(argv[argi])==40)
			{
				for(i=0; i<0x40; i++)
				{
					if(i<0x10)sscanf(&argv[argi][8 + i*2], "%02x", &tmp);
					if(i>=0x10)tmp = 0xff;
					hashblock[8+i] = tmp;
				}
				romid_set = 1;
			}
			else if(strlen(argv[argi])==16)
			{
				for(i=0; i<4; i++)
				{
					sscanf(&argv[argi][8 + i*2], "%02x", &tmp);
					keyY[8+i] = tmp;
				}
				romid_set = 2;
			}
			else if(strlen(argv[argi])==24)
			{
				for(i=0; i<8; i++)
				{
					sscanf(&argv[argi][8 + i*2], "%02x", &tmp);
					keyY[8+i] = tmp;
				}
				romid_set = 3;
			}
			else
			{
				printf("RomID is invalid.\n");
				return 0;
			}
		}

		if(strncmp(argv[argi], "--keyY=", 7)==0)
		{
			if(strlen(argv[argi])!=39)
			{
				printf("KeyY is invalid.\n");
			}
			else
			{
				for(i=0; i<0x10; i++)
				{
					sscanf(&argv[argi][7 + i*2], "%02x", &tmp);
					keyY[i] = tmp;
				}
				rawkeyY_set = 1;
			}
		}

		if(strncmp(argv[argi], "--CTR=", 6)==0)
		{
			if(strlen(argv[argi])!=38)
			{
				printf("CTR is invalid.\n");
			}
			else
			{
				for(i=0; i<0x10; i++)
				{
					sscanf(&argv[argi][6 + i*2], "%02x", &tmp);
					ctr[i] = tmp;
				}
			}
		}

		if(strncmp(argv[argi], "--imgpath=", 10)==0)
		{
			imgpath_len = strlen(argv[argi])-10;
			if(imgpath_len>255)imgpath_len = 255;
			for(i=0; i<imgpath_len; i++)
			{
				imgpath[i] = argv[argi][i + 10];
			}

			SHA256((unsigned char*)imgpath, (imgpath_len+1) * 2, hash);
			for(i=0; i<16; i++)ctr[i] = hash[i] ^ hash[i+16];
		}

		if(strncmp(argv[argi], "--exefscodehash=", 16)==0)
		{
			if(strlen(argv[argi])!=16+64)
			{
				printf("ExeFS .code hash is invalid.\n");
			}
			else
			{
				for(i=0; i<0x20; i++)
				{
					sscanf(&argv[argi][16 + i*2], "%02x", &tmp);
					exefscode_hash[i] = tmp;
				}
				codehash_set = 1;
			}
		}

		if(strncmp(argv[argi], "--genv60keys=", 13)==0)
		{
			if(stat(&argv[argi][13], &filestats)==-1)
			{
				printf("Failed to stat the input RSA modulo: %s\n", &argv[argi][13]);
			}
			else
			{
				rsamodulo_v60_size = filestats.st_size;

				f = fopen(&argv[argi][13], "rb");
				if(f)
				{
					rsamodulo_v60 = (unsigned char*)malloc(rsamodulo_v60_size);
					fread(rsamodulo_v60, 1, rsamodulo_v60_size, f);
					fclose(f);
				}
				else
				{
					printf("Failed to open the input RSA modulo: %s\n", &argv[argi][13]);
				}
			}
		}

		if(strncmp(argv[argi], "--rsaexponent=", 14)==0)
		{
			if(argv[argi][14]!='@')
			{
				tmp = 0;
				sscanf(&argv[argi][14], "%x", &tmp);
				rsaexponent[0xfc + 0] = (tmp >> 24) & 0xff;
				rsaexponent[0xfc + 1] = (tmp >> 16) & 0xff;
				rsaexponent[0xfc + 2] = (tmp >> 8) & 0xff;
				rsaexponent[0xfc + 3] = tmp & 0xff;

				rsaexponent_set = 1;
			}
			else
			{
				f = fopen(&argv[argi][15], "rb");
				if(f)
				{
					if(fread(rsaexponent, 1, 0x100, f)==0x100)
					{
						rsaexponent_set = 1;
					}
					else
					{
						printf("Failed to fully read the RSA exponent.\n");
					}

					fclose(f);
				}
				else
				{
					printf("Failed to open the input RSA exponent.\n");
				}
			}
		}
	}

	if(serveradr[0]==0)return 1;

	if(savetype==0 && !accessdescsig_set && !rawkeyY_set)
	{
		if(ncch_path[0]==0)
		{
			printf("Specify a raw keyY, or accessdescsig/NCCH path.\n");
			return 0;
		}

		f = fopen(ncch_path, "rb");
		if(f)
		{
			fseek(f, 0x600, SEEK_SET);
			fread(accessdesc_sig, 1, 0x8, f);
			fclose(f);
			accessdescsig_set = 1;
		}
		else
		{
			printf("Failed to open NCCH: %s\n", ncch_path);
			return 0;
		}
	}

	if(savetype==0 && (romid_set && accessdescsig_set))
	{
		if(romid_set==1)
		{
			keytype = 1;
			if(codehash_set && saveID)keytype = 2;
		}
		keyY_set = 1;
	}

	if(insave_path[0]==0 && (decrypt_blocks || genmac))return 0;
	if(savetype==0 && (!keyY_set && !rawkeyY_set))return 0;

	/*if(savetype && saveID==0)
	{
		printf("Specify a SaveID.\n");
		return 0;
	}*/

	if(insave_path[0])
	{
		f = fopen(insave_path, "rb");
		if(f)
		{
			fread(buffer, 1, 0x200, f);
			fclose(f);
		}
		else
		{
			printf("Failed to open save: %s\n", insave_path);
			return 0;
		}
	}

	if(use_server)
	{
		ctrclient_init();

		if (0 == ctrclient_connect(&client, serveradr, "8333"))
			return 1;
	}

	if(rsamodulo_v60)
	{
		if(!rsaexponent_set)
		{
			printf("No RSA exponent set, using default exponent: 65537.\n");

			tmp = 0x00010001;

			rsaexponent[0xfc + 0] = (tmp >> 24) & 0xff;
			rsaexponent[0xfc + 1] = (tmp >> 16) & 0xff;
			rsaexponent[0xfc + 2] = (tmp >> 8) & 0xff;
			rsaexponent[0xfc + 3] = tmp & 0xff;
		}
		
		i = 0;
		while(rsamodulo_v60_size>=0x100)
		{
			if(rsamodulo_v60_size > 0x100 || i!=0)printf("RSA-modulo input file pos: 0x%x\n", i);

			if(init_v60_keys(&client, &rsamodulo_v60[i], rsaexponent)!=0 && rsamodulo_v60_size==0x100)
			{
				free(rsamodulo_v60);
				return 1;
			}

			i++;
			rsamodulo_v60_size--;
		}

		free(rsamodulo_v60);
	}

	if(savetype==0 && !rawkeyY_set)
	{
		printf("Generating keyY...\n");

		if(keytype==0)
		{
			memcpy(keyY, accessdesc_sig, 8);
		}
		else if(keytype==1)
		{
			memcpy(hashblock, accessdesc_sig, 8);

			SHA256(hashblock, 0x48, hash);
			memcpy(keyY, hash, 0x10);

			printf("Hash block: ");
			for(i=0; i<0x48; i++)printf("%02x", hashblock[i]);
			printf("\n");
		}
		else if(keytype==2)
		{
			memcpy(hashblock, accessdesc_sig, 8);
			memcpy(&hashblock[0x48], &saveID, 8);
			memcpy(&hashblock[0x50], exefscode_hash, 0x20);

			SHA256(hashblock, 0x70, hash);
			memcpy(keyY, hash, 0x10);

			printf("Hash block: ");
			for(i=0; i<0x70; i++)printf("%02x", hashblock[i]);
			printf("\n");

			printf("Calculating AESMAC for the final savegame keyY...\n");

			if(!ctrclient_aes_select_key(&client, 0x2f))return 1;

			if(aes_calcmac(&client, keyY, hash, 0x20))return 1;
		}
	}

	if(rawkeyY_set)keyY_set = 1;

	if(keyY_set)
	{
		printf("Using keyY: ");
		for(i=0; i<0x10; i++)printf("%02x", keyY[i]);
		printf("\n");
	}

	printf("Using CTR: ");
	for(i=0; i<0x10; i++)printf("%02x", ctr[i]);
	printf("\n");

	if(keyY_set && use_server)
	{
		if(savetype==0)
		{
			if(!ctrclient_aes_set_ykey(&client, 0x33, keyY))
				return 1;
			if(!ctrclient_aes_set_ykey(&client, 0x37, keyY))
				return 1;
		}

		if(savetype>0)
		{
			if(!ctrclient_aes_set_ykey(&client, 0x30, keyY))
				return 1;

			if(!ctrclient_aes_set_ykey(&client, 0x34, keyY))
				return 1;

			if(!ctrclient_aes_set_ykey(&client, 0x3a, keyY))
				return 1;
		}
	}

	if(decrypt_blocks && use_server)
	{
		/*if(savetype==0)
		{
			if(!ctrclient_aes_select_key(&client, 0x37))
				return 1;
		}

		if(savetype==1 || savetype==2 || savetype==4)
		{
			if(!ctrclient_aes_select_key(&client, 0x34))
				return 1;
		}*/

		//for(i=0x10; i<0x30; i++)buffer[i] ^= 0xff;

		for(i=0x30; i<0x3b; i++)
		{
		printf("keyslot %x\n", i);
		if(!ctrclient_aes_select_key(&client, i))
				return 1;

		memcpy(outbuf, &buffer[0x0], 0x30);

		if(!ctrclient_aes_set_iv(&client, iv))
			return 1;
		if(!ctrclient_aes_cbc_decrypt(&client, &outbuf[0x0], 0x10))
			return 1;
		if(!ctrclient_aes_set_iv(&client, iv))
			return 1;
		if(!ctrclient_aes_cbc_decrypt(&client, &outbuf[0x10], 0x10))
			return 1;
		if(!ctrclient_aes_set_iv(&client, iv))
			return 1;
		if(!ctrclient_aes_cbc_decrypt(&client, &outbuf[0x20], 0x10))
			return 1;

		printf("Decrypted blocks:\n");
		hexdump(outbuf, 0x30);
		}
	}

	if(genmac)
	{
		if(gensavemac(&client, savetype, buffer, saveID, imageID, &updatemac) != 0)
			return 1;

		if(writemac && updatemac)
		{
			printf("Writing updated MAC...\n");
			f = fopen(insave_path, "r+");
			if(f == NULL)
			{
				printf("Failed to open save for writing.\n");
			}
			else
			{
				fwrite(buffer, 1, 0x10, f);
				fclose(f);
			}
		}
	}

	if(generate_xorpad && use_server)
	{
		if(savetype==0)save_genxorpad(&client, 0x37, ctr, xorpad_size, xorpad_path);
		if(savetype==2)save_genxorpad(&client, 0x34, ctr, xorpad_size, xorpad_path);
		if(savetype==3)save_genxorpad(&client, 0x34, ctr, xorpad_size, xorpad_path);
		if(savetype==4)save_genxorpad(&client, 0x34, ctr, xorpad_size, xorpad_path);
	}

	ctrclient_disconnect(&client);

    return 0;
}

