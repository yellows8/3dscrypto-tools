#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/sha.h>

#include "ctrclient.h"
#include "utils.h"

void addcounter(unsigned char *ctr, unsigned long val)
{
	unsigned long carry, sum;
	int vali, pos;

	for(vali=0; vali<4; vali++)
	{
		carry = (val >> (vali*8)) & 0xff;

		for(pos=15 - vali; pos>=0; pos--)
		{
			sum = ctr[pos] + carry;
			carry = 0;
			if((unsigned char)sum < ctr[pos])carry = 1;
			ctr[pos] = sum;
		}
	}
}

int write_xorpad(ctrclient *client, FILE *foutput, unsigned int size)
{
	unsigned char *buffer;
	unsigned int chunksize = CHUNKMAXSIZE;
	int i;
	unsigned int curpos = 0;

	buffer = (unsigned char*)malloc(chunksize);

	while(curpos<size)
	{
		if(size - curpos < chunksize)chunksize = size - curpos;

		memset(buffer, 0, chunksize);
		printf("Chunk pos %x size %x\n", curpos, chunksize);

		if(!ctrclient_aes_ctr_crypt(client, buffer, chunksize))
		{
			printf("crypt fail\n");
			free(buffer);
			return 1;
		}

		printf("Writing...\n");

		if(fwrite(buffer, 1, chunksize, foutput) != chunksize)
		{
			printf("Write fail.\n");
			free(buffer);
			return 1;
		}

		fflush(foutput);

		curpos+= chunksize;
	}

	free(buffer);

	return 0;
}

int main(int argc, char *argv[])
{
	FILE *fimg;
	ctrclient client;
	unsigned char ctr[0x10];
	unsigned char cid[0x10];
	unsigned char hash[0x20];
	char serveradr[256];

	int argi, i, pos;
	unsigned int tmp=0;
	unsigned int imageoff = 0;
	int cid_set = 0, ctr_set = 0;
	unsigned int keyslot = 0;
	unsigned int size = 0;

	char imagefn[256];

	memset(ctr, 0, 0x10);
	memset(cid, 0, 0x10);
	memset(hash, 0, 0x20);
	memset(imagefn, 0, 256);
	memset(serveradr, 0, 256);

	if(argc==1)
	{
		printf("ctr-nandcrypt by yellows8\n");
		printf("Create xorpads for NAND en-/decryption, options:\n");
		printf("--serveradr=<addr> Use the specified server address instead of the default address.\n");
		printf("--imagefn=<path> Output path for xorpad file\n");
		printf("--imageoff=<hexoffset> Base NAND offset\n");
		printf("--size=<hexsize> Xorpad size\n");
		printf("--keyslot=<hexkeyslot> The keyslot to be used\n");
		printf("--cid=<hexcid> The NAND CID to be used\n");
		printf("--ctr=<hexctr> The NAND CID to be used\n");
		return 0;
	}

	for(argi=1; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--serveradr=", 12)==0)strncpy(serveradr, &argv[argi][12], 255);
		if(strncmp(argv[argi], "--imagefn=", 10)==0)strncpy(imagefn, &argv[argi][10], 255);
		if(strncmp(argv[argi], "--imageoff=", 11)==0)sscanf(&argv[argi][11], "%x", &imageoff);
		if(strncmp(argv[argi], "--size=", 7)==0)sscanf(&argv[argi][7], "%x", &size);
		if(strncmp(argv[argi], "--keyslot=", 10)==0)sscanf(&argv[argi][10], "%x", &keyslot);
		if(strncmp(argv[argi], "--cid=", 6)==0)
		{
			if(strlen(argv[argi]) != 38)
			{
				printf("Invalid CID.\n");
			}
			else
			{
				for(i=0; i<0x10; i++)
				{
					sscanf(&argv[argi][6 + i*2], "%02x", &tmp);
					cid[i] = tmp;
				}
				cid_set = 1;
			}
		}

		if(strncmp(argv[argi], "--ctr=", 6)==0)
		{
			if(strlen(argv[argi]) != 38)
			{
				printf("Invalid base CTR.\n");
			}
			else
			{
				for(i=0; i<0x10; i++)
				{
					sscanf(&argv[argi][6 + i*2], "%02x", &tmp);
					ctr[i] = tmp;
				}
				ctr_set = 1;
			}
		}
	}

	if(serveradr[0]==0)return 0;

	if(cid_set)
	{
		SHA256(cid, 0x10, hash);
		memcpy(ctr, hash, 0x10);
		addcounter(ctr, imageoff>>4);

		printf("Generated CTR:\n");
		for(i=0; i<0x10; i++)printf("%02x", ctr[i]);
		printf("\n");
	}
	else if(ctr_set)
	{
		addcounter(ctr, imageoff>>4);

		printf("Using CTR:\n");
		for(i=0; i<0x10; i++)printf("%02x", ctr[i]);
		printf("\n");
	}

	if(keyslot==0)
	{
		printf("Specify a keyslot.\n");
		return 0;
	}

	if(size==0)
	{
		printf("Specify a size.\n");
		return 0;
	}

	if(imagefn[0]==0)return 0;

	ctrclient_init();

	if (0 == ctrclient_connect(&client, serveradr, "8333"))
		return 1;
	if (!ctrclient_aes_select_key(&client, keyslot))
		return 1;
	if (!ctrclient_aes_set_ctr(&client, ctr))
		return 1;

	fimg = fopen(imagefn, "wb");
	if(fimg==NULL)
	{
		ctrclient_disconnect(&client);
		return 0;
	}

	write_xorpad(&client, fimg, size);
	fclose(fimg);

	ctrclient_disconnect(&client);

	return 0;
}

