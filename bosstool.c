#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "polarssl/rsa.h"
#include "polarssl/sha2.h"

#include "ctrclient.h"
#include "utils.h"
int decrypt_data(ctrclient *client, unsigned char *buf, unsigned int size)
{
	unsigned int chunksize = CHUNKMAXSIZE;
	unsigned int curpos = 0;

	printf("Decrypting...\n");
	while(curpos<size)
	{
		if(size - curpos < chunksize)chunksize = size - curpos;
		printf("chunk pos %x size %x\n", curpos, chunksize);

		if (!ctrclient_aes_ctr_crypt(client, &buf[curpos], chunksize))
		{
			return 1;
		}

		curpos+= chunksize;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	ctrclient client;
	unsigned char *buffer;
	unsigned char ctr[16];

	int argi;
	unsigned int bufsz = 0, tmpsz, allocsize;
	unsigned int payloadsz = 0;
	FILE *f;
	struct stat filestat;
	int plaintext = 0;
	int output_type = 0;
	//int verify = 0;
	unsigned int outoff = 0x28;

	char infn[256];
	char outfn[256];
	char serveradr[256];

	memset(ctr, 0, 0x10);
	memset(infn, 0, 256);
	memset(outfn, 0, 256);
	memset(serveradr, 0, 256);

	for(argi=1; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--serveradr=", 12)==0)strncpy(serveradr, &argv[argi][12], 255);
		if(strncmp(argv[argi], "--input=", 8)==0)strncpy(infn, &argv[argi][8], 255);
		if(strncmp(argv[argi], "--output=", 9)==0)strncpy(outfn, &argv[argi][9], 255);
		if(strncmp(argv[argi], "-p", 2)==0)plaintext = 1;
		if(strncmp(argv[argi], "--payloadhdr", 12)==0)
		{
			output_type = 1;
		}
		else if(strncmp(argv[argi], "--payload", 9)==0)
		{
			output_type = 2;
		}

		//if(strncmp(argv[argi], "--verify", 8)==0)verify = 1;
		if(strncmp(argv[argi], "--payloadsz=", 12)==0)sscanf(&argv[argi][12], "%x", &payloadsz);
	}

	if(infn[0]==0)return 1;

	if(stat(infn, &filestat)==-1)return 1;

	bufsz = filestat.st_size;
	allocsize = (bufsz + 0xf) & ~0xf;
	buffer = (unsigned char*)malloc(allocsize);
	if(buffer==NULL)return 1;
	memset(buffer, 0, bufsz);

	f = fopen(infn, "rb");
	if(f==NULL)return 1;
	if(fread(buffer, 1, bufsz, f) != bufsz)return 1;
	fclose(f);

	if(memcmp(buffer, "boss", 4))
	{
		printf("Invalid magic number\n");
		free(buffer);
		return 1;
	}

	memcpy(ctr, &buffer[0x1c], 0xc);
	ctr[0xf] = 0x01;

	if(!plaintext)
	{
		ctrclient_init();

		if (0 == ctrclient_connect(&client, serveradr, "8333"))
		{
			free(buffer);
			exit(1);
		}


		if (!ctrclient_aes_select_key(&client, 0x38))
		{
			free(buffer);
			return 1;
		}
		if (!ctrclient_aes_set_ctr(&client, ctr))
		{
			free(buffer);
			return 1;
		}

		if(payloadsz)bufsz = 0x176 + payloadsz;

		tmpsz = bufsz-0x28;
		if(tmpsz & 0xf)tmpsz = (tmpsz + 0xf) & ~0xf;

		if(decrypt_data(&client, &buffer[0x28], tmpsz)!=0)
		{
			free(buffer);
			return 1;
		}

		ctrclient_disconnect(&client);
	}

	if(outfn[0])
	{
		if(output_type>=1)outoff+=0x132;
		if(output_type>=2)outoff+=0x1c;

		printf("Writing output...\n");
		f = fopen(outfn, "wb");
		fwrite(&buffer[outoff], 1, bufsz-outoff, f);
		fclose(f);
	}
	free(buffer);

	printf("Done\n");

    return 0;
}

