#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/sha.h>

#include "ctrclient.h"
#include "utils.h"

void putbe16(u8* p, u16 n)//Based on the le version of the utils.c code.
{
	p[1] = n;
	p[0] = n>>8;
}

void putbe32(u8* p, u32 n)//Based on the le version of the utils.c code.
{
	p[3] = n;
	p[2] = n>>8;
	p[1] = n>>16;
	p[0] = n>>24;
}

int decrypt_data(ctrclient *client, unsigned char *buf, unsigned int size)
{
	unsigned int chunksize = CHUNKMAXSIZE;
	unsigned int curpos = 0;

	printf("Crypting...\n");
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
	u16 tmpval16=0;

	u32 programID[2] = {0};
	u32 nsdataid = 0;

	SHA256_CTX ctx;

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
		else if(strncmp(argv[argi], "--build", 7)==0)//Build a boss-container file where the final content is the input file. The --programID and --nsdataid params should be used.
		{
			output_type = 3;
		}

		//if(strncmp(argv[argi], "--verify", 8)==0)verify = 1;
		if(strncmp(argv[argi], "--payloadsz=", 12)==0)sscanf(&argv[argi][12], "%x", &payloadsz);

		if(strncmp(argv[argi], "--programID=", 12)==0)sscanf(&argv[argi][12], "%08x%08x", &programID[0], &programID[1]);
		if(strncmp(argv[argi], "--nsdataid=", 11)==0)sscanf(&argv[argi][11], "0x%08x", &nsdataid);
	}

	if(infn[0]==0)return 1;

	if(stat(infn, &filestat)==-1)return 1;

	bufsz = filestat.st_size;
	if(output_type==3)bufsz+= 0x28+0x132+0x13c;
	allocsize = (bufsz + 0xf) & ~0xf;
	buffer = (unsigned char*)malloc(allocsize);
	if(buffer==NULL)return 2;
	memset(buffer, 0, bufsz);

	f = fopen(infn, "rb");
	if(f==NULL)return 3;
	if(output_type==3)
	{
		if(fread(&buffer[0x28+0x132+0x13c], 1, filestat.st_size, f) != filestat.st_size)return 6;
	}
	if(output_type<3)
	{
		if(fread(buffer, 1, filestat.st_size, f) != filestat.st_size)return 6;
	}
	fclose(f);

	if(output_type<3 && memcmp(buffer, "boss", 4))
	{
		printf("Invalid magic number\n");
		free(buffer);
		return 5;
	}

	if(output_type==3)
	{
		memcpy(buffer, "boss", 4);
		putbe32(&buffer[0x4], 0x10001);
		putbe32(&buffer[0x8], bufsz);
		putbe32(&buffer[0xc], 0x10101010);//Timestamp doesn't seem to matter besides being non-zero anyway.
		putbe32(&buffer[0x10], 0x10101010);
		putbe16(&buffer[0x14], 0x1);
		putbe16(&buffer[0x18], 0x2);
		putbe16(&buffer[0x1a], 0x2);
	}

	if(output_type==3)
	{
		f = fopen("/dev/urandom", "rb");
		if(f==NULL)return 4;
		if(fread(&buffer[0x1c], 1, 0xc, f) != 0xc)
		{
			fclose(f);
			return 2;
		}
		fclose(f);
	}

	memcpy(ctr, &buffer[0x1c], 0xc);
	ctr[0xf] = 0x01;

	if(output_type==3)
	{
		putbe16(&buffer[0x28+0x10], 0x1);

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, &buffer[0x28], 0x12);

		SHA256_Update(&ctx, &tmpval16, 2);
		SHA256_Final(&buffer[0x28+0x12], &ctx);
	}

	if(output_type==3)
	{
		putbe32(&buffer[0x28+0x132+0x0], programID[0]);
		putbe32(&buffer[0x28+0x132+0x4], programID[1]);
		putbe32(&buffer[0x28+0x132+0x8], 0x0);
		putbe32(&buffer[0x28+0x132+0xc], 0x20001);
		putbe32(&buffer[0x28+0x132+0x10], filestat.st_size);
		putbe32(&buffer[0x28+0x132+0x14], 0x42534842);//NsDataId
		putbe32(&buffer[0x28+0x132+0x18], 0x1);

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, &buffer[0x28+0x132], 0x1c);

		SHA256_Update(&ctx, &tmpval16, 2);

		SHA256_Update(&ctx, &buffer[0x28+0x132+0x13c], filestat.st_size);
		SHA256_Final(&buffer[0x28+0x132+0x1c], &ctx);
	}

	if(!plaintext)
	{
		ctrclient_init();

		if (0 == ctrclient_connect(&client, serveradr, "8333"))
		{
			free(buffer);
			exit(9);
		}


		if (!ctrclient_aes_select_key(&client, 0x38))
		{
			free(buffer);
			return 9;
		}
		if (!ctrclient_aes_set_ctr(&client, ctr))
		{
			free(buffer);
			return 9;
		}

		if(payloadsz)bufsz = 0x176 + payloadsz;

		tmpsz = bufsz-0x28;
		if(tmpsz & 0xf)tmpsz = (tmpsz + 0xf) & ~0xf;

		if(decrypt_data(&client, &buffer[0x28], tmpsz)!=0)
		{
			free(buffer);
			return 9;
		}

		ctrclient_disconnect(&client);
	}

	if(outfn[0])
	{
		if(output_type<3)
		{
			if(output_type>=1)outoff+=0x132;
			if(output_type>=2)outoff+=0x1c;
		}
		else
		{
			outoff = 0;
		}

		printf("Writing output...\n");
		f = fopen(outfn, "wb");
		fwrite(&buffer[outoff], 1, bufsz-outoff, f);
		fclose(f);
	}
	free(buffer);

	printf("Done\n");

    return 0;
}

