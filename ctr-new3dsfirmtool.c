#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "ctrclient.h"
#include "utils.h"

int main(int argc, char *argv[])
{
	int argi;
	int genxorpad=0;
	unsigned int size=0;
	unsigned int *buffer32, pos;
	unsigned char *buffer;
	unsigned char *xorbuf;
	FILE *finput, *foutput;
	unsigned int keyslot=0x15;

	ctrclient client;

	struct stat instat;

	char infn[256];
	char outfn[256];
	char serveradr[256];

	if(argc==1)
	{
		printf("ctr-new3dsfirmtool by yellows8\n");
		printf("Crypt the ARM9 section binary in New3DS FIRM. The keyX for keyslot 0x15 must be set correctly before running this.\n");
		printf("Options:\n");
		printf("--serveradr=<addr> Server IP address to use\n");
		printf("--input=<path> Input path for the input ARM9 section\n");
		printf("--output=<path> Output path with data starting at the ARM9 section header\n");
		printf("--xorpad Generate a xorpad instead of just decrypting the input\n");
		printf("--keyslot=0x<hexval> Keyslot to use, default is 0x15.\n");
		return 0;
	}

	memset(serveradr, 0, 256);

	memset(infn, 0, 256);
	memset(outfn, 0, 256);

	for(argi=1; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--serveradr=", 12)==0)strncpy(serveradr, &argv[argi][12], 255);
		if(strncmp(argv[argi], "--input=", 8)==0)strncpy(infn, &argv[argi][8], 255);
		if(strncmp(argv[argi], "--output=", 9)==0)strncpy(outfn, &argv[argi][9], 255);
		if(strncmp(argv[argi], "--xorpad", 8)==0)genxorpad = 1;
		if(strncmp(argv[argi], "--keyslot=", 10)==0)sscanf(&argv[argi][10], "0x%x", &keyslot);
	}

	if(infn[0]==0 || outfn[0]==0 || serveradr[0]==0)return 1;

	if(stat(infn, &instat)==-1)
	{
		printf("Failed to stat %s\n", infn);
		return 1;
	}

	size = instat.st_size;

	if(size<=0x800)
	{
		printf("Input file is too small.\n");
		return 1;
	}

	buffer = (unsigned char*)malloc(size);
	if(buffer==NULL)return 1;

	xorbuf = (unsigned char*)malloc(size);
	if(xorbuf==NULL)
	{
		free(buffer);
		return 1;
	}

	buffer32 = (unsigned int*)buffer;
	memset(buffer, 0, size);
	memset(xorbuf, 0, size);

	finput = fopen(infn, "rb");
	foutput = fopen(outfn, "wb");
	if(finput==NULL || foutput==NULL)
	{
		free(buffer);
		free(xorbuf);
		if(finput)fclose(finput);
		if(foutput)fclose(foutput);
		return 1;
	}

	if(fread(buffer, 1, size, finput) != size)
	{
		printf("Failed to read the input file.\n");

		free(buffer);
		free(xorbuf);
		fclose(finput);
		fclose(foutput);
		return 1;
	}

	ctrclient_init();
	if(!ctrclient_connect(&client, serveradr, "8333"))
	{
		free(buffer);
		free(xorbuf);
		fclose(finput);
		fclose(foutput);
		return 2;
	}

	if(!ctrclient_aes_set_ykey(&client, keyslot, &buffer[0x10]))
	{
		free(buffer);
		free(xorbuf);
		fclose(finput);
		fclose(foutput);
		return 2;
	}

	if(!ctrclient_aes_set_ctr(&client, &buffer[0x20]))
	{
		free(buffer);
		free(xorbuf);
		fclose(finput);
		fclose(foutput);
		return 2;
	}

	if(!ctrclient_aes_ctr_crypt(&client, &xorbuf[0x800], size-0x800))
	{
		free(buffer);
		free(xorbuf);
		fclose(finput);
		fclose(foutput);
		return 2;
	}

	ctrclient_disconnect(&client);

	for(pos=0x800; pos<size; pos++)buffer[pos] ^= xorbuf[pos];

	for(pos=(0x800>>2); pos<(size>>2); pos++)//Locate the Process9 NCCH, to determine the actual ARM9 section plaintext binary size.
	{
		if(buffer32[pos] == 0x4843434e)break;
	}

	if(pos == (size>>2))
	{
		printf("Warning: failed to find Process9 NCCH, writing entire decrypted output anyway.\n");
	}
	else
	{
		size = ((pos<<2) - 0x100) + (buffer32[pos+1]*0x200);
	}

	if(!genxorpad)fwrite(buffer, 1, size, foutput);
	if(genxorpad)fwrite(xorbuf, 1, size, foutput);

	free(buffer);
	free(xorbuf);
	fclose(finput);
	fclose(foutput);

    	return 0;
}

