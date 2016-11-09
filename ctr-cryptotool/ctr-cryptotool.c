#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

#include <openssl/aes.h>

//Build with: gcc ctr-cryptotool.c -lcrypto -o ctr-cryptotool

static unsigned char constantkey[16];

unsigned int totalprocesses = 1;
unsigned long long bruteval_start = 0, bruteval_end = 0x10000;//0x100;//0x100000000;
unsigned int procid = 0;

unsigned int keyYbitpos_keyXequalivant[128] = {
/*keyY bit0*/ 14,
/*keyY bit1*/ 15,
/*keyY bit2*/ 0,
/*keyY bit3*/ 1,
/*keyY bit4*/ 2,
/*keyY bit5*/ 3,
/*keyY bit6*/ 4,
/*keyY bit7*/ 5,
/*keyY bit8*/ 22,
/*keyY bit9*/ 23,
/*keyY bit10*/ 8,
/*keyY bit11*/ 9,
/*keyY bit12*/ 10,
/*keyY bit13*/ 11,
/*keyY bit14*/ 12,
/*keyY bit15*/ 13,
/*keyY bit16*/ 30,
/*keyY bit17*/ 31,
/*keyY bit18*/ 16,
/*keyY bit19*/ 17,
/*keyY bit20*/ 18,
/*keyY bit21*/ 19,
/*keyY bit22*/ 20,
/*keyY bit23*/ 21,
/*keyY bit24*/ 38,
/*keyY bit25*/ 39,
/*keyY bit26*/ 24,
/*keyY bit27*/ 25,
/*keyY bit28*/ 26,
/*keyY bit29*/ 27,
/*keyY bit30*/ 28,
/*keyY bit31*/ 29,
/*keyY bit32*/ 46,
/*keyY bit33*/ 47,
/*keyY bit34*/ 32,
/*keyY bit35*/ 33,
/*keyY bit36*/ 34,
/*keyY bit37*/ 35,
/*keyY bit38*/ 36,
/*keyY bit39*/ 37,
/*keyY bit40*/ 54,
/*keyY bit41*/ 55,
/*keyY bit42*/ 40,
/*keyY bit43*/ 41,
/*keyY bit44*/ 42,
/*keyY bit45*/ 43,
/*keyY bit46*/ 44,
/*keyY bit47*/ 45,
/*keyY bit48*/ 62,
/*keyY bit49*/ 63,
/*keyY bit50*/ 48,
/*keyY bit51*/ 49,
/*keyY bit52*/ 50,
/*keyY bit53*/ 51,
/*keyY bit54*/ 52,
/*keyY bit55*/ 53,
/*keyY bit56*/ 70,
/*keyY bit57*/ 71,
/*keyY bit58*/ 56,
/*keyY bit59*/ 57,
/*keyY bit60*/ 58,
/*keyY bit61*/ 59,
/*keyY bit62*/ 60,
/*keyY bit63*/ 61,
/*keyY bit64*/ 78,
/*keyY bit65*/ 79,
/*keyY bit66*/ 64,
/*keyY bit67*/ 65,
/*keyY bit68*/ 66,
/*keyY bit69*/ 67,
/*keyY bit70*/ 68,
/*keyY bit71*/ 69,
/*keyY bit72*/ 86,
/*keyY bit73*/ 87,
/*keyY bit74*/ 72,
/*keyY bit75*/ 73,
/*keyY bit76*/ 74,
/*keyY bit77*/ 75,
/*keyY bit78*/ 76,
/*keyY bit79*/ 77,
/*keyY bit80*/ 94,
/*keyY bit81*/ 95,
/*keyY bit82*/ 80,
/*keyY bit83*/ 81,
/*keyY bit84*/ 82,
/*keyY bit85*/ 83,
/*keyY bit86*/ 84,
/*keyY bit87*/ 85,
/*keyY bit88*/ 102,
/*keyY bit89*/ 103,
/*keyY bit90*/ 88,
/*keyY bit91*/ 89,
/*keyY bit92*/ 90,
/*keyY bit93*/ 91,
/*keyY bit94*/ 92,
/*keyY bit95*/ 93,
/*keyY bit96*/ 110,
/*keyY bit97*/ 111,
/*keyY bit98*/ 96,
/*keyY bit99*/ 97,
/*keyY bit100*/ 98,
/*keyY bit101*/ 99,
/*keyY bit102*/ 100,
/*keyY bit103*/ 101,
/*keyY bit104*/ 118,
/*keyY bit105*/ 119,
/*keyY bit106*/ 104,
/*keyY bit107*/ 105,
/*keyY bit108*/ 106,
/*keyY bit109*/ 107,
/*keyY bit110*/ 108,
/*keyY bit111*/ 109,
/*keyY bit112*/ 126,
/*keyY bit113*/ 127,
/*keyY bit114*/ 112,
/*keyY bit115*/ 113,
/*keyY bit116*/ 114,
/*keyY bit117*/ 115,
/*keyY bit118*/ 116,
/*keyY bit119*/ 117,
/*keyY bit120*/ 6,
/*keyY bit121*/ 7,
/*keyY bit122*/ 120,
/*keyY bit123*/ 121,
/*keyY bit124*/ 122,
/*keyY bit125*/ 123,
/*keyY bit126*/ 124,
/*keyY bit127*/ 125
};

int load_bindata(char *arg, unsigned char **buf, unsigned int *size)
{
	int i;
	unsigned int tmp=0;
	unsigned char *bufptr;
	FILE *f;
	struct stat filestat;

	//if(strlen(arg) != size*2)exit(1);

	bufptr = *buf;

	if(arg[0]!='@')
	{
		if(bufptr==NULL)
		{
			*size = strlen(arg) / 2;
			*buf = (unsigned char*)malloc(*size);
			bufptr = *buf;
			if(bufptr==NULL)
			{
				printf("Failed to allocate memory for input buffer.\n");
				return 1;
			}

			memset(bufptr, 0, *size);
		}

		for(i=0; i<*size; i++)
		{
			if(i>=strlen(arg))break;
			sscanf(&arg[i*2], "%02x", &tmp);
			bufptr[i] = (unsigned char)tmp;
		}
	}
	else
	{
		if(stat(&arg[1], &filestat)==-1)
		{
			printf("Failed to stat %s\n", &arg[1]);
			return 2;
		}

		f = fopen(&arg[1], "rb");
		if(f==NULL)
		{
			printf("Failed to open %s\n", &arg[1]);
			return 2;
		}

		if(bufptr)
		{
			if(*size < filestat.st_size)*size = filestat.st_size;
		}
		else
		{
			*size = filestat.st_size;
			*buf = (unsigned char*)malloc(*size);
			bufptr = *buf;

			if(bufptr==NULL)
			{
				printf("Failed to allocate memory for input buffer.\n");
				return 1;
			}

			memset(bufptr, 0, *size);
		}

		if(fread(bufptr, 1, *size, f) != *size)
		{
			printf("Failed to read file %s\n", &arg[1]);
			fclose(f);
			return 3;
		}

		fclose(f);
	}

	return 0;
}

int fork_processes()
{
	pid_t ret;
	unsigned int i;
	unsigned long long chunksize = bruteval_end / totalprocesses;

	bruteval_start = chunksize;
	bruteval_end = chunksize*2;

	for(i=0; i<totalprocesses-1; i++)
	{
		procid = i+1;
		ret = fork();
		if(ret==0)
		{
			if(procid==totalprocesses-1)bruteval_end = 0x100000000;
			return 0;//child
		}
		if(ret==-1)return ret;

		bruteval_start+= chunksize;
		bruteval_end+= chunksize;
	}

	bruteval_start = 0;
	bruteval_end = chunksize;
	procid = 0;
}

unsigned char parsebuf[0x1000];

int parse_cryptdump(char *path)
{
	unsigned int biti, keyindex;
	unsigned int bitpos, keyindexother;
	unsigned int printi;
	int found = 0;
	FILE *finput;

	finput = fopen(path, "rb");
	fread(parsebuf, 1, 0x1000, finput);
	fclose(finput);

	for(biti=0; biti<128; biti++)
	{
		for(keyindex=0; keyindex<2; keyindex++)
		{
			if(keyindex==0)continue;

			if(keyindex==0)printf("keyX bit%d=1/keyY=0: ", biti);
			if(keyindex==1)printf("keyY bit%d ", biti);

			for(printi=0; printi<16; printi++)printf("%02x", parsebuf[((biti*0x20) + (keyindex*0x10)) + printi]);
			printf(" ");

			found = 0;
			for(bitpos=0; bitpos<128; bitpos++)
			{
				for(keyindexother=0; keyindexother<2; keyindexother++)
				{
					if(bitpos==biti && keyindex==keyindexother)continue;

					if(memcmp(&parsebuf[(biti*0x20) + (keyindex*0x10)], &parsebuf[(bitpos*0x20) + (keyindexother*0x10)], 0x10)==0)
					{
						if(keyindexother==0)printf("same as keyX bit%d,", bitpos);
						if(keyindexother==1)printf("same as keyY bit%d=1/keyX=0.", bitpos);

						found = 1;
						break;
					}
				}
				if(found)break;
			}

			found = 0;

			printf("\n");
		}
	}

	return 0;
}

void n128_lrot(unsigned char *num, unsigned long shift)
{
	unsigned long tmpshift;
	unsigned int i;
	unsigned char tmp[16];

	while(shift)
	{
		tmpshift = shift;
		if(tmpshift>=8)tmpshift = 8;

		if(tmpshift==8)
		{
			for(i=0; i<16; i++)tmp[i] = num[i == 15 ? 0 : i+1];

			memcpy(num, tmp, 16);
		}
		else
		{
			for(i=0; i<16; i++)tmp[i] = (num[i] << tmpshift) | (num[i == 15 ? 0 : i+1] >> (8-tmpshift));
			memcpy(num, tmp, 16);
		}

		shift-=tmpshift;
	}

}

void n128_rrot(unsigned char *num, unsigned long shift)
{
	unsigned long tmpshift;
	unsigned int i;
	unsigned char tmp[16];

	while(shift)
	{
		tmpshift = shift;
		if(tmpshift>=8)tmpshift = 8;

		if(tmpshift==8)
		{
			for(i=0; i<16; i++)tmp[i] = num[i == 0 ? 15 : i-1];

			memcpy(num, tmp, 16);
		}
		else
		{
			for(i=0; i<16; i++)tmp[i] = (num[i] >> tmpshift) | (num[i == 0 ? 15 : i-1] << (8-tmpshift));
			memcpy(num, tmp, 16);
		}

		shift-=tmpshift;
	}
}

void n128_add(unsigned char *a, unsigned char *b)
{
	unsigned int i, carry=0, val;
	unsigned char tmp[16];
	unsigned char tmp2[16];
	unsigned char *out = (unsigned char*)a;

	memcpy(tmp, (unsigned char*)a, 16);
	memcpy(tmp2, (unsigned char*)b, 16);

	for(i=0; i<16; i++)
	{
		val = tmp[15-i] + tmp2[15-i] + carry;
		out[15-i] = (unsigned char)val;
		carry = val >> 8;
	}
}

void n128_sub(unsigned char *a, unsigned char *b)
{
	unsigned int i, carry=0, val;
	unsigned char tmp[16];
	unsigned char tmp2[16];
	unsigned char *out = (unsigned char*)a;

	memcpy(tmp, (unsigned char*)a, 16);
	memcpy(tmp2, (unsigned char*)b, 16);

	carry = 0;

	for(i=0; i<16; i++)
	{
		val = 0x100;
		val += tmp[15-i] - tmp2[15-i] - carry;
		out[15-i] = (unsigned char)val;

		carry = val >> 8;
		carry = !carry;
	}
}

void n128_add_le(uint64_t *a, uint64_t *b)
{
	uint64_t *a64 = a;
	uint64_t *b64 = b;
	uint64_t tmp = (a64[0]>>1)+(b64[0]>>1) + (a64[0] & b64[0] & 1);
        
	tmp = tmp >> 63;
        a64[0] = a64[0] + b64[0];

	if(tmp==0)return;

        a64[1] = a64[1] + b64[1] + tmp;
}

void ctr_keygenerator(unsigned char *outkey, unsigned char *keyX, unsigned char *keyY)
{
	int i;
	int pos;
	unsigned char tmpkey[16];
	unsigned char tmpkeyX[16];
	unsigned char tmpkeyY[16];

	memcpy(tmpkeyX, keyX, 16);
	memcpy(tmpkeyY, keyY, 16);

	n128_lrot(tmpkeyX, 2);
	for(i=0; i<16; i++)tmpkey[i] = tmpkeyX[i] ^ tmpkeyY[i];

	printf("combined tmpkey: ");
	for(i=0; i<16; i++)printf("%02x", tmpkey[i]);
	printf("\n");

	n128_add(tmpkey, constantkey);

	n128_rrot(tmpkey, 41);

	memcpy(outkey, tmpkey, 16);
}

void ctr_keygenerator_reverse(unsigned char *in_finalnormalkey, unsigned char *keyX_xor, unsigned char *keyY_xor)
{
	int i;
	int pos;
	unsigned char tmpkey[16];
	unsigned char tmpkeyX[16];
	unsigned char tmpkeyY[16];

	memset(tmpkey, 0, 16);
	memset(tmpkeyX, 0, 16);
	memset(tmpkeyY, 0, 16);

	memcpy(tmpkey, in_finalnormalkey, 16);

	n128_lrot(tmpkey, 41);

	printf("tmpkey after rotate: ");
	for(i=0; i<16; i++)printf("%02x", tmpkey[i]);
	printf("\n");

	n128_sub(tmpkey, constantkey);

	printf("tmpkey after subtract: ");
	for(i=0; i<16; i++)printf("%02x", tmpkey[i]);
	printf("\n");

	memcpy(tmpkeyX, tmpkey, 16);
	memcpy(tmpkeyY, tmpkey, 16);

	n128_rrot(tmpkeyX, 2);

	if(keyX_xor)
	{
		for(i=0; i<16; i++)tmpkeyX[i] ^= keyX_xor[i];
	}

	if(keyY_xor)
	{
		for(i=0; i<16; i++)tmpkeyY[i] ^= keyY_xor[i];
	}

	printf("key as a keyX: ");
	for(i=0; i<16; i++)printf("%02x", tmpkeyX[i]);
	printf("\n");

	printf("key as a keyY: ");
	for(i=0; i<16; i++)printf("%02x", tmpkeyY[i]);
	printf("\n");

	n128_lrot(tmpkeyX, 2);
	n128_rrot(tmpkeyY, 2);

	printf("tmpkeyX converted to keyY: ");
	for(i=0; i<16; i++)printf("%02x", tmpkeyX[i]);
	printf("\n");

	printf("tmpkeyY converted to keyX: ");
	for(i=0; i<16; i++)printf("%02x", tmpkeyY[i]);
	printf("\n");
}

int popcount(uint32_t v) { //https://stackoverflow.com/questions/109023/how-to-count-the-number-of-set-bits-in-a-32-bit-integer
    v = v - ((v >> 1) & 0x55555555);                // put count of each 2 bits into those 2 bits
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333); // put count of each 4 bits into those 4 bits  
    return ((v + (v >> 4) & 0xF0F0F0F) * 0x1010101) >> 24;
}

int popcount64(uint64_t v) { //Modification of the above.
    v = v - ((v >> 1) & 0x5555555555555555ULL);                // put count of each 2 bits into those 2 bits
    v = (v & 0x3333333333333333ULL) + ((v >> 2) & 0x3333333333333333LL); // put count of each 4 bits into those 4 bits  
    return ((v + (v >> 4) & 0xF0F0F0FF0F0F0FULL) * 0x0101010101010101ULL) >> 56;
}

void brutebitlimits(AES_KEY *aeskey, unsigned int setbits)
{
	unsigned int i, pos;
	unsigned int min_setbits, max_setbits;
	unsigned int cur_setbits;
	unsigned char curkey[0x10];
	unsigned char count16[0x10];
	unsigned char stopblock[0x10];
	unsigned char addblock[0x10];

	time_t first_time;
	time_t last_time;
	
	uint64_t *curkey64 = (uint64_t*)curkey;
	uint32_t *curkey32 = (uint32_t*)curkey;

	memset(curkey, 0, 0x10);
	memset(count16, 0, 0x10);
	memset(stopblock, 0, 0x10);
	memset(addblock, 0, 0x10);

	addblock[0] = 1;
	stopblock[4] = 1;

	min_setbits = setbits;
	max_setbits = min_setbits;

	first_time = time(NULL);

	while(1)
	{
		last_time = time(NULL);
		if((last_time - first_time) >= 60)
		{
			first_time = last_time;

			printf("curkey:\n");
			for(i=0; i<0x10; i++)printf("%02x", curkey[i]);
			printf("\n");
			
			printf("count16:\n0x");
			for(i=0; i<0x10; i++)printf("%02x", count16[15-i]);
			printf("\n");
		}

		n128_add_le((uint64_t*)curkey, (uint64_t*)addblock);

		if(memcmp(curkey, stopblock, 0x10)==0)break;

		cur_setbits = 0;

		/*for(i=0; i<2; i++)
		{
			if(curkey64[i]==0)continue;
			for(pos=0; pos<64; pos++)
			{
				if(curkey64[i] & (1<<pos))cur_setbits++;
			}
		}*/

		for(i=0; i<2; i++)cur_setbits+= popcount(curkey64[i]);

		if((cur_setbits < min_setbits) || (cur_setbits > max_setbits))continue;

		n128_add_le((uint64_t*)count16, (uint64_t*)addblock);
	}

	printf("brutebitlimits() finshed, count16:\n0x");
	for(i=0; i<0x10; i++)printf("%02x", count16[15-i]);
	printf("\n");
}

int main(int argc, char *argv[])
{
	AES_KEY aeskey;
	unsigned int aes_num;
        unsigned char aes_ecount[AES_BLOCK_SIZE];

	size_t nc_off = 0;
	unsigned char streamblock[16];
	unsigned char *normalkey = NULL;
	unsigned char tmpkey[16];
	unsigned char *keyX = NULL;
	unsigned char *keyY = NULL;
	unsigned char xorkey0[16];
	unsigned char xorkey1[16];

	char outpath[256];

	unsigned char *buffer = NULL;
	unsigned char *ctr = NULL;
	unsigned char *cmpblock = NULL;
	unsigned int tmpsize, inbufsize=0;

	int argi, i, pos, printi;
	int ret=0;
	unsigned int brutekeypos = 0, brutekeypos_end = 0xc;
	unsigned long long bruteval64 = 0, bruteval_startoff = 0;
	int enable_brutebitlimits = 0;
	unsigned int setbits = 0;
	unsigned int tmp=0, val;
	unsigned int biti, bitpos;
	int cmpblock_set = 0, cmpblock_type = 0;
	int brutekeyposend_set = 0;
	int brutebits = 0;
	int foundblock = 0;
	unsigned int cmpblock_size = 0;
	unsigned int normalkey_set = 0, keyX_set = 0, keyY_set = 0, xorkey0_set = 0, xorkey1_set = 0;
	unsigned int reversekey = 0;
	FILE *foutkey, *f;
	struct stat filestats;
	int cryptmode = 2;

	time_t first_time, last_time;

	char *strptr;
	char tmpname[256];

	memset(streamblock, 0, 0x10);
	memset(tmpkey, 0, 0x10);
	memset(outpath, 0, sizeof(outpath));

	printf("ctr-cryptotool by yellows8\n");

	for(argi=1; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--normalkey=", 12)==0)
		{
			tmpsize = 0x10;
			if((ret = load_bindata(&argv[argi][12], (unsigned char**)&normalkey, &tmpsize))!=0 || tmpsize<0x10)
			{
				printf("The specified input for the normalkey is invalid.\n");
			}
			if(ret==0)normalkey_set = 1;
		}

		if(strncmp(argv[argi], "--keyX=", 7)==0)
		{
			tmpsize = 0x10;
			if((ret = load_bindata(&argv[argi][7], (unsigned char**)&keyX, &tmpsize))!=0 || tmpsize<0x10)
			{
				printf("The specified input for the keyX is invalid.\n");
			}
			if(ret==0)keyX_set = 1;
		}

		if(strncmp(argv[argi], "--keyY=", 7)==0)
		{
			tmpsize = 0x10;
			if((ret = load_bindata(&argv[argi][7], (unsigned char**)&keyY, &tmpsize))!=0 || tmpsize<0x10)
			{
				printf("The specified input for the keyY is invalid.\n");
			}
			if(ret==0)keyY_set = 1;
		}

		if(strncmp(argv[argi], "--xorkey0=", 10)==0)
		{
			if(strlen(&argv[argi][10]) != 32)
			{
				printf("Invalid xorkey0.\n");
			}
			else
			{
				pos=0;
				for(i=0; i<0x10; i++)
				{
					sscanf(&argv[argi][10+pos], "%02x", &tmp);
					xorkey0[i] = tmp;
					pos+=2;
				}

				xorkey0_set = 1;
			}
		}

		if(strncmp(argv[argi], "--xorkey1=", 10)==0)
		{
			if(strlen(&argv[argi][10]) != 32)
			{
				printf("Invalid xorkey1.\n");
			}
			else
			{
				pos=0;
				for(i=0; i<0x10; i++)
				{
					sscanf(&argv[argi][10+pos], "%02x", &tmp);
					xorkey1[i] = tmp;
					pos+=2;
				}

				xorkey1_set = 1;
			}
		}

		if(strncmp(argv[argi], "--ctr=", 6)==0)
		{
			tmpsize = 0x10;
			if(load_bindata(&argv[argi][6], (unsigned char**)&ctr, &tmpsize)!=0)
			{
				printf("Invalid hex input for the CTR.\n");
				return 1;
			}
		}

		if(strncmp(argv[argi], "--iv=", 5)==0)
		{
			tmpsize = 0x10;
			if(load_bindata(&argv[argi][5], (unsigned char**)&ctr, &tmpsize)!=0)
			{
				printf("Invalid hex input for the CTR.\n");
				return 1;
			}
		}

		if(strncmp(argv[argi], "--indata=", 9)==0)
		{
			ret = load_bindata(&argv[argi][9], &buffer, &inbufsize);
		}

		if(strncmp(argv[argi], "--outpath=", 10)==0)strncpy(outpath, &argv[argi][10], 255);

		if(strncmp(argv[argi], "--cmpblock=", 11)==0 || strncmp(argv[argi], "--cmpblock2=", 12)==0)
		{
			if(strncmp(argv[argi], "--cmpblock=", 11)==0)cmpblock_type = 0;
			if(strncmp(argv[argi], "--cmpblock2=", 12)==0)cmpblock_type = 1;

			if(argv[argi][11] == '@')
			{
				if(stat(&argv[argi][12], &filestats)==-1)
				{
					printf("Failed to stat cmpblock file: %s\n", &argv[argi][12]);
					return 2;
				}
				else
				{
					cmpblock_size = filestats.st_size;
					cmpblock = (unsigned char*)malloc(cmpblock_size);
					if(cmpblock==NULL)
					{
						printf("Failed to alloc memory for cmpblock, size=0x%x-bytes.\n", cmpblock_size);
						return 1;
					}
					memset(cmpblock, 0, cmpblock_size);

					f = fopen(&argv[argi][12], "rb");
					if(f)
					{
						fread(cmpblock, 1, cmpblock_size, f);
						fclose(f);
						cmpblock_set = 1;
					}
					else
					{
						printf("Failed to open cmpblock file: %s\n", &argv[argi][12]);
						return 2;
					}
				}
			}
			else if(strlen(&argv[argi][11]) == 32)
			{
				cmpblock_size = 0x10;
				cmpblock = (unsigned char*)malloc(cmpblock_size);
				if(cmpblock==NULL)
				{
					printf("Failed to alloc memory for cmpblock, size=0x%x-bytes.\n", cmpblock_size);
					return 1;
				}
				memset(cmpblock, 0, cmpblock_size);

				pos=0;
				for(i=0; i<0x10; i++)
				{
					sscanf(&argv[argi][11+pos], "%02x", &tmp);
					cmpblock[i] = tmp;
					pos+=2;
				}
				cmpblock_set = 1;
			}
			else
			{
				printf("Invalid compare block.\n");
			}
		}

		if(strncmp(argv[argi], "--brutekeypos=", 14)==0)sscanf(&argv[argi][14], "%x", &brutekeypos);//start bitpos for bruteforce
		if(strncmp(argv[argi], "--brutekeypos_end=", 18)==0)//end bitpos for bruteforce
		{
			sscanf(&argv[argi][18], "%x", &brutekeypos_end);
			brutekeyposend_set = 1;
		}
		if(strncmp(argv[argi], "--bruteval64=", 13)==0)sscanf(&argv[argi][13], "%llx", &bruteval_startoff);
		if(strncmp(argv[argi], "--brutebits=", 12)==0)sscanf(&argv[argi][12], "%d", &brutebits);
		if(strncmp(argv[argi], "--totalproc=", 12)==0)sscanf(&argv[argi][12], "%x", &totalprocesses);

		if(strncmp(argv[argi], "--brutebitlimits", 12)==0)enable_brutebitlimits = 1;
		if(strncmp(argv[argi], "--setbits=", 10)==0)sscanf(&argv[argi][10], "%x", &setbits);

		if(strncmp(argv[argi], "--parse=", 8)==0)return parse_cryptdump(&argv[argi][8]);

		if(strncmp(argv[argi], "--reversekey", 12)==0)reversekey = 1;

		if(strncmp(argv[argi], "--aesctr", 8)==0)cryptmode = 2;
		if(strncmp(argv[argi], "--aescbcdecrypt", 15)==0)cryptmode = 4;
		if(strncmp(argv[argi], "--aescbcencrypt", 15)==0)cryptmode = 5;
		if(strncmp(argv[argi], "--aesecbdec", 11)==0)cryptmode = 6;

		if(ret!=0)break;
	}

	if(normalkey==NULL)
	{
		normalkey = malloc(0x10);
		memset(normalkey, 0, 0x10);
	}

	if(ctr==NULL)
	{
		ctr = malloc(0x10);
		memset(ctr, 0, 0x10);
	}

	if(buffer==NULL)
	{
		buffer = malloc(0x10);
		memset(buffer, 0, 0x10);
		inbufsize = 0x10;
	}

	if(normalkey==NULL || ctr==NULL || buffer==NULL)
	{
		printf("Failed to alloc mem.\n");
		return 1;
	}

	if(xorkey0_set)
	{
		if(normalkey_set)
		{
			for(i=0; i<0x10; i++)normalkey[i] ^= xorkey0[i];
		}

		if(keyX_set)
		{
			for(i=0; i<0x10; i++)keyX[i] ^= xorkey0[i];
		}

		if(keyY_set)
		{
			for(i=0; i<0x10; i++)keyY[i] ^= xorkey0[i];
		}
	}

	if(xorkey1_set)
	{
		if(normalkey_set)
		{
			for(i=0; i<0x10; i++)normalkey[i] ^= xorkey1[i];
		}

		if(keyX_set)
		{
			for(i=0; i<0x10; i++)keyX[i] ^= xorkey1[i];
		}

		if(keyY_set)
		{
			for(i=0; i<0x10; i++)keyY[i] ^= xorkey1[i];
		}
	}

	if(enable_brutebitlimits)brutebitlimits(&aeskey, setbits);

	if(!brutekeyposend_set && brutebits)brutekeypos_end = 0x80;

	if((keyX_set && keyY_set) || reversekey)
	{
		strptr = getenv("HOME");
		if(strptr==NULL)
		{
			printf("getenv() for HOME failed.\n");
			return 9;
		}

		memset(tmpname, 0, sizeof(tmpname));
		snprintf(tmpname, sizeof(tmpname)-1, "%s/.3ds/aeshw_keygen_constant", strptr);
		f = fopen(tmpname, "rb");
		if(f==NULL)
		{
			printf("Failed to open the aeshw_keygen_constant file.\n");
			return 10;
		}

		fread(constantkey, 1, 16, f);
		fclose(f);
	}

	if(keyX_set && keyY_set)ctr_keygenerator(normalkey, keyX, keyY);

	if(reversekey)ctr_keygenerator_reverse(normalkey, keyX, keyY);

	printf("\nNormal-key:\n");
	for(i=0; i<16; i++)printf("%02x", normalkey[i]);

	printf("\nBuffer:\n");
	for(i=0; i<16; i++)printf("%02x", buffer[i]);

	printf("\nCTR/IV:\n");
	for(i=0; i<16; i++)printf("%02x", ctr[i]);
	printf("\n\n");

	printf("Crypting the data...\n");

	if(!cmpblock_set || cmpblock_type==0)
	{
		aes_num = 0;
		memset(aes_ecount, 0, AES_BLOCK_SIZE);

		if(cryptmode==2)
		{
			if (AES_set_encrypt_key(normalkey, 128, &aeskey) < 0)
    			{
        			printf("Failed to set AES key.\n");
       	 			return 1;
    			}

			AES_ctr128_encrypt(buffer, buffer, inbufsize, &aeskey, ctr, aes_ecount, &aes_num);
		}
		else if(cryptmode==4)
		{
			if (AES_set_decrypt_key(normalkey, 128, &aeskey) < 0)
    			{
        			printf("Failed to set AES key.\n");
       	 			return 1;
    			}

			AES_cbc_encrypt(buffer, buffer, inbufsize, &aeskey, ctr, AES_DECRYPT);
		}
		else if(cryptmode==5)
		{
			if (AES_set_encrypt_key(normalkey, 128, &aeskey) < 0)
    			{
        			printf("Failed to set AES key.\n");
       	 			return 1;
    			}

			AES_cbc_encrypt(buffer, buffer, inbufsize, &aeskey, ctr, AES_ENCRYPT);
		}
		else if(cryptmode==6)
		{
			if (AES_set_decrypt_key(normalkey, 128, &aeskey) < 0)
    			{
        			printf("Failed to set AES key.\n");
       	 			return 1;
    			}

			AES_ecb_encrypt(buffer, buffer, &aeskey, AES_DECRYPT);
		}

		printf("Output data:\n");
		for(i=0; i<16; i++)printf("%02x", buffer[i]);
		printf("\n");

		if(outpath[0])
		{
			f = fopen(outpath, "wb");
			if(f==NULL)
			{
				printf("Failed to open the output file.\n");
			}
			else
			{
				fwrite(buffer, 1, inbufsize, f);
				fclose(f);
			}
		}

		if(cmpblock_set && cmpblock_type==0)
		{
			for(pos=0; pos<cmpblock_size; pos+=0x10)
			{
				if(memcmp(buffer, &cmpblock[pos], 16)==0)
				{
					printf("\nSuccessfully found matching normalkey(cmpblockpos 0x%x): ", pos);
					for(i=0; i<16; i++)printf("%02x", normalkey[i]);
					printf(" keyX: ");
					for(i=0; i<16; i++)printf("%02x", keyX[i]);
					printf(" keyY: ");
					for(i=0; i<16; i++)printf("%02x", keyY[i]);
					printf("\n");
				}
			}
		}
	}
	else
	{
		if(totalprocesses>1)fork_processes();

		first_time = time(NULL);
		last_time = time(NULL);

		printf("Trying with brutekeypos=%x...\n", brutekeypos);

		for(; brutekeypos<=brutekeypos_end; brutekeypos++)
		{
			//if(brutebits && ((brutekeypos & 7) == 0))continue;//Don't bruteforce 32bits where the start bitpos is aligned to a byte, since that was already bruteforced.

			memcpy(tmpkey, normalkey, 16);
			for(bruteval64=bruteval_start+bruteval_startoff; bruteval64<bruteval_end; bruteval64++)
			{
				if(!brutebits)*((unsigned short*)&tmpkey[brutekeypos]) = /*(unsigned char)*/bruteval64;//*((unsigned int*)&tmpkey[brutekeypos]) = (unsigned int)bruteval64;
				if(brutebits)
				{
					for(biti=0; biti<32; biti++)
					{
						bitpos = (brutekeypos+biti) & 0x7f;
						bitpos = keyYbitpos_keyXequalivant[bitpos];
						tmp = bitpos >> 3;
						tmpkey[tmp] = tmpkey[tmp] & ~(1 << (bitpos & 7));
						val = (bruteval64 >> biti) & 1;
						if(val)tmpkey[tmp] |= val << (bitpos & 7);
					}
				}

				last_time = time(NULL);

				//if((bruteval64 & 0x000fffff) == 0)
				//if((last_time - first_time) >= 5)
				//{
					first_time = last_time;

					printf("\nTrying normalkey(brutekeypos=0x%x bruteval=0x%08llx bruteval_start=%08llx bruteval_end=%08llx procid=0x%x): ", brutekeypos, bruteval64, bruteval_start, bruteval_end, procid);
					for(printi=0; printi<16; printi++)printf("%02x", tmpkey[printi]);
				//}

				memset(streamblock, 0, 0x10);
				memset(buffer, 0, 0x10);

				aes_num = 0;
				memset(aes_ecount, 0, AES_BLOCK_SIZE);
				memset(ctr, 0, 0x10);

				if(cryptmode==0)
				{
					if (AES_set_encrypt_key(tmpkey, 128, &aeskey) < 0)
    					{
        					printf("Failed to set AES key.\n");
       			 			return 1;
    					}

					AES_ctr128_encrypt(buffer, buffer, 0x10, &aeskey, ctr, aes_ecount, &aes_num);
				}
				else
				{
					if (AES_set_decrypt_key(tmpkey, 128, &aeskey) < 0)
    					{
        					printf("Failed to set AES key.\n");
       			 			return 1;
    					}

					AES_ecb_encrypt(buffer, buffer, &aeskey, AES_DECRYPT);
				}

				printf(" Crypt-out: ");
				for(printi=0; printi<16; printi++)printf("%02x", buffer[printi]);

				for(pos=0; pos<cmpblock_size; pos+=0x10)
				{
					if(memcmp(buffer, &cmpblock[pos], 16)==0)
					{
						foundblock = 1;
						//break;
						printf("\nSuccessfully found normalkey(brutekeypos=0x%x bruteval=0x%08llx bruteval_start=%08llx bruteval_end=%08llx procid=0x%x cmpblockpos 0x%x): ", brutekeypos, bruteval64, bruteval_start, bruteval_end, procid, pos);
						for(i=0; i<16; i++)printf("%02x", tmpkey[i]);
						printf("\n");
					}
				}

				//if(foundblock)break;
			}
			//bruteval_startoff = 0;
			//if(foundblock)break;
		}

		if(!foundblock)printf("Failed to find the normalkey.\n");
		/*if(foundblock)
		{
			printf("\nSuccessfully found normalkey(brutekeypos=0x%x bruteval=0x%08llx bruteval_start=%08llx bruteval_end=%08llx procid=0x%x): ", brutekeypos, bruteval64, bruteval_start, bruteval_end, procid);
			for(i=0; i<16; i++)printf("%02x", tmpkey[i]);

			foutkey = fopen("bruteforced_normalkey.bin", "wb");
			fwrite(tmpkey, 1, 16, foutkey);
			fwrite(&cmpblock[pos], 1, 16, foutkey);
			fclose(foutkey);
		}*/
	}

	free(normalkey);
	free(keyX);
	free(keyY);

	free(buffer);
	free(ctr);

	return 0;
}

