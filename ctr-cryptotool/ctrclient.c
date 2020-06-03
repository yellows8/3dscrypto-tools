#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <io.h>

	#pragma comment(lib, "Ws2_32.lib")
#else
	#include <unistd.h>
	#include <errno.h>
	#include <netdb.h>
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <sys/socket.h>
	#include <arpa/inet.h>
#endif

#include <openssl/aes.h>
#include <openssl/modes.h>

#include <stdint.h>

#include "ctrclient.h"

static int network_initialized = 0, use_network = 0;
static int current_keyslot = 0;
static int current_ctr_network = 0, current_ivtype = 0;

static unsigned char current_aesctr[0x10];

typedef struct {
	unsigned int initialized_keys;//bit0 = normalkey, bit1=keyX, key2=keyY
	unsigned char normalkey[0x10];
	unsigned char keyX[0x10];
	unsigned char keyY[0x10];
} ctr_keyslot;

static ctr_keyslot ctr_keyslots[0x40];//DSi keyslots are handled the same way as 3DS keyslots here, but whatever.

static AES_KEY aeskey_enc, aeskey_dec;
static unsigned int aes_num;
static unsigned char aes_ecount[AES_BLOCK_SIZE];

static unsigned char constantkey[16];

static void putle32(unsigned char* p, unsigned int value)
{
	*p++ = value>>0;
	*p++ = value>>8;
	*p++ = value>>16;
	*p++ = value>>24;
}



static void* get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) 
	{
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
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

void ctr_keygenerator(unsigned char *outkey, unsigned char *keyX, unsigned char *keyY)
{
	int i;
	unsigned char tmpkey[16];
	unsigned char tmpkeyX[16];
	unsigned char tmpkeyY[16];

	memcpy(tmpkeyX, keyX, 16);
	memcpy(tmpkeyY, keyY, 16);

	n128_lrot(tmpkeyX, 2);
	for(i=0; i<16; i++)tmpkey[i] = tmpkeyX[i] ^ tmpkeyY[i];

	n128_add(tmpkey, constantkey);

	n128_rrot(tmpkey, 41);

	memcpy(outkey, tmpkey, 16);
}

static void ctr_loadkeys_file(char *path)
{
	unsigned int tmp, keyslot, i, pos;
	FILE *f;
	char *strptr;
	char line[256];

	f = fopen(path, "rb");
	if(f==NULL)
	{
		printf("ctr_loadkeys(): Failed to open %s\n", path);
		return;
	}

	while(1)
	{
		memset(line, 0, 256);
		if(fgets(line, 255, f) == NULL)break;

		pos = strlen(line);
		if(pos==0)continue;
		if(line[pos-1]==0x0a)line[pos-1] = 0;

		if(line[0]=='#')continue;//First char in a line set to '#' == comment.

		if(strncmp(line, "INCLUDE=", 8)==0)
		{
			if(strlen(&line[8])==0)
			{
				printf("ctr_loadkeys(): INCLUDE line is missing the path param.\n");
				continue;
			}

			if(strcmp(path, &line[8])==0)
			{
				printf("ctr_loadkeys(): INCLUDE line has the path set to the same path as the filepath currently being parsed.\n");
				continue;
			}

			ctr_loadkeys_file(&line[8]);

			continue;
		}

		strptr = strtok(line, " ");
		if(strptr==NULL)continue;

		sscanf(strptr, "0x%x", &tmp);
		keyslot = tmp;
		if(keyslot>=0x40)continue;

		while((strptr = strtok(NULL, " ")))
		{
			if(strncmp("normalkey=", strptr, 10)==0)
			{
				if(strlen(strptr) - 10 != 32)
				{
					printf("ctr_loadkeys(): Invalid normalkey for keyslot 0x%x.\n", keyslot);
					continue;
				}

				ctr_keyslots[keyslot].initialized_keys |= 0x1;

				pos = 10;
				for(i=0; i<16; i++)
				{
					sscanf(&strptr[pos], "%02x", &tmp);
					pos+=2;
					ctr_keyslots[keyslot].normalkey[i] = tmp;
				}
			}

			if(strncmp("keyX=", strptr, 5)==0)
			{
				if(strlen(strptr) - 5 != 32)
				{
					printf("ctr_loadkeys(): Invalid keyX for keyslot 0x%x.\n", keyslot);
					continue;
				}

				ctr_keyslots[keyslot].initialized_keys |= 0x2;

				pos = 5;
				for(i=0; i<16; i++)
				{
					sscanf(&strptr[pos], "%02x", &tmp);
					pos+=2;
					ctr_keyslots[keyslot].keyX[i] = tmp;
				}
			}

			if(strncmp("keyY=", strptr, 5)==0)
			{
				if(strlen(strptr) - 5 != 32)
				{
					printf("ctr_loadkeys(): Invalid keyX for keyslot 0x%x.\n", keyslot);
					continue;
				}

				ctr_keyslots[keyslot].initialized_keys |= 0x4;

				pos = 5;
				for(i=0; i<16; i++)
				{
					sscanf(&strptr[pos], "%02x", &tmp);
					pos+=2;
					ctr_keyslots[keyslot].keyY[i] = tmp;
				}
			}
		}
	}

	fclose(f);
}

static void ctr_loadkeys()
{
	char *home;
	char path[256];

	memset(path, 0, 256);

	home = getenv("HOME");
	if (home == NULL)
	{
		return;
	}

	snprintf(path, sizeof(path), "%s/.3ds/%s", home, "aeskeyslots_keys");

	ctr_loadkeys_file(path);
}

int update_aeskeystate()
{
	if(!((ctr_keyslots[current_keyslot].initialized_keys & 1) || ((ctr_keyslots[current_keyslot].initialized_keys & 0x6) == 0x6)))
	{
		printf("update_aeskeystate() was called without the final normal-key being set.\n");
		return 2;
	}

	if(AES_set_encrypt_key(ctr_keyslots[current_keyslot].normalkey, 128, &aeskey_enc) < 0)
    	{
        	printf("Failed to set AES key.\n");
       	 	return 1;
    	}

	if(AES_set_decrypt_key(ctr_keyslots[current_keyslot].normalkey, 128, &aeskey_dec) < 0)
    	{
        	printf("Failed to set AES key.\n");
       	 	return 1;
    	}

	return 1;
}

void ctrclient_init()
{
#ifdef _WIN32
	WSADATA wsaData;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (iResult != 0) 
	{
		fprintf(stderr, "WSAStartup failed: %d\n", iResult);
	}
#endif

	network_initialized = 0;
	use_network = 0;
	current_keyslot = 0;
	current_ctr_network = 0;
	current_ivtype = 0;

	memset(ctr_keyslots, 0, sizeof(ctr_keyslots));
	memset(current_aesctr, 0, sizeof(current_aesctr));

	aes_num = 0;
	memset(current_aesctr, 0, sizeof(current_aesctr));
	memset(aes_ecount, 0, sizeof(aes_ecount));

	ctr_loadkeys();
}


int ctrclient_connect(ctrclient* client, const char* hostname, const char* port)
{
    struct addrinfo hints;
	struct addrinfo *servinfo;
	struct addrinfo *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
	unsigned int authsize = 0;
	unsigned char auth[MAX_CHALLENGESIZE];
	FILE* authfile = 0;
	FILE *fkey = NULL;

	const char* homedir = getenv("HOME");
	if (homedir != 0)
	{
		char tmpname[256];
		memset(tmpname, 0, sizeof(tmpname));
		snprintf(tmpname, sizeof(tmpname)-1, "%s/.3ds/auth.txt", homedir);
		authfile = fopen(tmpname, "rb");

		memset(tmpname, 0, sizeof(tmpname));
		snprintf(tmpname, sizeof(tmpname)-1, "%s/.3ds/aeshw_keygen_constant", homedir);
		fkey = fopen(tmpname, "rb");
	}	
	if (authfile == 0)
	{
		authfile = fopen("auth.txt", "rb");
	}

	if (authfile == 0)
	{
		fprintf(stderr, "Could not open auth.txt file\n");
		if(fkey)fclose(fkey);
		return 1;
	}
	else
	{
		fseek(authfile, 0, SEEK_END);
		authsize = ftell(authfile);
		if (authsize >= MAX_CHALLENGESIZE)
			authsize = MAX_CHALLENGESIZE;
		fseek(authfile, 0, SEEK_SET);
		fread(auth, 1, authsize, authfile);
		fclose(authfile);
	}

	if(fkey==NULL)
	{
		fprintf(stderr, "Failed to open the aeshw_keygen_constant file.\n");
		return 0;
	}

	fread(constantkey, 1, 16, fkey);
	fclose(fkey);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(hostname, port, &hints, &servinfo)) != 0) 
	{
        fprintf(stderr, "getaddrinfo: %d, %s\n", rv, gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) 
	{
        if ((client->sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) 
		{
            continue;
        }

        if (connect(client->sockfd, p->ai_addr, p->ai_addrlen) == -1) 
		{
            ctrclient_disconnect(client);
            continue;
        }

        break;
    }

    if (p == NULL) 
	{
		fprintf(stderr, "ctrclient: failed to connect\n");
        return 1;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof(s));
    

    freeaddrinfo(servinfo);

	network_initialized = 1;

	if (!ctrclient_sendbuffer(client, auth, authsize))
	{
		network_initialized = 0;
		return 0;
	}

	fprintf(stdout, "ctrclient: connected to %s\n", s);

	return 1;
}

void ctrclient_disconnect(ctrclient* client)
{
#ifdef _WIN32
	closesocket(client->sockfd);
#else
	close(client->sockfd);
#endif

	client->sockfd = 0;
	network_initialized = 0;
}

int ctrclient_sendbuffer(ctrclient* client, const void* buffer, unsigned int size)
{
	unsigned char* bytebuffer = (unsigned char*)buffer;

	if(!network_initialized)return 0;

	while(size)
	{
		int nbytes = send(client->sockfd, bytebuffer, size, 0);
		
		if (nbytes <= 0)
		{
			perror("send");
			return 0;
		}

		size -= nbytes;
		bytebuffer += nbytes;
	}

	return 1;
}


int ctrclient_recvbuffer(ctrclient* client, void* buffer, unsigned int size)
{
	unsigned char* bytebuffer = (unsigned char*)buffer;

	if(!network_initialized)return 0;

	while(size)
	{
		int nbytes = recv(client->sockfd, bytebuffer, size, 0);
		
		if (nbytes <= 0)
		{
			perror("recv");
			return 0;
		}

		size -= nbytes;
		bytebuffer += nbytes;
	}

	return 1;
}

int ctrclient_sendlong(ctrclient* client, unsigned int value)
{
	unsigned char buffer[4];


	buffer[0] = value>>0;
	buffer[1] = value>>8;
	buffer[2] = value>>16;
	buffer[3] = value>>24;

	return ctrclient_sendbuffer(client, buffer, 4);
}


static int ctrclient_aes_crypto(ctrclient* client, unsigned char* buffer, unsigned int size, unsigned int command)
{
	unsigned char header[8];

	while(size)
	{
		unsigned int maxsize = CHUNKMAXSIZE;
		if (maxsize > size)
			maxsize = size;

		if (!ctrclient_sendlong(client, command))
			return 0;
		if (!ctrclient_sendlong(client, maxsize))
			return 0;
		if (!ctrclient_sendbuffer(client, buffer, maxsize))
			return 0;
		if (!ctrclient_recvbuffer(client, header, 8))
			return 0;
		if (!ctrclient_recvbuffer(client, buffer, maxsize))
			return 0;

		buffer += maxsize;
		size -= maxsize;
	}

	return 1;
}

static int ctrclient_aes_ccm_crypto(ctrclient* client, unsigned int maclen, unsigned char* mac, unsigned char* assocbuffer, unsigned int assocsize, unsigned char* payloadbuffer, unsigned int payloadsize, unsigned int command)
{
	unsigned char header[8];
	aesccmheader ccmheader;
	unsigned int assocblockcount = assocsize / 16;
	unsigned int payloadblockcount = payloadsize / 16;
	unsigned char macresult[16];

	maclen = (maclen-2)/2;

	if (assocblockcount > 0xFFFF)
		return 0;
	if (assocblockcount*16 != assocsize)
		return 0;
	if (payloadblockcount > 0xFFFF)
		return 0;
	if (payloadblockcount*16 != payloadsize)
		return 0;

	memset(&ccmheader, 0, sizeof(aesccmheader));
	putle32(ccmheader.assocblockcount, assocblockcount);
	putle32(ccmheader.payloadblockcount, payloadblockcount);
	putle32(ccmheader.maclen, maclen);
	if (command == CMD_AESCCMDEC)
		memcpy(ccmheader.mac, mac, 0x10);


	if (!ctrclient_sendlong(client, command))
		return 0;
	if (!ctrclient_sendlong(client, payloadsize + assocsize + sizeof(aesccmheader)))
		return 0;
	if (!ctrclient_sendbuffer(client, &ccmheader, sizeof(aesccmheader)))
		return 0;
	if (!ctrclient_sendbuffer(client, assocbuffer, assocsize))
		return 0;
	if (!ctrclient_sendbuffer(client, payloadbuffer, payloadsize))
		return 0;
	if (!ctrclient_recvbuffer(client, header, 8))
		return 0;
	if (!ctrclient_recvbuffer(client, payloadbuffer, payloadsize))
		return 0;
	if (!ctrclient_recvbuffer(client, macresult, 16))
		return 0;

	if (command == CMD_AESCCMENC)
	{
		if (mac)
			memcpy(mac, macresult, 16);
	}
	else if (macresult[0] != 1)
	{
		return 2;
	}

	return 1;
}

int ctrclient_aes_ccm_encrypt(ctrclient* client, unsigned char* buffer, unsigned int size, unsigned char mac[16])
{
	return ctrclient_aes_ccm_crypto(client, 16, mac, 0, 0, buffer, size, CMD_AESCCMENC);
}

int ctrclient_aes_ccm_encryptex(ctrclient* client, unsigned char* payloadbuffer, unsigned int payloadsize, unsigned char* assocbuffer, unsigned int assocsize, unsigned int maclen, unsigned char mac[16])
{
	return ctrclient_aes_ccm_crypto(client, maclen, mac, assocbuffer, assocsize, payloadbuffer, payloadsize, CMD_AESCCMENC);
}

int ctrclient_aes_ccm_decrypt(ctrclient* client, unsigned char* buffer, unsigned int size, unsigned char mac[16])
{
	return ctrclient_aes_ccm_crypto(client, 16, mac, 0, 0, buffer, size, CMD_AESCCMDEC);
}


int ctrclient_aes_ccm_decryptex(ctrclient* client, unsigned char* payloadbuffer, unsigned int payloadsize, unsigned char* assocbuffer, unsigned int assocsize, unsigned int maclen, unsigned char mac[16])
{
	return ctrclient_aes_ccm_crypto(client, maclen, mac, assocbuffer, assocsize, payloadbuffer, payloadsize, CMD_AESCCMDEC);
}


int ctrclient_aes_ctr_crypt(ctrclient* client, unsigned char* buffer, unsigned int size)
{
	unsigned int pos = 0;

	if(use_network)return ctrclient_aes_crypto(client, buffer, size, CMD_AESCTR);

	while(pos < size)
	{
		CRYPTO_ctr128_encrypt(&buffer[pos], &buffer[pos], 0x10, &aeskey_enc, current_aesctr, aes_ecount, &aes_num, (block128_f)AES_encrypt);
		pos+= 0x10;
	}

	return 1;
}

int ctrclient_aes_cbc_decrypt(ctrclient* client, unsigned char* buffer, unsigned int size)
{
	unsigned int pos = 0;

	if(use_network)return ctrclient_aes_crypto(client, buffer, size, CMD_AESCBCDEC);

	AES_cbc_encrypt(&buffer[pos], &buffer[pos], size, &aeskey_dec, current_aesctr, AES_DECRYPT);

	return 1;
}

int ctrclient_aes_cbc_encrypt(ctrclient* client, unsigned char* buffer, unsigned int size)
{
	unsigned int pos = 0;

	if(use_network)return ctrclient_aes_crypto(client, buffer, size, CMD_AESCBCENC);

	AES_cbc_encrypt(&buffer[pos], &buffer[pos], size, &aeskey_dec, current_aesctr, AES_ENCRYPT);

	return 1;
}


int ctrclient_aes_control(ctrclient* client, aescontrol* control)
{
	unsigned char header[8];
	unsigned int size = sizeof(aescontrol);

	if (size != 40)
		return 0;

	if (!ctrclient_sendlong(client, CMD_AESCONTROL))
		return 0;
	if (!ctrclient_sendlong(client, size))
		return 0;
	if (!ctrclient_sendbuffer(client, control, size))
		return 0;
	if (!ctrclient_recvbuffer(client, header, 8))
		return 0;

	return 1;
}

int ctrclient_aes_set_key(ctrclient* client, unsigned int keyslot, unsigned char key[16])
{
	//aescontrol control;

	if(keyslot>0x40)keyslot = 0x3f;
	current_keyslot = keyslot;

	memcpy(ctr_keyslots[current_keyslot].normalkey, key, 0x10);
	ctr_keyslots[current_keyslot].initialized_keys |= 0x1;
	use_network = 0;
	return update_aeskeystate();

	/*memset(&control, 0, sizeof(aescontrol));
	putle32(control.flags, AES_FLAGS_SET_KEY | AES_FLAGS_SELECT_KEY);
	putle32(control.keyslot, keyslot);
	memcpy(control.key, key, 16);

	return ctrclient_aes_control(client, &control);*/
}

int ctrclient_aes_set_ykey(ctrclient* client, unsigned int keyslot, unsigned char key[16])
{
	int ret=0;
	aescontrol control;

	if(keyslot>0x40)keyslot = 0x3f;
	current_keyslot = keyslot;

	memcpy(ctr_keyslots[current_keyslot].keyY, key, 0x10);
	ctr_keyslots[current_keyslot].initialized_keys |= 0x4;
	use_network = 1;
	if((ctr_keyslots[current_keyslot].initialized_keys & 0x6) == 0x6)use_network = 0;

	if(!use_network)
	{
		ctr_keygenerator(ctr_keyslots[current_keyslot].normalkey, ctr_keyslots[current_keyslot].keyX, ctr_keyslots[current_keyslot].keyY);
		return update_aeskeystate();
	}

	if(current_ctr_network != use_network)
	{
		if(current_ivtype==0)ret = ctrclient_aes_set_iv(client, current_aesctr);
		if(current_ivtype==1)ret = ctrclient_aes_set_nonce(client, current_aesctr);
		if(ret!=1)return ret;

		current_ctr_network = use_network;
	}

	memset(&control, 0, sizeof(aescontrol));
	putle32(control.flags, AES_FLAGS_SET_YKEY | AES_FLAGS_SELECT_KEY);
	putle32(control.keyslot, keyslot);
	memcpy(control.key, key, 16);

	return ctrclient_aes_control(client, &control);
}

int ctrclient_aes_select_key(ctrclient* client, unsigned int keyslot)
{
	int ret=0;
	aescontrol control;

	if(keyslot>0x40)keyslot = 0x3f;
	current_keyslot = keyslot;

	use_network = 1;
	if((ctr_keyslots[current_keyslot].initialized_keys & 1) || ((ctr_keyslots[current_keyslot].initialized_keys & 0x6) == 0x6))use_network = 0;

	if(!use_network)return update_aeskeystate();

	if(current_ctr_network != use_network)
	{
		if(current_ivtype==0)ret = ctrclient_aes_set_iv(client, current_aesctr);
		if(current_ivtype==1)ret = ctrclient_aes_set_nonce(client, current_aesctr);
		if(ret!=1)return ret;

		current_ctr_network = use_network;
	}

	memset(&control, 0, sizeof(aescontrol));
	putle32(control.flags, AES_FLAGS_SELECT_KEY);
	putle32(control.keyslot, keyslot);

	return ctrclient_aes_control(client, &control);
}


int ctrclient_aes_set_iv(ctrclient* client, unsigned char iv[16])
{
	aescontrol control;

	memcpy(current_aesctr, iv, 16);

	current_ctr_network = use_network;
	current_ivtype = 0;

	if(!use_network)return 1;

	memset(&control, 0, sizeof(aescontrol));
	putle32(control.flags, AES_FLAGS_SET_IV);
	memcpy(control.iv, iv, 16);

	return ctrclient_aes_control(client, &control);
}

int ctrclient_aes_set_ctr(ctrclient* client, unsigned char ctr[16])
{
	return ctrclient_aes_set_iv(client, ctr);
}

int ctrclient_aes_set_nonce(ctrclient* client, unsigned char nonce[12])
{
	aescontrol control;

	memcpy(current_aesctr, nonce, 12);

	current_ctr_network = use_network;
	current_ivtype = 1;

	if(!use_network)return 1;

	memset(&control, 0, sizeof(aescontrol));
	putle32(control.flags, AES_FLAGS_SET_IV | AES_FLAGS_SET_NONCE);
	memcpy(control.iv, nonce, 12);

	return ctrclient_aes_control(client, &control);
}

