#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>

#include "ctrclient.h"
#include "types.h"
#include "utils.h"
#include "tmd.h"

#include "polarssl/aes.h"
#include <openssl/sha.h>

#define _FILE_OFFSET_BITS 64 /* for pre libcurl 7.19.0 curl_off_t magic */
#include <curl/curl.h>

int intitlekey_set = 0;
unsigned char intitlekey[16];
int titleversion_set = 0;
unsigned int titleversion = 0;

int dltitle = 0, packcia = 0, dectitle = 0, disasm_title = 0;
int noromfs = 0;
int disablencch = 0;

int serveradr_set = 0;
char serveradr[256];
char commonkey_path[256];

int settings_initialized = 0;
int settingspath_set = 0;
size_t settings_bufsize = 0;
char *settings_buf = NULL;
char settingspath[256];

int tikdecrypt_titlekey(char *path, unsigned char *titlekey);

/********* Sample code generated by the curl command line tool **********
 * Lines with [REMARK] below might need to be modified to make this code 
 * usable. Add error code checking where appropriate.
 * Compile this with a suitable header include path. Then link with 
 * libcurl.
 * If you use any *_LARGE options, make sure your compiler figure
 * out the correct size for the curl_off_t variable.
 * Read the details for all curl_easy_setopt() options online on:
 * http://curlm.haxx.se/libcurl/c/curl_easy_setopt.html
 ************************************************************************/
int http_request(char *url, FILE *outfile)
{
  CURLcode ret;
  CURL *hnd = curl_easy_init();

  curl_easy_setopt(hnd, CURLOPT_INFILESIZE_LARGE, (curl_off_t)-1);
  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_FILE, outfile);
  curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 0);
  curl_easy_setopt(hnd, CURLOPT_HEADER, 0);
  curl_easy_setopt(hnd, CURLOPT_FAILONERROR, 0);
  curl_easy_setopt(hnd, CURLOPT_DIRLISTONLY, 0);
  curl_easy_setopt(hnd, CURLOPT_APPEND, 0);
  curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 0);
  curl_easy_setopt(hnd, CURLOPT_UNRESTRICTED_AUTH, 0);
  curl_easy_setopt(hnd, CURLOPT_TRANSFERTEXT, 0);
  curl_easy_setopt(hnd, CURLOPT_USERPWD, NULL);
  curl_easy_setopt(hnd, CURLOPT_RANGE, NULL);
  curl_easy_setopt(hnd, CURLOPT_TIMEOUT, 0);
  curl_easy_setopt(hnd, CURLOPT_LOW_SPEED_LIMIT, 0);
  curl_easy_setopt(hnd, CURLOPT_LOW_SPEED_TIME, 0);
  curl_easy_setopt(hnd, CURLOPT_MAX_SEND_SPEED_LARGE, (curl_off_t)0);
  curl_easy_setopt(hnd, CURLOPT_MAX_RECV_SPEED_LARGE, (curl_off_t)0);
  curl_easy_setopt(hnd, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)0);
  curl_easy_setopt(hnd, CURLOPT_COOKIE, NULL);
  curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, NULL);
  curl_easy_setopt(hnd, CURLOPT_SSLCERT, NULL);
  curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, NULL);
  curl_easy_setopt(hnd, CURLOPT_SSLKEY, NULL);
  curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, NULL);
  curl_easy_setopt(hnd, CURLOPT_KEYPASSWD, NULL);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 2);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 1);
  curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50);
  curl_easy_setopt(hnd, CURLOPT_CRLF, 0);
  curl_easy_setopt(hnd, CURLOPT_QUOTE, NULL);
  curl_easy_setopt(hnd, CURLOPT_POSTQUOTE, NULL);
  curl_easy_setopt(hnd, CURLOPT_PREQUOTE, NULL);
  curl_easy_setopt(hnd, CURLOPT_WRITEHEADER, NULL);
  curl_easy_setopt(hnd, CURLOPT_SSLVERSION, 3);
  curl_easy_setopt(hnd, CURLOPT_TIMECONDITION, 0);
  curl_easy_setopt(hnd, CURLOPT_TIMEVALUE, 0);
  curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, NULL);
  curl_easy_setopt(hnd, CURLOPT_HTTPPROXYTUNNEL, 0);
  curl_easy_setopt(hnd, CURLOPT_INTERFACE, NULL);
  curl_easy_setopt(hnd, CURLOPT_RANDOM_FILE, NULL);
  curl_easy_setopt(hnd, CURLOPT_CONNECTTIMEOUT, 0);
  curl_easy_setopt(hnd, CURLOPT_ENCODING, NULL);
  curl_easy_setopt(hnd, CURLOPT_POSTREDIR, 0);
  ret = curl_easy_perform(hnd);
  curl_easy_cleanup(hnd);
  return (int)ret;
}

int pack_cia(uint64_t titleid, char *titlepath)
{
	int ret;
	char sys_cmd[1024];


	snprintf(sys_cmd, 1023, "make_cdn_cia %s %s/%016"PRIx64".cia", titlepath, titlepath, titleid);
	ret = system(sys_cmd);
	return ret;
}

int settings_load()
{
	char *strptr;
	FILE *f;
	struct stat filestat;

	settings_initialized = 0;

	if(!settingspath_set)
	{
		strptr = getenv("HOME");
		if(strptr == NULL)
		{
			printf("$HOME env-var is not set and --settingspath was not used, the settings file will not be loaded.\n");
			return 1;
		}

		memset(settingspath, 0, sizeof(settingspath));
		snprintf(settingspath, sizeof(settingspath)-1, "%s/.3ds/ctrclient-title_settings", strptr);
	}

	if(settings_buf)
	{
		free(settings_buf);
		settings_buf = NULL;
	}

	if(stat(settingspath, &filestat)==-1)
	{
		printf("Failed to stat() the settings file, now creating one at the settingspath.\n");
		filestat.st_size = 0;

		f = fopen(settingspath, "wb");
		if(f)
		{
			fclose(f);
		}
		else
		{
			printf("Failed to create the settings-file.\n");
			return 2;
		}
	}

	settings_bufsize = filestat.st_size + 1;
	settings_buf = malloc(settings_bufsize);
	if(settings_buf==NULL)
	{
		printf("Failed to alloc mem for the settings file.\n");
		return 4;
	}
	memset(settings_buf, 0, settings_bufsize);

	if(settings_bufsize - 1)
	{
		f = fopen(settingspath, "rb");

		if(f == NULL)
		{
			free(settings_buf);
			printf("Failed to open the settings file.\n");
			return 2;
		}
	
		if(fread(settings_buf, 1, settings_bufsize - 1, f) != (settings_bufsize - 1))
		{
			free(settings_buf);
			fclose(f);
			printf("Failed to read the settings file.\n");
			return 3;
		}

		fclose(f);
	}

	settings_initialized = 1;

	return 0;
}

void settings_shutdown()
{
	if(settings_initialized)return;

	memset(settings_buf, 0, settings_bufsize);
	free(settings_buf);
	settings_buf = NULL;
	settings_bufsize = 0;
}

int settings_get_titleline(uint64_t titleid, char *line, uint32_t line_maxsize, uint32_t *bufpos)
{
	uint32_t pos;
	char *strptr;
	char tidstr[32];

	if(!settings_initialized)return 1;

	memset(tidstr, 0, sizeof(tidstr));
	snprintf(tidstr, sizeof(tidstr)-1, "titleid=%016"PRIx64, titleid);

	strptr = strstr(settings_buf, tidstr);
	if(strptr==NULL)return 2;

	while(((unsigned long long)strptr) != ((unsigned long long)settings_buf))
	{
		if(*strptr == '\n' || *strptr == '\r')
		{
			strptr++;
			break;
		}

		strptr--;
	}

	if(bufpos)*bufpos = ((unsigned long long)strptr) - ((unsigned long long)settings_buf);

	pos = 0;
	while(pos < line_maxsize)
	{
		if(strptr[pos]==0 || strptr[pos]==0x0a || strptr[pos]==0x0d)break;
		line[pos] = strptr[pos];
		pos++;
	}
	if(pos != line_maxsize)line[pos] = 0;

	return 0;
}

int settings_get_ticketkeyinfo(uint64_t titleid, unsigned char *keyindex, unsigned char *encrypted_titlekey, unsigned char *plaintext_titlekey)
{
	int ret;
	uint32_t tmp;
	int i;
	char *strptr;
	char line[256];

	memset(line, 0, sizeof(line));

	if((ret = settings_get_titleline(titleid, line, sizeof(line)-1, NULL))!=0)return ret;

	strptr = strstr(line, "keyindex=0x");
	if(strptr==NULL)
	{
		printf("titleID %016"PRIx64" is listed in the settings file, but the keyindex field for it is missing/invalid.\n", titleid);
		return 3;
	}

	sscanf(&strptr[11], "%02x", &tmp);
	*keyindex = tmp;

	strptr = strstr(line, "encrypted_titlekey=");
	if(strptr==NULL)
	{
		printf("titleID %016"PRIx64" is listed in the settings file, but the encrypted_titlekey field for it is missing.\n", titleid);
		return 4;
	}

	for(i=0; i<0x10; i++)
	{
		if(sscanf(&strptr[19 + i*2], "%02x", &tmp)!=1)
		{
			printf("Invalid hex for the settings-file encrypted_titlekey field with titleID %016"PRIx64".\n", titleid);
			return 6;
		}
		encrypted_titlekey[i] = tmp;
	}

	strptr = strstr(line, "plaintext_titlekey=");
	if(strptr==NULL)
	{
		printf("titleID %016"PRIx64" is listed in the settings file, but the plaintext_titlekey field for it is missing.\n", titleid);
		return 5;
	}

	for(i=0; i<0x10; i++)
	{
		if(sscanf(&strptr[19 + i*2], "%02x", &tmp)!=1)
		{
			printf("Invalid hex for the settings-file plaintext_titlekey field with titleID %016"PRIx64".\n", titleid);
			return 7;
		}
		plaintext_titlekey[i] = tmp;
	}

	return 0;
}

int settings_set_ticketkeyinfo(uint64_t titleid, unsigned char *keyindex, unsigned char *encrypted_titlekey, unsigned char *plaintext_titlekey)
{
	FILE *f;
	char *newbuf = NULL;
	char *strptr;
	int entryexists = 0;
	int i;
	int ret;
	size_t newbufsize = 0;
	uint32_t line_bufpos = 0;
	unsigned char tmp_keyindex=0;
	unsigned char tmpkey0[0x10];
	unsigned char tmpkey1[0x10];
	char tmpline[256];
	char tmpstr[64];

	if(!settings_initialized)return 1;

	printf("Writing ticketkeyinfo to the settings-file, for titleid=%016"PRIx64"...\n", titleid);

	memset(tmpline, 0, sizeof(tmpline));

	if(settings_get_titleline(titleid, tmpline, sizeof(tmpline)-1, &line_bufpos)==0)
	{
		if((ret = settings_get_ticketkeyinfo(titleid, &tmp_keyindex, tmpkey0, tmpkey1)))return ret;
		entryexists = 1;
	}

	if(entryexists==0)
	{
		snprintf(tmpline, sizeof(tmpline)-1, "titleid=%016"PRIx64" keyindex=0x%02x", titleid, (unsigned int)*keyindex);

		memset(tmpstr, 0, sizeof(tmpstr));
		strncpy(tmpstr, " encrypted_titlekey=", sizeof(tmpstr)-1);
		for(i=0; i<0x10; i++)
		{
			snprintf(&tmpstr[20 + i*2], sizeof(tmpstr)-1, "%02x", encrypted_titlekey[i]);
		}
		strncat(tmpline, tmpstr, sizeof(tmpline)-1);

		memset(tmpstr, 0, sizeof(tmpstr));
		strncpy(tmpstr, " plaintext_titlekey=", sizeof(tmpstr)-1);
		for(i=0; i<0x10; i++)
		{
			snprintf(&tmpstr[20 + i*2], sizeof(tmpstr)-1, "%02x", plaintext_titlekey[i]);
		}
		strncat(tmpline, tmpstr, sizeof(tmpline)-1);
		strncat(tmpline, "\n", sizeof(tmpline)-1);

		newbufsize = settings_bufsize + strlen(tmpline);

		newbuf = malloc(newbufsize);
		if(newbuf==NULL)
		{
			printf("Failed to alloc mem for the settings file.\n");
			return 4;
		}
		memset(newbuf, 0, newbufsize);

		memcpy(newbuf, settings_buf, settings_bufsize-1);
		memcpy(&newbuf[settings_bufsize-1], tmpline, strlen(tmpline));

		free(settings_buf);
		settings_buf = newbuf;
		settings_bufsize = newbufsize;
	}
	else
	{
		strptr = strstr(tmpline, "keyindex=0x");
		if(strptr==NULL)
		{
			printf("settings_set_ticketkeyinfo(): The keyindex field is missing/invalid in the read line for titleID %016"PRIx64".\n", titleid);
			return 8;
		}
		memset(tmpstr, 0, sizeof(tmpstr));
		snprintf(tmpstr, sizeof(tmpstr)-1, "%02x", *keyindex);
		memcpy(&strptr[11], tmpstr, 2);

		strptr = strstr(tmpline, "encrypted_titlekey=");
		if(strptr==NULL)
		{
			printf("settings_set_ticketkeyinfo(): The encrypted_titlekey field is missing/invalid in the read line for titleID %016"PRIx64".\n", titleid);
			return 9;
		}

		memset(tmpstr, 0, sizeof(tmpstr));
		for(i=0; i<0x10; i++)
		{
			snprintf(&tmpstr[i*2], 3, "%02x", encrypted_titlekey[i]);
		}
		memcpy(&strptr[19], tmpstr, 0x20);

		strptr = strstr(tmpline, "plaintext_titlekey=");
		if(strptr==NULL)
		{
			printf("settings_set_ticketkeyinfo(): The plaintext_titlekey field is missing/invalid in the read line for titleID %016"PRIx64".\n", titleid);
			return 10;
		}

		memset(tmpstr, 0, sizeof(tmpstr));
		for(i=0; i<0x10; i++)
		{
			snprintf(&tmpstr[i*2], 3, "%02x", plaintext_titlekey[i]);
		}
		memcpy(&strptr[19], tmpstr, 0x20);

		memcpy(&settings_buf[line_bufpos], tmpline, strlen(tmpline));
	}

	if(settings_bufsize - 1)
	{
		f = fopen(settingspath, "wb");
	
		if(f == NULL)
		{
			free(settings_buf);
			printf("Failed to open the settings file for writing.\n");
			return 2;
		}

		if(fwrite(settings_buf, 1, settings_bufsize - 1, f) != (settings_bufsize - 1))
		{
			fclose(f);
			printf("Failed to write the settings file.\n");
			return 3;
		}

		fclose(f);
	}

	return 0;
}

ctr_tmd_body *tmd_get_body(unsigned char *tmdbuf) 
{
	unsigned int type = getbe32(tmdbuf);
	ctr_tmd_body *body = NULL;

	if (type == TMD_RSA_2048_SHA256 || type == TMD_RSA_2048_SHA1)
	{
		body = (ctr_tmd_body*)(tmdbuf + sizeof(ctr_tmd_header_2048));
	}
	else if (type == TMD_RSA_4096_SHA256 || type == TMD_RSA_4096_SHA1)
	{
		body = (ctr_tmd_body*)(tmdbuf + sizeof(ctr_tmd_header_4096));
	}

	return body;
}

int cdn_download(uint64_t titleid, char *titledir, char *name, char *path)
{
	int ret;
	FILE *f;
	struct stat filestat;
	char url[256];

	memset(url, 0, 256);

	if(path[0]==0)snprintf(path, 255, "%s/%s", titledir, name);
	snprintf(url, 255, "http://nus.cdn.c.shop.nintendowifi.net/ccs/download/%016"PRIx64"/%s", titleid, name);

	if(strcmp(name, "cetk") == 0)
	{
		if(stat(path, &filestat)==0)
		{
			printf("cetk already exists locally, skipping download for it.\n");
			return 0;
		}
	}

	f = fopen(path, "wb");
	if(f==NULL)
	{
		printf("Failed to open %s\n", path);
		return 1;
	}

	printf("Downloading %s to %s...\n", url, path);

	ret = http_request(url, f);
	fclose(f);

	return ret;
}

int download_contents(uint64_t titleid, char *titlepath, ctr_tmd_contentchunk *chunks, u16 total_contents)
{
	int ret;
	char path[256];
	char dlname[32];

	u16 index;
	u32 contentid;

	printf("Total contents: %x\n", total_contents);

	for(index=0; index<total_contents; index++)
	{
		contentid = getbe32(chunks[index].id);

		printf("Index %d:\n", index);
		printf("ContentID %08x\n\n", contentid);

		memset(path, 0, 256);
		memset(dlname, 0, 32);
		snprintf(dlname, 31, "%08x", contentid);

		ret = cdn_download(titleid, titlepath, dlname, path);
		if(ret!=0)
		{
			printf("Failed to download contentID %08x: %d", contentid, ret);
			return ret;
		}
	}

	return 0;
}

int decrypt_ncch(u32 contentid, char *titlepath)
{
	int ret;
	char sys_cmd[1024];
	char basepath[64];
	char noromfs_cmd[16];
	char serveradr_cmd[64];
	char disasm_cmd[64];

	memset(sys_cmd, 0, 1023);
	memset(basepath, 0, 64);
	memset(noromfs_cmd, 0, 16);
	memset(serveradr_cmd, 0, 64);
	memset(disasm_cmd, 0, 64);
	snprintf(basepath, 63, "%s/%08x", titlepath, contentid);
	if(noromfs)strncpy(noromfs_cmd, "--noromfs", 15);
	if(serveradr_set)snprintf(serveradr_cmd, 63, "--serveradr=%s", serveradr);
	if(disasm_title)snprintf(disasm_cmd, 63, "--disasm");

	snprintf(sys_cmd, 1023, "ctrclient-ncch --input=%s.app --output=%s.bin --ctrtoolprefix=%s %s %s %s", basepath, basepath, basepath, noromfs_cmd, serveradr_cmd, disasm_cmd);
	ret = system(sys_cmd);
	return ret;
}

int decrypt_contents(uint64_t titleid, char *titlepath, ctr_tmd_contentchunk *chunks, u16 total_contents)
{
	int ret;
	FILE *f;
	unsigned char *buffer;

	char path[256];
	char outpath[256];
	unsigned char titlekey[16];
	unsigned char iv[16];
	unsigned char calchash[32];
	aes_context aes_ctx;

	u16 index;
	u32 contentid;
	uint64_t contentsize;
	u32 contentsz_aligned;
	u32 hashsize;

	memset(titlekey, 0, 16);
	if(intitlekey_set)
	{
		memcpy(titlekey, intitlekey, 16);
		printf("Using input titlekey.\n");
	}
	else
	{
		memset(path, 0, 256);
		snprintf(path, 255, "%s/cetk", titlepath);
		ret = tikdecrypt_titlekey(path, titlekey);
		if(ret!=0)
		{
			printf("Failed to decrypt titlekey: %d\n", ret);
			return ret;
		}
	}

	ret = aes_setkey_dec(&aes_ctx, titlekey, 128);
	if(ret!=0)
	{
		printf("Failed to set key: %d\n", ret);
		return ret;
	}

	printf("Total contents: %x\n", total_contents);

	for(index=0; index<total_contents; index++)
	{
		contentid = getbe32(chunks[index].id);
		contentsize = getbe64(chunks[index].size);
		contentsz_aligned = ((u32)contentsize + 15) & ~15;

		printf("Index %d:\n", index);
		printf("ContentID: %08x\n", contentid);
		printf("Content Size: %016"PRIx64"\n", contentsize);

		memset(iv, 0, 16);
		memcpy(iv, chunks[index].index, 2);

		memset(path, 0, 256);
		memset(outpath, 0, 256);
		snprintf(path, 255, "%s/%08x", titlepath, contentid);
		snprintf(outpath, 255, "%s/%08x.app", titlepath, contentid);

		buffer = (unsigned char*)malloc(contentsz_aligned);
		if(buffer==NULL)
		{
			printf("Failed to alloc content buffer.\n");
			return 1;
		}
		memset(buffer, 0, contentsz_aligned);

		f = fopen(path, "rb");
		if(f==NULL)
		{
			printf("Failed to open %s for reading.\n", path);
			free(buffer);
			return 1;
		}

		if(fread(buffer, 1, contentsz_aligned, f) != contentsz_aligned)
		{
			printf("Failed to read content.\n");
			free(buffer);
			return 1;
		}
		fclose(f);

		ret = aes_crypt_cbc(&aes_ctx, AES_DECRYPT, (int)contentsz_aligned, iv, buffer, buffer);
		if(ret!=0)
		{
			printf("Failed to decrypt content: %d\n", ret);
			free(buffer);
			return ret;
		}

		f = fopen(outpath, "wb");
		if(f==NULL)
		{
			printf("Failed to open %s for writing.\n", outpath);
			free(buffer);
			return 1;
		}

		if(fwrite(buffer, 1, contentsz_aligned, f) != contentsz_aligned)
		{
			printf("Failed to write content.\n");
			free(buffer);
			return 1;
		}
		fclose(f);

		memset(calchash, 0, 32);
		if((getbe16(chunks[index].type) & 0x2000) == 0)//assumption going by wiiu tmd(s)
		{
			hashsize = 0x20;
			SHA256(buffer, (int)contentsize, calchash);
		}
		else
		{
			hashsize = 0x14;
			SHA1(buffer, (int)contentsize, calchash);
		}
		free(buffer);

		printf("Content hash: ");
		if(memcmp(chunks[index].hash, calchash, hashsize)==0)
		{
			printf("GOOD!\n");
		}
		else
		{
			printf("BAD!\n");
			printf("Aborting...\n");
			return 4;
		}
		printf("\n");
	}

	if((titleid>>36) == 0x4800)
	{
		printf("Skipping using ctrclient-ncch since this is a TWL title.\n");
	}
	else if(disablencch==0)
	{
		for(index=0; index<total_contents; index++)
		{
			contentid = getbe32(chunks[index].id);

			ret = decrypt_ncch(contentid, titlepath);
			if(ret!=0)
			{
				printf("Failed to decrypt contentID %08x NCCH.\n", contentid);
				return ret;
			}
		}
	}

	return 0;
}

int parse_tmd(uint64_t titleid, char *titlepath)
{
	int ret = 0;
	unsigned char *tmdbuf;
	unsigned int tmdsz = 0;
	ctr_tmd_body *tmdbody = NULL;

	FILE *f;
	struct stat tmdstat;
	char path[256];

	memset(path, 0, 256);
	snprintf(path, 255, "%s/tmd", titlepath);

	if(stat(path, &tmdstat)==-1)
	{
		printf("Failed to stat %s\n", path);
		return 1;
	}

	tmdsz = tmdstat.st_size;
	tmdbuf = (unsigned char*)malloc(tmdsz);
	if(tmdbuf==NULL)
	{
		printf("Failed to alloc TMD buffer.\n");
		return 1;
	}
	memset(tmdbuf, 0, tmdsz);
	
	f = fopen(path, "rb");
	if(f==NULL)
	{
		printf("Failed to open %s\n", path);
		free(tmdbuf);
		return 1;
	}

	if(fread(tmdbuf, 1, tmdsz, f) != tmdsz)
	{
		printf("Failed to read TMD.\n");
		fclose(f);
		free(tmdbuf);
		return 1;
	}
	fclose(f);

	tmdbody = tmd_get_body(tmdbuf);
	if(tmdbody==NULL)
	{
		printf("Unknown type %x\n", getbe32(tmdbuf));
		free(tmdbuf);
		return 3;
	}

	if(tmdbody->version!=1)
	{
		printf("TMD version is %x, only version 1 is supported.\n", tmdbody->version);
		free(tmdbuf);
		return 3;
	}

	if(dltitle)
	{
		ret = download_contents(titleid, titlepath, (ctr_tmd_contentchunk*)(tmdbody->contentinfo + 36*64), getbe16(tmdbody->contentcount));
		if(ret!=0)
		{
			printf("Failed to download contents.\n");
			free(tmdbuf);
			return ret;
		}
	}

	if(dectitle)
	{
		ret = decrypt_contents(titleid, titlepath, (ctr_tmd_contentchunk*)(tmdbody->contentinfo + 36*64), getbe16(tmdbody->contentcount));
		if(ret!=0)printf("Failed to decrypt contents.\n");
	}

	free(tmdbuf);

	return ret;
}

int download_title(uint64_t titleid, char *titlepath)
{
	int ret;
	char path[256];
	char dlname[16];

	memset(path, 0, 256);
	memset(dlname, 0, 16);
	snprintf(path, 255, "%s/tmd", titlepath);
	if(!titleversion_set)strncpy(dlname, "tmd", 15);
	if(titleversion_set)snprintf(dlname, 15, "tmd.%u", titleversion);

	ret = cdn_download(titleid, titlepath, dlname, path);
	if(ret!=0)
	{
		printf("Failed to download TMD: %d\n", ret);
		return ret;
	}

	memset(path, 0, 256);
	ret = cdn_download(titleid, titlepath, "cetk", path);
	if(ret!=0)
	{
		printf("Failed to download ticket: %d\n", ret);
		return ret;
	}

	ret = parse_tmd(titleid, titlepath);
	if(ret!=0)
	{
		printf("Failed to download contents/parse tmd: %d\n", ret);
		return ret;
	}

	if(packcia)
	{
		ret = pack_cia(titleid, titlepath);
		if(ret!=0)
		{
			printf("Failed to pack CIA: %d\n", ret);
			return ret;
		}
	}

	return 0;
}

int get_key(const char *name, uint8_t *key, uint32_t len)//based on the save_extract func
{
	char path[256];

	char *home = getenv("HOME");
	if (home == NULL)
	{
		return -1;
	}
	snprintf(path, sizeof(path), "%s/.3ds/%s", home, name);

	FILE *fp = fopen(path, "rb");
	if (fp == 0)
	{
		return -1;
	}

	if (fread(key, len, 1, fp) != 1)
	{
		fclose(fp);
		return -1;
	}
	fclose(fp);

	return 0;
}

int load_key(const char *path, uint8_t *key, uint32_t len)
{
	FILE *fp = fopen(path, "rb");
	if (fp == 0)
	{
		return -1;
	}

	if (fread(key, len, 1, fp) != 1)
	{
		fclose(fp);
		return -1;
	}
	fclose(fp);

	return 0;
}

int decrypt_titlekey(unsigned char *ticket, unsigned char *titlekey)
{
	ctrclient client;
	aes_context aes_ctx;

	unsigned char key[16];
	unsigned char iv[16];
	char keyname[16];

	unsigned char keyindex;
	int ret = 0;
	int normalkey = 0;

	memset(key, 0, 16);
	memcpy(titlekey, &ticket[0x1bf], 16);
	memset(iv, 0, 16);
	memcpy(iv, &ticket[0x1dc], 8);
	keyindex = ticket[0x1f1];

	printf("Using commonkey index %u\n", keyindex);

	memset(keyname, 0, 16);

	if(!normalkey)
	{
		snprintf(keyname, 15, "commonkeyY_%u", keyindex);
	}
	else
	{
		printf("Using dev commonkey\n");
		snprintf(keyname, 15, "common-key");
	}

	if(commonkey_path[0]==0)
	{
		if(get_key(keyname, key, 16)!=0)
		{
			printf("Failed to load %s\n", keyname);
			return 1;
		}
	}
	else
	{
		if(load_key(commonkey_path, key, 16)!=0)
		{
			printf("Failed to load %s\n", commonkey_path);
			return 1;
		}
		normalkey = 1;
	}

	if(normalkey)
	{
		ret = aes_setkey_dec(&aes_ctx, key, 128);
		if(ret != 0)return 2;
	}
	else
	{
		ctrclient_init();
		if (0 == ctrclient_connect(&client, serveradr, "8333"))
			return 2;
		if (!ctrclient_aes_set_ykey(&client, 0x3d, key))
			return 2;
	}

	if(normalkey)
	{
		ret = aes_crypt_cbc(&aes_ctx, AES_DECRYPT, 16, iv, titlekey, titlekey);
		if(ret != 0)return 2;
	}
	else
	{
		if(!ctrclient_aes_set_iv(&client, iv))
			return 2;
		if(!ctrclient_aes_cbc_decrypt(&client, titlekey, 16))
			return 2;

		ctrclient_disconnect(&client);
	}

	return 0;
}

int tikdecrypt_titlekey(char *path, unsigned char *titlekey)
{
	int i, ret;
	FILE *ftik;
	unsigned char keyindex=0;
	unsigned char tikbuf[0x2a4];
	unsigned char encrypted_titlekey[0x10];
	unsigned char plaintext_titlekey[0x10];

	memset(tikbuf, 0, 0x2a4);
	memset(titlekey, 0, 16);
	memset(encrypted_titlekey, 0, 0x10);
	memset(plaintext_titlekey, 0, 0x10);

	ftik = fopen(path, "rb");
	if(ftik==NULL)
	{
		printf("Failed to open %s\n", path);
		return 1;
	}
	if(fread(tikbuf, 1, 0x2a4, ftik) != 0x2a4)
	{
		printf("Failed to read tik\n");

		fclose(ftik);
		return 1;
	}
	fclose(ftik);

	if(settings_get_ticketkeyinfo(getbe64(&tikbuf[0x1dc]), &keyindex, encrypted_titlekey, plaintext_titlekey)==0)
	{
		if(keyindex != tikbuf[0x1f1])
		{
			printf("The keyindex from the settings-file(0x%02x) doesn't match the one from the ticket(0x%02x), normal titlekey decryption will be done instead of using the settings-file titlekey.\n", keyindex, tikbuf[0x1f1]);
		}
		else if(memcmp(encrypted_titlekey, &tikbuf[0x1bf], 0x10))
		{
			printf("The encrypted_titlekey from the settings-file doesn't match the one from the ticket, normal titlekey decryption will be done instead of using the settings-file titlekey.\n");
		}
		else
		{
			printf("Using plaintext titlekey from settings-file: ");
			for(i=0; i<16; i++)printf("%02x", plaintext_titlekey[i]);
			printf("\n");

			memcpy(titlekey, plaintext_titlekey, 0x10);
			return 0;
		}
	}
	else
	{
		printf("Failed to load cached keyinfo from settings-file(if settings are even loaded), normal titlekey decryption will be done instead.\n");
	}

	ret = decrypt_titlekey(tikbuf, titlekey);
	if(ret)return ret;

	printf("Encrypted titlekey: ");
	for(i=0; i<16; i++)printf("%02x", tikbuf[0x1bf + i]);
	printf("\nDecrypted titlekey: ");
	for(i=0; i<16; i++)printf("%02x", titlekey[i]);
	printf("\n");

	settings_set_ticketkeyinfo(getbe64(&tikbuf[0x1dc]), &tikbuf[0x1f1], &tikbuf[0x1bf], titlekey);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	int argi, i, linei;
	int titleid_set = 0, found_start = 0;
	int pos;
	unsigned int tmp=0;
	int use_csv = 0, csv_versionhandling = 0, disabletitledups = 0;
	int enable_settingsloading = 1;
	uint64_t titleid = 0;
	uint64_t begintitleid = 0;
	FILE *f;
	char *strptr, *nextstrptr, *strptr2, *tidstr;
	char *csvbuf = NULL;
	size_t csvbufsize = 0, csvbuf_newsize = 0;
	unsigned char titlekey[16];
	char titlepath[256];
	char titlepathtmp[256];
	char titlepathbase[256];
	char csvpath[256];
	char linebuf[1024];
	char curlinebuf[1024];
	char tmpline[1024];
	char region[8];

	if(argc==1)
	{
		printf("ctrclient-title by yellows8\n");
		printf("Decrypt a retail 3DS ticket and optionally title contents\n");
		printf("--serveradr=<addr> Server address to use.\n");
		printf("--tik=<path> Path to the ticket for decrypting the titlekey, this can be used multiple times to decrypt multiple tickets at once. This done without the settings file.\n");
		printf("--dltitle Download a 3DS title.\n");
		printf("--packcia pack a 3DS title into a CIA.\n");
		printf("--noromfs Pass the --noromfs option to ctrclient-ncch.\n");
		printf("--disasm Pass the --disasm option to ctrclient-ncch.\n");
		printf("--titleid=<titleID> TitleID for the title to process.\n");
		printf("--titlepath=<path> Directory for the downloaded title(s), and the directory for the encrypted/decrypted title(Default is current directory). This directory is automatically created.\n");
		printf("--titlever=<decimalver> Download the specified decimal title version.\n");
		printf("--decrypt=titlekey Decrypt the title stored in titledir, and use ctrclient-ncch to decrypt the NCCH contents. When '=<titlekey>' is specified, use the input titlekey to decrypt content instead of decrypting the tik titlekey. Otherwise, when the settings file was successfully loaded, the plaintext titlekey from there will be used for the title if available.\n");
		printf("--decwithcommonkey=path When --decrypt is used, load normal commonkey from path.\n");
		printf("--disablencch Don't run ctrclient-ncch when --decrypt was used.\n");
		printf("--csv=<csv_filepath> Parse the input CSV, for the operation(s) specified via the other parameters. When just --csv is used, the CSV is read from stdin. For example, to dl+decrypt titles for a sysupdate via the yls8.mtheall.com site: curl \"<URL for CSV>\" | ctrclient-title ... --dltitle --decrypt --titlepath=<sysupdate outdir> --csv\n");
		printf("--begintitle=<titleID> TitleID to begin download/decryption with, for the CSV.\n");
		printf("--firstvercsv Only process the first title-version listed in the CSV, for each title.\n");
		printf("--lastvercsv Only process the last title-version listed in the CSV, for each title.\n");
		printf("--disabletitledups When processing the CSV, disable ignoring titles when the same titleID+titleversion were already handled(like with different SOAP regions).\n");
		printf("--disablesettings Disable using the settings file. The settings-file is used for storing a cache of titlekeys/etc.\n");
		printf("--settingspath=<path> Use the specified path for loading the settings file, instead of $HOME/.3ds/ctrclient-title_settings.\n");
		return 0;
	}

	memset(serveradr, 0, 256);

	memset(intitlekey, 0, 16);
	memset(titlepath, 0, 256);
	memset(titlepathtmp, 0, 256);
	memset(csvpath, 0, 256);
	memset(commonkey_path, 0, sizeof(commonkey_path));

	for(argi=1; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--serveradr=", 12)==0)
		{
			serveradr_set = 1;
			strncpy(serveradr, &argv[argi][12], 255);
		}

		if(strncmp(argv[argi], "--tik=", 6)==0)
		{
			tikdecrypt_titlekey(&argv[argi][6], titlekey);
		}

		if(strncmp(argv[argi], "--dltitle", 9)==0)
		{
			dltitle = 1;
		}
		if(strncmp(argv[argi], "--packcia", 9)==0)
		{
			packcia = 1;
		}
		if(strncmp(argv[argi], "--noromfs", 9)==0)
		{
			noromfs = 1;
		}
		if(strncmp(argv[argi], "--disasm", 8)==0)
		{
			disasm_title = 1;
		}

		if(strncmp(argv[argi], "--titleid=", 10)==0)
		{
			if(strlen(&argv[argi][10]) != 16)
			{
				printf("Invalid titleID.\n");
			}
			else
			{
				titleid_set = 1;
				sscanf(&argv[argi][10], "%016"PRIx64, &titleid);
			}
		}

		if(strncmp(argv[argi], "--titlepath=", 12)==0)strncpy(titlepath, &argv[argi][12], 255);

		if(strncmp(argv[argi], "--titlever=", 11)==0)
		{
			titleversion_set = 1;
			sscanf(&argv[argi][11], "%u", &titleversion);
		}

		if(strncmp(argv[argi], "--decrypt", 9)==0)
		{
			dectitle = 1;
			if(strlen(argv[argi]) == 10+32)
			{
				for(i=0; i<16; i++)
				{
					sscanf(&argv[argi][10 + i*2], "%02x", &tmp);
					intitlekey[i] = tmp;
				}

				intitlekey_set = 1;
			}
		}

		if(strncmp(argv[argi], "--disablencch", 13)==0)
		{
			disablencch = 1;
		}

		if(strncmp(argv[argi], "--decwithcommonkey=", 19)==0)
		{
			strncpy(commonkey_path, &argv[argi][19], sizeof(commonkey_path)-1);
		}

		if(strncmp(argv[argi], "--csv", 5)==0)
		{
			use_csv = 1;
			if(argv[argi][5] == '=')strncpy(csvpath, &argv[argi][6], 255);
		}

		if(strncmp(argv[argi], "--firstvercsv", 13)==0)csv_versionhandling = 1;
		if(strncmp(argv[argi], "--lastvercsv", 12)==0)csv_versionhandling = 2;
		if(strncmp(argv[argi], "--disabletitledups", 18)==0)disabletitledups = 1;

		if(strncmp(argv[argi], "--begintitle=", 13)==0)
		{
			if(strlen(&argv[argi][13]) != 16)
			{
				printf("Invalid titleID.\n");
			}
			else
			{
				sscanf(&argv[argi][13], "%016"PRIx64, &begintitleid);
			}
		}

		if(strncmp(argv[argi], "--disablesettings", 17)==0)
		{
			enable_settingsloading = 0;
		}

		if(strncmp(argv[argi], "--settingspath=", 15)==0)
		{
			settingspath_set = 1;
			memset(settingspath, 0, sizeof(settingspath));
			strncpy(settingspath, &argv[argi][15], sizeof(settingspath)-1);
		}
	}

	if(serveradr[0]==0)return 0;

	if(titleid_set==0 && !use_csv)return 0;

	if(enable_settingsloading)settings_load();

	if(titlepath[0]==0)
	{
		titlepath[0] = '.';
	}
	else
	{
		makedir(titlepath);
	}

	if(!use_csv)
	{
		if(dltitle)
		{
			ret = download_title(titleid, titlepath);
			settings_shutdown();
			return ret;
		}
		else if(dectitle)
		{
			ret = parse_tmd(titleid, titlepath);
			settings_shutdown();
			return ret;
		}
	}

	if(csvpath[0])
	{
		f = fopen(csvpath, "r");
		if(f==NULL)
		{
			printf("Failed to open CSV.\n");
			settings_shutdown();
			return 1;
		}
	}
	else
	{
		f = stdin;
	}

	found_start = 0;
	titleversion_set = 1;
	linei = 0;
	memset(linebuf, 0, 1024);

	if(!begintitleid)found_start = 1;

	while(fgets(linebuf, 1023, f))
	{
		if(!disabletitledups)
		{
			if(csvbuf_newsize)strncat(csvbuf, curlinebuf, csvbuf_newsize-1);
			csvbufsize = csvbuf_newsize;

			csvbuf_newsize = csvbufsize + strlen(linebuf);
			if(csvbufsize==0)csvbuf_newsize++;
			csvbuf = realloc(csvbuf, csvbuf_newsize);
			memset(&csvbuf[csvbufsize], 0, csvbuf_newsize-csvbufsize);

			memset(curlinebuf, 0, sizeof(curlinebuf));
			strncpy(curlinebuf, linebuf, sizeof(curlinebuf)-1);
		}

		strptr = strchr(linebuf, '\n');
		if(strptr)*strptr = 0;

		if(linei)//The CSV should have the following format: TitleID,Region,Title version(s)<,...>
		{
			strptr = strtok(linebuf, ",");//TID
			if(strptr==NULL)
			{
				printf("Skipping invalid line.\n");
				continue;
			}
			tidstr = strptr;
			sscanf(strptr, "%016"PRIx64, &titleid);

			if((begintitleid && !found_start) && titleid==begintitleid)
			{
				found_start = 1;
			}

			if(!found_start)continue;

			strptr = strtok(NULL, ",");//region
			if(strptr==NULL)
			{
				printf("Skipping invalid line.\n");
				continue;
			}
			memset(region, 0, 8);
			strncpy(region, strptr, 7);

			strptr = strtok(NULL, ",");//title-version
			if(strptr==NULL)
			{
				printf("Skipping invalid line.\n");
				continue;
			}


			strptr = strtok(strptr, " ");

			if(strptr==NULL)
			{
				printf("Skipping invalid line.\n");
				continue;
			}

			memset(titlepathbase, 0, 256);
			snprintf(titlepathbase, 255, "%s/%016"PRIx64, titlepath, titleid);
			makedir(titlepathbase);

			pos = strlen(titlepathbase);
			snprintf(&titlepathbase[pos], 255 - pos, "/%s", region);
			makedir(titlepathbase);

			while(strptr)
			{
				nextstrptr = strtok(NULL, " ");
				if(csv_versionhandling==2 && nextstrptr!=NULL)
				{
					strptr = nextstrptr;
					continue;
				}

				if(!disabletitledups)
				{
					if((strptr2 = strstr(csvbuf, tidstr)))
					{
						printf("Found TID dup for titleID %s.\n", tidstr);

						memset(tmpline, 0, sizeof(tmpline));
						
						pos = 0;
						while(pos < (sizeof(tmpline)-1))
						{
							if(strptr2[pos]==0 || strptr2[pos]==0x0a)break;
							tmpline[pos] = strptr2[pos];
							pos++;
						}
						if(pos != (sizeof(tmpline)-1))tmpline[pos] = 0;

						if(strstr(tmpline, strptr))
						{
							printf("Found titleID+titleversion duplicate: titleID %s version %s. Removing the just-created directory which won't be used: %s\n", tidstr, strptr, titlepathbase);
							rmdir(titlepathbase);
							break;
						}
					}
				}

				if(strptr[0] == 'v')strptr++;
				sscanf(strptr, "%u", &titleversion);

				memset(titlepathtmp, 0, 256);
				strncpy(titlepathtmp, titlepathbase, 255);
				pos = strlen(titlepathtmp);
				snprintf(&titlepathtmp[pos], 255 - pos, "/v%u", titleversion);
				makedir(titlepathtmp);

				printf("titleID: %016"PRIx64" region: %s titlever: %u. path: %s\n", titleid, region, titleversion, titlepathtmp);

				if(dltitle)
				{
					ret = download_title(titleid, titlepathtmp);
					if(ret!=0)
					{
						settings_shutdown();
						if(!disabletitledups)free(csvbuf);
						return ret;
					}
				}
				else if(dectitle)
				{
					ret = parse_tmd(titleid, titlepathtmp);
					if(ret!=0)
					{
						settings_shutdown();
						if(!disabletitledups)free(csvbuf);
						return ret;
					}
				}

				strptr = nextstrptr;
				if(csv_versionhandling==1)break;
			}
		}

		linei++;
		memset(linebuf, 0, 1024);
	}

	if(!disabletitledups)free(csvbuf);

	if(csvpath[0])fclose(f);

	settings_shutdown();

    	return 0;
}

