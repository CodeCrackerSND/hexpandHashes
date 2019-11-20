#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <unistd.h> - LINUX ONLY
#include <io.h>
//#include <openssl/crypto.h>
//#include <openssl/md5.h>
//#include <openssl/sha.h>
//#include <openssl/evp.h>
//#include <openssl/ossl_typ.h>
//#include <arpa/inet.h> - LINUX ONLY
//#include <winsock.h>
#include <winsock2.h>
#include <inttypes.h>
#include "byteorder.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

// The blocksize of MD5 in bytes.
#define MD5_BlockSize  64

#define MD5_Digestsize 16

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

unsigned int strntoul(const char* str, int length, int base) {
	// char buf[length+1];
	unsigned int Converted;
	char* buf = malloc(length*sizeof(char)+1);
	memcpy(buf, str, length);
	buf[length] = '\0';
	Converted = strtoul(buf, NULL, base);
	free(buf);
	return Converted;
}

/*
char* sha1_extend(EVP_MD_CTX *mdctx, char* signature, int length) {
	unsigned char* h_data;
	char* output;
	int h_data_size;
	int sha_switch;
	int i = 0, j = 0;
	int length_modulo = 0; //((EVP_MD_CTX*)(mdctx))->digest->block_size;

	int length_bytes = length_modulo/8;
	int trunc_length = length%length_modulo;
	int padding = ((trunc_length) < (length_modulo-length_bytes))
							? ((length_modulo-length_bytes) - trunc_length)
							: ((2*length_modulo-length_bytes) - trunc_length);
	//unsigned char data[length+padding+length_bytes];
	unsigned char* data = malloc(length+padding+length_bytes);
	memset(data, 'A', length+padding+length_bytes);
	EVP_DigestUpdate(mdctx, data, length+padding+length_bytes);

	//h_data = (unsigned char *)((SHA512_CTX *)mdctx->md_data)->h;
	//h_data_size = (mdctx->digest->md_size);
	sha_switch = length_modulo/16;
	i = 0;
	j = 0;
	while (i < h_data_size) {
		for (j = 0; j < sha_switch; j++) {
			h_data[i+j] = strntoul(signature+2*(i+sha_switch-1-j), 2, 16);
		}
		i+=sha_switch;
	}

	output = malloc((2*(padding+length_bytes)+1)*sizeof(char));
	output[0] = '8';
	output[1] = '0';

	for (i = 1; i < 2*(padding+length_bytes); i++) output[i] = '0';
	if (length_modulo == 128) sprintf(output+2*padding, "%032" PRIx32 , htole64(8*length));
	else sprintf(output+2*padding, "%016" PRIx32 , htole64(8*length));
	output[2*(padding+length_bytes)] = 0;

	return output;
}
*/

/*
char* md5_extend(EVP_MD_CTX *mdctx, char* signature, int length) {
	char* output;
	int i;
	int length_modulo = 0; //mdctx->digest->block_size;
	int length_bytes = length_modulo/8;
	int trunc_length = length&0x3f;
	int padding = ((trunc_length) < (length_modulo-length_bytes))
							? ((length_modulo-length_bytes) - trunc_length)
							: ((2*length_modulo-length_bytes) - trunc_length);
	//unsigned char data[length+padding+length_bytes];
	unsigned char* data = malloc(length+padding+length_bytes);
	memset(data, 'A', length+padding+length_bytes);
	EVP_DigestUpdate(mdctx, data, length+padding+length_bytes);
	//((MD5_CTX *)mdctx->md_data)->A = htonl(strntoul(signature, 8, 16));
	//((MD5_CTX *)mdctx->md_data)->B = htonl(strntoul(signature+8, 8, 16));
	//((MD5_CTX *)mdctx->md_data)->C = htonl(strntoul(signature+16, 8, 16));
	//((MD5_CTX *)mdctx->md_data)->D = htonl(strntoul(signature+24, 8, 16));

	output = malloc((2*(padding+length_bytes)+1)*sizeof(char));
	output[0] = '8';
	output[1] = '0';
	for (i = 1; i < 2*(padding+length_bytes); i++) output[i] = '0';
	sprintf(output+2*padding, "%016" PRIx64 , htobe64(8*length));
	output[2*(padding+length_bytes)] = 0;
	return output;
}
*/

void *extend_get_funcbyname(const char* str) {

return NULL;

/*
	if (strcmp(str, "md5") == 0) {
		return &md5_extend;
	} else if (strcmp(str, "sha1") == 0) {
		return &sha1_extend;
	} else if (strcmp(str, "sha256") == 0) {
		return &sha1_extend;
	} else if (strcmp(str, "sha512") == 0) {
		return &sha1_extend;
	} else {
		return NULL;
	}

*/

}

void sha_extend(char *type,
		char *signature,
		char *message,
		int length,
		unsigned char** digest,
		unsigned char** output)
{
	SHA1_CTX sha1;
	SHA256_CTX sha2;
	sha512_context sha3;
	int length_bytes;
	int trunc_length;
	int padding;
	unsigned char* data;
	unsigned char* h_data;
	char* Out_digest;
	char* outApend;
	int h_data_size;
	int sha_switch;
	int i = 0, j = 0;
	int k = 0;
	int length_modulo = 0; //((EVP_MD_CTX*)(mdctx))->digest->block_size;
	if (strcmp(type, "sha1") == 0)
	length_modulo = SHA1_BLOCK_LENGTH;  // Block size = 512 bits
	else if (strcmp(type, "sha256") == 0)
	length_modulo = SHA256_BLOCK_LENGTH;  // Block size = 512 bits
	else if (strcmp(type, "sha512") == 0)
	length_modulo = SHA512_BLOCK_LENGTH;  // Block size = 1024 bits


	length_bytes = length_modulo/8;
	trunc_length = length%length_modulo;
	padding = ((trunc_length) < (length_modulo-length_bytes))
					? ((length_modulo-length_bytes) - trunc_length)
					: ((2*length_modulo-length_bytes) - trunc_length);
	//unsigned char data[length+padding+length_bytes];
	data = malloc(length+padding+length_bytes);
	memset(data, 'A', length+padding+length_bytes);

	if (strcmp(type, "sha1") == 0)
	{
	sha1_init(&sha1);
	sha1_update(&sha1, data, length+padding+length_bytes);
	h_data = (unsigned char *)(&sha1.state);
	h_data_size = SHA1_DIGEST_LENGTH;
	}
	else if (strcmp(type, "sha256") == 0)
	{
	sha256_init(&sha2);
	sha256_update(&sha2, data, length+padding+length_bytes);
	h_data = (unsigned char *)(&sha2.state);
	h_data_size = SHA256_DIGEST_LENGTH;
	}
	else if (strcmp(type, "sha512") == 0)
	{
	sha512_init(&sha3);
	sha512_starts(&sha3);
	sha512_update(&sha3, data, length+padding+length_bytes);
	h_data = (unsigned char *)(&sha3.state);
	h_data_size = SHA512_DIGEST_LENGTH;  // not dword but 64 bits
	}


	sha_switch = length_modulo/16;
	i = 0;
	j = 0;
	while (i < h_data_size) {
		for (j = 0; j < sha_switch; j++) {
			h_data[i+j] = strntoul(signature+2*(i+sha_switch-1-j), 2, 16);
		}
		i+=sha_switch;
	}
	
	outApend = malloc((2*(padding+length_bytes)+1)*sizeof(char));
	outApend[0] = '8';
	outApend[1] = '0';

	for (i = 1; i < 2*(padding+length_bytes); i++) outApend[i] = '0';
	if (length_modulo == 128) sprintf(outApend+2*padding, "%032" PRIx32 , htole64(8*length));
	else sprintf(outApend+2*padding, "%016" PRIx32 , htole64(8*length));
	outApend[2*(padding+length_bytes)] = 0;

	Out_digest = malloc(h_data_size);

	if (strcmp(type, "sha1") == 0)
	{
	sha1_update(&sha1, message, strlen(message));
	sha1_final(&sha1, Out_digest);
	}
	else if (strcmp(type, "sha256") == 0)
	{
	sha256_update(&sha2, message, strlen(message)); /* This is the appended data. */
    sha256_final(&sha2, Out_digest);
	}
	else if (strcmp(type, "sha512") == 0)
	{
	sha512_update(&sha3, message, strlen(message)); /* This is the appended data. */
    sha512_finish(&sha3, Out_digest);
	}

	*digest = Out_digest;
	*output = outApend;



}


void md5_extend(char *signature,
		char *message,
		int length,
		unsigned char** digest,
		unsigned char** output)
{
	unsigned char *Out_digest;
	unsigned char *Out;
	int c;
	MD5_CTX mdctx;
	int i;
	int length_modulo = MD5_BlockSize; //mdctx->digest->block_size;
	int length_bytes = length_modulo/8;
	int trunc_length = length&0x3f;
	int padding = ((trunc_length) < (length_modulo-length_bytes))
							? ((length_modulo-length_bytes) - trunc_length)
							: ((2*length_modulo-length_bytes) - trunc_length);
	//unsigned char data[length+padding+length_bytes];
	unsigned char* data = malloc(length+padding+length_bytes);
	memset(data, 'A', length+padding+length_bytes);
	
	MD5_Init(&mdctx);
	MD5_Update(&mdctx, data, length+padding+length_bytes);

	mdctx.a = htonl(strntoul(signature, 8, 16));
	mdctx.b = htonl(strntoul(signature+8, 8, 16));
	mdctx.c = htonl(strntoul(signature+16, 8, 16));
	mdctx.d = htonl(strntoul(signature+24, 8, 16));

	Out = malloc((2*(padding+length_bytes)+1)*sizeof(char));
	Out[0] = '8';
	Out[1] = '0';
	for (i = 1; i < 2*(padding+length_bytes); i++) Out[i] = '0';
	sprintf(Out+2*padding, "%016" PRIx64 , htobe64(8*length));
	Out[2*(padding+length_bytes)] = 0;

	Out_digest = malloc(MD5_Digestsize);
	MD5_Update(&mdctx, message, strlen(message)); /* This is the appended data. */
    	MD5_Final(Out_digest, &mdctx);

	*digest = Out_digest;
	*output = Out;

}


int hash_extend(char* type,
		char *signature,
		char *message,
		int length,
		unsigned char** digest,
		unsigned char** output)

{

	if (strcmp(type, "md5") == 0)
	{
	md5_extend(signature, message, length, digest, output);
	return MD5_Digestsize;
	}

	if (strcmp(type, "sha1") == 0)
	{
	sha_extend(type, signature, message, length, digest, output);
	return SHA1_DIGEST_LENGTH;
	}

	if (strcmp(type, "sha256") == 0)
	{
	sha_extend(type, signature, message, length, digest, output);
	return SHA256_DIGEST_LENGTH;
	}

	if (strcmp(type, "sha512") == 0)
	{
	sha_extend(type, signature, message, length, digest, output);
	return SHA512_DIGEST_LENGTH;
	}


return 0;

}

/*
int hash_extend(const EVP_MD *md,
				char* (*extend_function)(EVP_MD_CTX *m, char* s, int l),
				char *signature,
				char *message,
				int length,
				unsigned char* digest,
				char** output) {
	EVP_MD_CTX *mdctx;
	unsigned int block_size;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	*output = (*extend_function)(mdctx, signature, length);
	EVP_DigestUpdate(mdctx, message, strlen(message));
	EVP_DigestFinal_ex(mdctx, digest, &block_size);
	EVP_MD_CTX_destroy(mdctx);
	return block_size;
}
*/

