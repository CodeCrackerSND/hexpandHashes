#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <unistd.h> - LINUX ONLY
#include <io.h>
#include <assert.h>
#include <getopt.h>
//#include <openssl/evp.h>
//#include <openssl/ossl_typ.h>
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "hexpand.h"
#include "getopt2.h"

#define EVP_MAX_MD_SIZE 64     /* SHA512 */

void help(void) {
	fprintf(stderr, "Usage:\n"
		"\thexpand -t type -s signature -l length -m message\n"
		"\thexpand --test\n\n"
		"Options:\n"
		"\t-t --type\tthe hash algorithm for expansion (md5, sha1, sha256, or sha512\n"
		"\t-s --sig\tthe result of the original hash function\n"
		"\t-l --length\tthe length of the original message\n"
		"\t-m --message\tthe message to be appended\n"
		"\t--test\t\truns a set of test cases\n");
	exit(EXIT_FAILURE);
}

struct test_case {
	char *type;
	char *sig;
	char *message;
	int length;
	char *expected;
};

/*
void test(void) {
	int success = 1;
	int i = 0;
	struct test_case t[] = {
		{"md5", "4697843037d962f62a5a429e611e0f5f", "b", 40, "d4ec08ed634b530a1c396d80060729ec"},
		{"sha1", "a56559418dc7908ce5f0b24b05c78e055cb863dc", "b", 40, "b7c89b959b72273e2dc2f29dc52d65a152f2a9ef"},
		{"sha256", "e33cdf9c7f7120b98e8c78408953e07f2ecd183006b5606df349b4c212acf43e", "b", 40, "1e86cd29eb59ce048221e7053682f508ace11246135d7d21089f6f74fd35b0a1"},
		{"sha512", "e411795f8b2a38c99a7b86c888f84c9b26d0f47f2c086d71a2c9282caf6a898820e2c1f3dc1fa45b20178da40f6cb7e4479d3d7155845ed7a4b8698b398f3d0c", "b", 40, "d5e39d5274db7d1ec920fefeb23f9f785eaffb4d3e1e8a7ecd59332863c2598c4c4431616eaba4fc1c752e4d0e8884f6f3cf8a4fc124dd1f026d83c398a2af80"},
		{0, 0, 0, 0}
	};
	while (t[i].type != 0) {
		const EVP_MD *type = EVP_get_digestbyname(t[i].type);
		void *func = extend_get_funcbyname(t[i].type);
		int c;
		unsigned char md_value[EVP_MAX_MD_SIZE];
		unsigned char* tmp;
		unsigned int block_size = hash_extend(type, func, t[i].sig, t[i].message, t[i].length, md_value, &tmp);
		//char output[2*block_size];
		char* output = malloc(2*block_size);
		for(c = 0; c < block_size; c++) {
			sprintf(output+2*c, "%02x", md_value[c]);
		}
		if (strcmp(output, t[i].expected) != 0) {
			printf("Test %i failed...\n", i);
			success &= 0;
		}
		i++;
	}

	if (success) {
		printf("All tests passed!\n");
		exit(EXIT_SUCCESS);
	} else {
		exit(EXIT_FAILURE);
	}
}
*/

static int test_flag = 0;

void HashTests()
{

int target, source;
int *hpointer;
char *result;
unsigned char* output;
unsigned char *md_value;
int size1;
unsigned char *HashString;

int i = 0;
char md5string[33];
unsigned char digest[16];
const char* string = "Hello World";
MD5_CTX context;

SHA1_CTX sha;
char results[SHA1_DIGEST_LENGTH];
char *buf;
int n;

char digest1[SHA512_DIGEST_LENGTH];
char result256[SHA256_BLOCK_LENGTH];
SHA256_CTX sha2;

unsigned int state[5];
char hash[SHA1_DIGEST_LENGTH];

// MD5 part start:
MD5_Init(&context);
MD5_Update(&context, string, strlen(string));
MD5_Final(digest, &context);

for(i = 0; i < 16; ++i)
    sprintf(&md5string[i*2], "%02x", (unsigned int)digest[i]);

printf("MD5 = %s\r\n", md5string);

buf = "abc";

// SHA1 part start:
n = strlen(buf);
sha1_init(&sha);
sha1_update(&sha, (char *)buf, n);

printf("\r\nState[0]=%X", sha.state[0]);
printf("\r\nState[1]=%X", sha.state[1]);
printf("\r\nState[2]=%X", sha.state[2]);
printf("\r\nState[3]=%X", sha.state[3]);
printf("\r\nState[4]=%X", sha.state[4]);

sha1_final(&sha, hash);

HashString = malloc(128);
HashString[0] = 0;
for (n = 0; n < SHA1_DIGEST_LENGTH; n++)
{
printf("%02x", (unsigned char)hash[n]);
sprintf(HashString, "%s%02x", HashString, (unsigned char)hash[n]);
}

printf("\r\nHashResult=%s", HashString);

putchar('\n');


for (i = 0; i < 5; ++i)
{

	*(sha.state+i) = strntoul(HashString+i*8, 8, 16);
	
		
}

	//state[0] = HashString[3] | (HashString[2] << 8) | (HashString[1] << 16) | (HashString[0] << 24);
	//stretch.h1 = hash[7] | (hash[6] << 8) | (hash[5] << 16) | (hash[4] << 24);
	//stretch.h2 = hash[11] | (hash[10] << 8) | (hash[9] << 16) | (hash[8] << 24);
	//stretch.h3 = hash[15] | (hash[14] << 8) | (hash[13] << 16) | (hash[12] << 24);
	//stretch.h4 = hash[19] | (hash[18] << 8) | (hash[17] << 16) | (hash[16] << 24);

printf("\r\nState[0]=%X", sha.state[0]);
printf("\r\nState[1]=%X", sha.state[1]);
printf("\r\nState[2]=%X", sha.state[2]);
printf("\r\nState[3]=%X", sha.state[3]);
printf("\r\nState[4]=%X", sha.state[4]);

sha1_init(&sha);
sha1_update(&sha, (char *)buf, n);

printf("\r\nState[0]=%X", sha.state[0]);
printf("\r\nState[1]=%X", sha.state[1]);
printf("\r\nState[2]=%X", sha.state[2]);
printf("\r\nState[3]=%X", sha.state[3]);
printf("\r\nState[4]=%X", sha.state[4]);

}

int main(int argc, char *argv[]) {
// Variables should be declarated first:
	char *signature = NULL;
	char *message = NULL;
	int length, c;
	char *type = NULL;
	void *func = NULL;
	unsigned char* output;
	unsigned int block_size;
	static struct option long_options[] = {
		{"test",    no_argument,       &test_flag, 1},
		{"type",    required_argument, 0, 't'},
		{"sig",     required_argument, 0, 's'},
		{"length",  required_argument, 0, 'l'},
		{"message", required_argument, 0, 'm'},
		{0, 0, 0, 0}
	};
	int optind = 0;
	unsigned char *md_value;

// HashTests();

	optind = 0;
	opterr = 0;
	while ((c = getopt_long(argc, argv, "l:m:s:t:", long_options, &optind)) != -1) {
		switch (c) {
			case 0:
				break;
			case 'l':
				length = atoi(optarg);
				break;
			case 'm':
				message = optarg;
				break;
			case 's':
				signature = optarg;
				break;
			case 't':
				type = optarg;
				//func = extend_get_funcbyname(optarg);
				//if (!type || !func) {
				//	fprintf(stderr, "%s is not a supported hash format\n", optarg);
				//	exit(EXIT_FAILURE);
				//}
				break;
			default:
				help();
		}
	}

	if (test_flag) {
		//test();
	}

	if (message == NULL || signature == NULL) {
		help();
	}

	//unsigned char md_value[EVP_MAX_MD_SIZE];
	// md_value = malloc(EVP_MAX_MD_SIZE);
	// input: type, signature, message, length
	// output: md_value, &output
	block_size = hash_extend(type, signature, message, length, &md_value, &output);
	printf("Append (hex):\t%s", output);
	for(c = 0; c < strlen(message); c++)
		printf("%02x", message[c]);

	printf("\nSignature:\t");
	for(c = 0; c < block_size; c++)
		printf("%02x", md_value[c]);
	printf("\n");

	free(md_value);
	free(output);
	exit(EXIT_SUCCESS);


}





