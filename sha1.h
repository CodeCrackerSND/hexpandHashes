/*********************************************************************
* Filename:   sha1.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA1_H
#define SHA1_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA1_DIGEST_LENGTH   20              // SHA1 outputs a 20 byte digest
#define SHA1_BLOCK_LENGTH    64              // SHA1 uses 512 bits blocks

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
//typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines


typedef struct {
	BYTE data[64];
	unsigned int datalen;
	unsigned long long bitlen;
	unsigned int state[5];
	unsigned int k[4];
} SHA1_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len);
void sha1_final(SHA1_CTX *ctx, BYTE hash[]);

#endif   // SHA1_H
