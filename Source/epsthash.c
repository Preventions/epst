/*
   Copyright 2020 CanCyber Foundation & EPST Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

/* 
  Hashing functions to complement/replace OpenSSL versions.
  NOTE: returned data must be freed by the calling functions.
 */

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <Windows.h>
#else
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#endif


#include <openssl/md5.h>
#include <openssl/sha.h>

#include "epstutils.h"
#include "epsthash.h"


char *epst_file_header(const unsigned char *data, unsigned long data_len) {
	int i, j;

	char *head = malloc(17);
	if (head == NULL) return NULL;

	if (data_len >= 8) {
		for (i = 0, j = 0; j < 8; i += 2, j++) {
			snprintf(head + i, 3, "%02x", data[j]);
		}
		head[16] = '\0';
	}
	else {
		strcpy(head, "00000000");
	}

	return head;
}

void digest_to_hex(unsigned char* digest, char* digest_ascii, size_t digest_length)
{
	size_t i;

	for (i = 0; i < digest_length; i++)
		sprintf(digest_ascii + (i * 2), "%02x", digest[i]);

	digest_ascii[digest_length * 2] = '\0';
}


char *epst_md5_hash(const unsigned char *data, unsigned long data_len) {
	unsigned char digest[MD5_DIGEST_LENGTH];
	MD5_CTX md5_context;

	MD5_Init(&md5_context);
	MD5_Update(&md5_context, (unsigned char*)data, (size_t)data_len);
	MD5_Final(digest, &md5_context);

	char *md5 = malloc(MD5_DIGEST_LENGTH * 2 + 1);
	if (md5 != NULL) digest_to_hex(digest, md5, MD5_DIGEST_LENGTH);

	return md5;
}


char *epst_sha256_hash(const unsigned char *data, unsigned long data_len) {
	unsigned char digest[SHA256_DIGEST_LENGTH];
	char *sha256;
	SHA256_CTX sha256_context;

	SHA256_Init(&sha256_context);
	SHA256_Update(&sha256_context, data, (size_t)data_len);
	SHA256_Final(digest, &sha256_context);

	sha256 = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
	if (sha256 != NULL) digest_to_hex(digest, sha256, SHA256_DIGEST_LENGTH);
	return sha256;
}


char *epst_sha1_hash(const unsigned char *data, unsigned long data_len) {
	unsigned char digest[SHA_DIGEST_LENGTH];
	char *sha1;
	SHA_CTX sha_context;

	SHA1_Init(&sha_context);
	SHA1_Update(&sha_context, data, (size_t)data_len);
	SHA1_Final(digest, &sha_context);

	sha1 = malloc(SHA_DIGEST_LENGTH * 2 + 1);
	if (sha1 != NULL) digest_to_hex(digest, sha1, SHA_DIGEST_LENGTH);
	return sha1;
}


// Do the hash calculations without using a shared
// memory buffer. Read the entire file into memory
// and do the hashing all at once.
int calc_file_hash_nb(EPST_FILE_HASH *fhp) {
	long fsize = 0;
	unsigned char *data; 

	data = read_file_data(fhp->filename, &fsize);
	fhp->fsize = fsize;

	if (data == NULL) {
		if (fsize > 0)	return EPST_FILE_HASH_MEM_ERROR;
		else			return EPST_FILE_HASH_READ_ERROR;
	}

	fhp->md5 = epst_md5_hash(data, fsize);
	fhp->sha1 = epst_sha1_hash(data, fsize);
	fhp->sha256 = epst_sha256_hash(data, fsize);

	free(data);
	return EPST_FILE_HASH_OK;
}

// Read the file data in chunks based on buffer size
int calc_file_hash_b(EPST_FILE_HASH *fhp, unsigned char*buffer, int bsize) {
	FILE *fp;
	size_t rb;
	errno_t err;
	unsigned char sha1_digest[SHA_DIGEST_LENGTH];
	SHA_CTX sha_context;

	unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256_context;

	unsigned char md5_digest[MD5_DIGEST_LENGTH];
	MD5_CTX md5_context;

	fhp->fsize = 0;
	fhp->md5 = NULL;
	fhp->sha1 = NULL;
	fhp->sha256 = NULL;

	if ((err = fopen_s(&fp, fhp->filename, "rb")) != 0) {
		return EPST_FILE_HASH_READ_ERROR;
	}

	MD5_Init(&md5_context);
	SHA1_Init(&sha_context);
	SHA256_Init(&sha256_context);

	while ((rb = fread(buffer, sizeof(unsigned char), bsize, fp)) != 0) {
		MD5_Update(&md5_context, buffer, rb);
		SHA1_Update(&sha_context, buffer, rb);
		SHA256_Update(&sha256_context, buffer, rb);

		fhp->fsize += (long)rb;
	}

	fclose(fp);

	MD5_Final(md5_digest, &md5_context);
	SHA1_Final(sha1_digest, &sha_context);
	SHA256_Final(sha256_digest, &sha256_context);

	// Ignore zero size files - may or may not be an error
	if (fhp->fsize == 0) return EPST_FILE_HASH_OK;

	fhp->md5 = malloc(MD5_DIGEST_LENGTH * 2 + 1);
	if (fhp->md5 != NULL) digest_to_hex(md5_digest, fhp->md5, MD5_DIGEST_LENGTH);

	fhp->sha1 = malloc(SHA_DIGEST_LENGTH * 2 + 1);
	if (fhp->sha1 != NULL) digest_to_hex(sha1_digest, fhp->sha1, SHA_DIGEST_LENGTH);

	fhp->sha256 = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
	if (fhp->sha256 != NULL) digest_to_hex(sha256_digest, fhp->sha256, SHA256_DIGEST_LENGTH);

	return EPST_FILE_HASH_OK;
}