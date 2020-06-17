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

// Prototypes for the hash utilities

char *epst_file_header(const unsigned char *data, unsigned long data_len);
char *epst_md5_hash(const unsigned char *data, unsigned long data_len);
char *epst_sha256_hash(const unsigned char *data, unsigned long data_len);
char *epst_sha1_hash(const unsigned char *data, unsigned long data_len);


typedef struct _EPST_FILE_HASH {
	char *filename;
	char *md5;
	char *sha1;
	char *sha256;
	char *header;
	long fsize;
	int error;
} EPST_FILE_HASH;

#define EPST_FILE_HASH_OK 0
#define EPST_FILE_HASH_ERROR 1
#define EPST_FILE_HASH_READ_ERROR 2
#define EPST_FILE_HASH_MEM_ERROR 3

int calc_file_hash_nb(EPST_FILE_HASH *fhp);
int calc_file_hash_b(EPST_FILE_HASH *fhp, unsigned char* buffer, int bsize);


