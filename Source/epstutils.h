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

#ifndef __EPSTUTILS__

#define __EPSTUTILS__

#ifndef MAX_PATH

#if defined(_WIN32)
#define MAX_PATH 260
#else
#define MAX_PATH 1024
#endif

#endif

#if defined(_WIN32)
#define DIR_SEP '\\'
#else
#define DIR_SEP '/'
#define DWORD size_t
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif


#ifndef min
#define min(x, y)  ((x < y) ? (x) : (y))
#endif

#define EPST_SCAN_REGEX		0
#define EPST_SCAN_RKEYS		1
#define EPST_SCAN_DNS		2
#define EPST_SCAN_IPS		3
#define EPST_SCAN_FNAMES	4
#define EPST_SCAN_MUTEX		5
#define EPST_SCAN_URL		6

#define MAX_SYSCMD_CODE_SIZE 80

typedef struct EPST_EventSignature_ {
	struct EPST_EventSignature_ *next;
	char *signature;
	int scan_type;
} EPST_EventSignature;

typedef struct EPST_StrListItem_ {
	struct EPST_StrListItem_ *next;
	char *item;
} EPST_StrListItem;

typedef struct EPST_Translate_ {
	struct EPST_Translate_ *next;
	char *english;
	char *translation;
} EPST_Translate;

typedef int BOOL;

void init_regex_test_buffer(char *rtest_fname);
void free_regex_test_buffer();

void init_local_sig_buffer(char *localsig_fname);
void free_local_sig_buffer();

BOOL init_epst_sigdata(size_t initial_size);
void free_epst_sigdata();
void restart_epst_sigdata();
char *get_epst_sigdata_string();

char *check_expand_variables(char *s, char *b, DWORD bsize);

char *do_research_get_hit(char *data, char *search, size_t datasize, char *hit, size_t hitsize);
char *do_list_research_get_hit(EPST_StrListItem *list, char *data, size_t datasize, char *hit, size_t hitsize);
BOOL add_epst_strlistitem(EPST_StrListItem **list, char *str);
BOOL add_epst_event_signature(EPST_EventSignature **list, int scan_type, char *signature);
void free_epst_event_signatures(EPST_EventSignature **list);
void free_epst_strlistitems(EPST_StrListItem **list);
void dump_epst_event_signatures(EPST_EventSignature *list, int eventid);
void dump_epst_strlistitems(EPST_StrListItem *list);
int count_epst_strlistitems(EPST_StrListItem *list);
char *filter_syscmd_research(char *cmd, EPST_StrListItem *research, EPST_StrListItem **fregex, EPST_StrListItem **fsigcode);
size_t append_local_signature_data(char *fname);
void load_event_signatures_from_file(EPST_EventSignature **list, int max_id, char *fname, int *sigcount);
void load_event_signatures_from_data(EPST_EventSignature **list, int max_id, int *sigcount);
void load_syscmd_signatures_from_file(char *fname, EPST_StrListItem **cmds, EPST_StrListItem **research);
void load_syscmd_signatures_from_data(EPST_StrListItem **cmds, EPST_StrListItem **research);
BOOL epst_strlistitem_exists(EPST_StrListItem *list, char *item);
char **load_signature_list_from_data(int *nstrs, BOOL expenv, EPST_StrListItem **research);
char **load_signature_list_from_file(char *fname, int *nstrs, BOOL expenv, EPST_StrListItem **research);
void free_signature_list(char ***str_array, int *cnt);
char *search_with_signature_list(char **signatures, int cnt, char *sample);
int bisearch_signature_list(char **signatures, int size, char *sample);
void dump_signature_list(char *fname, char **str_array, int cnt);
char *getCurrentDateTime();
char *getCurrentTime();
unsigned char *read_file_data(char *fname, long *fsize);
unsigned long read_file_header(const char *fname, long hsize, char *hbuf);
long seek_file_size(const char *fname);

BOOL is_win_event_file(const char *fname);
BOOL fname_has_extension(const char*fname, const char *ext);
BOOL is_history_file(char *fname);

long get_file_size_attr(char *fname);
char *get_first_string_in_file(const char *fname);
int download_signature_data(const char *fname, const char *code, const char *apikey, const char *version);
int download_signature_file(const char *fname, const char *code, const char *apikey, const char *version);
int upload_scan_results_file(const char *fname, const char *apikey, const char *results_sha256);
int upload_scan_file(const char *fname, const char *apikey, const char *results_sha256, const char *post_name);
int upload_scan_results_hit(const char *apikey, const char *hcode, const char *value);

int fexists(const char *filename);
void remove_epst_file(const char *fname);

int initialize_curl();
void finalize_curl();

void init_translate_data();
void free_translate_data();
const char *EPSTTranslate(const char *english);
int use_default_translate_data();

BOOL url_strings_in_file(char *fname);
void add_default_history_files(EPST_StrListItem **list);

int do_research(const char *source, const char *find, size_t *result_start, size_t *result_length);
int epst_test_regex(const char *source, long ssize, const char *find);


#if !defined(_WIN32)
typedef int errno_t;

errno_t fopen_s(FILE **f, const char *name, const char *mode);

void format_filetime_to_str(struct timespec *ts, char *buf, size_t bsize);
long get_fsize_from_file_attr(struct stat *fad);
int IsUserAdmin(void);

#else

void format_filetime_to_str(FILETIME *ft, char *buf, size_t bsize);
long get_fsize_from_file_attr(WIN32_FILE_ATTRIBUTE_DATA *fad);
BOOL IsUserAdmin(void);

#endif


#endif
