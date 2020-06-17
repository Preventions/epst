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
  Various general utilities for the endpoint scanning tool
*/

#if defined(_WIN32)
#include <Windows.h>
#include <io.h>
#include <share.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <sys/stat.h>

#include "epstutils.h"

#include "curl/curl.h"

#include <locale.h>


#define EPSTUTILS_STR_BUFFER_SIZE 2048
#define EPSTUTILS_MAX_DATA_LINES 100000

#if !defined(_WIN32)

#define _strdup strdup
#define _access access

#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <regex.h>
#include <ctype.h>


errno_t fopen_s(FILE **f, const char *name, const char *mode) {
    errno_t ret = 0;
    *f = fopen(name, mode);
    if (!*f)
        ret = errno;
    return ret;
}

// NOTE: Windows functions return 0 on failure, linux returns 0 on success
int DeleteFile(const char *fname) {
	return !remove(fname);
}

int MoveFile(const char *oldname, const char *newname) {
	return !rename(oldname,newname);
}

#endif


// Special Handling for the Directories and Environment Variables
// Various differences between Windows and Unix style file system

#if !defined(_WIN32)

static int GetLastError() {
	return 66;
}

// Special version of regex functions for OSX and Linux - RegexWrapper.cpp used for Windows

static int compile_regex(regex_t *r, const char *regex_text)
{
    int rc = regcomp (r, regex_text, REG_EXTENDED);
    if (rc != 0) {
		char error_message[1024];
		regerror (rc, r, error_message, 1024);
        printf ("Regex ERROR: %s\n", error_message);
        return 1;
    }
    return 0;
}

int do_research(const char *source, const char *find, size_t *result_start, size_t *result_length) {
	// Return the result referencing the source buffer
	// Avoids string/char copying etc.
	int rc = 0;
	*result_start = 0;
	*result_length = 0;
	regex_t re;
	regmatch_t m[1]; // Don't need the groups
	
	if (!compile_regex(&re,find)) {
		if (!regexec (&re, source, 1, m, 0)) {
			if (m[0].rm_so >= 0) {
				*result_start = (size_t)(m[0].rm_so);
				*result_length = (size_t)(m[0].rm_eo - m[0].rm_so);
				rc = 1;
			}
		}
	}
	
	regfree(&re);
	return rc;
}

int epst_test_regex(const char *source, long ssize, const char *find) {
	regex_t re;
	regmatch_t m[1];  // Don't need the groups
	const char *p = source;

    int rc = regcomp (&re, find, REG_EXTENDED);
    if (rc != 0) {
		char error_message[1024];
		regerror (rc, &re, error_message, 1024);
        printf ("Regex: %s\n", find);
        printf ("ERROR: %s\n", error_message);
		regfree(&re);
        return 0;
    }
 	
	printf("Regex: %s\n",find);
	while((p-source) < ssize) {
		int start, finish;
		
		if (regexec (&re, p, 1, m, 0)) break; // No Matches
		
		start = m[0].rm_so;
		if (start == -1) break;
		finish = m[0].rm_eo;
		
		printf("Found: %.*s\n",finish-start,p+start);
		p += finish;
	}
	
	regfree(&re);
	return 1;
}

static DWORD ExpandEnvironmentStrings(char *s, char *b, DWORD bsize) {
	size_t ps,pl,sl,el;
	char *eval;
	char evar[256];
	DWORD nl;
	BOOL err = FALSE;
	
	if (do_research(s,"%[A-Za-z_]*%",&ps,&pl)) {
		sl = strlen(s);
		
		if (pl >= 256) err = TRUE;
		if (pl < 5 || ps < 0) err = TRUE;
		if ((ps+pl) > sl) err = TRUE;
		
		if (err == FALSE) {
			strncpy(evar,&s[ps+1],pl-2);
			evar[pl-2] = '\0';
			eval = getenv(evar);
		} else eval = NULL;
		
		if (eval != NULL) {
			el = strlen(eval);
		
			if (el >= bsize) return 0;
			if ((el+sl-pl+1) >= bsize) return 0;
		
			if (ps > 0) memcpy(b,s,ps);
			memcpy(b+ps,eval,el);
		
			if ((ps+pl) < sl) memcpy(b+ps+el,s+ps+pl,sl-ps-pl+1);
			nl = el+sl-pl;
			b[nl] = '\0';
			return nl;
		}
	}
	
	// Fall through if env var does not exist
	strncpy(b, s, bsize);
	b[bsize-1] = '\0';
	return strlen(b);
}

#endif

static char *regex_test_buffer = NULL;
static long regex_test_buffer_size = 0;

static char *local_sig_buffer = NULL;
static long local_sig_buffer_size = 0;


char *check_expand_variables(char *s, char *b, DWORD bsize) {
	DWORD esize;
	char *r,*ns;
	char addhomedrive[1024];

	// Special Fix - should be added to signatures in file directly
	// Adding as convenience just in case - will miss drive otherwise
	if (!strncmp(s, "%HOMEPATH%", 10)) {
		snprintf(addhomedrive, 1024, "%%HOMEDRIVE%%%s", s);
		ns = addhomedrive;
	}
	else {
		ns = s;
	}

	esize = ExpandEnvironmentStrings(ns, b, bsize);
	if (esize == 0) {
		printf("%s: %d!\n", EPSTTranslate("ExpandEnvironmentStrings error occurred"), GetLastError());
		r = s;
	}
	else if (esize > bsize) {
		printf("%s\n", EPSTTranslate("ExpandEnvironmentStrings exceeded buffer size!"));
		r = s;
	}
	else {
		r = b;
	}

	return r;
}

// Perform the research operation and extract hit into provided buffer
// Return the hit buffer pointer or NULL if no result found or error
char *do_research_get_hit(char *data, char *search, size_t datasize, char *hit, size_t hitsize) {
	size_t rs, rl;

	if (data == NULL || hit == NULL) return NULL;

	if (do_research(data, search, &rs, &rl)) {
		// shouldn't happen
		if (rs >= datasize) return NULL;

		// Extract out the hit from the data
		if (rl >= (hitsize - 1)) rl = hitsize - 1;
		strncpy(hit, &data[rs], rl);
		hit[rl] = '\0';

		return hit;
	}

	return NULL;
}

char *do_list_research_get_hit(EPST_StrListItem *list, char *data, size_t datasize, char *hit, size_t hitsize) {
	char *r;

	while (list != NULL) {
		if (list->item != NULL) {
			r = do_research_get_hit(data, list->item, datasize, hit, hitsize);
			if (r != NULL) return r;
		}
		list = list->next;
	}

	return NULL;
}


static int qs_string_compare(const void *s1, const void *s2)
{
	return strcmp(*(char**)s1, *(char**)s2);
}

char *get_first_string_in_file(const char *fname) {
	errno_t err;
	FILE *fp;
	size_t sl = 0;
	char fstr[EPSTUTILS_STR_BUFFER_SIZE + 1];

	if ((err = fopen_s(&fp, fname, "r")) != 0) {
		perror(fname);
		return NULL;
	}

	if (fgets(fstr, EPSTUTILS_STR_BUFFER_SIZE, fp) != NULL) {
		sl = strlen(fstr);
		// Strip the training newline if any
		if (sl > 0 && fstr[sl - 1] == '\n') { fstr[--sl] = '\0'; }
		if (sl > 0 && fstr[sl - 1] == '\r') { fstr[--sl] = '\0'; }
	}

	fclose(fp);
	if (sl == 0) return NULL;

	return _strdup(fstr);
}

struct SigFileData {
	char *databuffer;
	size_t databuffersize;
	size_t datasize;
	size_t cur_read_loc;
};


// Create an in-memory buffer for reading signature data from files or curl download
// Mimic fgets function for string processing from the in-memory "file"
// First call to the init function should be set large enough so subsequent calls
// do not need to realloc memory.
static struct SigFileData epst_sigdata = { NULL, 0, 0, 0 };

static BOOL realloc_epst_sigdata(size_t newsize) {
	char *ptr;

	if (epst_sigdata.databuffer == NULL) 
		return init_epst_sigdata(newsize);

	// Not going to resize smaller
	if (newsize <= epst_sigdata.databuffersize)
		return TRUE;

	ptr = realloc(epst_sigdata.databuffer, newsize);
	if (ptr == NULL) {
		printf("ERROR: Could not realloc signature data buffer.\n");
		return FALSE;
	}
	epst_sigdata.databuffer = ptr;
	epst_sigdata.databuffersize = newsize;
	return TRUE;
}

BOOL init_epst_sigdata(size_t initial_size) {
	epst_sigdata.cur_read_loc = 0;
	epst_sigdata.datasize = 0;

	if (epst_sigdata.databuffer == NULL) {
		epst_sigdata.databuffer = malloc(initial_size);
		if (epst_sigdata.databuffer == NULL) {
			epst_sigdata.databuffersize = 0;
			return FALSE;
		}
		epst_sigdata.databuffersize = initial_size;
		epst_sigdata.databuffer[0] = '\0';
	}
	else if (epst_sigdata.databuffersize < initial_size) {
		return realloc_epst_sigdata(initial_size);
	}
	return TRUE;
}

void restart_epst_sigdata() {
	epst_sigdata.cur_read_loc = 0;
}

void free_epst_sigdata() {
	if (epst_sigdata.databuffer != NULL) {
		free(epst_sigdata.databuffer);
	}
	epst_sigdata.cur_read_loc = 0;
	epst_sigdata.datasize = 0;
	epst_sigdata.databuffer = NULL;
	epst_sigdata.databuffersize = 0;
}

static size_t append_epst_sigdata(void *ptr, size_t size, size_t nmemb, void *uptr) {
	size_t nbytes = size * nmemb;

	if ((epst_sigdata.datasize + nbytes + 1) >= epst_sigdata.databuffersize) {
		size_t newsize = epst_sigdata.datasize + nbytes + 2048;
		if (!realloc_epst_sigdata(newsize)) return 0;
	}

	memcpy(&(epst_sigdata.databuffer[epst_sigdata.datasize]), ptr, nbytes);
	epst_sigdata.datasize += nbytes;
	epst_sigdata.databuffer[epst_sigdata.datasize] = '\0';
	return nbytes;
}

char *get_epst_sigdata_string() {
	return epst_sigdata.databuffer;
}

static char *gets_epst_sigdata(char *buf, size_t bsize) {
	size_t i = 0;

	if (epst_sigdata.cur_read_loc >= epst_sigdata.datasize) return NULL;
	if (epst_sigdata.cur_read_loc >= epst_sigdata.databuffersize) return NULL;
	if (bsize < 2) return NULL;

	while (i < (bsize-1) ) {
		if (epst_sigdata.cur_read_loc >= epst_sigdata.datasize) break;
		if (epst_sigdata.cur_read_loc >= epst_sigdata.databuffersize) break;

		buf[i++] = epst_sigdata.databuffer[epst_sigdata.cur_read_loc++];
		if (buf[i - 1] == '\n') break;
	}

	// Strip off the newline - different from fgets but don't want them
	if (i > 1 && buf[i - 1] == '\n') i--;
	if (i > 1 && buf[i - 1] == '\r') i--;
	buf[i] = '\0';

	return buf;
}

size_t append_local_signature_data(char *fname) {
	char *s, *e;
	char header[100];
	size_t hl, dl;

	if (fname == NULL) return 0;
	if (local_sig_buffer == NULL || local_sig_buffer_size < 5) return 0;

	// Isolate the filename from the path
	s = strrchr(fname, DIR_SEP);
	if (s == NULL) s = fname;
	else s++;

	sprintf(header, "===> %s", s);
	hl = strlen(header);

	s = strstr(local_sig_buffer, header);
	if (s == NULL) return 0;

	s += hl;
	e = strstr(s, "===>");
	if (e == NULL) e = &local_sig_buffer[local_sig_buffer_size];
	dl = e - s;
	
	append_epst_sigdata("\n", 1, 1, NULL);
	append_epst_sigdata(s, 1, dl, NULL);
	return dl;
}


static BOOL load_epst_sig_file_data(char *fname) {
	FILE *fp;
	size_t fsize;
	errno_t err;
	size_t dr;

	epst_sigdata.cur_read_loc = 0;
	epst_sigdata.datasize = 0;

	if ((err = fopen_s(&fp, fname, "rb")) != 0) {
		perror(EPSTTranslate("Read File Data Warning"));
		return FALSE;
	}

	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (fsize <= 1) {
		printf("%s, Filesize = 0\n", fname);
		fclose(fp);
		return FALSE;
	}

	if (!init_epst_sigdata(fsize+2048)) {
		fclose(fp);
		return FALSE;
	}

	dr = fread(epst_sigdata.databuffer, sizeof(unsigned char), fsize, fp);
	if (dr != fsize) {
		perror(EPSTTranslate("Read File Data Size Difference"));
	}
	epst_sigdata.datasize = dr;
	epst_sigdata.databuffer[dr] = '\0';

	fclose(fp);
	return TRUE;
}

// Version of signature load intended to read from memory instead of a file
// It will attempt to realloc memory to store the data on the fly.
char **load_signature_list_from_data(int *nstrs, BOOL expenv, EPST_StrListItem **research) {
	long size;
	int cnt;
	size_t sl;
	char fstr[EPSTUTILS_STR_BUFFER_SIZE + 1];
	char **str_array, **new_ptr;
	char ebuf[2048];

	// Set initial size based on the hint passed in
	size = *nstrs;
	*nstrs = 0;

	// Check that there is some data in the buffer
	if (epst_sigdata.datasize < 5) return NULL;

	// Check if size hint seems reasonable
	if (size < 100 || size > EPSTUTILS_MAX_DATA_LINES) size = 1000;

	str_array = (char **)malloc(sizeof(char *)*(size + 1));
	if (str_array == NULL) {
		return NULL;
	}

	cnt = 0;
	while (gets_epst_sigdata(fstr, EPSTUTILS_STR_BUFFER_SIZE) != NULL) {
		char *s, *d;
		sl = strlen(fstr);

		// Trailing newline already stripped
		if (sl == 0) continue;

		// Ignore comment lines - may contain copyright message
		// Unfortunately found a file name in signature starting with #
		if (fstr[0] == '#') continue;

		d = fstr;
		if (expenv == TRUE) {
			d = check_expand_variables(d, ebuf, 2047);
			sl = strlen(d);
		}

		if (research != NULL && d[0] == '*' && sl > 3) {
			if (!epst_test_regex(regex_test_buffer, regex_test_buffer_size, &d[1]))
				continue;

			add_epst_strlistitem(research, &d[1]);
			continue;
		}

		s = (char *)malloc(sizeof(char)*(sl + 1));
		if (s == NULL) {
			// Running out of memory?
			break;
		}

		memcpy(s, d, sizeof(char)*(sl + 1));
		str_array[cnt++] = s;

		if (cnt >= size) {
			// Need to increase the array size
			size += 1024;
			new_ptr = (char **)realloc(str_array, sizeof(char *)*(size + 1));
			if (new_ptr == NULL) {
				// Running out of memory?
				// Keep what was already read in
				fprintf(stderr, "%s\n", EPSTTranslate("Signature List Read Realloc Failed - continuing"));
				break;
			}
			else {
				str_array = new_ptr;
			}
		}
	}

	if (cnt == 0 && str_array != NULL) {
		free(str_array);
		str_array = NULL;
	}
	*nstrs = cnt;

	// Sort the array to support binary search
	if (cnt > 0 && str_array != NULL) {
		qsort((void *)str_array, (size_t)cnt, sizeof(char *), qs_string_compare);
	}

	if (regex_test_buffer != NULL && research != NULL && *research != NULL) {
		printf("\n%s\n", EPSTTranslate("Validated Regex Signatures"));
		printf("============================\n");
		dump_epst_strlistitems(*research);
		printf("\n");
	}

	return str_array;
}

// Changing file load to use the in-memory version - file will be read into memory
char **load_signature_list_from_file(char *fname, int *nstrs, BOOL expenv, EPST_StrListItem **research) {
	load_epst_sig_file_data(fname); // Next function handles lack of data due to file read issues
	append_local_signature_data(fname);
	return load_signature_list_from_data(nstrs, expenv, research);
}

// Old version of signature load based on reading file line by line vs in-memory
char **file_load_signature_list_from_file(char *fname, int *nstrs, BOOL expenv, EPST_StrListItem **research) {
	long size;
	int cnt;
	size_t sl;
	errno_t err;
	FILE *fp;
	char fstr[EPSTUTILS_STR_BUFFER_SIZE + 1];
	char **str_array, **new_ptr;
	char ebuf[2048];

	if ((err = fopen_s(&fp, fname, "r")) != 0) {
		perror(fname);
		return NULL;
	}

	// Set initial size based on the hint passed in
	size = *nstrs;
	*nstrs = 0;

	// Check if size hint seems reasonable
	if (size < 100 || size > EPSTUTILS_MAX_DATA_LINES) size = 1000;

	str_array = (char **)malloc(sizeof(char *)*(size + 1));
	if (str_array == NULL) {
		fclose(fp);
		return NULL;
	}

	cnt = 0;
	while (fgets(fstr, EPSTUTILS_STR_BUFFER_SIZE, fp) != NULL) {
		char *s, *d;
		sl = strlen(fstr);
		// Strip the training newline if any
		if (sl > 0 && fstr[sl - 1] == '\n') { fstr[--sl] = '\0'; }
		if (sl > 0 && fstr[sl - 1] == '\r') { fstr[--sl] = '\0'; }

		if (sl == 0) continue;

		// Ignore comment lines - may contain copyright message
		// Unfortunately found a file name in signature starting with #
		if (fstr[0] == '#') continue;

		d = fstr;
		if (expenv == TRUE) {
			d = check_expand_variables(d, ebuf, 2047);
			sl = strlen(d);
		}

		if (research != NULL && d[0] == '*' && sl > 3) {
			if (!epst_test_regex(regex_test_buffer, regex_test_buffer_size, &d[1]))
				continue;

			add_epst_strlistitem(research, &d[1]);
			continue;
		}

		s = (char *)malloc(sizeof(char)*(sl + 1));
		if (s == NULL) {
			// Running out of memory?
			break;
		}

		memcpy(s, d, sizeof(char)*(sl + 1));
		str_array[cnt++] = s;

		if (cnt >= size) {
			// Need to increase the array size
			size += 1024;
			new_ptr = (char **)realloc(str_array, sizeof(char *)*(size + 1));
			if (new_ptr == NULL) {
				// Running out of memory?
				// Keep what was already read in
				fprintf(stderr, "%s\n", EPSTTranslate("Signature List Read Realloc Failed - continuing"));
				break;
			}
			else {
				str_array = new_ptr;
			}
		}
	}

	fclose(fp);

	if (cnt == 0 && str_array != NULL) {
		free(str_array);
		str_array = NULL;
	}
	*nstrs = cnt;

	// Sort the array to support binary search
	qsort((void *)str_array, (size_t)cnt, sizeof(char *), qs_string_compare);

	if (regex_test_buffer != NULL && research != NULL && *research != NULL) {
		printf("\n%s\n", EPSTTranslate("Validated Regex Signatures"));
		printf("============================\n");
		dump_epst_strlistitems(*research);
		printf("\n");
	}

	return str_array;
}


void free_signature_list(char ***str_array, int *cnt) {
	char **sa;
	int i=0;

	sa = *str_array;
	if (*cnt == 0 || sa == NULL) return;

	for (i = 0; i < (*cnt); i++) {
		char *p;
		if ((p = sa[i]) != NULL) {
			free(p);
		}
	}
	free(sa);
	*str_array = NULL;
	*cnt = 0;
}

// Special string based search of signatures in log event and history data
char *search_with_signature_list(char **signatures, int cnt, char *sample) {
	int i;
	if (signatures == NULL || sample == NULL) return NULL;

	for (i = 0; i < cnt; i++) {
		if (strstr(sample, signatures[i])) {
			return signatures[i];
		}
	}
	return NULL;
}

int bisearch_signature_list(char **signatures, int size, char *sample) {
	int right, left, middle,rc;

	left = 0;
	right = size - 1;
	while (left <= right) {
		middle = (left + right) / 2;
		rc = strcmp(signatures[middle], sample);
		if (rc == 0) return middle;
		if (rc < 0) { left = middle + 1; }
		else { right = middle - 1; }
	}

	// Signature not found
	return -1;
}

void dump_signature_list(char *fname, char **str_array, int cnt) {
	int i=0;
	printf("Data List from %s: %d\n", fname,cnt);
	printf("------------------------------------------\n");
	if (cnt > 0 && str_array != NULL) {
		for (i = 0; i < cnt; i++) {
			if (str_array[i] != NULL) {
				printf("%s\n",str_array[i]);
			}
		}
	}
	printf("===========================================\n");
}

BOOL add_epst_event_signature(EPST_EventSignature **list, int scan_type, char *signature) {
	EPST_EventSignature *current;
	char *sig = NULL;

	// Allows input signature to be NULL value
	if (signature != NULL) {
		sig = _strdup(signature);
		if (sig == NULL) return FALSE;
	}

	current = malloc(sizeof(EPST_EventSignature));
	if (current == NULL) {
		if (sig != NULL) free(sig);
		return FALSE;
	}

	current->next = *list;
	current->scan_type = scan_type;
	current->signature = sig;
	*list = current;
	return TRUE;
}

BOOL add_epst_strlistitem(EPST_StrListItem **list, char *str) {
	EPST_StrListItem *current;
	char *item = NULL;

	if (str == NULL) return FALSE;

	item = _strdup(str);
	if (item == NULL) return FALSE;

	current = malloc(sizeof(EPST_StrListItem));
	if (current == NULL) {
		if (item != NULL) free(item);
		return FALSE;
	}

	current->next = *list;
	current->item = item;
	*list = current;
	return TRUE;
}

void dump_epst_event_signatures(EPST_EventSignature *list, int eventid) {
	char *sc;

	while (list != NULL) {
		switch (list->scan_type) {
		case EPST_SCAN_RKEYS:	sc = "SCAN_RKEYS "; break;
		case EPST_SCAN_DNS:		sc = "SCAN_DNS   "; break;
		case EPST_SCAN_URL:		sc = "SCAN_URL   "; break;
		case EPST_SCAN_IPS:		sc = "SCAN_IPS   "; break;
		case EPST_SCAN_FNAMES:	sc = "SCAN_FNAMES"; break;
		case EPST_SCAN_MUTEX:	sc = "SCAN_MUTEX "; break;
		default:				sc = "SCAN_REGEX "; break;
		}
		char *s = list->signature;
		printf("EVT#%6d  %s %s\n", eventid, sc, (s != NULL ? s : ""));
		list = list->next;
	}
}

void dump_epst_strlistitems(EPST_StrListItem *list) {
	while (list != NULL) {
		char *s = list->item;
		printf("%s\n", (s != NULL ? s : ""));
		list = list->next;
	}
}

int count_epst_strlistitems(EPST_StrListItem *list) {
	int count = 0;
	while (list != NULL) {
		count++;
		list = list->next;
	}
	return count;
}

BOOL epst_strlistitem_exists(EPST_StrListItem *list, char *item) {
	if (item == NULL) return FALSE;

	while (list != NULL) {
		if (list->item != NULL) {
			if (!strcmp(list->item, item)) return TRUE;
		}
		list = list->next;
	}
	return FALSE;
}

void free_epst_event_signatures(EPST_EventSignature **list) {
	EPST_EventSignature *next, *current;

	current = *list;
	while (current != NULL) {
		next = current->next;
		if (current->signature) {
			free(current->signature);
			current->signature = NULL;
		}
		free(current);
		current = next;
	}
	*list = NULL;
}

void free_epst_strlistitems(EPST_StrListItem **list) {
	EPST_StrListItem *next, *current;

	current = *list;
	while (current != NULL) {
		next = current->next;
		if (current->item) {
			free(current->item);
			current->item = NULL;
		}
		current->next = NULL;
		free(current);
		current = next;
	}
	*list = NULL;
}

#if defined(_WIN32)
static BOOL checkUseFrenchTranslateData() {
	WCHAR lang[LOCALE_NAME_MAX_LENGTH];
	char *langenv;
	BOOL isFrench = FALSE;

	langenv = getenv("LANG");

	if (langenv != NULL && (!strcmp(langenv, "French") || !strcmp(langenv, "fr-CA"))) {
		isFrench = TRUE;
	}
	else {
		GetUserDefaultLocaleName(lang, LOCALE_NAME_MAX_LENGTH);
		if (!lstrcmpW(lang, L"fr-CA")) {
			printf("LANG=%ws\n", lang);
			isFrench = TRUE;
		}
		else {
			// If not English, print language setting
			if (wcsncmp(lang, L"en-", 3)) {
				printf("LANG=%ws\n", lang);
			}
		}
	}

	if (isFrench) {
		SetConsoleOutputCP(1252);
	}

	return isFrench;
}
#else
static BOOL checkUseFrenchTranslateData() {
	char *langenv;
	BOOL isFrench = FALSE;

	langenv = getenv("LANG");
	if (langenv != NULL && (!strcmp(langenv, "French") || !strncmp(langenv, "fr-CA",5))) {
		isFrench = TRUE;
	}

	langenv = getenv("EPST_LANG"); // Primarily for testing
	if (langenv != NULL && (!strcmp(langenv, "French") || !strcmp(langenv, "fr-CA"))) {
		isFrench = TRUE;
	}

	return isFrench;
}
#endif


static EPST_Translate *translate_data = NULL;

void free_translate_data() {
	EPST_Translate *next, *current;

	current = translate_data;
	while (current != NULL) {
		next = current->next;
		if (current->english) {
			free(current->english);
			current->english = NULL;
		}
		if (current->translation) {
			free(current->translation);
			current->translation = NULL;
		}
		current->next = NULL;
		free(current);
		current = next;
	}
	translate_data = NULL;
}

static BOOL add_translate_data(char *english, char *translation) {
	EPST_Translate *current;
	char *e = NULL;
	char *t = NULL;

	if (english == NULL || translation == NULL) return FALSE;
	if (strlen(english) == 0 || strlen(translation) == 0) return FALSE;

	e = _strdup(english);
	if (e == NULL) return FALSE;

	t = _strdup(translation);
	if (t == NULL) {
		free(e);
		return FALSE;
	}

	current = malloc(sizeof(EPST_Translate));
	if (current == NULL) {
		free(e);
		free(t);
		return FALSE;
	}

	current->next = translate_data;
	current->english = e;
	current->translation = t;
	translate_data = current;
	return TRUE;
}

int split_add_translate_data_line(char *line) {
	char *s;
	BOOL rc;

	if (line == NULL) return FALSE;

	s = strchr(line, '@');
	if (s == NULL) return FALSE;

	*s = '\0';
	rc = add_translate_data(line, s + 1);
	*s = '@';
	return rc;
}

void dump_all_translate_data() {
	EPST_Translate *next = translate_data;

	printf("---------------------------------------\n");
	while (next != NULL) {
		printf("E: %s\nT: %s\n", next->english, next->translation);
		next = next->next;
	}
	printf("=======================================\n\n");
}

static void load_translate_data_file(char *fname) {
	size_t sl;
	errno_t err;
	FILE *fp;
	char fstr[EPSTUTILS_STR_BUFFER_SIZE + 1];

	if ((err = fopen_s(&fp, fname, "r")) != 0) {
		perror(fname);
		return;
	}

	while (fgets(fstr, EPSTUTILS_STR_BUFFER_SIZE, fp) != NULL) {
		sl = strlen(fstr);
		// Strip the training newline if any
		if (sl > 0 && fstr[sl - 1] == '\n') { fstr[--sl] = '\0'; }
		if (sl > 0 && fstr[sl - 1] == '\r') { fstr[--sl] = '\0'; }

		if (sl == 0) continue;

		// Ignore comment lines - may contain copyright message
		if (fstr[0] == '#') continue;

		split_add_translate_data_line(fstr);
	}

	fclose(fp);
}

const char *EPSTTranslate(const char *english) {
	EPST_Translate *next = translate_data;
	char *e,*t;

	while (next != NULL) {
		e = next->english;
		if (e != NULL && !strcmp(e,english)) {
			t = next->translation;
			if (t != NULL) return t;
		}
		next = next->next;
	}

	return english;
}

void init_translate_data() {
	char *fname = "french.txt";

	if (checkUseFrenchTranslateData() == TRUE) {
		if (fexists(fname)) {
			load_translate_data_file(fname);
		}

		// If the translation file doesn't exist or can't be read properly use default
		if (translate_data == NULL) {
			use_default_translate_data();
		}
	}

	// dump_all_translate_data();
}

void dump_all_epst_event_signatures(EPST_EventSignature **list, int max_id) {
	int i;
	for (i = 0; i < max_id; i++) {
		dump_epst_event_signatures(list[i],i);
	}
}

void init_regex_test_buffer(char *rtest_fname) {

	if (regex_test_buffer_size > 0) return;

	// Allocates a buffer file size + 1 to null terminate
	if (fexists(rtest_fname)) {
		regex_test_buffer = (char *)read_file_data(rtest_fname, &regex_test_buffer_size);
		if (regex_test_buffer != NULL) {
			regex_test_buffer[regex_test_buffer_size] = '\0';
		}
		else {
			regex_test_buffer_size = 0;
		}
	}
}

void free_regex_test_buffer() {
	if (regex_test_buffer != NULL) {
		free(regex_test_buffer);
	}
	regex_test_buffer = NULL;
	regex_test_buffer_size = 0;
}


void init_local_sig_buffer(char *localsig_fname) {

	if (local_sig_buffer_size > 0) return;

	// Allocates a buffer file size + 1 to null terminate
	if (fexists(localsig_fname)) {
		local_sig_buffer = (char *)read_file_data(localsig_fname, &local_sig_buffer_size);
		if (local_sig_buffer != NULL) {
			local_sig_buffer[local_sig_buffer_size] = '\0';
		}
		else {
			local_sig_buffer_size = 0;
		}
	}
}

void free_local_sig_buffer() {
	if (local_sig_buffer != NULL) {
		free(local_sig_buffer);
	}
	local_sig_buffer = NULL;
	local_sig_buffer_size = 0;
}

void load_event_signatures_from_data(EPST_EventSignature **list, int max_id, int *sigcount) {
	size_t sl;
	char fstr[EPSTUTILS_STR_BUFFER_SIZE + 1];
	int event_id, scan_type;
	char *n, *r;
	BOOL rc;

	*sigcount = 0;
	while (gets_epst_sigdata(fstr, EPSTUTILS_STR_BUFFER_SIZE) != NULL) {
		sl = strlen(fstr);
		if (sl == 0) continue;

		// Ignore comment lines - may contain copyright message
		if (fstr[0] == '#') continue;

		// Extract the Event ID
		n = fstr;
		while (isspace((unsigned char)(*n))) n++;
		if (*n == '\0') continue;
		if (!isdigit((unsigned char)(*n))) continue;

		// Jump over the digits to the regular expression
		r = n;
		while (isdigit((unsigned char)(*r))) r++;
		if (*r != '\0') *r++ = '\0';				// Assume a space, comma or blank
		while (isspace((unsigned char)(*r))) r++;	// Trim leading but not trailing space

		// A few simple sanity checks on the number string
		sl = strlen(n);
		if (sl == 0 || sl > 5) continue;
		event_id = atoi(n); // Sanitized string so no tricky situations
		if (event_id < 0 || event_id >= max_id) continue;

		// Check for special types of scan flags
		if (strstr(r, "SCAN_RKEYS")) {
			scan_type = EPST_SCAN_RKEYS;
		} else if (strstr(r, "SCAN_DNS")) {
			scan_type = EPST_SCAN_DNS;
		} else if (strstr(r, "SCAN_URL")) {
			scan_type = EPST_SCAN_URL;
		} else if (strstr(r, "SCAN_IPS")) {
			scan_type = EPST_SCAN_IPS;
		} else if (strstr(r, "SCAN_FNAMES")) {
			scan_type = EPST_SCAN_FNAMES;
		} else if (strstr(r, "SCAN_MUTEX")) {
			scan_type = EPST_SCAN_MUTEX;
		} else {
			scan_type = EPST_SCAN_REGEX;
		}

		// If regex scan and null string only the event id is flagged
		if (scan_type > 0 || *r == '\0') {
			r = NULL;
		}

		// Test the regex expression and ignore if it has any error
		// If the buffer has content, a search will be performed
		// with results if any sent to the console.
		if (scan_type == EPST_SCAN_REGEX && r != NULL ) {
			if (!epst_test_regex(regex_test_buffer, regex_test_buffer_size, r)) 
				continue;
		}
		rc = add_epst_event_signature(&list[event_id], scan_type, r);
		if (rc == TRUE) (*sigcount)++;
	}

	if (regex_test_buffer != NULL) {
		printf("\n%s\n", EPSTTranslate("Validated Event Signatures"));
		printf("============================\n");
		dump_all_epst_event_signatures(list, max_id);
	}
}

void load_event_signatures_from_file(EPST_EventSignature **list, int max_id, char *fname, int *sigcount) {
	load_epst_sig_file_data(fname);
	append_local_signature_data(fname);
	load_event_signatures_from_data(list, max_id, sigcount);
}

// Create a filtered list of regex strings to match the command label
// Also filter out the signature scan codes into a separate list
// Return the command without the label or NULL if no search items or error
char *filter_syscmd_research(char *cmd, EPST_StrListItem *research, EPST_StrListItem **fregex, EPST_StrListItem **fsigcode) {
	char doall[4], dosome[MAX_SYSCMD_CODE_SIZE+3];
	char *excmd, *r;
	size_t cl;

	if (cmd == NULL) return NULL;

	// Extract out the command from its label
	excmd = strchr(cmd, ',');
	if (excmd == NULL) return NULL;

	cl = strlen(excmd+1);
	if (cl <= 2) return NULL;

	// Extract out the command label, create regex labels
	*excmd = '\0';
	cl = strlen(cmd);
	if (cl < 2) return NULL;
	if (cl > MAX_SYSCMD_CODE_SIZE) cl = MAX_SYSCMD_CODE_SIZE;
	strncpy(dosome, cmd, cl);
	*excmd++ = ',';

	dosome[cl++] = ',';
	dosome[cl] = '\0';
	dosome[1] = 'R';

	doall[0] = cmd[0];
	doall[1] = 'R';
	doall[2] = ',';
	doall[3] = '\0';

	while (research != NULL) {
		if (research->item != NULL) {
			r = NULL;
			if (!strncmp(research->item, doall, 3)) {
				r = &(research->item[3]);
			} else if (!strncmp(research->item, dosome,cl)) {
				r = &(research->item[cl]);
			}

			if (r != NULL) {
				// Note prefix removal
				if (!strncmp(r, "SCAN_", 5)) { add_epst_strlistitem(fsigcode, r+5); }
				else						 { add_epst_strlistitem(fregex, r); }
			}
		}
		research = research->next;
	}

	// If no search strings found, don't bother running the cmd
	if ((count_epst_strlistitems(*fregex) == 0) && (count_epst_strlistitems(*fsigcode) == 0))
		return NULL;

	return excmd;
}


void load_syscmd_signatures_from_data(EPST_StrListItem **cmds, EPST_StrListItem **research) {
	size_t sl,cl;
	char fstr[EPSTUTILS_STR_BUFFER_SIZE + 1];
	char *c, *r, *sep;

	while (gets_epst_sigdata(fstr, EPSTUTILS_STR_BUFFER_SIZE) != NULL) {
		sl = strlen(fstr);
		if (sl == 0) continue;

		// Ignore comment lines - may contain copyright message
		if (fstr[0] == '#') continue;

		c = NULL;
		r = NULL;

		// Must have a comma separator
		sep = strchr(fstr, ',');
		if (sep != NULL) cl = strlen(++sep);
		else cl = 0;

		// Handle some platform specific commands and regex strings
		if (cl > 2 && (sl - cl) < (MAX_SYSCMD_CODE_SIZE-1)) {
#if defined(_WIN32)
			if (!strncmp(fstr, "WC", 2)) { c = fstr; }
			if (!strncmp(fstr, "WR", 2)) { r = fstr; }
#endif

#if defined(__APPLE__)
			if (!strncmp(fstr, "MC", 2)) { c = fstr; }
			if (!strncmp(fstr, "MR", 2)) { r = fstr; }
#endif

#if defined(__linux__)
			if (!strncmp(fstr, "LC", 2)) { c = fstr; }
			if (!strncmp(fstr, "LR", 2)) { r = fstr; }
#endif
		}

		// Test the regex expression and ignore if it has any error
		// If the buffer has content, a search will be performed
		// with results if any sent to the console.
		if (r != NULL) {
			if (!epst_test_regex(regex_test_buffer, regex_test_buffer_size, sep))
				continue;
			add_epst_strlistitem(research, r);
		}

		if (c != NULL) {
			// No testing on quality of command - assuming it is good
			add_epst_strlistitem(cmds, c);
		}
	}

	if (regex_test_buffer != NULL) {
		printf("\n%s\n", EPSTTranslate("System Commands to Run"));
		printf("============================\n");
		dump_epst_strlistitems(*cmds);

		printf("\n%s\n", EPSTTranslate("Output Search Signatures"));
		printf("============================\n");
		dump_epst_strlistitems(*research);
		printf("\n\n");
	}
}

void load_syscmd_signatures_from_file(char *fname, EPST_StrListItem **cmds, EPST_StrListItem **research) {
	load_epst_sig_file_data(fname);
	append_local_signature_data(fname);
	load_syscmd_signatures_from_data(cmds, research);
}

BOOL fname_has_extension(const char*fname, const char *ext) {
	char *lext;

	if (fname == NULL) return FALSE;

	lext = strrchr(fname, '.');
	if (lext == NULL) return FALSE;

	if (!strcmp(lext, ext)) return TRUE;
	return FALSE;
}

BOOL is_win_event_file(const char *fname) {

	if (fname_has_extension(fname,".evtx")) {
		if (!fexists(fname)) return FALSE;

		// Unfortunately almost all the evtx files are locked
		// so can't perform any useful checks. Add based on ext
		// and handle the results returned by wevtutil
		return TRUE;

		//char hbuf[20];
		//unsigned long ths;
		//long fsize;

		// check if effectively empty file < 68Kb
		//fsize = seek_file_size(fname);
		//if (fsize < 70000L) return FALSE;

		//ths = 7;
		//memset(hbuf, 0, sizeof(hbuf));
		//unsigned long rhs = read_file_header(fname, ths, hbuf);
		//if (rhs == ths && !strncmp(hbuf, "ElfFile", ths)) return TRUE;
		//return FALSE;
	}
	if (fname_has_extension(fname, ".evt")) {
		// What special checks are useful for older EVT files?
		// May have same issue as with the EVTX files
		return TRUE;
	}
	
	return FALSE;
}

BOOL is_history_file(char *fname) {
	char *f;
	if (fname == NULL) return FALSE;

	f = strrchr(fname, DIR_SEP);
	if (f != NULL) {
		f++;
	}
	else {
		f = fname;
	}

	if (!strcmp(f, "index.dat")) return TRUE;
	if (!strcmp(f, "History")) return TRUE;
	if (!strcmp(f, "Bookmarks")) return TRUE;
	if (!strcmp(f, "WebCacheV01.dat")) return TRUE;
	if (!strcmp(f, "Archived History")) return TRUE;
	if (!strcmp(f, "appd.dat")) return TRUE;
	if (!strcmp(f, "places.sqlite")) return TRUE;
	if (!strcmp(f, "Content.IE5index.dat")) return TRUE;
	if (!strcmp(f, "History.db")) return TRUE;
	if (!strcmp(f, "History.plist")) return TRUE;
	return FALSE;
}

#if defined(_WIN32)
// Implementation of gettimeofday from:
// http://stackoverflow.com/questions/10905892/equivalent-of-gettimeday-for-windows

struct epst_timeval {
	time_t    tv_sec;         /* seconds */
	time_t    tv_usec;        /* and microseconds */
};

int gettimeofday(struct epst_timeval * tp, struct timezone * tzp)
{
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME  system_time;
	FILETIME    file_time;
	uint64_t    time;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tp->tv_sec = (time_t)((time - EPOCH) / 10000000L);
	tp->tv_usec = (time_t)(system_time.wMilliseconds * 1000);
	return 0;
}

#else
#define epst_timeval timeval
// gettimeofday is a standard unix function

#endif

static char datetime_buffer[64];

char *getCurrentDateTime() {
	char				fmt[64];
	struct epst_timeval tv;
	struct tm			*tm;

	gettimeofday(&tv, NULL);
	
	tm = localtime(&tv.tv_sec);
	strftime(fmt, sizeof(fmt), "%Y-%m-%d %H:%M:%S.%%03u", tm);
	snprintf(datetime_buffer, sizeof(datetime_buffer), fmt, tv.tv_usec/1000);
	return datetime_buffer;
}

char *getCurrentTime() {
	char				fmt[64];
	struct epst_timeval tv;
	struct tm			*tm;

	gettimeofday(&tv, NULL);

	tm = localtime(&tv.tv_sec);
	strftime(fmt, sizeof(fmt), "%H:%M:%S.%%03u", tm);
	snprintf(datetime_buffer, sizeof(datetime_buffer), fmt, tv.tv_usec/1000);
	return datetime_buffer;
}

void check_url_hit(char *s, char *src_name);
#define MIN_URL_SIZE 12
#define MAX_URL_SIZE 300

BOOL url_strings_in_file(char *fname) {
	char sb[MAX_URL_SIZE + 2];
	int c;
	FILE *fp;
	BOOL started = FALSE;
	BOOL stop = FALSE;
	size_t sbi = 0;
	char *p[] = { "https://", "http://", "tcp://", "ftp://" };
	size_t l[] = { 8, 7, 6, 6 };
	int n = 4;

#if defined(_WIN32)
	fp = _fsopen(fname, "rb", _SH_DENYNO);
	if (fp == NULL) {
		printf("%s: %s\n", fname, EPSTTranslate("Read File Data Warning"));
		if (CopyFile(fname, ".\\EPSTTemp.dat", FALSE)) {
			fp = _fsopen(".\\EPSTTemp.dat", "rb", _SH_DENYNO);
			if (fp == NULL) {
				printf("Could not open temp file\n");
				return FALSE;
			}
		}
		else {
			printf("Could not copy %s to EPSTTemp.dat\n",fname);
			return FALSE;
		}
	}
#else
	errno_t err;
	if ((err = fopen_s(&fp, fname, "rb")) != 0) {
		perror(EPSTTranslate("Read File Data Warning"));
		return FALSE;
	}
#endif

	sb[0] = '\0';
	stop = FALSE;

	while ((c = fgetc(fp)) != EOF) {
		if (c < 32 || c > 127) stop = TRUE;

		if (stop && !started) {
			stop = FALSE;
			continue;
		}

		if (stop && started) {
			stop = FALSE;
			started = FALSE;
			sb[sbi] = '\0';
			if (sbi > MIN_URL_SIZE) check_url_hit(sb, fname);
			sbi = 0;
			sb[sbi] = '\0';
		}
		else if (started) {
			sb[sbi++] = (char)c;
			// Check if passing by another prefix
			if (sbi > MIN_URL_SIZE && sb[sbi-2] == '/' && sb[sbi-1] == '/') {
				int i;
				for (i = 0; i < n; i++) {
					size_t len = l[i];
					if (!strncmp(p[i], &sb[sbi - len], len)) {
						sb[sbi - len] = '\0';
						check_url_hit(sb, fname);
						sbi = len;
						strcpy(sb, p[i]);
						break;
					}
				}
			}

			if (sbi >= MAX_URL_SIZE) {
				sb[MAX_URL_SIZE] = '\0';
				check_url_hit(sb, fname);
				started = FALSE;
				stop = FALSE;
				sbi = 0;
				sb[sbi] = '\0';
			}
		}
		else if ((c == (int)'h') || (c == (int)'t') || (c == (int)'f')) {
			// start search for https, http, tcp or ftp prefixed url strings
			started = TRUE;
			stop = FALSE;
			sb[0] = (char)c;
			sbi = 1;
		}
	}

	fclose(fp);

	sb[sbi] = '\0';
	if (sbi > MIN_URL_SIZE) check_url_hit(sb, fname);

	return TRUE;
}

void add_default_history_files(EPST_StrListItem **list) {
	char *fn;
	int i = 0;
	char ebuf[2048];
	char *fnames[] = {
#if defined(_WIN32)
		"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Bookmarks",
		"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History",
		"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Archived History",
		"%USERPROFILE%\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\History",
		"%USERPROFILE%\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\Archived History",
		"%USERPROFILE%\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\Bookmarks",
		"%LOCALAPPDATA%\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat",
		"%LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\appd.dat",
		"%LOCALAPPDATA%\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\index.dat",
		"%LOCALAPPDATA%\\Microsoft\\Windows\\Temporary Internet Files\\Low\\Content.IE5\\index.dat",
		"%LOCALAPPDATA%\\Temp\\Low\\Temporary Internet Files\\Content.IE5\\index.dat",
		"C:\\Windows\\Cookies\\index.dat",
		"C:\\Windows\\History\\index.dat",
		"C:\\Windows\\History\\History.IE5\\index.dat",
		"C:\\Windows\\Temporary Internet Files\\index.dat",
		"C:\\Windows\\Temporary Internet Files\\Content.IE5\\index.dat",
		"C:\\Windows\\UserData\\index.dat",
		"%USERPROFILE%\\Cookies\\index.dat",
		"%USERPROFILE%\\History\\index.dat",
		"%USERPROFILE%\\History\\History.IE5\\index.dat",
		"%USERPROFILE%\\Temporary Internet Files\\index.dat",
		"%USERPROFILE%\\Temporary Internet Files\\Content.IE5\\index.dat",
		"%USERPROFILE%\\UserData\\index.dat",
		"%USERPROFILE%\\Cookies\\index.dat",
		"%USERPROFILE%\\Local Settings\\History\\History.IE5\\index.dat",
		"%USERPROFILE%\\Local Settings\\Temporary Internet Files\\Content.IE5\\index.dat",
		"%USERPROFILE%\\UserData\\index.dat",
		"%USERPROFILE%\\Roaming\\Microsoft\\Windows\\Cookies\\index.dat",
		"%USERPROFILE%\\Roaming\\Microsoft\\Windows\\Cookies\\Low\\index.dat",
		"%USERPROFILE%\\Local\\Microsoft\\Windows\\History\\History.IE5\\index.dat",
		"%USERPROFILE%\\Local\\Microsoft\\Windows\\History\\History.IE5\\Low\\index.dat",
		"%USERPROFILE%\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\index.dat",
		"%USERPROFILE%\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Low\\Content.IE5index.dat",
		"%USERPROFILE%\\Roaming\\Microsoft\\Internet Explorer\\UserData\\index.dat",
		"%USERPROFILE%\\Roaming\\Microsoft\\Internet Explorer\\UserData\\Low\\index.dat",
#else
		"%HOME%/Library/Safari/History.db",
		"%HOME%/Library/Application Support/Google/Chrome/Default/History",
		"%HOME%/Library/Application Support/Google/Chrome/Default/Bookmarks",
#endif
		NULL
	};

	while ((fn = fnames[i++]) != NULL) {
		fn = check_expand_variables(fn, ebuf, 2047);
		if (fn == NULL) continue;
		if (!fexists(fn)) continue;
		if (epst_strlistitem_exists(*list, fn)) continue;

		add_epst_strlistitem(list, fn);
	}
}

unsigned char *read_file_data(char *fname, long *fsize) {
	FILE *fp;
	unsigned char *data = NULL;
	errno_t err;
	size_t dr;

	*fsize = 0;
	if ((err = fopen_s(&fp, fname, "rb")) != 0) {
		perror(EPSTTranslate("Read File Data Warning"));
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	*fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	data = (unsigned char *)malloc(sizeof(unsigned char)*(*fsize + 1));
	if (data == NULL) return NULL;

	dr = fread(data, sizeof(unsigned char), *fsize, fp);
	if (dr != *fsize) {
		perror(EPSTTranslate("Read File Data Size Difference"));
	}

	fclose(fp);
	
	return data;
}

unsigned long read_file_header(const char *fname, long hsize, char *hbuf) {
	FILE *fp;
	errno_t err;
	size_t hs = 0;

	if ((err = fopen_s(&fp, fname, "rb")) != 0) {
		perror(EPSTTranslate("Read File Header Warning"));
		return 0;
	}

	hs = fread(hbuf, sizeof(unsigned char), hsize, fp);
	fclose(fp);

	return (unsigned long)hs;
}


long seek_file_size(const char *fname) {
	FILE *fp;
	errno_t err;
	long fsize;

	if ((err = fopen_s(&fp, fname, "rb")) != 0) {
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fclose(fp);
	return fsize;
}

#if defined(_WIN32)

void format_filetime_to_str(FILETIME *ft, char *buf, size_t bsize) {
	SYSTEMTIME st;
	char szLocalDate[255], szLocalTime[255];

	FileTimeToLocalFileTime(ft, ft);
	FileTimeToSystemTime(ft, &st);
	GetDateFormat(LOCALE_USER_DEFAULT, DATE_LONGDATE, &st, NULL,szLocalDate, 255);
	GetTimeFormat(LOCALE_USER_DEFAULT, 0, &st, NULL, szLocalTime, 255);
	snprintf(buf,bsize,"%s %s", szLocalDate, szLocalTime);
}

long get_fsize_from_file_attr(WIN32_FILE_ATTRIBUTE_DATA *fad) {
	LARGE_INTEGER size;
	size.HighPart = fad->nFileSizeHigh;
	size.LowPart = fad->nFileSizeLow;
	return (long)size.QuadPart;
}

// This should be the faster way but apparently might return
// data values that are out of date - WTH
long get_file_size_attr(char *fname) {
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if (!GetFileAttributesEx(fname, GetFileExInfoStandard, &fad))
		return -1;

	return get_fsize_from_file_attr(&fad);
}

#else

void format_filetime_to_str(struct timespec *ts, char *buf, size_t bsize) {
	struct tm t;
 	tzset();
	buf[0] = '\0';
	
    if (localtime_r(&(ts->tv_sec), &t) == NULL) {
        return;
    }
	
	if (!strftime(buf, bsize, "%F %T", &t)) {
		buf[0] = '\0';
		return;
	}
	snprintf(&buf[strlen(buf)], bsize, ".%09ld", ts->tv_nsec);
}


long get_fsize_from_file_attr(struct stat *fad) {
	return (long)fad->st_size;
}


long get_file_size_attr(char *fname) {
	struct stat fad;
	if (!stat(fname,&fad)) {
		perror(fname);
		return -1;
	}

	return get_fsize_from_file_attr(&fad);
}

#endif

// check if a file exists
int fexists(const char *filename)
{
	if ((_access(filename, 0)) != -1) {
		// exists
		return 1; // True
	}
	return 0;
}

void remove_epst_file(const char *fname) {
	if (fexists(fname)) {
		if (!DeleteFile(fname)) {
			perror(fname);
			printf("%s: %s\n", fname, EPSTTranslate("File could not be removed."));
		}
	}
}

// Special to ensure purging any old yara rules files
// that have caused false hits during a scan
int remove_file_and_backup(const char *fname) {
	char bfname[MAX_PATH];
	char *p;
	size_t sl;

	if (fexists(fname)) {
		if (!DeleteFile(fname)) {
			perror(fname);
			printf("%s: %s\n", fname, EPSTTranslate("Old version of file could not be removed."));
		}
	}

	strcpy(bfname, fname);
	if ((p = strrchr(bfname, '.')) != NULL) {
		strcpy(p, ".bak");
	}
	else {
		sl = strlen(bfname);
		sl = min(255 - 4, sl);
		strcpy(bfname + sl, ".bak");
	}

	if (fexists(bfname)) {
		// Need to delete this backup as well
		if (!DeleteFile(bfname)) {
			perror(bfname);
			printf("%s: %s\n", fname, EPSTTranslate("Old backup could not be removed."));
		}
	}
	return 0;
}

// Move the specified file to a .bak version if
// it exists. Only return error if the move fails.
int move_file_to_backup(const char *fname) {
	char bfname[MAX_PATH];
	char *p;
	size_t sl;

	if (!fexists(fname)) return 0;

	strcpy(bfname, fname);
	if ((p = strrchr(bfname, '.')) != NULL) {
		strcpy(p, ".bak");
	}
	else {
		sl = strlen(bfname);
		sl = min(255 - 4, sl);
		strcpy(bfname + sl, ".bak");
	}

	if (fexists(bfname)) {
		// Need to delete this backup
		if (!DeleteFile(bfname)) {
			perror(bfname);
			printf("%s: %s\n", fname, EPSTTranslate("Old backup could not be removed."));
			return 1;
		}
	}

	if (!MoveFile(fname, bfname)) {
		perror(bfname);
		printf("%s: %s\n", fname, EPSTTranslate("Existing file could not be renamed as a backup."));
		return 1;
	}
	return 0;
}

int initialize_curl() {
	CURLcode res;

	// In windows, this will initialize the winsock stuff
	res = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_global_init() failed: %s\n", curl_easy_strerror(res));
		return 1;
	}
	return 0;
}

void finalize_curl() {
	curl_global_cleanup();
}

size_t write_curl_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t written;
	written = fwrite(ptr, size, nmemb, stream);
	return written;
}

#ifdef WINXP

// WinXP does not support https links
static char *signature_download_url = "http://endpoint.cancyber.org/indicators.php?toolkey=%s&query=%s&version=%s";

// Support different URLs for uploading file data vs string data
static char *scan_results_upload_hit_url = "http://endpoint.cancyber.org/sighting.php";
static char *scan_results_upload_file_url = "http://endpoint.cancyber.org/upload.php";

#else

static char *signature_download_url = "https://tool.cancyber.org/get/indicators?toolkey=%s&query=%s&version=%s";

// Support different URLs for uploading file data vs string data
static char *scan_results_upload_hit_url = "https://tool.cancyber.org/put/sightings";
static char *scan_results_upload_file_url = "https://tool.cancyber.org/put/upload";

#endif

static int use_curl_option = 0;

static void check_curl_cert(CURL *curl) {
	char *cert_env;
	
	// Zero means not set yet so do some env checks
	if (use_curl_option == 0) {
		use_curl_option = 1; // Default assume cert path is good
		cert_env = getenv("CURL_CA_BUNDLE");
		if (cert_env) {
			// Assume it's good, use as is
			printf("CURL_CA_BUNDLE = %s\n",cert_env);
			use_curl_option = 2;
		}
		else if (fexists("cacert.crt")) {
			use_curl_option = 4;
			printf("%s: cacert.crt\n", EPSTTranslate("Using Packaged Cert"));
		}
#if defined(__linux__)
		else {
			// These are hardcode based on known environments
			// May need to be tweaked for different linux flavors
			if (fexists("/etc/ssl/certs/ca-certificates.crt")) {
				use_curl_option = 1; // Standard default should be good
			} else if (fexists("/etc/ssl/certs/ca-bundle.crt")) {
				use_curl_option = 3; // Need to override default
				printf("Using CA_BUNDLE at /etc/ssl/certs/ca-bundle.crt\n");
			}
		}
#endif
	}
	
	if (use_curl_option == 1) return;
	
	cert_env = "/etc/ssl/certs/ca-bundle.crt";
	if (use_curl_option == 2) cert_env = getenv("CURL_CA_BUNDLE");
	if (use_curl_option == 4) cert_env = "cacert.crt";
	curl_easy_setopt(curl, CURLOPT_CAINFO, cert_env);
}

int download_signature_data(const char *fname, const char *code, const char *apikey, const char *version) {
	char url[1024];
	CURL *curl;
	CURLcode res;
	int rc;

	// Memory should already be allocated large enough
	// This call restarts the buffer
	init_epst_sigdata(10000);

	// Not used except for potential error/warning messages
	if (fname == NULL || fname[0] == '\0') return 1;

	sprintf(url, signature_download_url, apikey, code, version);

	if ((curl = curl_easy_init()) == NULL) {
		printf("%s: %s\n", EPSTTranslate("Could not initialize curl for signature file download"), fname);
		return 1;
	}

	rc = 0;
	curl_easy_setopt(curl, CURLOPT_URL, url);
	// curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	check_curl_cert(curl);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_epst_sigdata);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
	if ((res = curl_easy_perform(curl)) != CURLE_OK) {
		// Could potentially have an auto restore from backup but
		// may not even exist and other human intervention may be
		// required anyway. Just Flag the problem.
		fprintf(stderr, "%s: %s\n", EPSTTranslate("URL failed"), curl_easy_strerror(res));
		printf("%s: %s\n", EPSTTranslate("Download error occurred for signature file"), fname);
		printf("%s\n", EPSTTranslate("Please manually restore from backup or try again later."));
		rc = 1;
	}
	curl_easy_cleanup(curl);
	return rc;
}


int download_signature_file(const char *fname, const char *code, const char *apikey, const char *version) {
	char url[1024];
	FILE *fp;
	CURL *curl;
	CURLcode res;
	errno_t err;
	int rc;

	if (fname == NULL || fname[0] == '\0') return 1;

	sprintf(url, signature_download_url, apikey, code, version);

	if ((curl = curl_easy_init()) == NULL) {
		printf("%s: %s\n", EPSTTranslate("Could not initialize curl for signature file download"), fname);
		return 1;
	}

	// Ignore the return code for the move, but open may fail too
	if (!strcmp(code, "yara") || !strcmp(code, "experimental") || !strcmp(code, "experimentals") || !strcmp(code, "yaras")) {
		// Special fix to remove existing yara rules files
		// because they keep generating false hits during scans
		rc = remove_file_and_backup(fname);
	}
	else {
		rc = move_file_to_backup(fname);
	}

	if ((err = fopen_s(&fp, fname, "wb")) != 0) {
		perror(fname);
		printf("%s\n", EPSTTranslate("Could not open signature file for download."));
		curl_easy_cleanup(curl);
		return 1;
	}

	rc = 0;
	curl_easy_setopt(curl, CURLOPT_URL, url);
	// curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	check_curl_cert(curl);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_curl_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
	if ((res = curl_easy_perform(curl)) != CURLE_OK) {
		// Could potentially have an auto restore from backup but
		// may not even exist and other human intervention may be
		// required anyway. Just Flag the problem.
		fprintf(stderr, "%s: %s\n", EPSTTranslate("URL failed"), curl_easy_strerror(res));
		printf("%s: %s\n", EPSTTranslate("Download error occurred for signature file"),fname);
		printf("%s\n", EPSTTranslate("Please manually restore from backup or try again later."));
		rc = 1;
	}
	curl_easy_cleanup(curl);

	fclose(fp);
	return rc;
}

int upload_scan_results_file(const char *fname, const char *apikey, const char *results_sha256) {
	struct curl_httppost *post = NULL;
	struct curl_httppost *last = NULL;
	CURL *curl;
	CURLcode res;
	int rc;

	if (fname == NULL || fname[0] == '\0') return 1;

	if (apikey == NULL || apikey[0] == '\0') {
		printf("%s\n", EPSTTranslate("No API Key available for scan results upload."));
		return 1;
	}

	if (!fexists(fname)) {
		printf("%s: %s\n", EPSTTranslate("Results file does not exist for upload"), fname);
		return 1;
	}

	if ((curl = curl_easy_init()) == NULL) {
		printf("%s: %s\n", EPSTTranslate("Could not initialize curl for upload of results file"), fname);
		return 1;
	}

	rc = 0;
	curl_easy_setopt(curl, CURLOPT_URL, scan_results_upload_file_url);
//	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	check_curl_cert(curl);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
//  curl_easy_setopt(curl, CURLOPT_EXPECT_100_TIMEOUT_MS,5000L);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "epstkey",
		CURLFORM_COPYCONTENTS, apikey,
		CURLFORM_END);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "epstfile",
		CURLFORM_COPYCONTENTS, "epstjson",
		CURLFORM_END);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "epstjsonsha256",
		CURLFORM_COPYCONTENTS, results_sha256,
		CURLFORM_END);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "files[]",
		CURLFORM_FILE, fname,
		CURLFORM_END);

	curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
	res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		fprintf(stderr, "%s: %s\n", EPSTTranslate("Scan report upload failed"), curl_easy_strerror(res));
		rc = 1;
	}

	curl_formfree(post);
	curl_easy_cleanup(curl);

	printf("\n");

	return rc;
}

// Very similar to above function but making copy so that warnings and other
// options can be tweaked easily. Also includes additional post field to flag
// the file type to the PHP upload service. Values for post_name must be synced
// with those in upload.php: epsttrace, epstjson, epstsample, detected
// MRK: Add eventhits to upload.php
int upload_scan_file(const char *fname, const char *apikey, const char *results_sha256, const char *post_name) {
	struct curl_httppost *post = NULL;
	struct curl_httppost *last = NULL;
	CURL *curl;
	CURLcode res;
	int rc;

	if (fname == NULL || fname[0] == '\0') return 1;

	if (apikey == NULL || apikey[0] == '\0') {
		printf("%s\n", EPSTTranslate("No API Key available for trace file upload."));
		return 1;
	}

	if (!fexists(fname)) {
		printf("%s: %s: %s\n", fname, EPSTTranslate("File does not exist for upload"), post_name);
		return 1;
	}

	if ((curl = curl_easy_init()) == NULL) {
		printf("%s: %s: %s\n", post_name, EPSTTranslate("Could not initialize curl for upload of file"), fname);
		return 1;
	}

	rc = 0;
	curl_easy_setopt(curl, CURLOPT_URL, scan_results_upload_file_url);
	check_curl_cert(curl);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "epstkey",
		CURLFORM_COPYCONTENTS, apikey,
		CURLFORM_END);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "epstfile",
		CURLFORM_COPYCONTENTS, post_name,
		CURLFORM_END);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "epstjsonsha256",
		CURLFORM_COPYCONTENTS, results_sha256,
		CURLFORM_END);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "files[]",
		CURLFORM_FILE, fname,
		CURLFORM_END);

	curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
	res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		fprintf(stderr, "%s: %s: %s\n", post_name, EPSTTranslate("Scan file upload failed"), curl_easy_strerror(res));
		rc = 1;
	}

	curl_formfree(post);
	curl_easy_cleanup(curl);

	printf("\n");

	return rc;
}


int upload_scan_results_hit(const char *apikey, const char *hcode, const char *value) {
	struct curl_httppost *post = NULL;
	struct curl_httppost *last = NULL;

	CURL *curl;
	CURLcode res;
	int rc;

	if (value == NULL || *value == '\0') return 1;

	if (apikey == NULL || apikey[0] == '\0') {
		printf("%s\n", EPSTTranslate("No API Key available for upload."));
		return 1;
	}

	if ((curl = curl_easy_init()) == NULL) {
		printf("%s %s.\n", EPSTTranslate("Could not initialize curl for upload of hit result"), value);
		return 1;
	}

	rc = 0;
	curl_easy_setopt(curl, CURLOPT_URL, scan_results_upload_hit_url);
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	check_curl_cert(curl);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "epstkey",
		CURLFORM_COPYCONTENTS, apikey,
		CURLFORM_END);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "hcode",
		CURLFORM_COPYCONTENTS, hcode,
		CURLFORM_END);

	curl_formadd(&post, &last,
		CURLFORM_COPYNAME, "hvalue",
		CURLFORM_COPYCONTENTS, value,
		CURLFORM_END);

	curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
	res = curl_easy_perform(curl);

	if (res != CURLE_OK) {
		fprintf(stderr, "%s: %s\n", EPSTTranslate("Scan hit value upload failed"), curl_easy_strerror(res));
		rc = 1;
	}

	printf("\n");

	curl_formfree(post);
	curl_easy_cleanup(curl);
	return rc;
}


#if defined(_WIN32)
// Return TRUE if process is member of Administrators local group
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa376389(v=vs.85).aspx

BOOL IsUserAdmin(void)
{
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;

	b = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup);

	if (b)
	{
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
		{
			b = FALSE;
		}
		FreeSid(AdministratorsGroup);
	}

	return(b);
}
#else

// https://stackoverflow.com/questions/4159910/check-if-user-is-root-in-c

int IsUserAdmin(void)
{
	uid_t uid=getuid(), euid=geteuid();
	if (uid > 0 || uid!=euid) {
	    /* We might have elevated privileges beyond that of the user who invoked
	     * the program, due to suid bit. Be very careful about trusting any data! */
		return false;
	} else {
	    return true;
	}
}
#endif

#ifdef WINXP
int CyaSSL_check_domain_name(void * ssl, const char* dn)
{
	return wolfSSL_check_domain_name(ssl, dn);
}

int CyaSSL_Init() {
	return wolfSSL_Init();
}

#endif
