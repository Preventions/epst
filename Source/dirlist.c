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
  Read in the dirlist.txt file and setup the file/directory filters.
  File should contain a list of comma separated scan code and directory
  path or file extension. Codes are S for scan, R for recursive scan,
  E for exclude. S/E can be associated with a *.[ext] value to filter
  files for/from scanning.

  Note: If any file extensions are included in the scan list, the exclude
  list will be ignored. Also, if any directory paths are included in the
  recursive list, the scan and exclude lists will only be used to effectively
  stop the recursion. If there are no recursive paths and there is at least
  one scan path, only the files in these directories will be scanned. In
  this situation, the exclude list is effectively not required. If no scan
  or recurse directories are specified, the C: drive will be added to the
  recurse list as a default. If multiple drives need to be scanned, they
  should be added to the recurse list.
*/

#include <stdio.h>


#if defined(_WIN32)
#include <Windows.h>
#else
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif


#include "dirlist.h"
#include <string.h>
#include <stdlib.h>

#include "epstutils.h"

#define DIRLIST_MAX_ITEMS 30

static char *scan_dirs[DIRLIST_MAX_ITEMS];
static char *recurse_dirs[DIRLIST_MAX_ITEMS];
static char *exclude_dirs[DIRLIST_MAX_ITEMS];

static char *scan_exts[DIRLIST_MAX_ITEMS];
static char *exclude_exts[DIRLIST_MAX_ITEMS];

static int num_scan_dirs = 0;
static int num_recurse_dirs = 0;
static int num_exclude_dirs = 0;

// Current directory item being scanned or recursed
static int current_dir = 0;

static int num_scan_exts = 0;
static int num_exclude_exts = 0;

static char *malloc_dirstr(char *s) {
	size_t sl = strlen(s)+1;
	char *ns;
#if defined(_WIN32)
	size_t min_sl = 4;
#else
	size_t min_sl = 2;
#endif

	if (sl >= min_sl) {
		ns = (char *)malloc(sizeof(char)*(sl));
		if (ns != NULL) {
			memcpy(ns, s, sl);
			return(ns);
		}
		else {
			fprintf(stderr, "%s\n", EPSTTranslate("Error: dirlist memory allocation failed!"));
			exit(EXIT_FAILURE);
		}
	}
	return NULL;
}


static int add_dirs(char scode, char *dir) {
	int data_used = 0;
	char drive;
	char *dc;
	char ebuf[2048];

	// Check if environment variables need to be expanded
	if (strchr(dir, '%')) {
		ebuf[0] = '\0';
		dir = check_expand_variables(dir, ebuf, 2047);
		if (strchr(dir, '%')) {
			printf("%s: %s\n", EPSTTranslate("WARNING: Check Expanded DirList Item"), dir);
		}
	}

	// Validate it looks like a full path windows directory
#if defined(_WIN32)
	drive = dir[0];
	if (dir[1] != ':' || !(drive >= 'C' && drive <= 'Z')) {
		return(data_used);
	}
#else
	drive = dir[0];
	if (drive != '/') {
		return(data_used);
	}
#endif
	
	dc = malloc_dirstr(dir);
	if (dc == NULL) {
		return(data_used);
	}

	if (scode == 'S' && num_scan_dirs < DIRLIST_MAX_ITEMS) {
		scan_dirs[num_scan_dirs++] = dc;
		data_used = 1;
	}
	else if (scode == 'R' && num_recurse_dirs < DIRLIST_MAX_ITEMS) {
		recurse_dirs[num_recurse_dirs++] = dc;
		data_used = 1;
	}
	else if (scode == 'E' && num_exclude_dirs < DIRLIST_MAX_ITEMS) {
		exclude_dirs[num_exclude_dirs++] = dc;
		data_used = 1;
	}

	if (!data_used) free(dc);
	return data_used;
}


static int add_exts(char scode, char *ext) {
	int data_used = 0;
	char *ec;

	if (ext[0] != '*' || ext[1] != '.' || ext[2] == '\0')
		return(data_used);

	// Don't store the *
	ec = malloc_dirstr(ext+1);
	if (ec == NULL) {
		return(data_used);
	}

	if (scode == 'E' && num_exclude_exts < DIRLIST_MAX_ITEMS) {
		exclude_exts[num_exclude_exts++] = ec;
		data_used = 1;
	}
	else if (scode == 'S' && num_scan_exts < DIRLIST_MAX_ITEMS) {
		scan_exts[num_scan_exts++] = ec;
		data_used = 1;
	}

	if (!data_used) free(ec);
	return data_used;
}

int dirlist_initialize() {
	FILE *fp;
	char fstr[DIRLIST_STR_BUFFER_SIZE+1];
	char *dir;
	size_t sl;
	errno_t err;
	size_t min_len;

	// Get the endpoint tool folder and exclude it
	char executable_path[MAX_PATH];
	
#if defined(_WIN32)
	min_len = 4;
	if (GetModuleFileName(NULL, executable_path, MAX_PATH)) {
		char *slash = strrchr(executable_path, '\\');
		if (slash != NULL) *slash = '\0';
		add_dirs('E', executable_path);
	}
#else
	min_len = 3;
	if (getcwd(executable_path, MAX_PATH) != NULL) {
		char *slash = strrchr(executable_path, '/');
		if (slash != NULL) *slash = '\0';
		add_dirs('E', executable_path);
	}
#endif
	else {
		fprintf(stderr, "%s\n", EPSTTranslate("Executable folder not added to exclude directory list!"));
	}

	if ((err = fopen_s(&fp, "dirlist.txt", "r")) != 0) {
		perror("dirlist.txt Warning");
		return DIRLIST_WARNING;
	}

	// Assumes strings in the file are within buffer size.
	// Excessively long directory names may be truncated and
	// could cause some data to be ignored. Extra spaces will
	// not be trimmed away and may cause data to be ignored.
	while (fgets(fstr, DIRLIST_STR_BUFFER_SIZE, fp) != NULL) {
		int data_used = 0;
		sl = strlen(fstr);
		// Strip the training newline if any
		if (sl > 0 && fstr[sl - 1] == '\n') { fstr[--sl] = '\0'; }
		if (sl > 0 && fstr[sl - 1] == '\r') { fstr[--sl] = '\0'; }

		// Different min_len for unix and windows due to C: vs /
		if (sl >= min_len) {
			char scode = fstr[0];
			dir = fstr + 2;
			if (fstr[1] == ',' && (scode == 'S' || scode == 'R' || scode == 'E')) {
				if (fstr[2] == '*' && fstr[3] == '.' && fstr[4] != '\0') {
					data_used = add_exts(scode, dir);
				}
				else {
					data_used = add_dirs(scode, dir);
				}
			}
		}

		if (!data_used && sl > 0) {
			fprintf(stderr, "%s: <%s>\n", EPSTTranslate("dirlist.txt data ignored"), fstr);
		}
	}
	fclose(fp);

	return 0;
}

int dirlist_filter_file(char *fname) {
	int i;
	char *lext = strrchr(fname, '.');

	// File has no extension
	if (lext == NULL) {
		if (num_scan_exts > 0)
			return(DIRLIST_EXCLUDE);
		else
			return(DIRLIST_SCAN_ONLY);
	}

	if (num_scan_exts > 0) {
		for (i = 0; i < num_scan_exts; i++) {
			if (!strcmp(scan_exts[i], lext)) return(DIRLIST_SCAN_ONLY);
		}
		return(DIRLIST_EXCLUDE);
	}
	else if (num_exclude_exts > 0) {
		for (i = 0; i < num_exclude_exts; i++) {
			if (!strcmp(exclude_exts[i], lext)) return(DIRLIST_EXCLUDE);
		}
	}

	return DIRLIST_SCAN_ONLY;
}


const int dirlist_get_scan_mode(const char *dir) {
	int i;

	if (dir == NULL) { return DIRLIST_EXCLUDE; }

	for (i = 0; i < num_exclude_dirs; i++) {
		if (!strcmp(dir, exclude_dirs[i])) { return DIRLIST_EXCLUDE; }
	}

	for (i = 0; i < num_scan_dirs; i++) {
		if (!strcmp(dir, scan_dirs[i])) { return DIRLIST_SCAN_ONLY; }
	}

	// By default all other directories are recursed
	return DIRLIST_RECURSE;
}

char *dirlist_next_dir() {
	char *dir_to_scan = NULL;

	if (current_dir > num_scan_dirs && current_dir > num_recurse_dirs) {
		// No more directories to scan including the default C drive
		return NULL;
	}

	if (num_recurse_dirs > 0) {
		if (current_dir < num_recurse_dirs) { dir_to_scan = recurse_dirs[current_dir]; }
	}
	else if (num_scan_dirs > 0) {
		if (current_dir < num_scan_dirs) { dir_to_scan = scan_dirs[current_dir]; }
	}
	else {
		// set the default drive to scan
		dir_to_scan = "C:";
	}

	current_dir++;
	return(dir_to_scan);
}


// Dump out the data read from the file for debug/testing
void dirlist_dump(FILE *fp) {
	int i;

	fprintf(fp,"Exclude Directory List (%d):\n", num_exclude_dirs);
	for (i = 0; i < num_exclude_dirs; i++) fprintf(fp, "%s\n",exclude_dirs[i]);

	fprintf(fp, "Recurse Directory List (%d):\n", num_recurse_dirs);
	for (i = 0; i < num_recurse_dirs; i++) fprintf(fp, "%s\n",recurse_dirs[i]);

	fprintf(fp, "Scan Directory List (%d):\n", num_scan_dirs);
	for (i = 0; i < num_scan_dirs; i++) fprintf(fp, "%s\n",scan_dirs[i]);

	fprintf(fp, "Exclude Extensions List (%d):\n", num_exclude_exts);
	for (i = 0; i < num_exclude_exts; i++) fprintf(fp, "%s\n",exclude_exts[i]);

	fprintf(fp, "Scan Extensions List (%d):\n", num_scan_exts);
	for (i = 0; i < num_scan_exts; i++) fprintf(fp, "%s\n",scan_exts[i]);

	return;
}


void dirlist_finalize() {
	// Free up all the memory used
	int i;

	for (i = 0; i < num_exclude_dirs; i++) free(exclude_dirs[i]);
	num_exclude_dirs = 0;

	for (i = 0; i < num_recurse_dirs; i++) free(recurse_dirs[i]);
	num_recurse_dirs = 0;

	for (i = 0; i < num_scan_dirs; i++) free(scan_dirs[i]);
	num_scan_dirs = 0;

	for (i = 0; i < num_exclude_exts; i++) free(exclude_exts[i]);
	num_exclude_exts = 0;

	for (i = 0; i < num_scan_exts; i++) free(scan_exts[i]);
	num_scan_exts = 0;

	// Could memset the arrays to zeros too but no point
	return;
}