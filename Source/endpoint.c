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

#include <stdio.h>
#include <yara.h>


#if defined(_WIN32)

#include <Windows.h>
#include <winreg.h>

#else

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <inttypes.h>

#if defined(__APPLE__)
#include <sys/proc_info.h>
#include <libproc.h>
#endif


#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>

#if defined(__APPLE__)
#include <net/if_dl.h>
#endif

#include <sys/xattr.h>

#endif


#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "dirlist.h"
#include "epstutils.h"
#include "epsthash.h"

#include "args.h"
#include "yara/rules.h"


#if !defined(_WIN32)

static void Sleep(int usec) { usleep(usec); }
#define _strdup strdup
#define _strnicmp strnicmp

static int GetUserName(char *uname, size_t *uname_len) {
	char *name = getlogin();
	if (name == NULL) return 0;
	strncpy(uname,name,*uname_len);
	return strlen(uname);
}

#endif

// Keep version and build numbers in sync

#ifdef WINXP
// XP yara version different, Keep at 1.0
#define EPST_VERSION "1.0"
#define EPST_BUILD_NUMBER "1.0XPh"
#else
#define EPST_VERSION "1.3"
#define EPST_BUILD_NUMBER "1.300a"
#endif

#define TRACE_INFO 0
#define TRACE_WARNING 1
#define TRACE_ERROR 2

// Levels of Extra Trace - additive details
// First level also includes misc info like env variables
#define XTRACE_NONE 0
#define XTRACE_DIRS 1
#define XTRACE_FILES 2
#define XTRACE_HASH 3

#define SHOW_RD_META 1
#define SHOW_RD_STRINGS 2
#define SHOW_RD_TAGS 4

#define MAX_SAMPLE_FSIZE 10000000

// Use a fixed size array to read in process IDs
#define MAX_EPST_PID_COUNT 4096

#define __ENDPOINTSCANNER_MAIN__

// Flags to enable/disable scanning features
// Must include -X option on command line to
// disable turning all scan options on by default.
// Flags start false, can be turned true with
// command line options but will be overridden
// unless explicit scan mode is flagged.
static int explicit_scan_mode = FALSE;
static int do_yarafile_scan = FALSE;
static int do_hash_scan = FALSE;
static int do_dns_scan = FALSE;
static int do_url_scan = FALSE;
static int do_ips_scan = FALSE;
static int do_pid_scan = FALSE;
static int do_fnames_scan = FALSE;
static int do_rkeys_scan = FALSE;
static int do_mutex_scan = FALSE;
static int do_experimental = FALSE;
static int do_yara_source = FALSE;
static int do_event_scan = FALSE;
static int do_syscmds_scan = FALSE; // Tied to event scan for now

static int auto_register_sightings = FALSE;

static int running_as_admin = FALSE;


// Show only rule identifier/name (0), meta (1),
// and string matches (2) and maybe tags (4)
static int show_rule_details = 7;

static int extra_trace_details = 0;
static int fast_scan = FALSE;

// Arrays of string data to be loaded from files
static char **signatures_md5 = NULL;
static char **signatures_sha1 = NULL;
static char **signatures_sha256 = NULL;
static char **signatures_dns = NULL;
static char **signatures_url = NULL;
static char **signatures_ips = NULL;
static char **signatures_fnames = NULL;
static char **signatures_rkeys = NULL;
static char **signatures_mutex = NULL;

// Windows Event ID data stored as array of linked lists of regex strings
static EPST_EventSignature **event_signatures = NULL;
static EPST_StrListItem *event_files_found = NULL;
static int max_event_id = 65000; // Arbitrary guess, allow to be set with env variable
static int *event_ids_found = NULL; // Count of unique event ids discovered

static EPST_StrListItem *fname_sig_research = NULL;
static EPST_StrListItem *dns_sig_research = NULL;
static EPST_StrListItem *url_sig_research = NULL;

static EPST_StrListItem *history_files_found = NULL;
static EPST_StrListItem *url_hits_found = NULL;

static EPST_StrListItem *syscmds_to_run = NULL;
static EPST_StrListItem *syscmds_sig_research = NULL;

static int sigcount_md5 = 0;
static int sigcount_sha1 = 0;
static int sigcount_sha256 = 0;
static int sigcount_dns = 0;
static int sigcount_url = 0;
static int sigcount_ips = 0;
static int sigcount_fnames = 0;
static int sigcount_rkeys = 0;
static int sigcount_mutex = 0;
static int sigcount_events = 0;

static int total_files_processed = 0;
static int total_pids_processed = 0;

static int skipped_directories = 0;
static int scanned_directories = 0;
static int skipped_files = 0;

static const char *skipdirmsg = "";
static const char *scandirmsg = "";
static const char *skipfilemsg = "";
static const char *scanfilemsg = "";

static int using_threads = FALSE;

// 1 File, 2 stdout, 3 both
static int trace_flags = 1;

static int trace_to_stdout = FALSE;
static int trace_to_file = TRUE;

// Options to alter default download/upload operations
static int use_local_rules = FALSE;
static int suppress_results_upload = FALSE;
static int suppress_samples_upload = FALSE;

// Command line actions - flag true to perform then exit
static int show_help = FALSE;
static int show_version = FALSE;
static int upload_results_file = FALSE;
static int download_signatures = FALSE;

// Stop the Yara rules checking of a file if it has
// been flagged as hit a number of times already
static int yara_hit_count_limit = 0;

// Timeout in seconds
static int epst_timeout = 24*60*60;
static int epst_filescan_timeout = 23*60*60;
static int scan_timeout = 90;

static int num_threads_to_use = 8;
static int stack_size = DEFAULT_STACK_SIZE;

static long scan_sleep_time = 0;

static char *host_name = NULL;
static char *local_ipv4 = NULL;
static char *local_ipv6 = NULL;
static char *physical_address = NULL;
static char *api_key = NULL;

static YR_RULES* rules = NULL;

// Signature and output file names
static char *compiled_rules_fname = "epstrules.yara";
static char *scan_results_fname = "epstresults.json";
static char *scan_trace_fname = "scantrace.txt";
static char *sig_md5_fname = "md5.txt";
static char *sig_sha1_fname = "sha1.txt";
static char *sig_sha256_fname = "sha256.txt";
static char *sig_dns_fname = "dns.txt";
static char *sig_url_fname = "url.txt";
static char *sig_ips_fname = "ips.txt";
static char *sig_fnames_fname = "fnames.txt";
static char *sig_rkeys_fname = "rkeys.txt";
static char *sig_mutex_fname = "mutex.txt";
static char *sig_events_fname = "events.txt";
static char *api_key_fname = "apikey.lic";
static char *scan_detected_files_fname = "detected.txt";
static char *eventhits_fname = "eventhits.txt";
static char *regex_test_fname = "epst_test_regex.txt";
static char *epstlocal_fname = "epstlocal.txt";

static char *scan_results_sha256 = "";

// Optimization tests are made for this value
static char *use_runtime_folder = ".";

static char *active_pids_names[MAX_EPST_PID_COUNT];
static int active_pids[MAX_EPST_PID_COUNT];
static int active_pids_count = 0;

static time_t main_start_time;

// Buffer to read file data in chunks. This buffer will
// be shared between threads so needs to be locked
// during the calculation of the hash codes.
#define FILE_DATA_BUFFER_SIZE_L 65536
#define FILE_DATA_BUFFER_SIZE_M 32768
#define FILE_DATA_BUFFER_SIZE_S 16384

static unsigned char *file_data_buffer = NULL;
static size_t file_data_buffer_size = 0;

#define DNS_BUFFER_SIZE 2000000
static size_t dns_data_size = 0;

static FILE *trace_fp = NULL;
static FILE *results_fp = NULL;
static FILE *detected_fp = NULL;
static FILE *eventhits_fp = NULL;

static int results_hit_count = 0;

static int current_hit_upload_id = 1;

static char username[256];
static DWORD username_len = 256;

// Hash and name signature hit flags for files
#define MD5_HIT 1
#define SHA1_HIT 2
#define SHA256_HIT 4
#define FNAME_HIT 8

typedef struct _SCAN_RESULTS {
	int process_number; // Process ID for memory or zero for file
	int yara_hits;
	int sig_hits;
	int hit_flags;
	char *filename; // File or process executable
	char *md5;
	char *sha1;
	char *sha256;
} SCAN_RESULTS;

typedef struct COMPILER_RESULTS
{
	int errors;
	int warnings;

} COMPILER_RESULTS;

// Declare some functions used by the modified
// Yara threading code that is inlined below

SCAN_RESULTS *perform_signature_scan(int pid, char *fname);
int process_scan_results(SCAN_RESULTS *sr);
static void add_trace_message(const int code, const char *message, const char *data);
void trace_scanner_error(int error, const char *data);
int handle_scan_hit_message(int message, YR_RULE *rule, void *data);
static void calc_report_hash();
int compile_yara_rules_data(const char *rulesdata);
int compile_yara_rules();

// Note: there are various functions defined in the *_system.h includes
void get_system_config();
int epst_load_pids_to_scan();


args_option_t options[] =
{
	OPT_BOOLEAN('X', "explicit-scan", &explicit_scan_mode,
	"turn on explicit scan mode so all are off by default"),

	OPT_BOOLEAN('R', "rules-scan", &do_yarafile_scan,
		"scan files with yara rules"),

	OPT_BOOLEAN('H', "hash-scan", &do_hash_scan,
		"hash files and check master MD5, SHA1, SHA256 hit lists"),

	OPT_BOOLEAN('U', "url-scan", &do_url_scan,
		"scan the URL cache for items in the hit list"),

	OPT_BOOLEAN('D', "dns-scan", &do_dns_scan,
		"scan the DNS cache for items in the hit list"),

	OPT_BOOLEAN('I', "IP-scan", &do_ips_scan,
		"scan active sockets and dns cache for IPs in hit list"),

	OPT_BOOLEAN('P', "process-scan", &do_pid_scan,
		"scan memory of all active processes with Yara rules"),

	OPT_BOOLEAN('N', "name-scan", &do_fnames_scan,
		"scan directory tree for file names in hit list"),

	OPT_BOOLEAN('K', "registry-scan", &do_rkeys_scan,
		"scan the registry for keys in hit list"),

	OPT_BOOLEAN('M', "mutex-scan", &do_mutex_scan,
	"scan mutex items for keys in hit list"),

	OPT_BOOLEAN('W', "win-event-scan", &do_event_scan,
	"scan event logs and command output for specific events"),

	OPT_INTEGER('T', "trace-mode", &trace_flags,
	"trace to file (1), trace to stdout (2) both (3)", "NUMBER"),

	OPT_INTEGER('y', "rule-details", &show_rule_details,
	"bit flags for basic (0), meta (1), string matches (2), tags (4)", "NUMBER"),

	OPT_INTEGER('t', "threads", &num_threads_to_use,
	"specify NUMBER of threads to use for scanning files", "NUMBER"),

	OPT_INTEGER('l', "limit-hits", &yara_hit_count_limit,
	"per file max NUMBER of matching rules to record", "NUMBER"),

	OPT_INTEGER('e', "expiry-timeout", &scan_timeout,
	"number of SECONDS before a file or process scan times out", "SECONDS"),

	OPT_INTEGER('m', "max-scantime", &epst_timeout,
	"force scanning to complete after max number of SECONDS", "SECONDS"),

	OPT_INTEGER('s', "sleep-delay", &scan_sleep_time,
	"CPU throttling number of MICROSECONDS to sleep between file scans", "MICROSECONDS"),

	OPT_STRING('r', "compiled-rules", &compiled_rules_fname,
	"specify name for a compiled Yara rules file","FILENAME"),

	OPT_STRING('O', "output-folder", &use_runtime_folder,
	"specify folder name for downloaded and generated files","FOLDER"),

	OPT_INTEGER('k', "stack-size", &stack_size,
	"set maximum stack size (default=16384)", "SLOTS"),

	OPT_BOOLEAN('f', "fast-scan", &fast_scan,
	"fast matching mode"),

	OPT_BOOLEAN('a', "auto-sight", &auto_register_sightings,
	"automatically attempt to register sightings with MISP server"),

	OPT_INTEGER('x', "extra-trace", &extra_trace_details,
	"level of extra details in the trace (0,1,2,3)","TRACE"),

	OPT_BOOLEAN('u', "upload-results", &upload_results_file,
	"upload existing results file then exit"),

	OPT_BOOLEAN('Z', "suppress-upload", &suppress_results_upload,
	"suppress default upload of results to MISP server"),

	OPT_BOOLEAN('S', "suppress-samples", &suppress_samples_upload,
	"suppress default upload of hit samples to MISP server"),

	OPT_BOOLEAN('d', "download-rules", &download_signatures,
	"download new set of rules and signatures then exit"),

	OPT_BOOLEAN('L', "local-rules", &use_local_rules,
	"use local rules and signature files already downloaded"),

	OPT_BOOLEAN('E', "experimental", &do_experimental,
	"use experimental vs normal yara rules (same filename, different download)"),

	OPT_BOOLEAN('Y', "yaradev", &do_yara_source,
	"use development vs normal yara rules"),

	OPT_BOOLEAN('v', "version", &show_version,
	"display the tool and yara version and exit"),

	OPT_BOOLEAN('h', "help", &show_help,
	"show this help and exit"),

	OPT_END()
};

// Inline a bunch of code based on how
// the Yara application handled threading
#include "epsthreads.h"

MUTEX hash_file_mutex;

static int trace_initialize() {
	int err = 0;

	if (!trace_to_file) return 0;

	// Set both trace modes on to start
	trace_to_file = TRUE;
	trace_to_stdout = TRUE;

	if (trace_flags == 0) {
		trace_to_file = FALSE;
		trace_to_stdout = FALSE;
		return 0;
	}
	if (trace_flags == 1)
		trace_to_stdout = FALSE;

	if (trace_flags == 2) {
		trace_to_file = FALSE;
		return 0;
	}

	if ((err = fopen_s(&trace_fp, scan_trace_fname, "w")) != 0) {
		perror(EPSTTranslate("Trace File Warning"));
		trace_to_file = FALSE;
		trace_fp = NULL;
		return err;
	}

	fprintf(trace_fp, "%s: %s\n", EPSTTranslate("Started"), getCurrentDateTime());
	fprintf(trace_fp, "%s %s\n", EPSTTranslate("Endpoint Scanner Version"), EPST_BUILD_NUMBER);
	fprintf(trace_fp, "%s %s\n", EPSTTranslate("YARA Library Version"), YR_VERSION);

	if (running_as_admin) { fprintf(trace_fp, "%s\n", EPSTTranslate("Running as User Admin")); }
	else				  { fprintf(trace_fp, "%s\n", EPSTTranslate("NOT Running as User Admin")); }

	if (do_experimental) {
		fprintf(trace_fp, "%s\n", EPSTTranslate("Experimental Mode Active"));
	}
	if (do_yara_source) {
		fprintf(trace_fp, "%s\n", EPSTTranslate("Yara Development Mode Active"));
	}

	fflush(trace_fp);

	return 0;
}

static void trace_finalize() {
	if (trace_fp != NULL) {
		fprintf(trace_fp, "%s: %s\n", EPSTTranslate("Finished"), getCurrentDateTime());

		fclose(trace_fp);
		trace_fp = NULL;
	}
}

// Trace handling to file, stdout and stderr
static void add_trace_message(const int code, const char *message, const char *data) {
	char buf[2048];
	char *ctrl;

	if (using_threads) mutex_lock(&output_mutex);

	if (code == TRACE_ERROR) {
		ctrl = "%s E=> %s: <%s>\n";
		snprintf(buf, 2048, ctrl, getCurrentTime(), message, data);
		fprintf(stderr, "%s",buf);
	}
	else if (trace_to_file || trace_to_stdout) {
		if (code == TRACE_WARNING)
			ctrl = "%s W=> %s: <%s>\n";
		else
			ctrl = "%s I=> %s: <%s>\n";
		snprintf(buf, 2048, ctrl, getCurrentTime(), message, data);
		if (trace_to_stdout) printf("%s",buf);
	}

	if (trace_to_file) {
		fprintf(trace_fp, "%s", buf);
		fflush(trace_fp);
	}

	if (using_threads) mutex_unlock(&output_mutex);
}

static void add_trace_message_value(const int code, const char *message, int value) {
	char buf[20];
	sprintf(buf, "%d", value);
	add_trace_message(code, message, buf);
}

// Pass in the environment variable block from main
static void trace_dump_env(const char *envp[]) {
	int i = 0;
	const char *v;

	if (!trace_to_file) return;

	add_trace_message(TRACE_INFO, "Environment Variables", "Start");
	while ((v = envp[i++]) != NULL) {
		fprintf(trace_fp, "%s\n", v);
	}
	add_trace_message(TRACE_INFO, "Environment Variables", "End");
}

static void trace_dum_dirlist() {
	if (!trace_to_file) return;

	add_trace_message(TRACE_INFO, "DirList Values", "Start");
	dirlist_dump(trace_fp);
	add_trace_message(TRACE_INFO, "DirList Values", "End");
}

void trace_scanner_error(int error, const char *data)
{
	char emsg[2048];

	switch (error)
	{
	case ERROR_SUCCESS:
		break;
	case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
		add_trace_message(TRACE_WARNING, "Could not attach to process", data);
		break;
	case ERROR_INSUFFICIENT_MEMORY:
		add_trace_message(TRACE_ERROR, "Out of memory", data);
		break;
	case ERROR_SCAN_TIMEOUT:
		add_trace_message(TRACE_WARNING, "Scanning timed out", data);
		break;
	case ERROR_COULD_NOT_OPEN_FILE:
		add_trace_message(TRACE_WARNING, "Could not open file", data);
		break;
	case ERROR_UNSUPPORTED_FILE_VERSION:
		add_trace_message(TRACE_ERROR, "Rules compiled with wrong version", data);
		break;
	case ERROR_CORRUPT_FILE:
		add_trace_message(TRACE_ERROR, "Compiled rules file corrupt", data);
		break;
	case ERROR_EXEC_STACK_OVERFLOW:
		add_trace_message(TRACE_ERROR, "Stack overflow evaluating condition", data);
		break;
	case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE:
		add_trace_message(TRACE_ERROR, "Invalid external variable type", data);
		break;
	case ERROR_WRONG_ARGUMENTS:
		add_trace_message(TRACE_WARNING, "Invalid arguments for hash function (md5, sha1, sha256 or checksum32)", data);
		break;
	default:
		sprintf(emsg, "%s %d", EPSTTranslate("Internal Error"), error);
		add_trace_message(TRACE_ERROR, emsg, data);
		break;
	}
}

static void print_scan_progress(BOOL lastOne) {
	printf("%s: %d, %s: %d    %s: %d, %s: %d", skipdirmsg, skipped_directories, scandirmsg, scanned_directories, skipfilemsg, skipped_files, scanfilemsg, total_files_processed);

	if (lastOne) printf("\n");
	else         printf("\r");
}

int initialize_eventhits() {
	int err = 0;

	if ((err = fopen_s(&eventhits_fp, eventhits_fname, "w")) != 0) {
		perror(EPSTTranslate("Event Hits Warning"));
		eventhits_fp = NULL;
		return err;
	}
	return 0;
}

static void finalize_eventhits() {
	if (eventhits_fp != NULL) {
		fclose(eventhits_fp);
		eventhits_fp = NULL;
	}

	if (!do_event_scan) return;

	// Upload the eventhits.txt file
	if (suppress_results_upload == FALSE) {
		long fsize = seek_file_size(eventhits_fname);
		if (fsize > 0) {
			printf("%s\n", EPSTTranslate("Uploading Event Hit Details"));
			upload_scan_file(eventhits_fname, api_key, scan_results_sha256, "eventhits");
		}
	}
}


static int initialize_detected_files() {
	int err = 0;

	if ((err = fopen_s(&detected_fp, scan_detected_files_fname, "w")) != 0) {
		perror(EPSTTranslate("Detected Files Warning"));
		detected_fp = NULL;
		return err;
	}
	return 0;
}

static int add_detected_file(char *fname) {
	size_t sl;

	if (detected_fp == NULL || fname == NULL) return 0;

	// Guard against buffer overflow reading later
	sl = strlen(fname);
	if (sl == 0 || sl > (2048 - 2)) return 0;

	// Calling function must do the mutex locking
	fprintf(detected_fp, "%s\n", fname);
	return 1;
}

static int finalize_detected_files() {
	int err = 0;
	char fname[2048];

	if (detected_fp != NULL) {
		fclose(detected_fp);
		detected_fp = NULL;
	}

	if (suppress_results_upload == FALSE && suppress_samples_upload == FALSE) {
		if ((err = fopen_s(&detected_fp, scan_detected_files_fname, "r")) != 0) {
			perror(EPSTTranslate("Upload Detected Files Read Warning"));
			detected_fp = NULL;
			return err;
		}
		
		printf("%s\n", EPSTTranslate("Uploading Detected Samples"));
		while (fgets(fname, 2048, detected_fp) != NULL) {
			size_t sl = strlen(fname);

			// Strip the training newline if any
			if (sl > 0 && fname[sl - 1] == '\n') { fname[--sl] = '\0'; }
			if (sl > 0 && fname[sl - 1] == '\r') { fname[--sl] = '\0'; }

			if (sl == 0) continue;

			// Check if file still exists and not too large for upload
			if (!fexists(fname)) continue;
			if (seek_file_size(fname) > MAX_SAMPLE_FSIZE) continue;
			upload_scan_file(fname, api_key, scan_results_sha256,"epstsample");
		}

		fclose(detected_fp);
		detected_fp = NULL;
		printf("%s\n", EPSTTranslate("Completed Upload of Detected Samples"));
	}

	// Upload the detected.txt file
	if (suppress_results_upload == FALSE) {
		long fsize = seek_file_size(scan_detected_files_fname);
		if (fsize > 0)
			upload_scan_file(scan_detected_files_fname, api_key, scan_results_sha256, "detected");
	}
	return 0;
}

// A few helper functions to render out some JSON data
// Do some of the possible NULL pointer error checks
// here too and ignore effectively missing data.
static int hit_json_object_cnt = 0;

void add_results_start_hit() {
	if (hit_json_object_cnt == 0) {
		fprintf(results_fp, "{");
	}
	else {
		fprintf(results_fp, ",\n{");
	}
	hit_json_object_cnt++;
}

void fp_add_json_raw_text(FILE *fp, const char *text) {
	fprintf(fp, "%s", text);
	fflush(fp);
}

void add_results_raw_text(const char *text) {
	fprintf(results_fp, "%s", text);
	fflush(results_fp);
}

// If a value pointer is NULL it may be skipped
// so need to check before adding the comma for
// the previous value
void check_add_results_comma(char *ptr) {
	if (ptr != NULL) add_results_raw_text(",\n");
}

// Required values so don't skip if NULL value
void fp_add_json_pair_ss_r(FILE *fp, const char *s1, const char *s2, const char *sep) {
	const char *v = (s2 != NULL) ? s2 : "";

	fprintf(fp, "\"%s\" : \"%s\"", s1, v);
	fprintf(fp, "%s", sep);
	fflush(fp);
}

void add_results_pair_ss_r(const char *s1, const char *s2, const char *sep) {
	fp_add_json_pair_ss_r(results_fp, s1, s2, sep);
}

void fp_add_json_pair_ss(FILE *fp,const char *s1, const char *s2, const char *sep) {
	if (s1 == NULL || s2 == NULL || sep == NULL) return;

	fprintf(fp, "\"%s\" : \"%s\"", s1,s2);
	fprintf(fp, "%s", sep);
	fflush(fp);
}

void add_results_pair_ss(const char *s1, const char *s2, const char *sep) {
	fp_add_json_pair_ss(results_fp,s1, s2, sep);
}

// Special for Windows file names but escape used by other file functions
void fp_add_json_pair_sn(FILE *fp, const char *s1, const char *s2, const char *sep) {
	char *s;
	if (s1 == NULL || s2 == NULL || sep == NULL) return;

	fprintf(fp, "\"%s\" : \"", s1);
	s = (char *)s2;
	while (*s != '\0') {
		if ((int)(*s) < 32 || (int)(*s) > 127) {
			s++;
			continue;
		}
		if (*s == '\\' || *s == '\"') {
			fprintf(fp, "\\");
		}
		fprintf(fp, "%c", (int)(*s));
		s++;
	}
	fprintf(fp, "\"%s", sep);
	fflush(fp);
}

void add_results_pair_sn(const char *s1, const char *s2, const char *sep) {
	fp_add_json_pair_sn(results_fp, s1, s2, sep);
}

void fp_add_json_pair_si(FILE *fp, const char *s1, int i, const char *sep) {
	if (s1 == NULL || sep == NULL) return;

	fprintf(fp, "\"%s\" : %d", s1, i);
	fprintf(fp, "%s", sep);
	fflush(fp);
}

void add_results_pair_si(const char *s1, int i, const char *sep) {
	fp_add_json_pair_si(results_fp, s1, i, sep);
}

void fp_add_json_pair_st(FILE *fp, const char *s, const char *t, const char *sep) {
	if (s == NULL || t == NULL || sep == NULL) return;

	fprintf(fp, "\"%s\" : %s", s, t);
	fprintf(fp, "%s", sep);
	fflush(fp);
}

void add_results_pair_st(const char *s, const char *t, const char *sep) {
	fp_add_json_pair_st(results_fp, s, t, sep);
}

void add_results_pair_sas(const char *s, const char *a[], int cnt, const char *sep) {
	int i;

	if (cnt <= 0 || s == NULL) return;

	fprintf(results_fp, "\"%s\" : [\"%s\"", s,a[0]);
	for (i = 1; i < cnt; i++) {
		fprintf(results_fp, ", \"%s\"", a[i]);
	}

	fprintf(results_fp, "]%s", sep);
	fflush(results_fp);
}

void fp_add_json_hash_triple(FILE *fp, const char *md5, const char *sha1, const char *sha256) {
	fp_add_json_pair_ss(fp, "MD5", md5, ",\n");
	fp_add_json_pair_ss(fp, "SHA1", sha1, ",\n");
	fp_add_json_pair_ss(fp, "SHA256", sha256, ",\n");
}

void add_results_yara_string(uint8_t* data, int length)
{
	int i=0;
	char* str = (char*)(data);

	for (i = 0; i < length; i++)
	{
		if (str[i] >= 32 && str[i] <= 126)
			fprintf(results_fp, "%c", str[i]);
		else
			fprintf(results_fp, "\\\\x%02X", (uint8_t)str[i]);
	}
}

static char cescapes[] =
{
	0  , 0  , 0  , 0  , 0  , 0  , 0  , 'a',
	'b', 't', 'n', 'v', 'f', 'r', 0  , 0  ,
	0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  ,
	0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  ,
};


void add_results_yara_escaped_data(uint8_t* data, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++)
	{
		switch (data[i])
		{
		case '\"':
		case '\\':
			fprintf(results_fp, "\\%c", data[i]);
			break;

		default:
			if (data[i] >= 127)
				fprintf(results_fp, "\\u%04x", data[i]);
			else if (data[i] >= 32)
				fprintf(results_fp, "%c", data[i]);
			else if (cescapes[data[i]] != 0)
				fprintf(results_fp, "\\%c", cescapes[data[i]]);
			else
				fprintf(results_fp, "\\u%04x", data[i]);
		}
	}
}

void add_results_yara_hex_string(uint8_t* data, int length)
{
	int i=0;
	int lt = min(32, length);
	for (i = 0; i < lt; i++)
		fprintf(results_fp, "%02X ", (uint8_t)data[i]);

	if (length > 32)
		fprintf(results_fp, "...");
}

// Attempt to register the sighting value with the central MISP server.
// This will not provide as much information as is stored in the JSON
// formatted results file. The system will need to have internet access.
// Output from the server if any will be spewed to stdout.
void register_sighting(const char *hcode, const char *value) {
	if (!auto_register_sightings) return;

	// This function does some error checking but
	// may need to escape the string here.
	if (using_threads) mutex_lock(&output_mutex);
	printf("%s %s : %s\n", EPSTTranslate("Sighting"), hcode, value);
	upload_scan_results_hit(api_key, hcode, value);
	if (using_threads) mutex_unlock(&output_mutex);
}



static int results_initialize() {
	int err;

	if (!GetUserName(username, &username_len)) strcpy(username, "Unknown");

	if ((err = fopen_s(&results_fp, scan_results_fname, "w")) != 0) {
		add_trace_message(TRACE_ERROR, "Results File", "Open Failed");
		perror("Results File Warning");
		results_fp = NULL;
		return err;
	}
	
	if (host_name == NULL) { host_name = _strdup("unknown"); }

	// First 8 bytes in file used to test if file valid
	add_results_raw_text("{\"EPST\":\""); 
	add_results_raw_text(EPST_BUILD_NUMBER);
	add_results_raw_text("\",\n");
	add_results_pair_ss_r("Version", EPST_VERSION, ",\n");
	add_results_pair_ss_r("Started", getCurrentDateTime(),",\n");

	// All are required but these need to be escaped so
	// using a different function but ensure non NULL
	add_results_pair_sn("User", username, ",\n");
	add_results_pair_sn("Host", host_name, ",\n");
	add_results_pair_sn("Rules", compiled_rules_fname, ",\n");
	
	add_results_pair_ss_r("APIKEY", api_key, ",\n");
	add_results_pair_ss_r("IPV4", local_ipv4, ",\n");
	add_results_pair_ss_r("IPV6", local_ipv6, ",\n");
	add_results_pair_ss_r("MAC", physical_address, ",\n");
	add_results_raw_text("\"HitData\" : [\n");

	fflush(results_fp);
	return 0;
}

static void results_finalize() {
	// Should not be NULL but check here anyway
	if (results_fp != NULL) {
		fprintf(results_fp, 
			"],\n\"Finished\" : \"%s\",\n\"TotalFiles\" : %d,\n\"TotalPIDs\" : %d,\n\"TotalHits\" : %d}\n", 
			getCurrentDateTime(), total_files_processed, total_pids_processed, results_hit_count);

		fclose(results_fp);
		results_fp = NULL;
		calc_report_hash();
	}
}

static SCAN_RESULTS *alloc_scan_results() {
	SCAN_RESULTS *sr;

	sr = (SCAN_RESULTS *)calloc(1,sizeof(SCAN_RESULTS));
	return sr;
}

static void free_scan_results(SCAN_RESULTS *sr) {
	if (sr != NULL) {
		sr->yara_hits = 0;

		if (sr->filename != NULL) free(sr->filename);
		if (sr->md5 != NULL) free(sr->md5);
		if (sr->sha1 != NULL) free(sr->sha1);
		if (sr->sha256 != NULL) free(sr->sha256);

		free(sr);
	}
}

void update_eventid_stats(int eventid) {
	if (event_ids_found != NULL && eventid < max_event_id)
		event_ids_found[eventid]++;
}

void trace_dump_eventid_stats() {
	int i;
	if (event_ids_found == NULL) return;

	add_trace_message(TRACE_INFO, "Event ID Found Stats", "Start");
	for (i = 0; i < max_event_id; i++) {
		if (event_ids_found[i] > 0) {
			fprintf(trace_fp, "EID %d: %d\n", i, event_ids_found[i]);
		}
	}
	add_trace_message(TRACE_INFO, "Event ID Found Stats", "End");
}

// Attempt to allocate a fairly big chunk size - try smaller ones if not
size_t initialize_file_data_buffer() {
	file_data_buffer = malloc(sizeof(unsigned char) * (FILE_DATA_BUFFER_SIZE_L));
	if (file_data_buffer != NULL) return FILE_DATA_BUFFER_SIZE_L;

	file_data_buffer = malloc(sizeof(unsigned char) * (FILE_DATA_BUFFER_SIZE_M));
	if (file_data_buffer != NULL) return FILE_DATA_BUFFER_SIZE_M;

	file_data_buffer = malloc(sizeof(unsigned char) * (FILE_DATA_BUFFER_SIZE_S));
	if (file_data_buffer != NULL) return FILE_DATA_BUFFER_SIZE_S;

	return 0;
}

static void init_file_hash_buffer() {

	// Certain other scans reuse this data buffer and if called first do the allocation
	if (file_data_buffer != NULL && file_data_buffer_size >= (FILE_DATA_BUFFER_SIZE_S)) return;
	if (!(do_hash_scan || do_fnames_scan || do_yarafile_scan || do_event_scan)) return;

	if (file_data_buffer != NULL) {
		free(file_data_buffer);
		file_data_buffer_size = 0;
		file_data_buffer = NULL;
	}

	file_data_buffer_size = initialize_file_data_buffer();
	if (file_data_buffer == NULL)
		add_trace_message(TRACE_WARNING, "File Data Buffer", "Not Allocated");
}

static void prepare_sigdata_load_buffers() {
	init_epst_sigdata(17000000);  // This should be the initial upper end size to avoid realloc
	init_regex_test_buffer(regex_test_fname);
	init_local_sig_buffer(epstlocal_fname);
}

static void free_sigdata_load_buffers() {
	free_epst_sigdata();
	free_regex_test_buffer();
	free_local_sig_buffer();
}

static int yararules_initialize() {
	char error_code[20];
	int rc;
	char *rulesdata = NULL;

	if (!(do_yarafile_scan || do_pid_scan)) {
		add_trace_message(TRACE_INFO, "Yara Rule Scanning", "Not Active");
		return 0;
	}

	// Changing to assume all yara rules downloads will be in source form vs compiled
	// If using local file, it may be compiled so it will go through the two step check
	if (use_local_rules == FALSE) {
		if (do_experimental && do_yara_source) {
			printf("%s\n", EPSTTranslate("Experimental Development Signatures Mode Active"));
			download_signature_data(compiled_rules_fname, "experimentals", api_key, EPST_VERSION);
		}
		else if (do_experimental) {
			printf("%s\n", EPSTTranslate("Experimental Signatures Mode Active"));
			download_signature_data(compiled_rules_fname, "experimental", api_key, EPST_VERSION);
		}
		else if (do_yara_source) {
			printf("%s\n", EPSTTranslate("Development Signatures Mode Active"));
			download_signature_data(compiled_rules_fname, "yaras", api_key, EPST_VERSION);
		}
		else {
			download_signature_data(compiled_rules_fname, "yara", api_key, EPST_VERSION);
		}
		// TBD: Certain yarac compiler features are not available by compiling internally
		// If required, may need a check to determine if the download data contains binary
		// content. If the data is already compiled, implement a yr_rules_load_stream
		// option and avoid the calls below - no local rule additions allowed then
		append_local_signature_data(compiled_rules_fname);
		rulesdata = get_epst_sigdata_string();
	}

	rc = yr_initialize();
	if (rc != ERROR_SUCCESS)
	{
		sprintf(error_code, "%d", rc);
		add_trace_message(TRACE_ERROR, "Yara Initialization Code", error_code);
		return rc;
	}

	if (rulesdata != NULL && strlen(rulesdata) > 5) {
		add_trace_message(TRACE_INFO, "Compiling Yara Source Data", "Start");
		rc = compile_yara_rules_data(rulesdata);

		if (rc == ERROR_SUCCESS)
			add_trace_message(TRACE_INFO, "Compiling Yara Source Data", "Finish");
	}
	else {
		add_trace_message(TRACE_INFO, "Loading compiled Yara rule file", compiled_rules_fname);
		rc = yr_rules_load(compiled_rules_fname, &rules);

		// Rule files are normally pre-compiled but providing internal
		// compiling for special situations when the full blown
		// yarac compiler is not available.
		if (rc == ERROR_INVALID_FILE) {
			add_trace_message(TRACE_INFO, "Compiling Yara Source", "Start");
			rc = compile_yara_rules();

			if (rc == ERROR_SUCCESS)
				add_trace_message(TRACE_INFO, "Compiling Yara Source", "Finish");
		}
	}

	if (rc == ERROR_INVALID_FILE) {
		add_trace_message(TRACE_ERROR, "Yara rule file is invalid", compiled_rules_fname);
		return rc;
	}
	if (rc != ERROR_SUCCESS)
	{
		trace_scanner_error(rc, compiled_rules_fname);
		return rc;
	}

	return 0;
}

static int signatures_initialize() {
	int rc;
	
	// Force exit if yara rules error occurs
	rc = yararules_initialize();
	if (rc != 0) return rc;

	if (do_hash_scan) {
		// Set size hints for initial array allocations
		sigcount_md5 = 15000;
		sigcount_sha1 = 15000;
		sigcount_sha256 = 15000;

		if (use_local_rules) {
			signatures_md5 = load_signature_list_from_file(sig_md5_fname, &sigcount_md5, FALSE, NULL);
			signatures_sha1 = load_signature_list_from_file(sig_sha1_fname, &sigcount_sha1, FALSE, NULL);
			signatures_sha256 = load_signature_list_from_file(sig_sha256_fname, &sigcount_sha256, FALSE, NULL);
		}
		else {
			download_signature_data(sig_md5_fname, "md5", api_key, EPST_VERSION);
			append_local_signature_data(sig_md5_fname);
			signatures_md5 = load_signature_list_from_data(&sigcount_md5, FALSE, NULL);

			download_signature_data(sig_sha1_fname, "sha1", api_key, EPST_VERSION);
			append_local_signature_data(sig_sha1_fname);
			signatures_sha1 = load_signature_list_from_data(&sigcount_sha1, FALSE, NULL);

			download_signature_data(sig_sha256_fname, "sha256", api_key, EPST_VERSION);
			append_local_signature_data(sig_sha256_fname);
			signatures_sha256 = load_signature_list_from_data(&sigcount_sha256, FALSE, NULL);
		}

		if (signatures_md5 == NULL && signatures_sha1 == NULL && signatures_sha256 == NULL)
			do_hash_scan = FALSE;
	}

	// Special situations allow these signatures to be used to scan event log data
	if (do_dns_scan || do_event_scan || do_url_scan) {
		sigcount_dns = 16500;

		if (use_local_rules) {
			signatures_dns = load_signature_list_from_file(sig_dns_fname, &sigcount_dns, FALSE, &dns_sig_research);
		}
		else {
			download_signature_data(sig_dns_fname, "domain", api_key, EPST_VERSION);
			append_local_signature_data(sig_dns_fname);
			signatures_dns = load_signature_list_from_data(&sigcount_dns, FALSE, &dns_sig_research);
		}
		if (signatures_dns == NULL)
			do_dns_scan = FALSE;
	}

	if (do_ips_scan || do_event_scan || do_url_scan) {
		sigcount_ips = 15000;
		if (use_local_rules) {
			signatures_ips = load_signature_list_from_file(sig_ips_fname, &sigcount_ips, FALSE, NULL);
		}
		else {
			download_signature_data(sig_ips_fname, "ip", api_key, EPST_VERSION);
			append_local_signature_data(sig_ips_fname);
			signatures_ips = load_signature_list_from_data(&sigcount_ips, FALSE, NULL);
		}
		if (signatures_ips == NULL)
			do_ips_scan = FALSE;
	}

	if (do_url_scan || do_event_scan) {
		sigcount_url = 15000;
		if (use_local_rules) {
			signatures_url = load_signature_list_from_file(sig_url_fname, &sigcount_url, FALSE, &url_sig_research);
		}
		else {
			download_signature_data(sig_url_fname, "url", api_key, EPST_VERSION);
			append_local_signature_data(sig_url_fname);
			signatures_url = load_signature_list_from_data(&sigcount_url, FALSE, &url_sig_research);
		}

		if (signatures_url != NULL) {
			int i;
			// Specially handling for URL's with trailing slash
			// May give false hit in rare cases but could miss a
			// hit if the slash is not removed
			for (i = 0; i < sigcount_url; i++) {
				char *u = signatures_url[i];
				size_t len = strlen(u);
				if (u[len - 1] == '/') u[len - 1] = '\0';
			}
		}

		// URL Scan in history files can still be done with DNS and IPS
		if (signatures_url == NULL && signatures_ips == NULL && signatures_dns == NULL)
			do_url_scan = FALSE;
	}

	if (do_fnames_scan || do_event_scan) {
		sigcount_fnames = 10000;
		if (use_local_rules) {
			signatures_fnames = load_signature_list_from_file(sig_fnames_fname, &sigcount_fnames, TRUE, &fname_sig_research);
		}
		else {
			download_signature_data(sig_fnames_fname, "filename", api_key, EPST_VERSION);
			append_local_signature_data(sig_fnames_fname);
			signatures_fnames = load_signature_list_from_data(&sigcount_fnames, TRUE, &fname_sig_research);
		}
		if (signatures_fnames == NULL)
			do_fnames_scan = FALSE;
	}

	if (do_rkeys_scan || do_event_scan) {
		sigcount_rkeys = 1000;
		if (use_local_rules) {
			signatures_rkeys = load_signature_list_from_file(sig_rkeys_fname, &sigcount_rkeys, TRUE, NULL);
		}
		else {
			download_signature_data(sig_rkeys_fname, "regkey", api_key, EPST_VERSION);
			append_local_signature_data(sig_rkeys_fname);
			signatures_rkeys = load_signature_list_from_data(&sigcount_rkeys, TRUE, NULL);
		}
		if (signatures_rkeys == NULL)
			do_rkeys_scan = FALSE;
	}

	if (do_mutex_scan || do_event_scan) {
		sigcount_mutex = 200;
		if (use_local_rules) {
			signatures_mutex = load_signature_list_from_file(sig_mutex_fname, &sigcount_mutex, FALSE, NULL);
		}
		else {
			download_signature_data(sig_mutex_fname, "mutex", api_key, EPST_VERSION);
			append_local_signature_data(sig_mutex_fname);
			signatures_mutex = load_signature_list_from_data(&sigcount_mutex, FALSE, NULL);
		}
		if (signatures_mutex == NULL)
			do_mutex_scan = FALSE;
	}

	if (do_event_scan) {
		// Reusing the events signature file for now - only load if event_scan is activated
		// Tried adding a -C option to activate separately but code error: too many arguments
		if (use_local_rules) {
			load_syscmd_signatures_from_file(sig_events_fname, &syscmds_to_run, &syscmds_sig_research);
		}
		else {
			download_signature_data(sig_events_fname, "events", api_key, EPST_VERSION);
			append_local_signature_data(sig_events_fname);
			load_syscmd_signatures_from_data(&syscmds_to_run, &syscmds_sig_research);
		}

		if (count_epst_strlistitems(syscmds_sig_research) && count_epst_strlistitems(syscmds_to_run))
			do_syscmds_scan = TRUE;
		else
			do_syscmds_scan = FALSE;
	}

	if (do_event_scan) {
		sigcount_events = 0;

#if defined(_WIN32)
		// Load signature file and create the array of linked lists of regex strings
		event_signatures = calloc(max_event_id, sizeof(EPST_EventSignature *));
		if (event_signatures != NULL) {
			if (use_local_rules) {
				load_event_signatures_from_file(event_signatures, max_event_id, sig_events_fname, &sigcount_events);
			}
			else {
				restart_epst_sigdata(); // Loaded into memory above
				load_event_signatures_from_data(event_signatures, max_event_id, &sigcount_events);
			}
		} else {
			fprintf(stderr, "%s\n", EPSTTranslate("Event Signature Alloc Failed"));
		}
#endif
		
		if (sigcount_events > 0) {
			// Array for recording statistics of event ids detected in logs
			event_ids_found = calloc(max_event_id, sizeof(int));
		}
		else {
			do_event_scan = FALSE;
			if (event_signatures != NULL) {
				free(event_signatures);
				event_signatures = NULL;
			}
		}
	}

	add_trace_message_value(TRACE_INFO, "MD5 Signature Items Loaded", sigcount_md5);
	add_trace_message_value(TRACE_INFO, "SHA1 Signature Items Loaded", sigcount_sha1);
	add_trace_message_value(TRACE_INFO, "SHA256 Signature Items Loaded", sigcount_sha256);
	add_trace_message_value(TRACE_INFO, "DNS Signature Items Loaded", sigcount_dns + count_epst_strlistitems(dns_sig_research));
	add_trace_message_value(TRACE_INFO, "URL Signature Items Loaded", sigcount_url + count_epst_strlistitems(url_sig_research));
	add_trace_message_value(TRACE_INFO, "IP Signature Items Loaded", sigcount_ips);
	add_trace_message_value(TRACE_INFO, "Filename Signature Items Loaded", sigcount_fnames + count_epst_strlistitems(fname_sig_research));
	add_trace_message_value(TRACE_INFO, "Register Keys Signature Items Loaded", sigcount_rkeys);
	add_trace_message_value(TRACE_INFO, "Mutex Signature Items Loaded", sigcount_mutex);
	add_trace_message_value(TRACE_INFO, "Event ID Signature Items Loaded", sigcount_events);
	add_trace_message_value(TRACE_INFO, "System Command Items Loaded", count_epst_strlistitems(syscmds_to_run));
	add_trace_message_value(TRACE_INFO, "System Command Signature Items Loaded", count_epst_strlistitems(syscmds_sig_research));

	if (!do_hash_scan) add_trace_message(TRACE_INFO, "Hash Scan", "Not Active");
	if (!do_dns_scan) add_trace_message(TRACE_INFO, "DNS Scan", "Not Active");
	if (!do_url_scan) add_trace_message(TRACE_INFO, "URL Scan", "Not Active");
	if (!do_ips_scan) add_trace_message(TRACE_INFO, "IP Address Scan", "Not Active");
	if (!do_fnames_scan) add_trace_message(TRACE_INFO, "Filenames Scan", "Not Active");
	if (!do_rkeys_scan) add_trace_message(TRACE_INFO, "Registry Keys Scan", "Not Active");
	if (!do_mutex_scan) add_trace_message(TRACE_INFO, "Mutex Scan", "Not Active");
	if (!do_event_scan) add_trace_message(TRACE_INFO, "Event Scan", "Not Active");
	if (!do_syscmds_scan) add_trace_message(TRACE_INFO, "SysCmds Scan", "Not Active");

	return 0;
}

static void remove_downloaded_signature_files() {
	if (use_local_rules) return;

	remove(sig_md5_fname);
	remove(sig_sha1_fname);
	remove(sig_sha256_fname);
	remove(sig_dns_fname);
	remove(sig_url_fname);
	remove(sig_ips_fname);
	remove(sig_fnames_fname);
	remove(sig_rkeys_fname);
	remove(sig_mutex_fname);
	remove(sig_events_fname);
}

void signatures_finalize() {
	// Free function checks for NULLs, etc
	free_signature_list(&signatures_md5, &sigcount_md5);
	free_signature_list(&signatures_sha1, &sigcount_sha1);
	free_signature_list(&signatures_sha256, &sigcount_sha256);
	free_signature_list(&signatures_dns, &sigcount_dns);
	free_signature_list(&signatures_url, &sigcount_url);
	free_signature_list(&signatures_ips, &sigcount_ips);
	free_signature_list(&signatures_fnames, &sigcount_fnames);
	free_signature_list(&signatures_rkeys, &sigcount_rkeys);
	free_signature_list(&signatures_mutex, &sigcount_mutex);

	// Free the events signatures linked lists and array
	if (event_signatures != NULL) {
		int i;
		for (i = 0; i < max_event_id; i++) {
			free_epst_event_signatures(&event_signatures[i]);
		}
		free(event_signatures);
		event_signatures = NULL;
	}

	if (event_ids_found != NULL) free(event_ids_found);
	event_ids_found = NULL;
}


char *extract_ipconfig_data(char *s) {
	char *cp;
	size_t sl;

	if ((cp = strchr(s, ':')) != NULL) {
		cp++;
		if (*cp == ' ') cp++;

		sl = strlen(cp);
		if (sl > 0 && cp[sl - 1] == '\n') cp[--sl] = '\0';
		if (sl > 0 && cp[sl - 1] == '\r') cp[--sl] = '\0';

		return _strdup(cp);
	}
	return NULL;
}

void handle_compiler_errors(int error, const char* fname, int line, const char* message, void* user_data) {
	// Ignore warnings - use the compiler to get these
	if (error == YARA_ERROR_LEVEL_ERROR) {
		fprintf(stderr, "%s(%d): error: %s\n", fname, line, message);
	}
}

int compile_yara_rules() {
	COMPILER_RESULTS cr;
	YR_COMPILER *compiler = NULL;
	FILE  *rfile;
	int rc;

	// Rules file didn't contain compiled rules.
	// Handle as a text file with rules in source form.

	if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
		return EXIT_FAILURE;

	// Not handling external variables - use compiler instead

	yr_compiler_set_callback(compiler, handle_compiler_errors, &cr);

	if ((rfile = fopen(compiled_rules_fname, "r")) == NULL)
		return ERROR_INVALID_FILE;

	cr.warnings = 0;
	cr.errors = yr_compiler_add_file(compiler, rfile, NULL, compiled_rules_fname);
	fclose(rfile);

	// Ignoring warnings so no check here - Just concerned with any errors
	if (cr.errors > 0) return EXIT_FAILURE;

	rc = yr_compiler_get_rules(compiler, &rules);
	yr_compiler_destroy(compiler);

	return rc;
}

int compile_yara_rules_data(const char *rulesdata) {
	COMPILER_RESULTS cr;
	YR_COMPILER *compiler = NULL;
	int rc;

	if (rulesdata == NULL) return EXIT_FAILURE;

	// Rules file didn't contain compiled rules.
	// Handle as a text file with rules in source form.

	if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
		return EXIT_FAILURE;

	// Not handling external variables - use compiler instead

	yr_compiler_set_callback(compiler, handle_compiler_errors, &cr);

	cr.warnings = 0;
	cr.errors = yr_compiler_add_string(compiler, rulesdata, NULL);

	// Ignoring warnings so no check here - Just concerned with any errors
	if (cr.errors > 0) return EXIT_FAILURE;

	rc = yr_compiler_get_rules(compiler, &rules);
	yr_compiler_destroy(compiler);

	return rc;
}

int epst_filescan_timed_out()
{
	if (difftime(time(NULL), main_start_time) < epst_filescan_timeout) return FALSE;
	return TRUE;
}

int epst_timed_out()
{
	if (difftime(time(NULL), main_start_time) < epst_timeout) return FALSE;
	return TRUE;
}

int epst_do_scan_again()
{
	// Perform some relatively quick running scans again if the total time
	// for the later scans is over an hour. Currently do DNS and IPS before
	// the longer running file and process scans.
	if (difftime(time(NULL), main_start_time) < 3600) return FALSE;
	return TRUE;
}


static int epst_initialize() {
	int rc;
	
	if (explicit_scan_mode == FALSE) {
		// Default to turning on all scan options
		do_yarafile_scan = TRUE;
		do_hash_scan = TRUE;
		do_dns_scan = TRUE;
		do_ips_scan = TRUE;
		do_pid_scan = TRUE;
		do_fnames_scan = TRUE;
		do_rkeys_scan = TRUE;
		do_mutex_scan = TRUE;

		// Event ID Scan is not active by default - allow it to be set independently

		// Default on but turned off with suppress-upload option
		if (suppress_results_upload)
			auto_register_sightings = FALSE;
		else
			auto_register_sightings = TRUE;

		// Just make sure
		if (suppress_results_upload)
			suppress_samples_upload = TRUE;
	}

	// Special mechanism that may be packaged with tool download
	if (suppress_samples_upload == FALSE) {
		if (fexists(".DoNotSendSamples"))
			suppress_samples_upload = TRUE;
	}

	trace_initialize();
	initialize_detected_files();
	dirlist_initialize();

	if (use_local_rules == FALSE) {
		printf("%s\n", EPSTTranslate("Downloading rules and signature files"));
	}

	prepare_sigdata_load_buffers();
	rc = signatures_initialize();
	free_sigdata_load_buffers();

	// In-memory downloads may obsolete need for these calls
	if (use_local_rules == FALSE) {
		remove_downloaded_signature_files();
		remove(compiled_rules_fname);
	}

	// Most likely a yara rules/compile error above, exit after cleanup
	if (rc != 0) return rc;

	get_system_config();

	// Call after getting the system data so
	// it can be filed right away.
	if ((rc = results_initialize()) != 0)
		return rc;

	mutex_init(&output_mutex);
	mutex_init(&hash_file_mutex);

	return 0;
}

void epst_finalize() {
	results_finalize();
	trace_finalize();

	if (suppress_results_upload == FALSE) {
		printf("%s\n", EPSTTranslate("Uploading results JSON file."));
		upload_scan_results_file(scan_results_fname, api_key, scan_results_sha256);

		printf("%s\n", EPSTTranslate("Uploading results trace file."));
		upload_scan_file(scan_trace_fname, api_key, scan_results_sha256,"epsttrace");
	}

	finalize_detected_files();
	finalize_eventhits();

	finalize_curl();

	if (do_yarafile_scan || do_pid_scan) {
		if (rules != NULL) {
			yr_rules_destroy(rules);
			rules = NULL;
		}

		yr_finalize();
	}

	signatures_finalize();
	dirlist_finalize();

	if (file_data_buffer != NULL) free(file_data_buffer);

	free_epst_strlistitems(&event_files_found);
	free_epst_strlistitems(&history_files_found);
	free_epst_strlistitems(&url_hits_found);
	free_epst_strlistitems(&fname_sig_research);
	free_epst_strlistitems(&dns_sig_research);
	free_epst_strlistitems(&url_sig_research);
	free_epst_strlistitems(&syscmds_to_run);
	free_epst_strlistitems(&syscmds_sig_research);

	mutex_destroy(&output_mutex);
	mutex_destroy(&hash_file_mutex);

	if (host_name != NULL) free(host_name);
	if (api_key != NULL) free(api_key);
	if (local_ipv4 != NULL) free(local_ipv4);
	if (local_ipv6 != NULL) free(local_ipv6);
	if (physical_address != NULL) free(physical_address);

	return;
}

// Only call this function for rules that found a hit
int handle_scan_hit_message(int message, YR_RULE *rule, void *data)
{
	SCAN_RESULTS *sr;
	char *ht;
	char buf[1024];
	int result_hit_limit = FALSE;
	int cnt;

	sr = (SCAN_RESULTS *)data;

	if (sr != NULL) {
		// Register independent of the other details
		ht = (sr->process_number > 0) ? "YPS" : "YFS";
		
		if (strcmp(rule->ns->name, "default") == 0) {
			register_sighting(ht, rule->identifier);
		}
		else {
			snprintf(buf, 1023, "%s|%s", rule->ns->name, rule->identifier);
			register_sighting(ht, buf);
		}

		if (using_threads) mutex_lock(&output_mutex);

		add_results_start_hit();

		// Dump out the hit flags
		ht = (sr->process_number > 0) ? "YRProcessScan" : "YRFileScan";
		add_results_pair_ss("HitType", ht, ",\n");

		add_results_pair_sn("Name", sr->filename, ",\n");
		add_results_pair_ss("YRuleID", rule->identifier, ",\n");
		add_results_pair_ss("YRuleNS", rule->ns->name, ",\n");
		add_results_pair_si("PID", sr->process_number, ",\n");
		
		// Some useful output since results/trace file will be locked while open
		printf("\nHIT: %s\n", sr->filename != NULL ? sr->filename : "Unknown" );
		printf("PID: %d RULE: %s\n\n",sr->process_number,rule->identifier);

		if (show_rule_details & SHOW_RD_META) {
			YR_META* meta;

			// Show Meta as an object with name/value pairs
			add_results_pair_st("MetaData", "{", "");

			yr_rule_metas_foreach(rule, meta)
			{
				if (meta != rule->metas)
					add_results_raw_text(",\n");

				if (meta->type == META_TYPE_INTEGER)
				{
					add_results_pair_si(meta->identifier, (int)meta->integer, "");
				}
				else if (meta->type == META_TYPE_BOOLEAN)
				{
					add_results_pair_st(meta->identifier, meta->integer ? "true" : "false","");
				}
				else
				{
					add_results_pair_st(meta->identifier, "\"", "");
					add_results_yara_escaped_data((uint8_t*)(meta->string), strlen(meta->string));
					add_results_raw_text("\"");
				}
			}

			add_results_raw_text("},\n");
		}

		// String Matches if any
		if (show_rule_details & SHOW_RD_STRINGS) {
			YR_STRING* string;
			int match_cnt = 0;

			// Show Meta as an array of strings
			add_results_pair_st("MatchData", "[", "\n");

			cnt = 0;
			yr_rule_strings_foreach(rule, string)
			{
				YR_MATCH* match;
				// char buf[20];

				match_cnt = 0;
				yr_string_matches_foreach(string, match)
				{
					match_cnt++;
					// Generate the actual hit data for the variable
					//sprintf(buf,"0x%I64x",match->base + match->offset);
					//add_results_raw_text("\"");
					//add_results_raw_text(buf);
					//add_results_raw_text("\",\n");

					//add_results_raw_text("\"");
					//if (STRING_IS_HEX(string))
					//	add_results_yara_hex_string(match->data, match->data_length);
					//else
					//	add_results_yara_string(match->data, match->data_length);
					//add_results_raw_text("\"");
				}

				// Generate out a string variable name if it found a match
				if (match_cnt) {
					if (cnt > 0) add_results_raw_text(",\n");
					cnt++;

					add_results_raw_text("\"");
					add_results_raw_text(string->identifier);
					add_results_raw_text("\"");
				}

			}

			add_results_raw_text("],\n");
		}

		if (show_rule_details & SHOW_RD_TAGS)
		{
			const char* tag;

			add_results_pair_st("Tags", "[", "");

			yr_rule_tags_foreach(rule, tag)
			{
				// print a comma except for the first tag
				if (tag != rule->tags) add_results_raw_text(",");

				add_results_raw_text("\"");
				add_results_raw_text(tag);
				add_results_raw_text("\"");
			}

			add_results_raw_text("],\n");
		}

		sr->yara_hits++;
		results_hit_count++;

		add_results_pair_si("YHitNumber", sr->yara_hits, "}\n");

		if (using_threads) mutex_unlock(&output_mutex);

		if (yara_hit_count_limit != 0 && sr->yara_hits >= yara_hit_count_limit)
			result_hit_limit = TRUE;
	}

	if (result_hit_limit)
		return CALLBACK_ABORT;

	return CALLBACK_CONTINUE;
}

// Note the use of a different mutex for threaded operation of hash
void get_file_hash_codes(EPST_FILE_HASH *fhp) {
	if (file_data_buffer != NULL) {
		if (using_threads) mutex_lock(&hash_file_mutex);
		fhp->error = calc_file_hash_b(fhp, file_data_buffer, (int)file_data_buffer_size);
		if (using_threads) mutex_unlock(&hash_file_mutex);
	}
	else
		fhp->error = calc_file_hash_nb(fhp);
}


// Double check for hash codes even if not doing hash scan.
// Get the values when one of the other scans get a hit.
void check_hash_codes(SCAN_RESULTS *sr) {
	EPST_FILE_HASH fh;

	if (sr->sha256 != NULL || 
		sr->sha1 != NULL ||
		sr->md5 != NULL ||
		sr->process_number > 0 || 
		sr->filename == NULL) return;

	fh.filename = sr->filename;
	get_file_hash_codes(&fh);

	if (fh.error != EPST_FILE_HASH_OK) {
		if (fh.error == EPST_FILE_HASH_MEM_ERROR)
			add_trace_message(TRACE_WARNING, "Hash scan could not allocate file data", sr->filename);
		else
			add_trace_message(TRACE_WARNING, "Hash scan could not read file", sr->filename);
		return;
	}

	// Copy over the memory pointers
	sr->md5 = fh.md5;
	sr->sha1 = fh.sha1;
	sr->sha256 = fh.sha256;
}

// This should only be called after the report has been closed
static void calc_report_hash() {
	EPST_FILE_HASH fh;

	fh.filename = scan_results_fname;
	get_file_hash_codes(&fh);

	if (fh.error != EPST_FILE_HASH_OK) {
		printf("%s: %s", EPSTTranslate("Hash could not be calculated for results file"), scan_results_fname);
		return;
	}

	if (fh.sha256 != NULL) {
		scan_results_sha256 = fh.sha256;
		printf("%s: %s\n", EPSTTranslate("Results File Hash"), scan_results_sha256);
	}

	// Should free the other fields, but cleaned by exit
}

void add_hashcode_trace(SCAN_RESULTS *sr) {
	char buf[256];

	if (extra_trace_details < XTRACE_HASH) return;

	if (sr->filename == NULL || sr->process_number > 0) return;

	char *md5 = (sr->md5 != NULL ? sr->md5 : "UNKNOWN");
	char *sha1 = (sr->sha1 != NULL ? sr->sha1 : "UNKNOWN");
	char *sha256 = (sr->sha256 != NULL ? sr->sha256 : "UNKNOWN");

	sprintf(buf, "MD5:%s,SHA1:%s,SHA256:%s", md5, sha1, sha256);
	add_trace_message(TRACE_INFO, buf, sr->filename);
}


void perform_hash_scan(SCAN_RESULTS *sr) {
	int rc;

	if (!do_hash_scan || sr == NULL || sr->filename == NULL) return;

	check_hash_codes(sr);  
	add_hashcode_trace(sr);

	if (sr->md5 != NULL && sigcount_md5 > 0) {
		rc = bisearch_signature_list(signatures_md5, sigcount_md5, sr->md5);
		if (rc >= 0) {
			register_sighting("MHM",sr->md5);
			sr->hit_flags |= MD5_HIT; 
			sr->sig_hits++;
		}
	}

	if (sr->sha1 != NULL && sigcount_sha1 > 0) {
		rc = bisearch_signature_list(signatures_sha1, sigcount_sha1, sr->sha1);
		if (rc >= 0) {
			register_sighting("S1M",sr->sha1);
			sr->hit_flags |= SHA1_HIT;
			sr->sig_hits++;
		}
	}

	if (sr->sha256 != NULL && sigcount_sha256 > 0) {
		rc = bisearch_signature_list(signatures_sha256, sigcount_sha256, sr->sha256);
		if (rc >= 0) {
			register_sighting("S2M",sr->sha256);
			sr->hit_flags |= SHA256_HIT;
			sr->sig_hits++;
		}
	}
}

void perform_fnames_scan(SCAN_RESULTS *sr) {
	int rc;
	char *r;
	size_t rs, rl;

	if (!do_fnames_scan || sr == NULL || sr->filename == NULL) return;

	// NOTE: added a return after hit found, double hits not expected
	if (sigcount_fnames > 0) {
		// Check the full path first
		rc = bisearch_signature_list(signatures_fnames, sigcount_fnames, sr->filename);
		if (rc >= 0) {
			register_sighting("FNM", sr->filename);
			sr->hit_flags |= FNAME_HIT;
			sr->sig_hits++;
			return;
		}

		// Now check just the filename
		if ((r = strrchr(sr->filename, DIR_SEP)) != NULL) {
			rc = bisearch_signature_list(signatures_fnames, sigcount_fnames, r + 1);
			if (rc >= 0) {
				register_sighting("FNM", r + 1);
				sr->hit_flags |= FNAME_HIT;
				sr->sig_hits++;
				return;
			}
		}
	}

	// Check if any regex matches exist in full path
	EPST_StrListItem *list = fname_sig_research;
	while (list != NULL) {
		if (list->item != NULL) {
			if (do_research(sr->filename, list->item, &rs, &rl)) {
				register_sighting("FNM", sr->filename);
				sr->hit_flags |= FNAME_HIT;
				sr->sig_hits++;
				return;
			}
		}
		list = list->next;
	}
}

void trace_signature_scan(int starting, SCAN_RESULTS *sr) {
	long tid;
	char buf[256];
	const char *seflag;

	if (extra_trace_details < XTRACE_FILES) return;

	if (sr == NULL || sr->filename == NULL) return;

	tid = (long)GetCurrentThreadId();
	if (sr->process_number == 0) {
		seflag = starting ? EPSTTranslate("Starting File Scan") : EPSTTranslate("Finished File Scan");
		sprintf(buf, "%s %ld %s", EPSTTranslate("Thread"), tid, seflag);
	}
	else {
		// Currently not using threads for process scans but may later
		seflag = starting ? EPSTTranslate("Starting Process Scan") : EPSTTranslate("Finished Process Scan");
		sprintf(buf, "%s %ld %s %d", EPSTTranslate("Thread"), tid, seflag, sr->process_number);
	}
	add_trace_message(TRACE_INFO, buf, sr->filename);
}

// Setup and perform the signature and hash scanning first.
// Allocate the results data structure but assumes fname has
// already been duplicated since it may have been in the queue.
// Results data structure is initiated and returned even if
// none of the signature scans are going to be performed.
SCAN_RESULTS *perform_signature_scan(int pid, char *fname) {
	SCAN_RESULTS *sr;
	sr = alloc_scan_results();
	if (sr != NULL) {
		sr->process_number = pid;
		sr->filename = fname;

		trace_signature_scan(1, sr);

		// Run the other scans and hashing if process ID is zero
		if (pid == 0) {
			perform_hash_scan(sr);
			perform_fnames_scan(sr);
		}
	}
	return sr;
}

static int epst_dir_file_count(const char *scanDir, int stop_at_limit);
static void fp_add_json_proximity_filelist(FILE *fp, const char *hitDir, const char *hitFile);

static void cleanup_hit_detail_files() {
	char dfname[2048];
	int i;
	
	for(i=1;i<current_hit_upload_id;i++) {
		sprintf(dfname,"%s%cepstfilehit%d.json",use_runtime_folder,DIR_SEP,i);
		remove_epst_file(dfname);
	}
}

static void fp_add_json_file_details(FILE *fp, const char *fname) {
#if defined(_WIN32)
	if (fname != NULL) {
		WIN32_FILE_ATTRIBUTE_DATA fad;
		char dt[1024];

		if (GetFileAttributesEx(fname, GetFileExInfoStandard, &fad)) {
			fp_add_json_raw_text(fp, ",\n");
			fp_add_json_pair_si(fp, "FileAttr", fad.dwFileAttributes, ",\n");
			format_filetime_to_str(&(fad.ftCreationTime), dt, 1023);
			fp_add_json_pair_ss(fp, "Created", dt, ",\n");
			format_filetime_to_str(&(fad.ftLastAccessTime), dt, 1023);
			fp_add_json_pair_ss(fp, "Accessed", dt, ",\n");
			format_filetime_to_str(&(fad.ftLastWriteTime), dt, 1023);
			fp_add_json_pair_ss(fp, "Modified", dt, ",\n");
			fp_add_json_pair_si(fp, "Size", get_fsize_from_file_attr(&fad), "");
		}
	}
#elif defined(__APPLE__)
	if (fname != NULL) {
		struct stat fad;
		char dt[1024];

		if (stat(fname, &fad) >= 0) {
			fp_add_json_raw_text(fp, ",\n");
			fp_add_json_pair_si(fp, "FileAttr", fad.st_mode, ",\n");
			format_filetime_to_str(&(fad.st_birthtimespec), dt, 1023);
			fp_add_json_pair_ss(fp, "Created", dt, ",\n");
			format_filetime_to_str(&(fad.st_ctimespec), dt, 1023);
			fp_add_json_pair_ss(fp, "StatChanged", dt, ",\n");
			format_filetime_to_str(&(fad.st_mtimespec), dt, 1023);
			fp_add_json_pair_ss(fp, "Modified", dt, ",\n");
			fp_add_json_pair_si(fp, "Size", get_fsize_from_file_attr(&fad), "");
		}
	}
#elif defined(__linux__)
	// Linux may or may not have st_birthtime available
	if (fname != NULL) {
		struct stat fad;
		char dt[1024];

		if (stat(fname, &fad) >= 0) {
			fp_add_json_raw_text(fp, ",\n");
			fp_add_json_pair_si(fp, "FileAttr", fad.st_mode, ",\n");
			format_filetime_to_str(&(fad.st_ctim), dt, 1023);
			fp_add_json_pair_ss(fp, "StatChanged", dt, ",\n");
			format_filetime_to_str(&(fad.st_mtim), dt, 1023);
			fp_add_json_pair_ss(fp, "Modified", dt, ",\n");
			fp_add_json_pair_si(fp, "Size", get_fsize_from_file_attr(&fad), "");
		}
	}
#endif
}


// The list iterator calling this function is platform specific
static void fp_add_json_proximity_filelist_item(FILE *fp, const char *hitDir, const char *itemFileName, int itemNum) {
	char full_path[MAX_PATH];
	EPST_FILE_HASH fh;

	if (itemNum > 0) { fprintf(fp, ",\n"); }
	fprintf(fp, "{");

	snprintf(full_path, sizeof(full_path), "%s%c%s", hitDir, DIR_SEP, itemFileName);
	fh.filename = full_path;
	get_file_hash_codes(&fh);

	if (fh.error != EPST_FILE_HASH_OK) {
		fp_add_json_hash_triple(fp, "UNKNOWN", "UNKNOWN", "UNKNOWN");
	}
	else {
		fp_add_json_hash_triple(fp, fh.md5, fh.sha1, fh.sha256);
		if (fh.md5 != NULL) free(fh.md5);
		if (fh.sha1 != NULL) free(fh.sha1);
		if (fh.sha256 != NULL) free(fh.sha256);
	}

	fp_add_json_pair_sn(fp, "Name", itemFileName, "");
	fp_add_json_file_details(fp, full_path);

	fprintf(fp, "}");
}


// ONLY CALL FROM process_scan_results after value checks
static void detail_file_hit(SCAN_RESULTS *sr) {
	char dfname[MAX_PATH];
	char dpath[MAX_PATH];
	FILE *fp;
	int err, count,max_count;
	char *tf,*f;
	
	if (sr == NULL || sr->filename == NULL) return;

	sprintf(dfname, "%s%cepstfilehit%d.json", use_runtime_folder, DIR_SEP, current_hit_upload_id);

	if ((err = fopen_s(&fp, dfname, "w")) != 0) {
		perror("Detail File Hit");
		add_trace_message(TRACE_ERROR, "Detail File Hit", "Open Failed");
		return;
	}
	
	// First 11 bytes in file used to test if file valid
	fprintf(fp,"{\"EPSTFILEHIT\":\"%s\",\n",EPST_BUILD_NUMBER); 
	fp_add_json_pair_ss_r(fp,"Version", EPST_VERSION, ",\n");
	fp_add_json_pair_ss_r(fp,"Found", getCurrentDateTime(),",\n");

	// All are required but these need to be escaped so
	// using a different function but ensure non NULL
	fp_add_json_pair_sn(fp,"User", username, ",\n");
	fp_add_json_pair_sn(fp,"Host", host_name, ",\n");
	fp_add_json_pair_sn(fp,"Rules", compiled_rules_fname, ",\n");
	
	fp_add_json_pair_ss_r(fp,"APIKEY", api_key, ",\n");
	fp_add_json_pair_ss_r(fp,"IPV4", local_ipv4, ",\n");
	fp_add_json_pair_ss_r(fp,"IPV6", local_ipv6, ",\n");
	fp_add_json_pair_ss_r(fp,"MAC", physical_address, ",\n");
	
	// *** THIS BLOCK IS DUPLICATED FROM MAIN REPORTING FUNCTION ****
	// Data output format may be tweaked in future - intended for immediate
	// hit registration with extra meta data until full report is submitted
	
	// Dump out the hit flags
	fp_add_json_pair_ss(fp,"HitType", "FileSignatureMatch", ",\n");

	tf = (sr->yara_hits > 0) ? "true" : "false";
	fp_add_json_pair_st(fp,"YaraHit", tf, ",\n");

	tf = (sr->hit_flags & MD5_HIT) ? "true" : "false";
	fp_add_json_pair_st(fp,"MD5Hit", tf, ",\n");

	tf = (sr->hit_flags & SHA1_HIT) ? "true" : "false";
	fp_add_json_pair_st(fp,"SHA1Hit", tf, ",\n");

	tf = (sr->hit_flags & SHA256_HIT) ? "true" : "false";
	fp_add_json_pair_st(fp,"SHA256Hit", tf, ",\n");

	tf = (sr->hit_flags & FNAME_HIT) ? "true" : "false";
	fp_add_json_pair_st(fp,"NameHit", tf, ",\n");

	fp_add_json_hash_triple(fp, sr->md5, sr->sha1, sr->sha256);
	
	fp_add_json_pair_si(fp,"YaraHits", sr->yara_hits, ",\n");

	fp_add_json_pair_sn(fp, "Name", sr->filename, "");
	fp_add_json_file_details(fp, sr->filename);

	// **** HIT PROXIMITY FILES ****
	// Only generate proximity list if folder has less than a threshold number
	// of files. Need to exclude the hit file from the proximity list as well
	max_count = 1000;
	fprintf(fp, ",\n\"ProximityFiles\": [\n");

	// Split the path and filename
	strcpy(dpath, sr->filename);
	if ((f = strrchr(dpath, DIR_SEP)) != NULL) {
		*f = '\0';
		count = epst_dir_file_count(dpath, max_count);
		if (count > 1 && count < max_count) {
			fp_add_json_proximity_filelist(fp, dpath, f+1);
		}
	}

	fprintf(fp,"]}\n");
	fclose(fp);
	
	if (auto_register_sightings) {
		upload_scan_file(dfname, api_key, "NOT_READY", "epstfilehit");
	}
	
	current_hit_upload_id++;
}

// Process the combined scan results. Add to results file if open
// and free the associated memory. There may not be any hits.
int process_scan_results(SCAN_RESULTS *sr) {
	int rc = 0;
	char *tf,*fname;

	if (sr == NULL) return rc;

	// Generate out hit data for file scan items if any
	// Skip PID data here since it is already been filed
	if ((sr->hit_flags != 0 || sr->yara_hits != 0) && sr->process_number == 0) {
		// Make sure there is at least this item - should not be NULL but checking regardless
		// Required to ensure JSON data is valid format - other details may not be included if NULL
		fname = (sr->filename == NULL) ? "Unknown" : sr->filename;

		// Note this call does it's own mutex lock
		add_trace_message(TRACE_INFO, "HIT", fname);

		check_hash_codes(sr);

		if (using_threads) mutex_lock(&output_mutex);

		printf("\nHit: %s\n", fname);
		if (sr->sha256 != NULL) printf("SHA256: %s\n", sr->sha256);

		// CREATE/UPLOAD THE FILE HIT DATA AS SINGLE ITEM
		detail_file_hit(sr);

		add_results_start_hit();

		// Dump out the hit flags
		add_results_pair_ss("HitType", "FileSignatureMatch", ",\n");

		tf = (sr->yara_hits > 0) ? "true" : "false";
		add_results_pair_st("YaraHit", tf, ",\n");

		tf = (sr->hit_flags & MD5_HIT) ? "true" : "false";
		add_results_pair_st("MD5Hit", tf, ",\n");

		tf = (sr->hit_flags & SHA1_HIT) ? "true" : "false";
		add_results_pair_st("SHA1Hit", tf, ",\n");

		tf = (sr->hit_flags & SHA256_HIT) ? "true" : "false";
		add_results_pair_st("SHA256Hit", tf, ",\n");

		tf = (sr->hit_flags & FNAME_HIT) ? "true" : "false";
		add_results_pair_st("NameHit", tf, ",\n");

		add_results_pair_ss("MD5", sr->md5, ",\n");
		add_results_pair_ss("SHA1", sr->sha1, ",\n");
		add_results_pair_ss("SHA256", sr->sha256, ",\n");

		add_results_pair_sn("Name", fname, "");

#if defined(_WIN32)
		if (sr->filename != NULL) {
			WIN32_FILE_ATTRIBUTE_DATA fad;
			char dt[1024];

			if (GetFileAttributesEx(sr->filename, GetFileExInfoStandard, &fad)) {
				add_results_raw_text(",\n");
				add_results_pair_si("FileAttr", fad.dwFileAttributes, ",\n");
				format_filetime_to_str(&(fad.ftCreationTime), dt, 1023);
				add_results_pair_ss("Created", dt, ",\n");
				format_filetime_to_str(&(fad.ftLastAccessTime), dt, 1023);
				add_results_pair_ss("Accessed", dt, ",\n");
				format_filetime_to_str(&(fad.ftLastWriteTime), dt, 1023);
				add_results_pair_ss("Modified", dt, ",\n");
				add_results_pair_si("Size", get_fsize_from_file_attr(&fad), "");
			}
		}
#elif defined(__APPLE__)
		if (sr->filename != NULL) {
			struct stat fad;
			char dt[1024];

			if (stat(sr->filename, &fad) >= 0) {
				add_results_raw_text(",\n");
				add_results_pair_si("FileAttr", fad.st_mode, ",\n");
				format_filetime_to_str(&(fad.st_birthtimespec), dt, 1023);
				add_results_pair_ss("Created", dt, ",\n");
				format_filetime_to_str(&(fad.st_ctimespec), dt, 1023);
				add_results_pair_ss("StatChanged", dt, ",\n");
				format_filetime_to_str(&(fad.st_mtimespec), dt, 1023);
				add_results_pair_ss("Modified", dt, ",\n");
				add_results_pair_si("Size", get_fsize_from_file_attr(&fad), "");
			}
		}
#elif defined(__linux__)
		// Linux may or may not have st_birthtime available
		if (sr->filename != NULL) {
			struct stat fad;
			char dt[1024];

			if (stat(sr->filename, &fad) >= 0) {
				add_results_raw_text(",\n");
				add_results_pair_si("FileAttr", fad.st_mode, ",\n");
				format_filetime_to_str(&(fad.st_ctim), dt, 1023);
				add_results_pair_ss("StatChanged", dt, ",\n");
				format_filetime_to_str(&(fad.st_mtim), dt, 1023);
				add_results_pair_ss("Modified", dt, ",\n");
				add_results_pair_si("Size", get_fsize_from_file_attr(&fad), "");
			}
		}		
#endif

		add_results_raw_text("}");

		// Update inside the lock - may be threaded results
		results_hit_count += (sr->sig_hits);

		add_detected_file(sr->filename);

		if (using_threads) mutex_unlock(&output_mutex);
	}

	trace_signature_scan(0, sr);

	free_scan_results(sr);
	return rc;
}

// Perform the analysis and file scanning operations
// Non threaded version with sleep pause to ease cpu
void epst_scan_file(char *file_path) {
	int yara_result = ERROR_SUCCESS;
	SCAN_RESULTS *scan_results;
	int flags = 0;

	if (fast_scan) flags |= SCAN_FLAGS_FAST_MODE;

	scan_results = perform_signature_scan(0, file_path);
	if (scan_results == NULL) {
		// Most likely an out of memory situation so exit
		add_trace_message(TRACE_WARNING, "Could not allocate scan results data", file_path);
		free(file_path);
		return;
	}

	if (do_yarafile_scan) {
		yara_result = yr_rules_scan_file(
			rules,
			file_path,
			flags,
			scan_callback,
			(void *)scan_results,
			scan_timeout);

		if (yara_result != ERROR_SUCCESS)
		{
			trace_scanner_error(yara_result, file_path);
		}
	}

	process_scan_results(scan_results);

	if (scan_sleep_time > 0) Sleep(scan_sleep_time);
}

void epst_scan_pid(char *name,int pid) {
	int yara_result = ERROR_SUCCESS;
	SCAN_RESULTS *scan_results;
	int flags = 0;

	if (fast_scan) flags |= SCAN_FLAGS_FAST_MODE;

	scan_results = perform_signature_scan(pid, name);
	if (scan_results == NULL) {
		// Most likely an out of memory situation so exit
		add_trace_message(TRACE_WARNING, "Could not allocate scan results data", name);
		return;
	}

	if (do_pid_scan) {
		yara_result = yr_rules_scan_proc(
			rules,
			pid,
			flags,
			scan_callback,
			(void *)scan_results,
			scan_timeout);

		if (yara_result != ERROR_SUCCESS)
		{
			trace_scanner_error(yara_result, name);
		}
		else {
			// Only record successful scans of PIDs
			total_pids_processed++;
		}
	}

	process_scan_results(scan_results);

	if (scan_sleep_time > 0) Sleep(scan_sleep_time);
}

void epst_process_file(char *fpath) {
	char *dup_fpath;

	if (extra_trace_details >= XTRACE_FILES) {
		add_trace_message(TRACE_INFO, "Processing", fpath);
	}
	
	total_files_processed++;

	// Check if CPU throttling mode is active
	if (scan_sleep_time > 0) {
		// Need to make a copy of this string
		// Will be freed by the scan results
		dup_fpath = _strdup(fpath);

		if (dup_fpath == NULL) {
			add_trace_message(TRACE_ERROR, "Filepath strdup error", fpath);
			return;
		}

		epst_scan_file(dup_fpath);
	}
	else {
		// This function does the fpath strdup
		file_queue_put(fpath);
	}
}

// Special filter to eliminate false hits on the yara rules file
int is_yara_rules_file(const char *fullpath, const char *fname) {
	char hbuf[20];
	unsigned long ths = 4;

	// Quick test first to avoid extra processing steps
	if (!(*fname == 'e' || *fname == 'E')) return FALSE;

	if (!strcasecmp(fname, "epstrules.yara") || !strcasecmp(fname, "epstrules.bak")) {
		memset(hbuf, 0, sizeof(hbuf));
		unsigned long rhs = read_file_header(fullpath, ths, hbuf);

		if (rhs == 0 || rhs != ths) {
			// if header can't be read, assume it is
			printf("\n%s: %s\n\n", EPSTTranslate("Warning: Could not read header for EPST Rules File Check"), fullpath);
			return TRUE;
		}
		if (!strncmp(hbuf, "YARA", ths)) return TRUE;

		printf("\n%s: %s\n\n", EPSTTranslate("Warning: Header Mismatch for EPST Rules File Check"), fullpath);
	}
	return FALSE;
}


void epst_unload_pids() {
	int i;

	for (i = 0; i < active_pids_count; i++) {
		// IMPORTANT: memory has already been freed
		// by the process/free results code
		active_pids_names[i] = NULL;
	}
	active_pids_count = 0;
}

void epst_scan_pids() {
	int rc,i;
	char *name;
	char dv[20];

	if (!do_pid_scan) {
		add_trace_message(TRACE_INFO, "Process Memory Scan", "Not Active");
		return;
	}

	add_trace_message(TRACE_INFO, "Process Memory Scan", "Started");

	rc = epst_load_pids_to_scan();
	if (rc != 0) {
		add_trace_message(TRACE_ERROR, "Get Process IDs", "Failed");
		return;
	}

	if (active_pids_count <= 0) {
		add_trace_message(TRACE_WARNING, "Process IDs", "None Found");
		return;
	}
	add_trace_message_value(TRACE_INFO, "Process IDs Found", active_pids_count);

	// Threads not being used for process scans so mutex locking not required
	printf("%s: %d\n", EPSTTranslate("Process IDs Found"), active_pids_count);
	
	for (i = 0; i < active_pids_count; i++) {
		if (epst_timed_out()) break;
		
		name = active_pids_names[i];
		if (name == NULL) name = _strdup("UNKNOWN");

		sprintf(dv, "PID=%d", active_pids[i]);
		add_trace_message(TRACE_INFO, name, dv);
		
		printf("%s %d %s=%d, %s\n", EPSTTranslate("Scan"),i+1, EPSTTranslate("PID"),active_pids[i],name);
		
		if (!strstr(name,"EndpointScanner")) {
			epst_scan_pid(name, active_pids[i]);
		} else {
			printf("%s %s\n", EPSTTranslate("WARNING: Another EPST may be running. Skipping"),name);
		}
	}

	if (i) printf("\n");
	
	epst_unload_pids();

	if (epst_timed_out()) {
		add_trace_message(TRACE_WARNING, "Process Memory Scan", "Timed Out");
	} else {
		add_trace_message(TRACE_INFO, "Process Memory Scan", "Finished");
	}
}

static void register_ip_sighting(char *ipwp) {
	add_trace_message(TRACE_INFO, ipwp, "IP Hit");

	// Avoid duplicate reporting but keep in trace file
	if (epst_strlistitem_exists(url_hits_found, ipwp)) return;
	add_epst_strlistitem(&url_hits_found, ipwp);

	add_results_start_hit();
	add_results_pair_ss("HitType", "IPScan", ", ");
	add_results_pair_ss("Found", ipwp, "}");
	results_hit_count++;

	register_sighting("IPM", ipwp);
}

// IPs may be detected multiple times so this function
// may be called with the same values at different times
// from the socket and dns data. Use a flag to skip if
// it was already found.
void check_ip_hit(char *ip, char *port) {
	int rc;
	char ipwp[1024];

	// Filter the standard ones
	if (!strcmp(ip, "0.0.0.0") || !strcmp(ip, "127.0.0.1")) return;
	if (!strcmp(ip, "::") || !strcmp(ip, "::1")) return;
	if (local_ipv4 != NULL && !strcmp(local_ipv4, ip)) return;
	if (local_ipv6 != NULL && !strcmp(local_ipv6, ip)) return;

	// Port information is useful for analysis but not lookup
	if (*port != '\0') {
		snprintf(ipwp, 1024, "%s#%s", ip, port);
	}
	else {
		strcpy(ipwp, ip);
	}

	add_trace_message(TRACE_INFO, ipwp, "Checking IP");
	rc = bisearch_signature_list(signatures_ips, sigcount_ips, ip);
	if (rc >= 0) {
		register_ip_sighting(ipwp);
	}
}

static void register_dns_sighting(char *dns) {
	add_trace_message(TRACE_INFO, dns, "DNS Hit");

	// Avoid duplicate reporting but keep in trace file
	if (epst_strlistitem_exists(url_hits_found, dns)) return;
	add_epst_strlistitem(&url_hits_found, dns);

	add_results_start_hit();
	add_results_pair_ss("HitType", "DNSScan", ", ");
	add_results_pair_ss("Found", dns, "}");
	results_hit_count++;

	// MRK
	//printf("\nDNS Hit: %s\n", dns);
	register_sighting("DNS", dns);
}

// Check if any regex matches exist in the DNS string buffer
void recheck_dns_hit(char *s) {
	size_t rs, rl, sl;
	char dns[256];
	char *h;

	EPST_StrListItem *list = dns_sig_research;
	sl = strlen(s);

	while (list != NULL) {
		if (list->item != NULL) {
			h = s;
			while (h != NULL) {
				if (do_research(h, list->item, &rs, &rl)) {
					// Extract out the hit from the buffer and advance
					// the pointer to continue checking for more hits
					h = &h[rs];
					
					if (h >= (s + sl)) {
						// exceeds the buffer limits
						fprintf(stderr, "%s", EPSTTranslate("WARNING: DNS Regex Search Result Out of Bounds"));
						h = NULL;
						continue;
					}

					// Trim the boundary characters
					if (*h == ':') { h++; rl--; }
					if (*h == ' ') { h++; rl--; }

					if (rl > 255) rl = 255;
					strncpy(dns, h, rl);
					dns[rl] = '\0';
					
					// Check for end of data buffer
					h = h + rl;
					if (*h == '\0' || h >= (s + sl)) h = NULL;

					// Sanity check - arbitrary minimum size
					if (strlen(dns) > 4) { register_dns_sighting(dns); }
				}
				else {
					// No (more) hits detected for this item
					h = NULL;
				}
			}
		}
		list = list->next;
	}
}

// Check the input string against the list of partial DNS names
// in the hit list. Assumes a : separated set of values in the
// string so both the partial and full values can be registered.
void check_dns_hit(char *s) {
	int i,sl;
	char dns[256], tdns[256];
	char *h = NULL;
	char *t;

	for (i = 0; i < sigcount_dns; i++) {
		h = strstr(s, signatures_dns[i]);
		while (h != NULL) {
			// Found a hit in the buffer
			sl = 0;

			while (*h != ':' && h > s) h--;
			if (*h == ':') h += 2; // Assume one space
			while (*h != ':' && *h != '\0' && sl < 255) {
				dns[sl++] = *h++;
			}
			dns[sl] = '\0';

			if (sl > 0) {
				// Need to perform a few more checks to make sure not a partial match
				if (strcmp(dns, signatures_dns[i])) {
					// Not an exact match so check sub.domain by adding . prefix
					snprintf(tdns, sizeof(tdns), ".%s", signatures_dns[i]);
					t = strstr(dns, tdns);
					if (t == NULL) {
						// Not found as part of subdomain, flag unused
						sl = 0;
					}
				}
			}

			if (sl > 0) { register_dns_sighting(dns); }

			// Continue search after this hit
			h = strstr(h, signatures_dns[i]);
		}
	}

	// Do the regex checks if any
	if (dns_sig_research != NULL) recheck_dns_hit(s);
}

void register_url_sighting(char *hit, char *scantype, char *fname) {
	char event[2048];
	if (hit == NULL) return;

	snprintf(event, 2043, "%s|%s|%s", scantype, fname, hit);
	add_trace_message(TRACE_INFO, event, "HST Hit");

	// Avoid duplicate reporting but keep in trace file
	if (epst_strlistitem_exists(url_hits_found, hit)) return;
	add_epst_strlistitem(&url_hits_found, hit);

	add_results_start_hit();
	add_results_pair_ss("HitType", "HSTScan", ", ");

	add_results_pair_st("Found", "\"", "");
	add_results_yara_escaped_data((uint8_t*)(hit), strlen(hit));
	add_results_raw_text("\",\n");

	add_results_pair_sn("File", fname, "}");

	results_hit_count++;

	// MRK
	//printf("\nHST Hit: %s\n", event);
	register_sighting(scantype, hit);
}


void check_url_hit(char *s, char *src_name) {
	char *sp, *r;
	char hit[1024];
	char dns[1024];
	char *p[] = { "https://", "http://", "tcp://", "ftp://" };
	int n = 4;
	int i;

	// Just in case there are multiple urls in the same string, advance to the nearest
	// prefix to speed up the signature searches which are the most cpu intensive. They
	// use strstr to find the signatures within the string buffer.
	for (i = 0; i < n; i++) {
		if ((sp = strstr(s, p[i])) != NULL) {
			add_trace_message(TRACE_INFO, "Checking URL", sp);

			r = search_with_signature_list(signatures_url, sigcount_url, sp);
			if (r == NULL) {
				r = do_list_research_get_hit(url_sig_research, sp, strlen(sp), hit, 1024);
			}

			if (r != NULL) {
				register_url_sighting(r, "ULM", src_name);
				return;
			}

			// Advance past the url prefix for IP and DNS scan. These scans use a
			// strstr test but need a secondary test to ensure starting after prefix
			sp += strlen(p[i]);

			r = search_with_signature_list(signatures_ips, sigcount_ips, sp);
			if (r != NULL) {
				// Need a few more checks - start after prefix and no extra numbers
				size_t len = strlen(r);
				if (!strncmp(sp, r, len) && !isdigit((int)sp[len])) {
					register_url_sighting(r, "IPM", src_name);
					return;
				}
			}

			r = search_with_signature_list(signatures_dns, sigcount_dns, sp);

			// Need a few more checks - start after prefix
			if (r != NULL) {
				if (strncmp(sp, r, strlen(r))) {
					r = NULL;
				}
			}

			if (r == NULL) {
				// Special for DNS regex
				strcpy(dns, ": ");
				strncpy(dns + 2, sp, 1020);
				dns[1022] = '\0';
				r = do_list_research_get_hit(dns_sig_research, dns, strlen(dns), hit, 1024);
			}

			if (r != NULL) {
				register_url_sighting(r, "DNS", src_name);
				return;
			}
		}
	}
}

static void register_cmd_sighting(char *hit, char *cmdlabel, char *data) {
	char chbuf[2048];

	snprintf(chbuf, 2047, "%s: %s", cmdlabel, hit);
	add_trace_message(TRACE_INFO, chbuf, "CMD Hit");
	add_trace_message(TRACE_INFO, "Output Data", data);

	add_results_start_hit();
	add_results_pair_ss("HitType", "CMDScan", ", ");
	add_results_pair_sn("Label", cmdlabel, ", ");
	add_results_pair_st("Found", "\"", "");
	add_results_yara_escaped_data((uint8_t*)(hit), strlen(hit));
	add_results_raw_text("\"}");

	results_hit_count++;

	// MRK
	//printf("\nCMD Hit: %s\n", chbuf);
	register_sighting("CMD", chbuf);
}

static void scan_syscmd_output(char *data, char *cmdlabel, EPST_StrListItem *research, EPST_StrListItem *sigcodes) {
	size_t sl;
	char hit[1024];
	char *code, *r;

	sl = strlen(data);
	if (sl < 5) return; // arbitrary size

	if (cmdlabel == NULL) cmdlabel = "Unknown";

	while (research != NULL) {
		if (research->item != NULL) {
			if (do_research_get_hit(data, research->item, sl, hit, 1024)) {
				// Sanity check - arbitrary minimum size
				if (strlen(hit) > 1) {
					register_cmd_sighting(hit, cmdlabel, data);
				}
			}
		}
		research = research->next;
	}

	while (sigcodes != NULL) {
		code = sigcodes->item;
		if (code != NULL) {
			r = NULL;
			// Note SCAN_ prefix was skipped over during filter
			if (!strncmp(code, "RKEYS", 5)) {
				r = search_with_signature_list(signatures_rkeys, sigcount_rkeys, data);
			} else
			if (!strncmp(code, "DNS", 3)) {
				r = search_with_signature_list(signatures_dns, sigcount_dns, data);
				if (r == NULL)
					r = do_list_research_get_hit(dns_sig_research, data, sl, hit, 1024);
			} else
			if (!strncmp(code, "URL", 3)) {
				r = search_with_signature_list(signatures_url, sigcount_url, data);
				if (r == NULL)
					r = do_list_research_get_hit(url_sig_research, data, sl, hit, 1024);
			} else
			if (!strncmp(code, "IPS", 3)) {
				r = search_with_signature_list(signatures_ips, sigcount_ips, data);
			} else
			if (!strncmp(code, "FNAMES", 6)) {
				r = search_with_signature_list(signatures_fnames, sigcount_fnames, data);
				if (r == NULL)
					r = do_list_research_get_hit(fname_sig_research, data, sl, hit, 1024);
			} else
			if (!strncmp(code, "MUTEX", 5)) {
				r = search_with_signature_list(signatures_mutex, sigcount_mutex, data);
			}

			if (r != NULL && strlen(r) > 1) {
				register_cmd_sighting(r, cmdlabel, data);
			}
		}
		sigcodes = sigcodes->next;
	}
}

static char last_dns_extracted[256];


// Include platform specific system information gathering code
// Many of these functions require static vars/funcs so inlining
#if defined(_WIN32)
#include "win_system.h"
#endif

#if defined(__APPLE__)
#include "mac_system.h"
#endif

#if defined(__linux__)
#include "linux_system.h"
#endif


static void epst_scan_syscmds() {
	EPST_StrListItem *list = syscmds_to_run;
	EPST_StrListItem *fr = NULL;  // Regex strings
	EPST_StrListItem *fsc = NULL; // Scan Sig Codes
	char *cmd, *label, *sep;

	if (!do_syscmds_scan) return;
	if (syscmds_sig_research == NULL) return;

	while (list != NULL) {
		if (list->item != NULL) {
			cmd = filter_syscmd_research(list->item, syscmds_sig_research, &fr, &fsc);
			if (cmd != NULL) {
				label = list->item;
				add_trace_message(TRACE_INFO, "System Command Start", label);

				// filter function checks for separator, temp split string
				sep = strchr(label, ',');
				if (sep != NULL) *sep = '\0';
				run_scan_syscmd(cmd, label, fr, fsc);
				if (sep != NULL) *sep = ',';

				add_trace_message(TRACE_INFO, "System Command", "Finished");
			}
			else {
				add_trace_message(TRACE_WARNING, "System Command Not Executed", list->item);
			}
			free_epst_strlistitems(&fr);
			free_epst_strlistitems(&fsc);
		}

		list = list->next;
	}
}

static void epst_scan_url() {
	if (!do_url_scan) return;

	add_default_history_files(&history_files_found);
	if (history_files_found == NULL) {
		add_trace_message(TRACE_WARNING, "History Scan", "No Browser History or Bookmark Files Found");
	}
	else {
		add_trace_message(TRACE_INFO, "History Scan", "Started");
		EPST_StrListItem *list = history_files_found;
		while (list != NULL) {
			char *s = list->item;
			if (s != NULL) {
				add_trace_message(TRACE_INFO, "URL Scan", s);
				if (!url_strings_in_file(s)) {
					add_trace_message(TRACE_WARNING, "URL Scan File Read Error", s);
				}
			}
			list = list->next;
		}
		add_trace_message(TRACE_INFO, "History Scan", "Finished");
	}
}

// No real error checking on the runtime folder or fname.
// Should only be called once at the start if a custom output
// folder is required instead of the default current working
// directory normally where the executable lives.
static char *modify_runtime_fname(char *fname) {
	char buf[2048];

	if (fname == NULL) return NULL;
	sprintf(buf, "%s%c%s", use_runtime_folder,DIR_SEP, fname);
	return _strdup(buf);
}

static void update_output_fnames() {
	if (use_runtime_folder == NULL) use_runtime_folder = ".";
	if (!strcmp(use_runtime_folder,".")) return;

	// NOTE: Known memory "leak": modified runtime file names are
	// allocated but not freed, left for exit to cleanup

	// If using local rules, assume these are in the default
	// location with the license key and executable.
	if (use_local_rules == FALSE) {
		compiled_rules_fname = modify_runtime_fname(compiled_rules_fname);
		sig_md5_fname = modify_runtime_fname(sig_md5_fname);
		sig_sha1_fname = modify_runtime_fname(sig_sha1_fname);
		sig_sha256_fname = modify_runtime_fname(sig_sha256_fname);
		sig_dns_fname = modify_runtime_fname(sig_dns_fname);
		sig_url_fname = modify_runtime_fname(sig_url_fname);
		sig_ips_fname = modify_runtime_fname(sig_ips_fname);
		sig_fnames_fname = modify_runtime_fname(sig_fnames_fname);
		sig_rkeys_fname = modify_runtime_fname(sig_rkeys_fname);
		sig_mutex_fname = modify_runtime_fname(sig_mutex_fname);
		sig_events_fname = modify_runtime_fname(sig_events_fname);
		regex_test_fname = modify_runtime_fname(regex_test_fname);
		epstlocal_fname = modify_runtime_fname(epstlocal_fname);
	}

	scan_detected_files_fname = modify_runtime_fname(scan_detected_files_fname);
	scan_results_fname = modify_runtime_fname(scan_results_fname);
	scan_trace_fname = modify_runtime_fname(scan_trace_fname);
	eventhits_fname = modify_runtime_fname(eventhits_fname);
}

#define exit_with_code(code) { rc = code; goto _exit; }


int main(int argc, const char** argv, const char *envp[]) {
	int rc = 0;
	char *next_dir;
	int result;

	argc = args_parse(options, argc, argv);

	init_translate_data();

	if (show_version) {
		printf("%s %s\n", EPSTTranslate("Endpoint Scanner Version"), EPST_VERSION);
		printf("%s %s\n", EPSTTranslate("YARA Library Version"), YR_VERSION);
		return EXIT_SUCCESS;
	}

	if (show_help)
	{
		printf("%s\n", EPSTTranslate("End Point Scanning Tool uses signature data and Yara rules"));
		printf("%s\n\n", EPSTTranslate("to check files, processes and system resources for malware."));

		args_print_usage(options, 35);

		printf("\n%s\n", EPSTTranslate("Important Files (Rules, Signatures, Trace, Results):"));
		printf("  %s\n", compiled_rules_fname);
		printf("  %s\n", scan_results_fname);
		printf("  %s\n", scan_trace_fname);
		printf("  %s\n", eventhits_fname);
		printf("  %s\n", sig_md5_fname);
		printf("  %s\n", sig_sha1_fname);
		printf("  %s\n", sig_sha256_fname);
		printf("  %s\n", sig_dns_fname);
		printf("  %s\n", sig_url_fname);
		printf("  %s\n", sig_ips_fname);
		printf("  %s\n", sig_events_fname);
		printf("  %s\n", sig_fnames_fname);
		printf("  %s\n", sig_rkeys_fname);
		printf("  %s\n", sig_mutex_fname);
		printf("  %s\n", api_key_fname);
		printf("  dirlist.txt\n\n");

		return EXIT_SUCCESS;
	}

	if (!IsUserAdmin()) {
		printf("\n\n");
		printf("****************************************************************\n");
		printf("%s\n", EPSTTranslate("************** WARNING: NOT Running as Admin/Root **************"));
		printf("****************************************************************\n\n");
	}
	else {
		running_as_admin = TRUE;
	}

	if (extra_trace_details < XTRACE_NONE) extra_trace_details = XTRACE_NONE;
	if (extra_trace_details > XTRACE_HASH) extra_trace_details = XTRACE_HASH;

	// Read the API key from the license file if it exists
	// or set it to some default - this value is used by the
	// central MISP interface server to match up with a
	// registered organization. It also ties in with other
	// reporting and analysis services.
	api_key = get_first_string_in_file(api_key_fname);
	if (api_key == NULL) api_key = _strdup("fefefe00000000000000f8f8f8");

	if (suppress_results_upload) {
		auto_register_sightings = FALSE;
		suppress_samples_upload = TRUE;
	}

	// Check if any hits to the server are required - either upload or download
	if (auto_register_sightings || download_signatures || upload_results_file ||
		(use_local_rules == FALSE) || (suppress_results_upload == FALSE)) {
		if (initialize_curl()) return EXIT_FAILURE;
	}

	update_output_fnames();

	if (upload_results_file) {
		printf("%s\n", EPSTTranslate("Uploading results JSON file"));
		calc_report_hash();
		rc = upload_scan_results_file(scan_results_fname, api_key, scan_results_sha256);

		finalize_curl();
		return rc;
	}

	if (download_signatures) {
		printf("%s\n", EPSTTranslate("Downloading rules and signature files"));

		if (do_experimental && do_yara_source) {
			printf("%s\n", EPSTTranslate("Experimental Development Signatures Mode Active"));
			download_signature_file(compiled_rules_fname, "experimentals", api_key, EPST_VERSION);
		}
		else if (do_experimental) {
			printf("%s\n", EPSTTranslate("Experimental Signatures Mode Active"));
			download_signature_file(compiled_rules_fname, "experimental", api_key, EPST_VERSION);
		}
		else if (do_yara_source) {
			printf("%s\n", EPSTTranslate("Development Signatures Mode Active"));
			download_signature_file(compiled_rules_fname, "yaras", api_key, EPST_VERSION);
		}
		else {
			download_signature_file(compiled_rules_fname, "yara", api_key, EPST_VERSION);
		}
		download_signature_file(sig_md5_fname, "md5", api_key, EPST_VERSION);
		download_signature_file(sig_sha1_fname, "sha1", api_key, EPST_VERSION);
		download_signature_file(sig_sha256_fname, "sha256", api_key, EPST_VERSION);
		download_signature_file(sig_dns_fname, "domain", api_key, EPST_VERSION);
		download_signature_file(sig_url_fname, "url", api_key, EPST_VERSION);
		download_signature_file(sig_ips_fname, "ip", api_key, EPST_VERSION);
		download_signature_file(sig_fnames_fname, "filename", api_key, EPST_VERSION);
		download_signature_file(sig_rkeys_fname, "regkey", api_key, EPST_VERSION);
		download_signature_file(sig_mutex_fname, "mutex", api_key, EPST_VERSION);
		download_signature_file(sig_events_fname, "events", api_key, EPST_VERSION);

		if (download_signatures) {
			finalize_curl();
			return EXIT_SUCCESS;
		}
	}

	if (num_threads_to_use > YR_MAX_THREADS)
	{
		fprintf(stderr, "%s %d\n", EPSTTranslate("Maximum number of threads is"), YR_MAX_THREADS);
		return EXIT_FAILURE;
	}

	// Some option checks
	if (scan_timeout < 5) { scan_timeout = 5; }
	if (epst_timeout < 60) { epst_timeout = 60; }
	if (scan_timeout > epst_timeout) { scan_timeout = epst_timeout; }
	
	// Default set to max 24 hrs full scan, 23 hrs allocated for file system
	// Keep proportion similar if timeout values are set on command line
	epst_filescan_timeout = (epst_timeout/24)*23;
	
	main_start_time = time(NULL);
	
	printf("%s\n", EPSTTranslate("Starting Endpoint Scan"));
	if ((rc = epst_initialize()) != 0) exit_with_code(rc);

	if (extra_trace_details > XTRACE_NONE) { trace_dump_env(envp); }
	trace_dum_dirlist();

	// These are relatively fast and could change by the time a longer running
	// file scan completes so these are run before and possibly after as well
	epst_scan_sockets();
	epst_scan_dns();

	// Note that this could already be initialized for the DNS scan
	init_file_hash_buffer();

	// Possible increase the number of slots available
	if (stack_size != DEFAULT_STACK_SIZE && stack_size > 10000)
	{
		yr_set_configuration(YR_CONFIG_STACK_SIZE, &stack_size);
	}
	
	// Create an External Variable indicating files being scanned
	if (rules != NULL) {
        if ( (result = yr_rules_define_boolean_variable(rules,"is_filescan",TRUE)) != ERROR_SUCCESS) {
			add_trace_message(TRACE_INFO, "Could not define external variable is_filescan to", "TRUE");
        }
	}

	if (do_yarafile_scan || do_hash_scan || do_fnames_scan)
	{
		add_trace_message(TRACE_INFO, "File Scan", "Start");

		if (scan_sleep_time == 0) {
			add_trace_message(TRACE_INFO, "Threaded Processing", "Active");

			// No CPU throttling so blast through it with threads
			if ((rc = epst_init_threads()) != 0) exit_with_code(rc);
		}

		// Do any translation once as globals since these messages are printed alot
		skipdirmsg = EPSTTranslate("Directories Skipped");
		scandirmsg = EPSTTranslate("Scanned");
		skipfilemsg = EPSTTranslate("Files Skipped");
		scanfilemsg = EPSTTranslate("Scanned");

		printf("\n");
		print_scan_progress(FALSE);

		while ((next_dir = dirlist_next_dir()) != NULL) {
			epst_process_dir(next_dir);
		}

		if (scan_sleep_time == 0) {
			// Wait for the threads to finish
			add_trace_message(TRACE_INFO, "Finalizing Threads", "Start");
			epst_finialize_threads();
			add_trace_message(TRACE_INFO, "Finalizing Threads", "Finished");
		}

		print_scan_progress(TRUE);

		if (epst_filescan_timed_out()) {
			add_trace_message(TRACE_WARNING, "EPST File Scan", "Timed Out");			
		}
		printf("\n%s\n", EPSTTranslate("File Scan Complete"));
		add_trace_message(TRACE_INFO, "File Scan", "Finished");
	}

	// Update External Variable indicating process memory being scanned not files
	if (rules != NULL) {
        if ( (result = yr_rules_define_boolean_variable(rules,"is_filescan",FALSE)) != ERROR_SUCCESS) {
			add_trace_message(TRACE_INFO, "Could not define external variable is_filescan to", "FALSE");
        }
	}

	printf("%s\n", EPSTTranslate("Starting System Scan"));
	if (running_as_admin) {
		if (!epst_timed_out()) { epst_scan_pids(); }
	} else if (do_pid_scan) {
		printf("\n%s\n\n", EPSTTranslate("Not Running as Admin: Skipping Process Scan"));
	}
	
	if (!epst_timed_out()) { epst_scan_mutex(); }
	if (!epst_timed_out()) { epst_scan_rkeys(); }

#if defined(_WIN32)

	if (running_as_admin) {
		if (!epst_timed_out()) { epst_scan_event_files(); }
	}
	else if (do_event_scan) {
		printf("\n%s\n\n", EPSTTranslate("Not Running as Admin: Skipping Event Log Scan"));
	}
#endif

	epst_scan_url();
	epst_scan_syscmds();

	if (epst_do_scan_again()) {
		if (!epst_timed_out()) { epst_scan_sockets(); }
		if (!epst_timed_out()) { epst_scan_dns(); }
	}

	printf("%s\n", EPSTTranslate("Finished System Scan"));

_exit:

	epst_finalize();
	cleanup_hit_detail_files();
	free_translate_data();

	printf("%s\n", EPSTTranslate("Finished Endpoint Scan"));

	return rc;
}