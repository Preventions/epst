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

// WINDOWS VERSION
// This file contains code blocks designed to obtain system information which is mostly
// platform specific. Separating the code to avoid complicating it with too many ifdefs
// although this will result in some duplication. Corresponding versions for OSX/Linux
// should follow the same function prototypes. This is primarily required to compensate
// for system commands returning data in different formats.


void get_system_config() {
	char pbuf[256];
	char *g;
	FILE *pfp;

	if ((pfp = _popen("ipconfig /all", "rt")) == NULL) {
		add_trace_message(TRACE_ERROR, "System Config", "Pipe Open Failed");
		return;
	}

	// Only get the first value assuming it is most relevant
	// Also make sure not to leak memory by overwriting
	while (fgets(pbuf, 256, pfp)) {
		if (strstr(pbuf, "Host Name") != NULL) {
			if (host_name == NULL)
				host_name = extract_ipconfig_data(pbuf);
			continue;
		}
		if (strstr(pbuf, "Physical Address") != NULL) {
			if (physical_address == NULL)
				physical_address = extract_ipconfig_data(pbuf);
			continue;
		}

		if (strstr(pbuf, "Link-local IPv6 Address") != NULL) {
			if (local_ipv6 == NULL)
				local_ipv6 = extract_ipconfig_data(pbuf);
			if (local_ipv6 == NULL) continue;

			// Get rid of the zone and preferred attributes
			if ((g = strchr(local_ipv6, '%'))) {
				*g = '\0';
				continue;
			}
			if ((g = strchr(local_ipv6, '('))) {
				*g = '\0';
				continue;
			}
		}

		if (strstr(pbuf, "IPv4 Address") != NULL) {
			if (local_ipv4 == NULL)
				local_ipv4 = extract_ipconfig_data(pbuf);
			if (local_ipv4 == NULL) continue;

			// Get rid of the zone and preferred attributes
			if ((g = strchr(local_ipv4, '('))) {
				*g = '\0';
				continue;
			}
		}
	}

	if (!feof(pfp)) {
		add_trace_message(TRACE_WARNING, "System Config Interrupted", "EOF Not Reached");
	}

	_pclose(pfp);
	return;
}

static void query_win_event_logs() {
	char pbuf[256];
	FILE *pfp;

	add_trace_message(TRACE_INFO, "Query Enumerate Event Logs", "Start");
	if ((pfp = _popen("wevtutil el", "rt")) == NULL) {
		add_trace_message(TRACE_ERROR, "Event Log Enumerate List", "Pipe Open Failed");
		return;
	}

	while (fgets(pbuf, 256, pfp)) {
		size_t sl = strlen(pbuf);
		if (sl > 0 && pbuf[sl - 1] == '\n') { pbuf[--sl] = '\0'; }
		if (sl > 0 && pbuf[sl - 1] == '\r') { pbuf[--sl] = '\0'; }

		if (sl > 0) { add_epst_strlistitem(&event_files_found, pbuf); }
	}

	if (!feof(pfp)) {
		add_trace_message(TRACE_WARNING, "Event Log Enumerate List Interrupted", "EOF Not Reached");
	}

	_pclose(pfp);
	add_trace_message(TRACE_INFO, "Query Enumerate Event Logs", "End");
	return;
}

static size_t evt_data_size = 0;
static int current_evt_id = -1;
static char *current_event_fname;

void register_evt_sighting(char *hit, char *scantype) {
	char event[2048];
	char *h = (hit == NULL ? "EVENTID" : hit);

	snprintf(event, 2043, "EID|%d|%s|%s|%s", current_evt_id, scantype, current_event_fname, h);
	add_trace_message(TRACE_INFO, event, "EVT Hit");

	add_results_start_hit();
	add_results_pair_ss("HitType", "EVTScan", ", ");

	add_results_pair_st("Found", "\"", "");
	add_results_yara_escaped_data((uint8_t*)(h), strlen(h));
	add_results_raw_text("\",\n");

	add_results_pair_sn("File", current_event_fname, ",\n");
	add_results_pair_ss("ScanType", scantype, ",\n");
	add_results_pair_si("EventID", current_evt_id, "}");

	results_hit_count++;

	// MRK
	//printf("\nEVT Hit: %s\n", event);
	register_sighting("EVT", event);
}


void file_evt_sighting(char *hit, char *scantype) {
	char *h = (hit == NULL ? "EVENTID" : hit);

	if (eventhits_fp == NULL) return;

	fprintf(eventhits_fp, "EID:%d:%s:%s\nHit:%s\n", current_evt_id, scantype, current_event_fname, h);
}

void file_evt_details(char *details) {
	if (eventhits_fp == NULL) return;

	fprintf(eventhits_fp, "Event: %s\n=================================\n\n", details);
}

void init_scan_evt_buffer() {
	current_evt_id = -1;
	evt_data_size = 0;
	file_data_buffer[0] = '\0';
}

void process_scan_evt_buffer() {
	EPST_EventSignature *list;
	char hit[1024];

	// Check if a event has been extracted properly
	if (evt_data_size == 0 || current_evt_id == -1) {
		init_scan_evt_buffer();
		return;
	}

	update_eventid_stats(current_evt_id);

	if (current_evt_id >= max_event_id) {
		printf("EXCEEDS MAX EVENT ID: %d %s\n", current_evt_id, current_event_fname);
		init_scan_evt_buffer();
		return;
	}

	// Do special case for signatures assigned to all (0) then the specific ID
	for (int i = 0; i < 2; i++) {
		if (i == 0) { list = event_signatures[0]; }
		else        { list = event_signatures[current_evt_id]; }

		// Special check to avoid double scan
		if (i == 1 && current_evt_id == 0) list = NULL;

		while (list != NULL) {
			char *sc,*r,*s;
			switch (list->scan_type) {
			case EPST_SCAN_RKEYS:
				sc = "SCAN_RKEYS";
				r = search_with_signature_list(signatures_rkeys, sigcount_rkeys, file_data_buffer);
				break;
			case EPST_SCAN_DNS:
				sc = "SCAN_DNS";
				r = search_with_signature_list(signatures_dns, sigcount_dns, file_data_buffer);
				if (r == NULL)
					r = do_list_research_get_hit(dns_sig_research, file_data_buffer, evt_data_size, hit, 1024);
				break;
			case EPST_SCAN_URL:
				sc = "SCAN_URL";
				r = search_with_signature_list(signatures_url, sigcount_url, file_data_buffer);
				if (r == NULL)
					r = do_list_research_get_hit(url_sig_research, file_data_buffer, evt_data_size, hit, 1024);
				break;
			case EPST_SCAN_IPS:
				sc = "SCAN_IPS";
				r = search_with_signature_list(signatures_ips, sigcount_ips, file_data_buffer);
				break;
			case EPST_SCAN_FNAMES:
				sc = "SCAN_FNAMES";
				r = search_with_signature_list(signatures_fnames, sigcount_fnames, file_data_buffer);
				if (r == NULL)
					r = do_list_research_get_hit(fname_sig_research, file_data_buffer, evt_data_size, hit, 1024);
				break;
			case EPST_SCAN_MUTEX:
				sc = "SCAN_MUTEX";
				r = search_with_signature_list(signatures_mutex, sigcount_mutex, file_data_buffer);
				break;
			default:
				sc = "SCAN_REGEX";
				s = list->signature;
				if (s == NULL) { r = "EVENTID"; }
				else { r = do_research_get_hit(file_data_buffer, s, evt_data_size, hit, 1024); }
				break;
			}

			// Check for a result and register it
			if (r != NULL) {
				register_evt_sighting(r, sc);
				file_evt_sighting(r, sc);
				file_evt_details(file_data_buffer);
			}
			list = list->next;
		}
	}
	
	init_scan_evt_buffer();
}

static void query_parse_events(const char *cmd) {
	char pbuf[1024];
	FILE *pfp;

	if ((pfp = _popen(cmd, "rt")) == NULL) {
		add_trace_message(TRACE_ERROR, "Event Log Query Parse", "Pipe Open Failed");
		return;
	}

	init_scan_evt_buffer();

	while (fgets(pbuf, 1024, pfp)) {
		size_t sl = strlen(pbuf);
		// Special case to keep newline but strip line return \r\n to \n
		// The newline may be important for the regex expressions (just in case)
		if (sl > 0 && pbuf[sl - 1] == '\n') { pbuf[--sl] = '\0'; }
		if (sl > 0 && pbuf[sl - 1] == '\r') { pbuf[--sl] = '\n'; }

		if (sl <= 1) continue;

		if (sl > 6 && !strncmp(pbuf, "Event[", 6)) {
			process_scan_evt_buffer();
			continue;
		}

		if (sl > 12 && !strncmp(pbuf, "  Event ID: ", 12)) {
			current_evt_id = atoi(pbuf + 12);

			if (current_evt_id >= max_event_id) {
				add_trace_message_value(TRACE_WARNING, "Found Out of Range Event ID:", current_evt_id);
			}
		}

		if ((evt_data_size + sl + 1) < file_data_buffer_size) {
			strcpy((char *)(file_data_buffer)+evt_data_size, pbuf);
			evt_data_size += sl;
		}
		else {
			// Not going to fit in the buffer so process and ignore the rest
			add_trace_message(TRACE_WARNING, "Event Details Exceeded Buffer", "Truncating");
			process_scan_evt_buffer();
			continue;
		}
	}

	process_scan_evt_buffer();

	if (!feof(pfp)) {
		add_trace_message(TRACE_WARNING, "Event Log Query Interrupted", "EOF Not Reached");
	}

	_pclose(pfp);
	return;
}


static void run_scan_syscmd(char *cmd, char *label, EPST_StrListItem *research, EPST_StrListItem *sigcodes) {
	char pbuf[2048];
	FILE *pfp;

	if ((pfp = _popen(cmd, "rt")) == NULL) {
		add_trace_message(TRACE_ERROR, cmd, "Pipe Open Failed");
		return;
	}

	while (fgets(pbuf, 2048, pfp)) {
		size_t sl = strlen(pbuf);
		if (sl > 0 && pbuf[sl - 1] == '\n') { pbuf[--sl] = '\0'; }
		if (sl > 0 && pbuf[sl - 1] == '\r') { pbuf[--sl] = '\0'; }

		if (sl > 0) {
			scan_syscmd_output(pbuf, label, research, sigcodes);
		}
	}

	_pclose(pfp);
	return;
}

static void trace_dump_command_output(const char *cmd) {
	char pbuf[1024];
	FILE *pfp;

	if (!trace_to_file || trace_fp == NULL) return;

	if ((pfp = _popen(cmd, "rt")) == NULL) {
		add_trace_message(TRACE_ERROR, cmd, "Pipe Open Failed");
		return;
	}

	fprintf(trace_fp, "CMD: %s\n", cmd);
	while (fgets(pbuf, 1024, pfp)) {
		size_t sl = strlen(pbuf);
		if (sl > 0 && pbuf[sl - 1] == '\n') { pbuf[--sl] = '\0'; }
		if (sl > 0 && pbuf[sl - 1] == '\r') { pbuf[--sl] = '\0'; }

		if (sl > 0) {
			fprintf(trace_fp, "%s\n", pbuf);
		}
	}

	_pclose(pfp);
	return;
}

static void epst_scan_event_files() {
	EPST_StrListItem *list;
	char cmd[1024];
	size_t sl;

	// Directly reference the global variables defined in endpoint.c
	if (event_signatures == NULL) return;
	if (!do_event_scan) return;

	// Open the file to store event hit details
	initialize_eventhits();

	if (file_data_buffer == NULL) {
		add_trace_message(TRACE_ERROR, "Event Log Buffer", "Allocation Failed");
		return;
	}

	if (event_files_found == NULL) { query_win_event_logs(); }
	if (event_files_found == NULL) {
		add_trace_message(TRACE_WARNING, "Event Log Scan", "No Log Files Found");
		return;
	}

	add_trace_message(TRACE_INFO, "Scan Event Logs", "Start");
	list = event_files_found;
	while (list != NULL) {
		char *efname = list->item;
		// Make sure the resulting command string fits the buffer
		if (efname != NULL && (sl = strlen(efname)) < 1000) {
			BOOL is_file = FALSE;
			current_event_fname = efname;
			is_file = is_win_event_file(efname);
			add_trace_message(TRACE_INFO, "Scan Event Log", efname);
			if (extra_trace_details > XTRACE_NONE) {
				if (is_file) {
					snprintf(cmd, 1023, "wevtutil gli \"%s\" /lf", efname);
					trace_dump_command_output(cmd);
				}
				else {
					snprintf(cmd, 1023, "wevtutil gl \"%s\" /f:text", efname);
					trace_dump_command_output(cmd);
					snprintf(cmd, 1023, "wevtutil gli \"%s\"", efname);
					trace_dump_command_output(cmd);
				}
			}

			if (is_file) { snprintf(cmd, 1023, "wevtutil qe \"%s\" /lf /f:text", efname); }
			else		 { snprintf(cmd, 1023, "wevtutil qe \"%s\" /f:text", efname); }

			query_parse_events(cmd);
		}
		list = list->next;
	}
	trace_dump_eventid_stats();
	add_trace_message(TRACE_INFO, "Scan Event Logs", "End");
}


// Currently uses global data structures but setup the
// function to potentially use a different mechanism
int epst_load_pids_to_scan() {
	int cpid,i;
	char pbuf[1024];
	char *np,*pp;
	FILE *pfp;

	active_pids_count = 0;

	// Just in case let's initialize these arrays
	for (i = 0; i < (MAX_EPST_PID_COUNT); i++) {
		active_pids_names[i] = NULL;
		active_pids[i] = 0;
	}

	// This version uses the tasklist command
	if ((pfp = _popen("tasklist /NH /FO CSV", "rt")) == NULL) {
		add_trace_message(TRACE_ERROR, "Process List", "Pipe Open Failed");
		return 1;
	}

	cpid = GetCurrentProcessId();

	// Can't use sscanf to extract the image name and pid since
	// the image name might include spaces. Using the csv output
	// format to improve parsing.
	while (fgets(pbuf, 1024, pfp)) {
		if (*pbuf == '\"' && (pp = strstr(pbuf, "\",\"")) != NULL && isdigit(*(pp + 3)) ) {
			*pp = '\0';
			pp += 3;
			np = pbuf + 1;

			active_pids[active_pids_count] = atoi(pp);
			if (active_pids[active_pids_count] == cpid || active_pids[active_pids_count] == 0) continue;

			if (!strcmp("tasklist.exe", np)) continue;

			active_pids_names[active_pids_count] = _strdup(np);
			active_pids_count++;
			if (active_pids_count >= (MAX_EPST_PID_COUNT)) break;
		}
	}

	if (!feof(pfp)) {
		add_trace_message(TRACE_WARNING, "Process Identification Interrupted", "EOF Not Reached");
	}

	_pclose(pfp);
	return 0;
}

static int epst_dir_file_count(const char *scanDir, int stop_at_limit)
{
	WIN32_FIND_DATA fdFile;
	HANDLE hFind = NULL;
	int file_count = 0;

	char path_mask[MAX_PATH];

	size_t dl = strlen(scanDir);
	if (dl >= (MAX_PATH - 3)) { return 0; }

	//Specify a file mask with a * wildcard to find everything
	snprintf(path_mask, sizeof(path_mask), "%s\\*", scanDir);

	if ((hFind = FindFirstFile(path_mask, &fdFile)) == INVALID_HANDLE_VALUE) { return 0; }

	do
	{
		if (!(fdFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			file_count++;
		}

		if (stop_at_limit > 0 && file_count >= stop_at_limit) break;

	} while (FindNextFile(hFind, &fdFile));

	FindClose(hFind);
	return file_count;
}

static void fp_add_json_proximity_filelist(FILE *fp, const char *hitDir, const char *hitFile) {
	WIN32_FIND_DATA fdFile;
	HANDLE hFind = NULL;
	int file_count = 0;
	char path_mask[MAX_PATH];

	size_t dl = strlen(hitDir);
	if (dl >= (MAX_PATH - 3)) { return; }

	//Specify a file mask with a * wildcard to find everything
	snprintf(path_mask, sizeof(path_mask), "%s\\*", hitDir);

	if ((hFind = FindFirstFile(path_mask, &fdFile)) == INVALID_HANDLE_VALUE) { return; }

	do
	{
		if (!strcmp(fdFile.cFileName, hitFile)) continue;

		if (!(fdFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			fp_add_json_proximity_filelist_item(fp,hitDir, fdFile.cFileName, file_count);
			file_count++;
		}
	} while (FindNextFile(hFind, &fdFile));

	FindClose(hFind);
}



// WINDOWS VERSION of directory scan
int epst_process_dir(const char *scanDir)
{
	WIN32_FIND_DATA fdFile;
	HANDLE hFind = NULL;
	int recurse;

	static char path_with_mask[MAX_PATH];

	// Assume recursion of all directories unless flagged
	const int scan_code = dirlist_get_scan_mode(scanDir);
	switch (scan_code) {
	case DIRLIST_EXCLUDE:
		add_trace_message(TRACE_INFO, "Excluded", scanDir);
		skipped_directories++;
		return FALSE;
	case DIRLIST_SCAN_ONLY:
		recurse = FALSE;
		break;
	case DIRLIST_RECURSE:
		recurse = TRUE;
		break;
	default:
		recurse = TRUE;
	}

	size_t dl = strlen(scanDir);
	if (dl >= (MAX_PATH - 3)) {
		add_trace_message(TRACE_WARNING, "Skipping Path Too Long", scanDir);
		skipped_directories++;
		return FALSE;
	}

	//Specify a file mask with a * wildcard to find everything
	snprintf(path_with_mask, sizeof(path_with_mask), "%s\\*", scanDir);

	if ((hFind = FindFirstFile(path_with_mask, &fdFile)) == INVALID_HANDLE_VALUE)
	{
		add_trace_message(TRACE_WARNING, "Directory Access Denied", path_with_mask);
		skipped_directories++;
		return FALSE;
	}

	scanned_directories++;

	do
	{
		//Filter out the control directories
		if (strcmp(fdFile.cFileName, ".") != 0 && strcmp(fdFile.cFileName, "..") != 0)
		{
			char full_path[MAX_PATH];

			snprintf(full_path, sizeof(full_path), "%s\\%s", scanDir, fdFile.cFileName);

			if (fdFile.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY)
			{
				if (recurse == TRUE) {
					// Check for potential symbolic link - issue discovered with recursive links
					if (fdFile.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
						add_trace_message(TRACE_WARNING, "Skipping Symbolic Link", full_path);
						skipped_directories++;
					}
					else {
						epst_process_dir(full_path);
					}
				}
				else {
					add_trace_message(TRACE_INFO, "Skipping Directory", full_path);
					skipped_directories++;
				}
			}
			else if (is_yara_rules_file(full_path, fdFile.cFileName) == TRUE) {
				add_trace_message(TRACE_INFO, "Skipping Yara Rules File", full_path);
				skipped_files++;
			}
			else if (dirlist_filter_file(full_path) == DIRLIST_SCAN_ONLY) {
				// This updates total files processed
				epst_process_file(full_path);

				if (do_event_scan) {
					if (is_win_event_file(full_path)) {
						add_epst_strlistitem(&event_files_found, full_path);
					}
				}

				if (do_url_scan) {
					if (is_history_file(fdFile.cFileName)) {
						add_epst_strlistitem(&history_files_found, full_path);
					}
				}
			}
			else {
				skipped_files++;
			}

			// Generate some indicator of progress and activity
			print_scan_progress(FALSE);
		}
	} while (FindNextFile(hFind, &fdFile) && !epst_filescan_timed_out());

	// Depth first search so print trace message afterwards.
	// Added folder trace to give sense of progress when there
	// are huge numbers of empty folders. Also useful for restarts
	// in the event of a crash.
	if (extra_trace_details > XTRACE_NONE) {
		add_trace_message(TRACE_INFO, "Scanned Directory", scanDir);
	}

	FindClose(hFind);
	return TRUE;
}


// Assumes a string from netstat - check for likely IP
// Return pointer past the IP address or NULL if not found.
// Input string will be modified to segment data.
char *extract_check_ipv4(char *s) {
	char *cp, *pp, *port;

	pp = strchr(s, '.');
	if (pp != NULL) {
		// reverse to whitespace
		while (isdigit(pp[-1])) pp--;

		// Find the end of the IP address (port)
		cp = strchr(pp, ':');
		if (cp != NULL) {
			*cp++ = '\0';
			port = cp;
			while (isdigit(*cp)) cp++;
			*cp++ = '\0';
		}
		else {
			// Advance to end of string
			// Unlikely to be a valid IP
			while (*cp != '\0') cp++;
			port = "";
		}
		check_ip_hit(pp,port);
		return cp;
	}
	return NULL;
}

char *extract_check_ipv6(char *s) {
	char *cp, *pp, *zone, *port;

	pp = strchr(s, '[');
	if (pp != NULL) {
		pp++;

		// Find the end of the IP address (port)
		cp = strchr(pp, ']');
		if (cp != NULL) {
			*cp++ = '\0';
			port = ++cp; // skip semi-colon
			while (isdigit(*cp)) cp++;
			*cp++ = '\0';
		}
		else {
			// Advance to end of string
			// Unlikely to be a valid IP
			while (*cp != '\0') cp++;
			port = "";
		}

		// Check for zone attribute and strip it
		zone = strchr(pp, '%');
		if (zone != NULL) *zone = '\0';

		check_ip_hit(pp,port);
		return cp;
	}
	return NULL;
}


// Scan the open sockets and check the IP addresses found
// against a known set of bad addresses in sorted list.
// Assumes well formed data from netstat command.
void epst_scan_sockets() {
	char pbuf[256];
	char *remaining;
	FILE *pfp;

	if (!do_ips_scan) return;

	add_trace_message(TRACE_INFO, "Socket Scan", "Started");

	if ((pfp = _popen("netstat -an", "rt")) == NULL) {
		add_trace_message(TRACE_ERROR, "Open Socket List", "Pipe Open Failed");
		return;
	}

	while (fgets(pbuf, 256, pfp)) {
		// check for first (local) IPv4 address
		if ((remaining = extract_check_ipv4(pbuf)) != NULL) {
			// check for the second (foreign) address
			extract_check_ipv4(remaining);
		}
		else {
			// Possibly IPv6 address format
			if ((remaining = extract_check_ipv6(pbuf)) != NULL) {
				// check for the second (foreign) address
				extract_check_ipv6(remaining);
			}
		}
	}

	if (!feof(pfp)) {
		add_trace_message(TRACE_WARNING, "Socket Identification Interrupted", "EOF Not Reached");
	}

	_pclose(pfp);

	add_trace_message(TRACE_INFO, "Socket Scan", "Finished");

	return;
}

// Extract the dns or IP information from the ipconfig output.
// Strip off the new line and either add it to the dns buffer
// or perform the check on the fly. If an IP, check immediately
// since they are sorted items with a fast binary lookup.
void extract_dns_data(char *s, int isIP) {
	size_t sl;

	sl = strlen(s);
	if (sl > 0 && s[sl - 1] == '\n') { s[--sl] = '\0'; }
	if (sl > 0 && s[sl - 1] == '\r') { s[--sl] = '\0'; }

	if (isIP) {
		// skip over the leading ': ' characaters
		s += 2; 
		check_ip_hit(s,"");
	}
	else {
		if (!strcmp(last_dns_extracted, s)) return;

		if ((dns_data_size + sl + 1) < file_data_buffer_size) {
			// Include the leading ': ' separator characters
			strcpy((char *)(file_data_buffer) + dns_data_size, s);
			dns_data_size += sl;
			add_trace_message(TRACE_INFO, "DNS Buffered", s+2);
		}
		else {
			// Not going to fit in the buffer so scan individual
			add_trace_message(TRACE_INFO, "DNS Scan", s+2);
			check_dns_hit(s);
		}
		strcpy(last_dns_extracted, s);
	}
}

// Could possibly check each found dns against the list as they
// are read from the pipe but each search could take a while if
// there are a lot of signatures to check. This may cause issues
// with the pipe so instead, allocate a fairly large buffer and
// concat all the dns cache values together with a : separator.
// If the buffer could not be allocated or is too small, fall
// back to scan on the fly.
void epst_scan_dns() {
	char pbuf[256];
	unsigned char *nb;
	size_t sl;
	char *cp;
	FILE *pfp;

	if (!do_dns_scan) return;

	add_trace_message(TRACE_INFO, "DNS Scan", "Started");

	// Reuse the file data buffer since it is nolonger needed
	// but attempt to increase the size for more dns items.
	nb = (unsigned char *)malloc(sizeof(unsigned char)*(DNS_BUFFER_SIZE));
	if (nb != NULL) {
		if (file_data_buffer != NULL) free(file_data_buffer);
		file_data_buffer = nb;
		file_data_buffer_size = DNS_BUFFER_SIZE;
	}
	dns_data_size = 0;
	last_dns_extracted[0] = '\0';

	if (file_data_buffer == NULL) {
		add_trace_message(TRACE_ERROR, "DNS Buffer", "Allocation Failed");
		return;
	}

	if ((pfp = _popen("ipconfig /displaydns", "rt")) == NULL) {
		add_trace_message(TRACE_ERROR, "Open DNS List", "Pipe Open Failed");
		return;
	}

	while (fgets(pbuf, 256, pfp)) {
		cp = strchr(pbuf, ':');
		if (cp == NULL) {
			sl = strlen(pbuf);
			if (sl < 10) continue;
			if (pbuf[6] == '-') continue;
			if (pbuf[0] == 'W') continue; // Skip header
			if (!strncmp(pbuf, "    No records", 14)) continue;
			if (!strncmp(pbuf, "    Name does not exist.", 24)) continue;

			// Assume this is a DNS item with four leading spaces
			// Add the : separator to be consistent with other items
			// May still get some garbage strings added but these
			// extra characters should not effect the hit search.
			cp = pbuf + 2;
			*cp = ':';
			extract_dns_data(cp, 0);
		}
		else {
			// May need more cases specified here to cover all the record types
			if ((strstr(pbuf, "Record Name") != NULL)) { extract_dns_data(cp, 0); continue; }
			if ((strstr(pbuf, "CNAME Record") != NULL)) { extract_dns_data(cp, 0); continue; }
			if ((strstr(pbuf, "DNAME") != NULL)) { extract_dns_data(cp, 0); continue; }
			if ((strstr(pbuf, "A (Host) Record") != NULL)) { extract_dns_data(cp, 1); continue; }
			if ((strstr(pbuf, "AAAA") != NULL)) { extract_dns_data(cp, 1); continue; }
			if ((strstr(pbuf, "PTR Record") != NULL)) { extract_dns_data(cp, 0); continue; }
		}
	}

	if (!feof(pfp)) {
		add_trace_message(TRACE_WARNING, "DNS List Interrupted", "EOF Not Reached");
	}

	_pclose(pfp);

	check_dns_hit(file_data_buffer);

	add_trace_message(TRACE_INFO, "DNS Scan", "Finished");

	return;
}

void epst_scan_mutex() {
	int i;
	char *mutex_name;
	HANDLE hMutex;

	if (!do_mutex_scan) return;

	add_trace_message(TRACE_INFO, "Mutex Scan", "Started");

	for (i = 0; i < sigcount_mutex; i++) {
		mutex_name = signatures_mutex[i];
		if (mutex_name == NULL || *mutex_name == '\0') continue;

		hMutex = OpenMutex(MUTEX_ALL_ACCESS, TRUE, mutex_name);
		if (hMutex == NULL) continue;

		// The Windows Mutant Exists
		ReleaseMutex(hMutex);
		CloseHandle(hMutex);

		add_trace_message(TRACE_INFO, "MUTANT Hit", mutex_name);
		add_results_start_hit();
		add_results_pair_ss("HitType", "MutexScan", ", ");
		add_results_pair_sn("Found", mutex_name, "}\n");
		results_hit_count++;

		register_sighting("MOM", mutex_name);
	}
	
	add_trace_message(TRACE_INFO, "Mutex Scan", "Finished");

	return;
}


#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383


// Adapted from MS example on Enumerating Registry Subkeys
// Removing special Windows types to ensure compiler warnings
// if configuration is setup to do Unicode or wide strings
int is_in_registry_items(HKEY hKey, char *rkey, char *item) {
	char			achKey[MAX_KEY_LENGTH];			// buffer for subkey name
	char			achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	unsigned long   cbName;							// size of name string 
	unsigned long   cchClassName = MAX_PATH;		// size of class string 
	unsigned long   cSubKeys = 0;					// number of subkeys 
	unsigned long   cbMaxSubKey;					// longest subkey size 
	unsigned long   cchMaxClass;					// longest class string 
	unsigned long   cValues;						// number of values for key 
	unsigned long   cchMaxValue;					// longest value name 
	unsigned long   cbMaxValueData;					// longest value data 
	unsigned long   cbSecurityDescriptor;			// size of security descriptor 
	FILETIME ftLastWriteTime;						// last write time 

	unsigned long   i, rc;
	int found = FALSE;

	char  achValue[MAX_VALUE_NAME];
	unsigned long   cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	rc = RegQueryInfoKeyA(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	// Enumerate the subkeys, until RegEnumKeyEx fails.
	if (cSubKeys > 0)
	{
		for (i = 0; i<cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			rc = RegEnumKeyExA(hKey, i, achKey, &cbName, NULL, NULL, NULL, &ftLastWriteTime);
			if (rc == ERROR_SUCCESS)
			{
				if (!strcmp(item, achKey)) {
					found = TRUE;
					break;
				}
			}
		}
	}

	// Enumerate the key values. 
	if (found == FALSE && cValues > 0)
	{
		for (i = 0, rc = ERROR_SUCCESS; i<cValues; i++)
		{
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			rc = RegEnumValueA(hKey, i, achValue, &cchValue, NULL, NULL, NULL, NULL);

			if (rc == ERROR_SUCCESS)
			{
				if (!strcmp(item, achValue)) {
					found = TRUE;
					break;
				}
			}
		}
	}

	RegCloseKey(hKey);
	return found;
}

int is_in_registry(HKEY hKey, char *rkey, int isfor64, char *hive_name) {
	HKEY hTestKey;
	char ts[2048];
	char *item,*sp;
	size_t sl;

	REGSAM qflag = (isfor64 != 0) ? (KEY_READ | KEY_WOW64_64KEY) : (KEY_READ | KEY_WOW64_32KEY);

	// First try the simple test just searching directly before breaking it down
	if (RegOpenKeyEx(hKey, rkey, 0, qflag, &hTestKey) == ERROR_SUCCESS)
	{
		// Found a hit
		RegCloseKey(hTestKey);
		return TRUE;
	}
	RegCloseKey(hTestKey);
	hTestKey = NULL;

	// Make a working copy of the key
	strcpy(ts, rkey);
	sl = strlen(ts);
	if (sl <= 0) return FALSE;

	// Special Check for one specific set of registry key values
	if (sl > 46 && !_strnicmp("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\", ts, 46)) {
		item = ts+45;
		rkey = ts;
	}
	else {
		if (ts[sl - 1] == '\\') {
			sl--;
			ts[sl] = '\0';
		}

		// Find last key segment to search as item or subkey
		rkey = ts;
		sp = ts;
		item = NULL;
		while (*sp != '\0') {
			if (*sp == '\\') item = sp;
			sp++;
		}
	}

	// Shouldn't happen but check anyway
	if (item == NULL) return FALSE;
	*item = '\0';
	item++;

	// Check for the item in the sub-key elements if it exists
	if (RegOpenKeyEx(hKey, rkey, 0, qflag, &hTestKey) != ERROR_SUCCESS)
	{
		// Nothing to see here
		RegCloseKey(hTestKey);
		return FALSE;
	}

	return is_in_registry_items(hTestKey, rkey, item);
}

int check_rkey_hit(char *rkey) {
	HKEY hKey;
	char *hive_name = "NOHIVE";
	char tmpstr[2048];

	if (rkey == NULL || *rkey == '\0') return 0;

	// Check all currently known hive specification formats and short codes
	if (!strncmp(rkey, "HKEY_CURRENT_CONFIG\\", 20)) {
		hKey = HKEY_CURRENT_CONFIG;
		rkey = rkey + 20;
		hive_name = "HKEY_CURRENT_CONFIG";
	}
	else if (!strncmp(rkey, "HKCC\\", 5)) {
		hKey = HKEY_CURRENT_CONFIG;
		rkey = rkey + 5;
		hive_name = "HKEY_CURRENT_CONFIG";
	}
	else if (!strncmp(rkey, "HKEY_CLASSES_ROOT\\", 18)) {
		hKey = HKEY_CLASSES_ROOT;
		rkey = rkey + 18;
		hive_name = "HKEY_CLASSES_ROOT";
	}
	else if (!strncmp(rkey, "HKCR\\", 5)) {
		hKey = HKEY_CLASSES_ROOT;
		rkey = rkey + 5;
		hive_name = "HKEY_CLASSES_ROOT";
	}
	else if (!strncmp(rkey, "HKEY_CURRENT_USER\\", 18)) {
		hKey = HKEY_CURRENT_USER;
		rkey = rkey + 18;
		hive_name = "HKEY_CURRENT_USER";
	}
	else if (!strncmp(rkey, "HKCU\\", 5)) {
		hKey = HKEY_CURRENT_USER;
		rkey = rkey + 5;
		hive_name = "HKEY_CURRENT_USER";
	}
	else if (!strncmp(rkey, "HKEY_LOCAL_MACHINE\\", 19)) {
		hKey = HKEY_LOCAL_MACHINE;
		rkey = rkey + 19;
		hive_name = "HKEY_LOCAL_MACHINE";
	}
	else if (!strncmp(rkey, "HKLM\\", 5)) {
		hKey = HKEY_LOCAL_MACHINE;
		rkey = rkey + 5;
		hive_name = "HKEY_LOCAL_MACHINE";
	}
	else if (!strncmp(rkey, "HKEY_USERS\\", 11)) {
		hKey = HKEY_USERS;
		rkey = rkey + 11;
		hive_name = "HKEY_USERS";
	}
	else if (!strncmp(rkey, "HKU\\", 4)) {
		hKey = HKEY_USERS;
		rkey = rkey + 4;
		hive_name = "HKEY_USERS";
	}
	else if (!strncmp(rkey, "SOFTWARE\\", 9)) {
		hKey = HKEY_LOCAL_MACHINE;
		rkey = rkey + 0; // leave as is
		hive_name = "HKEY_LOCAL_MACHINE";
	}
	else if (!strncmp(rkey, "%regrun%\\", 9)) {
		char *rr = getenv("regrun");
		if (rr != NULL) printf("%s %s\n", EPSTTranslate("regrun environment variable is"), rr);

		hKey = HKEY_LOCAL_MACHINE;
		rkey = rkey + 9;
		sprintf(tmpstr, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\%s", rkey);
		hive_name = "HKEY_LOCAL_MACHINE";
		rkey = tmpstr;
	}
	else {
		printf("%s %s\n", EPSTTranslate("Unknown Hive Name for registry key"), rkey);
		return 0;
	}

	// check both 64 and 32 bit registries
	if (is_in_registry(hKey, rkey, 0, hive_name)) return 1;
	if (is_in_registry(hKey, rkey, 1, hive_name)) return 1;

	return 0;
}


void epst_scan_rkeys() {
	int i;
	char *rkey_name;

	if (!do_rkeys_scan) return;
	
	add_trace_message(TRACE_INFO, "Registry Scan", "Started");

	for (i = 0; i < sigcount_rkeys; i++) {
		rkey_name = signatures_rkeys[i];
		if (rkey_name == NULL || *rkey_name == '\0') continue;

		if (!check_rkey_hit(rkey_name)) continue;

		add_trace_message(TRACE_INFO, "Registry Hit", rkey_name);
		add_results_start_hit();
		add_results_pair_ss("HitType", "RKeyScan", ", ");
		add_results_pair_sn("Found", rkey_name, "}\n");
		results_hit_count++;

		register_sighting("RKM", rkey_name);
	}
	
	add_trace_message(TRACE_INFO, "Registry Scan", "Finished");

	return;
}

