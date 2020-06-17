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

// MAC OSX VERSION
// This file contains code blocks designed to obtain system information which is mostly
// platform specific. Separating the code to avoid complicating it with too many ifdefs
// although this will result in some duplication. Corresponding versions for OSX/Linux
// should follow the same function prototypes. This is primarily required to compensate
// for system commands returning data in different formats.


// Based on https://stackoverflow.com/questions/7072989/iphone-ipad-osx-how-to-get-my-ip-address-programmatically
// and https://stackoverflow.com/questions/677530/how-can-i-programmatically-get-the-mac-address-of-an-iphone
// This is unfortunately Mac OS X specific

#define IFT_ETHER 0x6

void get_system_ips() {
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *addr = NULL;
	const char *address;
    int success = 0;
	char addrBuf[ MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN) ];
	
    // retrieve the current interfaces - returns 0 on success
    success = getifaddrs(&interfaces);
    if (success == 0) {
        // Loop through linked list of interfaces
        addr = interfaces;
        while(addr != NULL) {
			int active = 0;
			if ((addr->ifa_flags & IFF_UP) && !(addr->ifa_flags & IFF_LOOPBACK)) {
				// Interface is up and not a loopback
				active = 1;
			}
			
            if(addr->ifa_addr->sa_family == AF_INET) {
				address = inet_ntop(AF_INET,&((struct sockaddr_in *)addr->ifa_addr)->sin_addr, addrBuf, INET_ADDRSTRLEN);
				if (address && strcmp(address,"127.0.0.1")) {
					add_trace_message(TRACE_INFO, addr->ifa_name, address);
					
					if (active && *(addr->ifa_name) == 'e' && local_ipv4 == NULL)
						local_ipv4 = strdup(address);
				}
            }
            else if(addr->ifa_addr->sa_family == AF_INET6) {
                address = inet_ntop(AF_INET6,&((struct sockaddr_in6 *)addr->ifa_addr)->sin6_addr, addrBuf, INET6_ADDRSTRLEN);
				if (address) {
					add_trace_message(TRACE_INFO, addr->ifa_name, address);
					if (active && *(addr->ifa_name) == 'e' && local_ipv6 == NULL)
						local_ipv6 = strdup(address);
				}
            }
			else if ( (addr->ifa_addr->sa_family == AF_LINK) && (((const struct sockaddr_dl *) addr->ifa_addr)->sdl_type == IFT_ETHER) ) {
	            const struct sockaddr_dl *s_addr = (const struct sockaddr_dl *) addr->ifa_addr;
	            const unsigned char *base = (const unsigned char*) &s_addr->sdl_data[s_addr->sdl_nlen];
				char ether[100];
				char partial[3];
				
	            strcpy(ether, ""); 
	            for (int i = 0; i < s_addr->sdl_alen; i++) {
	                if (i != 0) {
	                    strcat(ether, ":");
	                }
	                
	                sprintf(partial, "%02X", base[i]);
	                strncat(ether, partial,100);
	            }
				add_trace_message(TRACE_INFO, addr->ifa_name, ether);
				if (active && !strcmp(addr->ifa_name,"en0") && physical_address == NULL)
					physical_address = strdup(ether);
	        }

            addr = addr->ifa_next;
        }
    }
    // Free memory
    freeifaddrs(interfaces);
}


void get_system_config() {
	char sbuf[1000];
	
	if (!gethostname(sbuf,1000)) {
		host_name = strdup(sbuf);
	}
	
	get_system_ips();
	return;
}


static void run_scan_syscmd(char *cmd, char *label, EPST_StrListItem *research, EPST_StrListItem *sigcodes) {
	char pbuf[2048];
	FILE *pfp;

	if ((pfp = popen(cmd, "r")) == NULL) {
		add_trace_message(TRACE_ERROR, cmd, "Pipe Open Failed");
		return;
	}

	while (fgets(pbuf, 2048, pfp)) {
		size_t sl = strlen(pbuf);
		if (sl > 0 && pbuf[sl - 1] == '\n') { pbuf[--sl] = '\0'; }

		if (sl > 0) {
			scan_syscmd_output(pbuf, label, research, sigcodes);
		}
	}

	pclose(pfp);
	return;
}

static void trace_dump_command_output(const char *cmd) {
	char pbuf[1024];
	FILE *pfp;

	if (!trace_to_file || trace_fp == NULL) return;

	if ((pfp = popen(cmd, "r")) == NULL) {
		add_trace_message(TRACE_ERROR, cmd, "Pipe Open Failed");
		return;
	}

	fprintf(trace_fp, "CMD: %s\n", cmd);
	while (fgets(pbuf, 1024, pfp)) {
		size_t sl = strlen(pbuf);
		if (sl > 0 && pbuf[sl - 1] == '\n') { pbuf[--sl] = '\0'; }

		if (sl > 0) {
			fprintf(trace_fp, "%s\n", pbuf);
		}
	}

	pclose(pfp);
	return;
}


// Currently uses global data structures but setup the
// function to potentially use a different mechanism
int epst_load_pids_to_scan() {
	active_pids_count = 0;

	// Just in case let's initialize these arrays
	for (int i = 0; i < (MAX_EPST_PID_COUNT); i++) {
		active_pids_names[i] = NULL;
		active_pids[i] = 0;
	}
	
	// Unfortunately this implementation only seems to be suitable for Mac OS X not Linux in general
	// Based on https://stackoverflow.com/questions/3018054/retrieve-names-of-running-processes
	pid_t cpid;
	char pbuf[1024];

	int numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
	pid_t pids[numberOfProcesses];
	bzero(pids, sizeof(pids));
	
	cpid = getpid();
	printf("Current Process ID: %d\n\n",cpid);
	proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
	for (int i = 0; i < numberOfProcesses; ++i) {
	    if (pids[i] == 0) { continue; }
	    if (pids[i] == cpid) {
			printf("Skipping Self PID %d\n\n",pids[i]);
			continue;
		}
	    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
	    bzero(pathBuffer, PROC_PIDPATHINFO_MAXSIZE);
	    proc_pidpath(pids[i], pathBuffer, sizeof(pathBuffer));
		
		// WARNING: Cast not tecnically correct but yara code takes int
		active_pids[active_pids_count] = (int)pids[i];
		active_pids_names[active_pids_count] = strdup(pathBuffer);
		active_pids_count++;

		if (active_pids_count >= (MAX_EPST_PID_COUNT)) break;
	}
	
	return 0;
}

static int epst_dir_file_count(const char *scanDir, int stop_at_limit)
{
	DIR *dp;
	int file_count = 0;

	int dl = strlen(scanDir);
	if (dl >= (MAX_PATH - 3)) { return 0; }

	dp = opendir(scanDir);
	if (!dp) { return 0; }

    struct dirent *de = readdir(dp);

	while(de)
	{
		//Filter out the control directories
		if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
		{
			struct stat st;
			char full_path[MAX_PATH];

			// Special check for root directory
			if (!strcmp(scanDir,"/") || !strcmp(scanDir,"/.")) {
				snprintf(full_path, sizeof(full_path), "/%s", de->d_name);
			} else {
				snprintf(full_path, sizeof(full_path), "%s/%s", scanDir, de->d_name);
			}
		
	        int err = lstat(full_path, &st);

			if (err == 0 && S_ISREG(st.st_mode))
			{
				file_count++;
			}
		}
		
		if (stop_at_limit > 0 && file_count >= stop_at_limit) break;
		
		de = readdir(dp);
	}

	closedir(dp);
	return file_count;
}

static void fp_add_json_proximity_filelist(FILE *fp, const char *hitDir, const char *hitFile) {
	DIR *dp;
	int file_count = 0;

	int dl = strlen(hitDir);
	if (dl >= (MAX_PATH - 3)) { return; }

	dp = opendir(hitDir);
	if (!dp) { return; }

    struct dirent *de = readdir(dp);

	while(de)
	{
		//Filter out the control directories and hit file
		if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0 && strcmp(de->d_name, hitFile) != 0)
		{
			struct stat st;
			char full_path[MAX_PATH];

			// Special check for root directory
			if (!strcmp(hitDir,"/") || !strcmp(hitDir,"/.")) {
				snprintf(full_path, sizeof(full_path), "/%s", de->d_name);
			} else {
				snprintf(full_path, sizeof(full_path), "%s/%s", hitDir, de->d_name);
			}
		
	        int err = lstat(full_path, &st);

			if (err == 0 && S_ISREG(st.st_mode))
			{
				fp_add_json_proximity_filelist_item(fp,hitDir, de->d_name, file_count);
				file_count++;
			}
		}
		
		de = readdir(dp);
	}

	closedir(dp);
}


// OS X VERSION of directory scan
int epst_process_dir(const char *scanDir)
{
	DIR *dp;
	int recurse;

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

	int dl = strlen(scanDir);
	if (dl >= (MAX_PATH - 3)) {
		add_trace_message(TRACE_WARNING, "Skipping Path Too Long", scanDir);
		skipped_directories++;
		return FALSE;
	}

	dp = opendir(scanDir);
	if (!dp) {
		add_trace_message(TRACE_WARNING, "Directory Access Denied", scanDir);
		skipped_directories++;
		return FALSE;
	}

	scanned_directories++;

    struct dirent *de = readdir(dp);

	while(de && !epst_filescan_timed_out())
	{
		//Filter out the control directories
		if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0)
		{
			struct stat st;
			char full_path[MAX_PATH];

			// Special check for root directory
			if (!strcmp(scanDir,"/") || !strcmp(scanDir,"/.")) {
				snprintf(full_path, sizeof(full_path), "/%s", de->d_name);
			} else {
				snprintf(full_path, sizeof(full_path), "%s/%s", scanDir, de->d_name);
			}
		
	        int err = lstat(full_path, &st);
			
			if (err != 0) {
				add_trace_message(TRACE_WARNING, "Skipping File - lstat error", full_path);
				skipped_files++;
			}

			if (S_ISDIR(st.st_mode))
			{
				if (recurse == TRUE) {
					// Check for potential symbolic link - issue discovered with recursive links
					if (S_ISLNK(st.st_mode)) {
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
			else if (is_yara_rules_file(full_path, de->d_name) == TRUE) {
				add_trace_message(TRACE_INFO, "Skipping Yara Rules File", full_path);
				skipped_files++;
			}
			else if (S_ISREG(st.st_mode) && dirlist_filter_file(full_path) == DIRLIST_SCAN_ONLY) {
				// This updates total files processed
				epst_process_file(full_path);
				
				if (do_url_scan) {
					if (is_history_file(de->d_name)) {
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
		
		de = readdir(dp);
	}

	// Depth first search so print trace message afterwards.
	// Added folder trace to give sense of progress when there
	// are huge numbers of empty folders. Also useful for restarts
	// in the event of a crash.
	if (extra_trace_details > XTRACE_NONE) {
		add_trace_message(TRACE_INFO, "Scanned Directory", scanDir);
	}

	closedir(dp);
	return TRUE;
}


// Assumes a string from netstat - check for likely IP
// Return pointer past the IP address or NULL if not found.
// Input string will be modified to segment data.
char *extract_check_ipv4(char *s) {
	char *cp, *pp, *port;

	pp = strchr(s, '.');
	if (pp != NULL) {
		// reverse to non-digit
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
	char *cp, *pp, *port;

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

		check_ip_hit(pp,port);
		return cp;
	}
	return NULL;
}


// Scan the open sockets and check the IP addresses found
// against a known set of bad addresses in sorted list.
// Not using the netstat command as with Windows since the
// output is not as well formed. Using the lsof command instead
void epst_scan_sockets() {
	char pbuf[1024];
	char *remaining,*start;
	FILE *pfp;

	if (!do_ips_scan) return;

	add_trace_message(TRACE_INFO, "Socket Scan", "Started");

	if ((pfp = popen("/usr/sbin/lsof -Pnl -i | grep \"\\->\"", "r")) == NULL) {
		add_trace_message(TRACE_ERROR, "Open Socket List", "Pipe Open Failed");
		return;
	}

	while (fgets(pbuf, 1024, pfp)) {
		// Jump close to the IP addresses
		if (! ((start = strstr(pbuf,"TCP")) || (start = strstr(pbuf,"UDP"))) )
			continue;
		
		// check for first (local) IPv4 address
		if ((remaining = extract_check_ipv4(start)) != NULL) {
			// check for the second (foreign) address
			extract_check_ipv4(remaining);
		}
		else {
			// Possibly IPv6 address format
			if ((remaining = extract_check_ipv6(start)) != NULL) {
				// check for the second (foreign) address
				extract_check_ipv6(remaining);
			}
		}
	}

	if (!feof(pfp)) {
		add_trace_message(TRACE_WARNING, "Socket Identification Interrupted", "EOF Not Reached");
	}

	pclose(pfp);

	add_trace_message(TRACE_INFO, "Socket Scan", "Finished");

	return;
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
	
	// *************************************************************	
	// MRK TO DO: implement the equivalent of ipconfig /displaydns
	// *************************************************************

	add_trace_message(TRACE_INFO, "DNS Scan", "Not Performed for OS X");

	return;
}

void epst_scan_mutex() {
	int i;
	char *mutex_name;

	if (!do_mutex_scan) return;

	add_trace_message(TRACE_INFO, "Mutex Scan", "Not Performed for OS X");

	return;
}


void epst_scan_rkeys() {
	int i;
	char *rkey_name;

	if (!do_rkeys_scan) return;
	
	add_trace_message(TRACE_INFO, "Registry Scan", "Not Performed for OS X");

	return;
}