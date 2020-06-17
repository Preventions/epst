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

// LINUX VERSION
// This file contains code blocks designed to obtain system information which is mostly
// platform specific. Separating the code to avoid complicating it with too many ifdefs
// although this will result in some duplication. Corresponding versions for OSX/Linux
// should follow the same function prototypes. This is primarily required to compensate
// for system commands returning data in different formats.

#include <sys/ioctl.h>
#include <limits.h>


#define BUFFER_SIZE 1024

void get_system_ips() {
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *addr = NULL;
	const char *address;
    int success = 0;
	char addrBuf[ (INET_ADDRSTRLEN) + (INET6_ADDRSTRLEN) ];
	
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

            addr = addr->ifa_next;
        }
    }
    // Free memory
    freeifaddrs(interfaces);
}

// Get MAC address adapted from: https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program

void get_mac_eth0()
{
    struct ifreq s;
	unsigned char *mac;
	char buf[100];
		
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "eth0");
    if (!ioctl(fd, SIOCGIFHWADDR, &s)) {
		mac = (unsigned char *)(s.ifr_hwaddr.sa_data);
		sprintf(buf,"%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		physical_address = strdup(buf);
		printf("get_mac_eth0: %s\n",physical_address);
    }
	close(fd);
}

void get_linux_mac() {
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[BUFFER_SIZE];

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
		perror("get mac socket");
		return;
	}

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
		perror("get mac ioctl");
		return;    	
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			// don't count loopback
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) {
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					unsigned char *mac =(unsigned char *)(ifr.ifr_hwaddr.sa_data);
			  	 	sprintf(buf,"%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			  	  	physical_address = strdup(buf);
					break;
                }
            }
        }
        else {
			perror("ioctl");
		}
    }
	close(sock);
}


void get_system_config() {
	char sbuf[1000];
	
	if (!gethostname(sbuf,BUFFER_SIZE)) {
		host_name = strdup(sbuf);
	} else {
		perror("gethostname");
	}
	
	get_system_ips();
	
	//get_mac_eth0();
	get_linux_mac();
	
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

void trace_dump_command_output(const char *cmd) {
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


static char *name_for_pid(int pid) {
	char line[BUFFER_SIZE],path[PATH_MAX];
	FILE *fp;
	char *name = NULL;
	char *p;
	size_t sl;

	// Try to get the name as a path to the executable which is a softlink
    snprintf(path, PATH_MAX, "/proc/%d/exe", pid);

	name= realpath(path, NULL);
	if (name != NULL) {
		return name;
	}
	
	// Try to obtain the name from the status information
    snprintf(path, PATH_MAX, "/proc/%d/status", pid);

	// PID file may nolonger exist
    fp = fopen(path, "r");
    if (fp == NULL) return NULL;
	
	// Parse the file for the process name
	while(fgets(line,BUFFER_SIZE,fp) != NULL) {
		if (strncmp(line, "Name:", 5) == 0) {
			for(p=line+5;*p != '\0' && isspace((unsigned char)*p); )
				p++;
			
			// Strip the trailing newline if any
			sl = strlen(p)-1;
			if (sl > 0 && p[sl] == '\n') { p[sl] = '\0'; }
			
			name = strdup(p);
			break;
		}
	}
	
	fclose(fp);
	return name;
}


// Currently uses global data structures but setup the
// function to potentially use a different mechanism
int epst_load_pids_to_scan() {
	active_pids_count = 0;
	int i=0;

	// Just in case let's initialize these arrays
	for (i = 0; i < (MAX_EPST_PID_COUNT); i++) {
		active_pids_names[i] = NULL;
		active_pids[i] = 0;
	}

	// Modelled on http://man7.org/tlpi/code/online/dist/sysinfo/procfs_user_exe.c.html
	DIR *dp;
	struct dirent *de;
	int pid,cpid;
	char *name;
	
	dp = opendir("/proc");
	if (dp == NULL) {
		add_trace_message(TRACE_WARNING, "Access Denied - Could not read process information", "/proc");
		return 1;
	}
	
	cpid = getpid();
	printf("Current Process ID: %d\n\n",cpid);
	
	while(active_pids_count < (MAX_EPST_PID_COUNT)) {
		errno = 0;
		de = readdir(dp);
		if (de == NULL) {
			if (errno != 0) {
				add_trace_message(TRACE_WARNING, "Error Reading Directory", "/proc");
			}
			break;
		}
		
		// Skip directories that don't begin with a digit
		if (de->d_type != DT_DIR || !isdigit((unsigned char) de->d_name[0]))
			continue;
		
		pid = atoi(de->d_name);
		if (pid <= 1)
			continue;
		
		name = name_for_pid(pid);
		
		if (name == NULL) {
			printf("UNKNOWN NAME for PID %d\n",pid);
			name = strdup("UNKNOWN");
		}
		
		if (pid == cpid) {
			printf("Skipping Self PID %d Name=<%s>\n\n",pid, (name != NULL ? name : "UNKNOWN") );
			continue;
		}

		active_pids[active_pids_count] = pid;
		active_pids_names[active_pids_count] = name;
		active_pids_count++;
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


// Linux VERSION of directory scan
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


// Assumes a hex string from /proc/net - convert/check for IP
void extract_check_ipv4(char *s,char *p) {
	struct in_addr ip;
	int port;
	char *dip;
	char sport[20];
	
	sscanf(s,"%x",&ip.s_addr);
	sscanf(p,"%x",&port);
	snprintf(sport,20,"%d",port);
	dip = inet_ntoa(ip);
	check_ip_hit(dip,sport);
}

void extract_check_ipv6(char *s,char *p) {
	struct in6_addr tmp_ip;
	char ip_str[128];
	char sport[20];
	int port;

	sscanf(p,"%x",&port);
	snprintf(sport,20,"%d",port);

	if (sscanf(s,"%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
	    &tmp_ip.s6_addr[3], &tmp_ip.s6_addr[2], &tmp_ip.s6_addr[1], &tmp_ip.s6_addr[0],
	    &tmp_ip.s6_addr[7], &tmp_ip.s6_addr[6], &tmp_ip.s6_addr[5], &tmp_ip.s6_addr[4],
	    &tmp_ip.s6_addr[11], &tmp_ip.s6_addr[10], &tmp_ip.s6_addr[9], &tmp_ip.s6_addr[8],
	    &tmp_ip.s6_addr[15], &tmp_ip.s6_addr[14], &tmp_ip.s6_addr[13], &tmp_ip.s6_addr[12]) == 16)
	{
	    inet_ntop(AF_INET6, &tmp_ip, ip_str, sizeof ip_str);
		check_ip_hit(ip_str,sport);
	}
}

void parse_socket_file(char *fname) {
	FILE *fp;
	errno_t err;
	char fstr[BUFFER_SIZE + 1];
	
	if ((err = fopen_s(&fp, fname, "r")) != 0) {
		perror(fname);
		add_trace_message(TRACE_ERROR, "Open Socket File", fname);
		return;
	}
	
	fgets(fstr, BUFFER_SIZE, fp);  // skip header
	while (fgets(fstr, BUFFER_SIZE, fp) != NULL) {
		char lsocket[100],rsocket[100],lport[20],rport[20];
		char *s;
		
		s = fstr;
		while (*s == ' ') s++;
		
		*lsocket = *rsocket = *lport = *rport = '\0';
		int n = sscanf(s,"%*[0-9A-F]: %[0-9A-F]:%[0-9A-F] %[0-9A-F]:%[0-9A-F] ",lsocket,lport,rsocket,rport);
		
		if (n != 4) continue;
		
		if (!(!strcmp(lsocket,"00000000") || !strcmp(lsocket,"0100007F") || !strcmp(lsocket,"00000000000000000000000000000000"))) {
			n = strlen(lsocket);
			if (n == 8) extract_check_ipv4(lsocket,lport);
			if (n == 32) extract_check_ipv6(lsocket,lport);
		}

		if (!(!strcmp(rsocket,"00000000") || !strcmp(rsocket,"0100007F") || !strcmp(rsocket,"00000000000000000000000000000000"))) {
			n = strlen(rsocket);
			if (n == 8) extract_check_ipv4(rsocket,rport);
			if (n == 32) extract_check_ipv6(rsocket,rport);
		}
	}
	
	fclose(fp);
}

// Scan the open sockets and check the IP addresses found
// against a known set of bad addresses in sorted list.
// Not using the netstat command as with Windows since the
// output is not as well formed and the command may not be
// installed. Reading /proc/net/ files directly instead
void epst_scan_sockets() {

	if (!do_ips_scan) return;

	add_trace_message(TRACE_INFO, "Socket Scan", "Started");

	parse_socket_file("/proc/net/tcp");
	parse_socket_file("/proc/net/udp");

	parse_socket_file("/proc/net/tcp6");
	parse_socket_file("/proc/net/udp6");

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
	//char pbuf[256];
	unsigned char *nb;
	//size_t sl;
	//char *cp;
	//FILE *pfp;

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

	add_trace_message(TRACE_INFO, "DNS Scan", "Not Performed for Linux");

	return;
}

void epst_scan_mutex() {
	if (!do_mutex_scan) return;

	add_trace_message(TRACE_INFO, "Mutex Scan", "Not Performed for Linux");

	return;
}


void epst_scan_rkeys() {
	if (!do_rkeys_scan) return;
	
	add_trace_message(TRACE_INFO, "Registry Scan", "Not Performed for Linux");

	return;
}