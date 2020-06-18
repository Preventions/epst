# Endpoint Scanning Tool

The Endpoint Scanning Tool is an application designed to analyze a computer system to determine if there any are any indications of malware infection. A collection of indicator signatures and sophisticated rules are utilized by the tool to identify suspicious files and flag them for remediation.

## Tested on:
- Windows 64 bit

- Windows 32 bit

- Linux Alpine, Centos, Ubuntu

- MacOS

See build notes for tips of compiling.

```
End Point Scanning Tool uses signature data and Yara rules
to check files, processes and system resources for malware.

  -X,  --explicit-scan             turn on explicit scan mode so all are off by default
  -R,  --rules-scan                scan files with yara rules
  -H,  --hash-scan                 hash files and check master MD5, SHA1, SHA256 hit lists
  -U,  --url-scan                  scan the URL cache for items in the hit list
  -D,  --dns-scan                  scan the DNS cache for items in the hit list
  -I,  --IP-scan                   scan active sockets and dns cache for IPs in hit list
  -P,  --process-scan              scan memory of all active processes with Yara rules
  -N,  --name-scan                 scan directory tree for file names in hit list
  -K,  --registry-scan             scan the registry for keys in hit list
  -M,  --mutex-scan                scan mutex items for keys in hit list
  -W,  --win-event-scan            scan event logs and command output for specific events
  -T,  --trace-mode=NUMBER         trace to file (1), trace to stdout (2) both (3)
  -y,  --rule-details=NUMBER       bit flags for basic (0), meta (1), string matches (2), tags (4)
  -t,  --threads=NUMBER            specify NUMBER of threads to use for scanning files
  -l,  --limit-hits=NUMBER         per file max NUMBER of matching rules to record
  -e,  --expiry-timeout=SECONDS    number of SECONDS before a file or process scan times out
  -m,  --max-scantime=SECONDS      force scanning to complete after max number of SECONDS
  -s,  --sleep-delay=MICROSECONDS  CPU throttling number of MICROSECONDS to sleep between file scans
  -r,  --compiled-rules=FILENAME   specify name for a compiled Yara rules file
  -O,  --output-folder=FOLDER      specify folder name for downloaded and generated files
  -k,  --stack-size=SLOTS          set maximum stack size (default=16384)
  -f,  --fast-scan                 fast matching mode
  -a,  --auto-sight                automatically attempt to register sightings with MISP server
  -x,  --extra-trace=TRACE         level of extra details in the trace (0,1,2,3)
  -u,  --upload-results            upload existing results file then exit
  -Z,  --suppress-upload           suppress default upload of results to MISP server
  -S,  --suppress-samples          suppress default upload of hit samples to MISP server
  -d,  --download-rules            download new set of rules and signatures then exit
  -L,  --local-rules               use local rules and signature files already downloaded
  -E,  --experimental              use experimental vs normal yara rules (same filename, different download)
  -Y,  --yaradev                   use development vs normal yara rules
  -v,  --version                   display the tool and yara version and exit
  -h,  --help                      show this help and exit

Important Files (Rules, Signatures, Trace, Results):
  epstrules.yara
  epstresults.json
  scantrace.txt
  eventhits.txt
  md5.txt
  sha1.txt
  sha256.txt
  dns.txt
  url.txt
  ips.txt
  events.txt
  fnames.txt
  rkeys.txt
  mutex.txt
  apikey.lic
  dirlist.txt
```

A **dirlist.txt** file is an optional file that can be used to control the directories and file types
that are scanned, recursed or excluded. A sample version is included.
