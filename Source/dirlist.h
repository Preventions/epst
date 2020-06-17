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

#ifndef __DIRLIST__

#define __DIRLIST__

#define DIRLIST_EXCLUDE 0
#define DIRLIST_RECURSE 1
#define DIRLIST_SCAN_ONLY 2

#define DIRLIST_OK 0
#define DIRLIST_WARNING 1
#define DIRLIST_ERROR 2

#define DIRLIST_STR_BUFFER_SIZE 2048


int dirlist_initialize();
const int dirlist_get_scan_mode(const char *dir);
int dirlist_filter_file(char *fname);
char *dirlist_next_dir();
void dirlist_dump(FILE *fp);
void dirlist_finalize();

#endif