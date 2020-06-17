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

#if defined(_WIN32)

#include <iostream>
#include <string>
#include <regex>

extern "C" {
	int do_research(const char *source, const char *find, size_t *result_start, size_t *result_length);
	int epst_test_regex(const char *source, long ssize, const char *find);
}

int do_research(const char *source, const char *find, size_t *result_start, size_t *result_length) {

	// Return the result referencing the source buffer
	// Avoids string/char copying etc.
	*result_start = 0;
	*result_length = 0;

	try {
		std::regex r(find);
		std::cmatch cm;

		if (std::regex_search(source, cm, r)) {
			*result_start = (size_t)cm.prefix().length();
			*result_length = (size_t)cm[0].length();
			return 1;
		}
	}
	catch (std::regex_error& e) {
		// Syntax error in the regular expression
		// Catching but ignoring errors - catch regex
		// syntax errors with different code block.
		// This error could be memory related.

		// MRK - remove the error message output after testing
		std::cout << "Regex ERROR: " << e.what() << std::endl;

		return 0;
	}

	return 0;
}

// Valid the regex expression and test on a text buffer (optional)
// Output results and return non-zero if the expression passed
int epst_test_regex(const char *source, long ssize, const char *find) {
	try {
		std::regex r(find);
		std::cmatch cm;

		if (source != NULL) {
			std::cregex_iterator next = std::cregex_iterator(source,source+ssize,r);
			std::cregex_iterator end;

			std::cout << "Regex: " << find << std::endl;
			while (next != end) {
				std::cmatch match = *next;
				std::cout << "Found: " << match[0] << "\n";
				next++;
			}
		}
	}
	catch (std::regex_error& e) {
		std::cout << "Regex: " << find << std::endl;
		std::cout << "ERROR: " << e.what() << std::endl;
		return 0;
	}

	return 1;
}

#endif