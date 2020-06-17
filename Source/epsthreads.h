/*
Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Build in a variation of the Yara mainline code for handling scanner threads.
// Combines the queue, semaphore and mutex features for scanning lots of files.


#ifdef __ENDPOINTSCANNER_MAIN__

#include <fcntl.h>
#include <errno.h>

#if defined(_WIN32)

typedef HANDLE SEMAPHORE;
typedef CRITICAL_SECTION MUTEX;
typedef HANDLE THREAD;

typedef LPTHREAD_START_ROUTINE THREAD_START_ROUTINE;

#else

#include <sys/stat.h>
#include <pthread.h>
#include <semaphore.h>

typedef sem_t* SEMAPHORE;
typedef pthread_mutex_t MUTEX;
typedef pthread_t THREAD;
typedef void *(*THREAD_START_ROUTINE) (void *);

#endif

#if defined(__linux__)
#include <sys/syscall.h>
#endif


int mutex_init(MUTEX* mutex);
void mutex_destroy(MUTEX* mutex);
void mutex_lock(MUTEX* mutex);
void mutex_unlock(MUTEX* mutex);
int semaphore_init(SEMAPHORE* semaphore,int value);
void semaphore_destroy(SEMAPHORE* semaphore);
void semaphore_wait(SEMAPHORE* semaphore);
void semaphore_release(SEMAPHORE* semaphore);
int create_thread(THREAD* thread,THREAD_START_ROUTINE start_routine,void* param);
void thread_join(THREAD* thread);

#define MAX_QUEUED_FILES 64


typedef struct _THREAD_ARGS
{
	YR_RULES* rules;
	time_t start_time;

} THREAD_ARGS;


typedef struct _QUEUED_FILE
{
	char* path;

} QUEUED_FILE;

#if defined(_WIN32)

// Threading.c code inserted with some modifications (WINDOWS VERSION)
int mutex_init(MUTEX* mutex)
{
	InitializeCriticalSection(mutex);
	return 0;
}

void mutex_destroy(MUTEX* mutex)
{
	DeleteCriticalSection(mutex);
}

void mutex_lock(MUTEX* mutex)
{
	EnterCriticalSection(mutex);
}

void mutex_unlock(MUTEX* mutex)
{
	LeaveCriticalSection(mutex);
}

int semaphore_init(SEMAPHORE* semaphore,int value)
{
	*semaphore = CreateSemaphore(NULL, value, 65535, NULL);
	if (*semaphore == NULL)
		return GetLastError();
	return 0;
}


void semaphore_destroy(SEMAPHORE* semaphore)
{
	CloseHandle(*semaphore);
}

void semaphore_wait(SEMAPHORE* semaphore)
{
	WaitForSingleObject(*semaphore, INFINITE);
}


void semaphore_release(SEMAPHORE* semaphore)
{
	ReleaseSemaphore(*semaphore, 1, NULL);
}

int create_thread(THREAD* thread,THREAD_START_ROUTINE start_routine,void* param)
{
	*thread = CreateThread(NULL, 0, start_routine, param, 0, NULL);
	if (*thread == NULL)
		return GetLastError();
	else
		return 0;
}

void thread_join(THREAD* thread)
{
	WaitForSingleObject(*thread, INFINITE);
}

#else

// Threading.c code inserted with some modifications (LINUX VERSION)
int mutex_init(MUTEX* mutex)
{
	return pthread_mutex_init(mutex, NULL);
}

void mutex_destroy(MUTEX* mutex)
{
	pthread_mutex_destroy(mutex);
}

void mutex_lock(MUTEX* mutex)
{
	pthread_mutex_lock(mutex);
}

void mutex_unlock(MUTEX* mutex)
{
	pthread_mutex_unlock(mutex);
}

int semaphore_init(SEMAPHORE* semaphore,int value)
{
    // Mac OS X doesn't support unnamed semaphores via sem_init, that's why
    // we use sem_open instead sem_init and immediately unlink the semaphore
    // from the name. More info at:
    //
    // http://stackoverflow.com/questions/1413785/sem-init-on-os-x
    //
    // Also create name for semaphore from PID because running multiple instances
    // of YARA at the same time can cause that sem_open() was called in two processes
    // simultaneously while neither of them had chance to call sem_unlink() yet.
    char name[20];
    snprintf(name, sizeof(name), "/epst.sem.%i", (int)getpid());
    *semaphore = sem_open(name, O_CREAT, S_IRUSR, value);

    if (*semaphore == SEM_FAILED)
      return errno;

    if (sem_unlink(name) != 0)
      return errno;
	return 0;
}


void semaphore_destroy(SEMAPHORE* semaphore)
{
	sem_close(*semaphore);
}

void semaphore_wait(SEMAPHORE* semaphore)
{
	sem_wait(*semaphore);
}


void semaphore_release(SEMAPHORE* semaphore)
{
	sem_post(*semaphore);
}

int create_thread(THREAD* thread,THREAD_START_ROUTINE start_routine,void* param)
{
	return pthread_create(thread, NULL, start_routine, param);
}

void thread_join(THREAD* thread)
{
	pthread_join(*thread, NULL);
}

static long GetCurrentThreadId() {
#ifdef SYS_gettid
	 return (long)syscall(SYS_gettid);
#else
	 // This may not be strictly correct since return value could be a pointer
	 return (long)pthread_self();
#endif
}

#endif



// file_queue is size-limited queue stored as a circular array, files are
// removed from queue_head position and new files are added at queue_tail
// position. The array has room for one extra element to avoid queue_head
// being equal to queue_tail in a full queue. The only situation where
// queue_head == queue_tail is when queue is empty.

QUEUED_FILE file_queue[MAX_QUEUED_FILES + 1];

int queue_head;
int queue_tail;

SEMAPHORE used_slots;
SEMAPHORE unused_slots;

MUTEX queue_mutex;
MUTEX output_mutex;

int file_queue_init()
{
	int result;

	queue_tail = 0;
	queue_head = 0;

	result = mutex_init(&queue_mutex);

	if (result != 0)
		return result;

	result = semaphore_init(&used_slots, 0);

	if (result != 0)
		return result;

	return semaphore_init(&unused_slots, MAX_QUEUED_FILES);
}

void file_queue_destroy()
{
	mutex_destroy(&queue_mutex);
	semaphore_destroy(&unused_slots);
	semaphore_destroy(&used_slots);
}


void file_queue_finish()
{
	int i=0;
	for (i = 0; i < YR_MAX_THREADS; i++)
		semaphore_release(&used_slots);
}


void file_queue_put(const char* file_path)
{
	semaphore_wait(&unused_slots);
	mutex_lock(&queue_mutex);

	file_queue[queue_tail].path = _strdup(file_path);
	queue_tail = (queue_tail + 1) % (MAX_QUEUED_FILES + 1);

	mutex_unlock(&queue_mutex);
	semaphore_release(&used_slots);
}


char* file_queue_get()
{
	char* result;

	semaphore_wait(&used_slots);
	mutex_lock(&queue_mutex);

	if (queue_head == queue_tail) // queue is empty
	{
		result = NULL;
	}
	else
	{
		result = file_queue[queue_head].path;
		queue_head = (queue_head + 1) % (MAX_QUEUED_FILES + 1);
	}

	mutex_unlock(&queue_mutex);
	semaphore_release(&unused_slots);

	return result;
}

int scan_callback(
	int message,
	void* message_data,
	void* user_data)
{
	YR_MODULE_IMPORT* mi;

	switch (message)
	{
	case CALLBACK_MSG_RULE_MATCHING:
		return handle_scan_hit_message(message, (YR_RULE*)message_data, user_data);
	case CALLBACK_MSG_RULE_NOT_MATCHING:
		return CALLBACK_CONTINUE;

	case CALLBACK_MSG_IMPORT_MODULE:
		if (extra_trace_details >= XTRACE_HASH) {
			mi = (YR_MODULE_IMPORT*)message_data;
			add_trace_message(TRACE_INFO, "Begin Module Import", mi->module_name);
		}
		return CALLBACK_CONTINUE;

	case CALLBACK_MSG_MODULE_IMPORTED:
		// Removed the show module data code
		return CALLBACK_CONTINUE;
	}

	return CALLBACK_ERROR;
}


#if defined(_WIN32)
static DWORD WINAPI scanning_thread(LPVOID param)
#else
static void* scanning_thread(void* param)
#endif
{
	int yara_result = ERROR_SUCCESS;
	THREAD_ARGS* args = (THREAD_ARGS*)param;
	SCAN_RESULTS *scan_results;
	char* file_path = file_queue_get();

	int flags = 0;

	if (fast_scan) flags |= SCAN_FLAGS_FAST_MODE;

	while (file_path != NULL)
	{
		int elapsed_time = (int)difftime(time(NULL), args->start_time);

		if (elapsed_time < epst_filescan_timeout)
		{
			scan_results = perform_signature_scan(0, file_path);
			if (scan_results == NULL) {
				// Most likely an out of memory situation so exit
				add_trace_message(TRACE_ERROR,"Could not allocate scan results data",file_path);
				free(file_path);
				file_path = NULL;
				break;
			}

			if (do_yarafile_scan) {
				yara_result = yr_rules_scan_file(
					args->rules,
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

			// File the results
			process_scan_results(scan_results);

			file_path = file_queue_get();
		}
		else
		{
			file_path = NULL;
		}
	}

	return 0;
}

static THREAD thread_list[YR_MAX_THREADS];
static THREAD_ARGS thread_args;

int epst_init_threads() {
	int i;

	if (file_queue_init() != 0)
	{
		add_trace_message(TRACE_ERROR, "Threading Queue Initialization Failed!", "Terminating Program");
		return(EXIT_FAILURE);
	}

	time_t start_time = time(NULL);

	thread_args.rules = rules;
	thread_args.start_time = start_time;

	for (i = 0; i < num_threads_to_use; i++)
	{
		if (create_thread(&thread_list[i], scanning_thread, (void*)&thread_args))
		{
			add_trace_message(TRACE_ERROR, "Could not create thread!", "Terminating Program");
			return(EXIT_FAILURE);
		}
	}
	using_threads = TRUE;
	return 0;
}

void epst_finialize_threads() {
	int i;

	file_queue_finish();

	// Wait for scan threads to finish
	for (i = 0; i < num_threads_to_use; i++) {
		thread_join(&thread_list[i]);
	}

	using_threads = FALSE;
	file_queue_destroy();
}
#endif
