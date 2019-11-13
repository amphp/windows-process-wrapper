#pragma once

#include <Windows.h>

typedef enum amp_loop_status {
	AMP_LOOP_STATUS_UNINITIALIZED,
	AMP_LOOP_STATUS_STOPPED,
	AMP_LOOP_STATUS_RUNNING,
	AMP_LOOP_STATUS_STOPPING,
} amp_loop_status;

typedef struct _amp_watcher *amp_watcher;
#define AMP_INVALID_WATCHER ((amp_watcher)NULL)

typedef void (CALLBACK *amp_watcher_callback)(amp_watcher watcher);

void amp_loop_init();

BOOL amp_loop_run();
void amp_loop_stop();

amp_watcher amp_loop_watch(HANDLE handle, amp_watcher_callback callback, void *data);
amp_watcher amp_loop_wait(HANDLE handle, amp_watcher_callback callback, void *data);
amp_watcher amp_loop_set_timeout(const int timeout, amp_watcher_callback callback, void *data);
amp_watcher amp_loop_set_interval(const int interval, amp_watcher_callback callback, void *data);

void *amp_watcher_get_data(amp_watcher watcher);
void amp_watcher_set_data(amp_watcher watcher, void *data);
void amp_watcher_set_callback(amp_watcher watcher, amp_watcher_callback callback);
void amp_watcher_cancel(amp_watcher watcher);
