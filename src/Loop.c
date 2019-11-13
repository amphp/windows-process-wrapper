#include <stdlib.h>

#include "Loop.h"

typedef struct amp_timer amp_timer;
typedef struct amp_event amp_event;

struct _amp_watcher {
	BOOL is_cancelled;
	amp_watcher_callback callback;
	void *data;
};

struct amp_timer {
	struct _amp_watcher watcher;
	amp_timer *next_timer;
	DWORD interval;
	struct {
		ULONGLONG prev;
		ULONGLONG next;
	} ticks;
};

struct amp_event {
	struct _amp_watcher watcher;
	amp_event *next_event;
	HANDLE handle;
	BOOL watch;
};

static struct {
	amp_loop_status status;
	struct {
		DWORD count;
		amp_timer *next;
	} timers;
	struct {
		DWORD count;
		amp_event *next;
	} events;
} amp_loop_globals;

#define AMP_LOOP_GLOBAL(name) (amp_loop_globals.##name)

#define malloc_type(type, count) (type*)malloc(sizeof(type) * (count))

static void register_timer(amp_timer *timer)
{
	amp_timer **slot = &AMP_LOOP_GLOBAL(timers).next, *current = *slot;

	// Find the slot where the new timer belongs, if multiple timers match push it to the end
	while (current != NULL && timer->ticks.next <= current->ticks.next) {
		slot = &current->next_timer;
		current = current->next_timer;
	}

	timer->next_timer = current;
	*slot = timer;
}

static amp_watcher create_timer(const int timeout, amp_watcher_callback callback, void *data, const BOOL repeat)
{
	if (timeout < 0 || (timeout == 0 && repeat)) {
		return AMP_INVALID_WATCHER; // todo: error info
	}

	amp_timer *timer = malloc_type(amp_timer, 1);

	if (timer == NULL) {
		return AMP_INVALID_WATCHER; // todo: error info
	}

	timer->watcher.is_cancelled = FALSE;
	timer->watcher.callback = callback;
	timer->watcher.data = data;

	timer->interval = timeout * repeat;
	timer->ticks.prev = GetTickCount64();
	timer->ticks.next = timer->ticks.prev + timeout;

	register_timer(timer);
	AMP_LOOP_GLOBAL(timers).count++;

	return &timer->watcher;
}

static amp_watcher create_event(HANDLE handle, amp_watcher_callback callback, void *data, const BOOL watch)
{
	if (handle == NULL || handle == INVALID_HANDLE_VALUE) {
		return AMP_INVALID_WATCHER; // todo: error info
	}

	amp_event *event = malloc_type(amp_event, 1);

	if (event == NULL) {
		return AMP_INVALID_WATCHER; // todo: error info
	}

	event->watcher.is_cancelled = FALSE;
	event->watcher.callback = callback;
	event->watcher.data = data;

	event->handle = handle;
	event->watch = watch;

	event->next_event = AMP_LOOP_GLOBAL(events).next;
	AMP_LOOP_GLOBAL(events).next = event;
	AMP_LOOP_GLOBAL(events).count++;

	return &event->watcher;
}

static DWORD get_tick_timeout()
{
	while (AMP_LOOP_GLOBAL(timers).next != NULL) {
		if (!AMP_LOOP_GLOBAL(timers).next->watcher.is_cancelled) {
			const int timeout = (int)(AMP_LOOP_GLOBAL(timers).next->ticks.next - GetTickCount64());
			return timeout >= 0 ? timeout : 0;
		}

		// clean up cancelled timers
		amp_timer *tmp = AMP_LOOP_GLOBAL(timers).next;
		AMP_LOOP_GLOBAL(timers).next = tmp->next_timer;

		free(tmp);
		AMP_LOOP_GLOBAL(timers).count--;
	}

	return INFINITE;
}

static DWORD get_tick_events(amp_event **events)
{
	DWORD result = 0;
	amp_event **previous = &AMP_LOOP_GLOBAL(events).next, *current = *previous;

	while (current != NULL) {
		if (!current->watcher.is_cancelled) {
			events[result++] = current;
			previous = &current->next_event;
			current = current->next_event;
			continue;
		}

		// clean up cancelled event watchers
		amp_event *tmp = current;
		*previous = current = current->next_event;

		free(tmp);
		AMP_LOOP_GLOBAL(events).count--;
	}

	return result;
}

static void trigger_next_timer()
{
	amp_timer *timer = AMP_LOOP_GLOBAL(timers).next;
	const ULONGLONG then = timer->ticks.next;
	const ULONGLONG now = GetTickCount64();

	do {
		AMP_LOOP_GLOBAL(timers).next = timer->next_timer;

		timer->watcher.callback(&timer->watcher);

		if (timer->interval > 0) {
			do {
				timer->ticks.prev = timer->ticks.next;
				timer->ticks.next = timer->ticks.prev + timer->interval;
			} while (timer->ticks.next < now);

			register_timer(timer);
		} else {
			free(timer);
			AMP_LOOP_GLOBAL(timers).count--;
		}

		timer = AMP_LOOP_GLOBAL(timers).next;
	} while (timer->ticks.next == then);
}

static DWORD wait_for_events(amp_event **events, DWORD count, DWORD timeout)
{
	// Build an array of handles for all registered events
	HANDLE *handles = malloc_type(HANDLE, count);

	if (handles == NULL) {
		return WAIT_FAILED; // todo: error info
	}
	
	for (DWORD i = 0; i < count; i++) {
		handles[i] = events[i]->handle;
	}

	// Wait for a handle to become signaled
	// todo: check for MAXIMUM_WAIT_OBJECTS overflow
	const DWORD result = WaitForMultipleObjects(count, handles, FALSE, timeout);

	free(handles);

	return result;
}

static void loop_tick()
{
#define OBJECT_IS_SIGNALED(handle) (WaitForSingleObject((handle), 0) == WAIT_OBJECT_0)
	// First check when the next timer is
	const DWORD timeout = get_tick_timeout();

	// Allocate an array big enough to hold all registered events
	DWORD event_count = AMP_LOOP_GLOBAL(events).count;
	amp_event **events = malloc_type(amp_event*, event_count);

	if (events == NULL) {
		return; // todo: error info
	}

	// Get all registered events that haven't been cancelled
	event_count = get_tick_events(events);

	// If there are no registered events just wait until the next timer, stop the loop if there are no timers either
	if (event_count == 0) {
		free(events);

		if (timeout == INFINITE) {
			AMP_LOOP_GLOBAL(status) = AMP_LOOP_STATUS_STOPPING;
		} else {
			if (timeout > 0) {
				Sleep(timeout);
			}

			trigger_next_timer();
		}

		return;
	}

	const DWORD wait_result = wait_for_events(events, event_count, timeout);

	switch (wait_result)
	{
	case WAIT_TIMEOUT:
		trigger_next_timer();
	case WAIT_FAILED:
		free(events);
		return;
	default:
		break;
	}

	DWORD signaled_event_count = 0;
	amp_event **signaled_events = malloc_type(amp_event*, event_count);

	if (signaled_events == NULL) {
		free(events);
		return; // todo: error info
	}
	
	for (DWORD i = wait_result; i < event_count; i++) {
		if (WaitForSingleObject(events[i]->handle, 0) == WAIT_OBJECT_0) {
			signaled_events[signaled_event_count++] = events[i];
		}
	}

	free(events);

	for (DWORD i = 0; i < signaled_event_count; i++) {
		signaled_events[i]->watcher.callback(&signaled_events[i]->watcher);

		if (!signaled_events[i]->watch) {
			signaled_events[i]->watcher.is_cancelled = TRUE;
		}
	}

	free(signaled_events);
}

void amp_loop_init()
{
	AMP_LOOP_GLOBAL(status) = AMP_LOOP_STATUS_STOPPED;

	AMP_LOOP_GLOBAL(timers).count = 0;
	AMP_LOOP_GLOBAL(timers).next = NULL;

	AMP_LOOP_GLOBAL(events).count = 0;
	AMP_LOOP_GLOBAL(events).next = NULL;
}

BOOL amp_loop_run()
{
	if (AMP_LOOP_GLOBAL(status) != AMP_LOOP_STATUS_STOPPED) {
		return FALSE; // todo: error info
	}

	AMP_LOOP_GLOBAL(status) = AMP_LOOP_STATUS_RUNNING;

	do {
		loop_tick();
	} while (AMP_LOOP_GLOBAL(status) == AMP_LOOP_STATUS_RUNNING);

	AMP_LOOP_GLOBAL(status) = AMP_LOOP_STATUS_STOPPED;

	return TRUE;
}

void amp_loop_stop()
{
	AMP_LOOP_GLOBAL(status) = AMP_LOOP_STATUS_STOPPING;
}

amp_watcher amp_loop_watch(HANDLE handle, amp_watcher_callback callback, void *data)
{
	return create_event(handle, callback, data, TRUE);
}

amp_watcher amp_loop_wait(HANDLE handle, amp_watcher_callback callback, void *data)
{
	return create_event(handle, callback, data, FALSE);
}

amp_watcher amp_loop_set_timeout(const int timeout, amp_watcher_callback callback, void *data)
{
	return create_timer(timeout, callback, data, FALSE);
}

amp_watcher amp_loop_set_interval(const int interval, amp_watcher_callback callback, void *data)
{
	return create_timer(interval, callback, data, TRUE);
}

void *amp_watcher_get_data(amp_watcher watcher)
{
	return watcher->data;
}

void amp_watcher_set_data(amp_watcher watcher, void *data)
{
	watcher->data = data;
}

void amp_watcher_set_callback(amp_watcher watcher, amp_watcher_callback callback)
{
	watcher->callback = callback;
}

void amp_watcher_cancel(amp_watcher watcher)
{
	watcher->is_cancelled = TRUE;
}
