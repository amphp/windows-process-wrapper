#include <windows.h>
#include <stdio.h>
#include "Errors.h"
#include "Utils.h"

static PSLIST_HEADER errors;

typedef struct _error_item {
    SLIST_ENTRY entry;
    char* message;
} error_item_t;

BOOL errors_init()
{
    if (errors != NULL) {
        return FALSE;
    }

    errors = _aligned_malloc(sizeof(SLIST_HEADER), MEMORY_ALLOCATION_ALIGNMENT);

    if (errors == NULL) {
        return FALSE;
    }

    InitializeSListHead(errors);

    return TRUE;
}

BOOL errors_destroy()
{
    if (errors == NULL) {
        return FALSE;
    }

    InterlockedFlushSList(errors);
    _aligned_free(errors);

    errors = NULL;

    return TRUE;
}

int errors_count()
{
    if (errors == NULL) {
        return -1;
    }

    return QueryDepthSList(errors);
}

BOOL error_push(char* format, ...)
{
    if (errors == NULL) {
        return FALSE;
    }

    error_item_t *item = _aligned_malloc(sizeof(error_item_t), MEMORY_ALLOCATION_ALIGNMENT);

    if (item == NULL) {
        return FALSE;
    }

    char *message;

    va_list ap;

    va_start(ap, format);
    vasprintf(&message, format, ap);
    va_end(ap);

    item->message = message;
    InterlockedPushEntrySList(errors, &item->entry);

    return TRUE;
}

BOOL system_error_push(int code, char* message, ...)
{
    char *errstr = NULL;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&errstr, 0, NULL
        );

    if (message == NULL) {
        return error_push("%d: %s", code, errstr);
    }

    va_list ap;
    char *extra;

    va_start(ap, message);
    vasprintf(&extra, message, ap);
    va_end(ap);

    return error_push("%s: %d: %s", extra, code, errstr);
}

char *error_pop()
{
    if (errors == NULL) {
        return NULL;
    }

    error_item_t *item = (error_item_t*)InterlockedPopEntrySList(errors);

    if (item == NULL) {
        return NULL;
    }

    char *message = item->message;
    _aligned_free(item);

    return message;
}

/*
 * Output error messages to stderr and return -1
 */
RESULT errors_exit()
{
    char *message;

    while (NULL != (message = error_pop())) {
        fprintf(stderr, message);
    }

    errors_destroy();

    return FAILURE;
}
