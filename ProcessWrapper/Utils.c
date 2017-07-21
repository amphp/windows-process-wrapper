#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "Utils.h"

/*
 * Polyfill for vasprintf()
 * See https://stackoverflow.com/a/40160038/889949
 */
int vasprintf(char **strp, const char *fmt, va_list ap)
{
    // _vscprintf tells you how big the buffer needs to be
    int len = _vscprintf(fmt, ap);
    if (len == -1) {
        return -1;
    }

    size_t size = (size_t)len + 1;
    char *str = (char *)malloc(size);

    if (!str) {
        return -1;
    }

    // _vsprintf_s is the "secure" version of vsprintf
    int r = vsprintf_s(str, len + 1, fmt, ap);

    if (r == -1) {
        free(str);
        return -1;
    }

    *strp = str;

    return r;
}

/*
* Polyfill for asprintf()
* See https://stackoverflow.com/a/40160038/889949
*/
int asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    int r = vasprintf(strp, fmt, ap);
    va_end(ap);

    return r;
}
