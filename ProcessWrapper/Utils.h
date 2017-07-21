#pragma once

#define SUCCESS 0
#define FAILURE -1

typedef int RESULT;

int vasprintf(char **strp, const char *fmt, va_list ap);
int asprintf(char **strp, const char *fmt, ...);
