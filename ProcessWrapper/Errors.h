#pragma once

#define SUCCESS 0
#define FAILURE -1

typedef int RESULT;

BOOL errors_init();
BOOL errors_destroy();
int errors_count();
BOOL error_push(char* message, ...);
BOOL system_error_push(int code, char* message, ...);
char *error_pop();
RESULT errors_output_all();
