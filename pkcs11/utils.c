#include "utils.h"

#include <stdarg.h>
#include <stdio.h>

bool __rsc_dbg = false;

void debug(const char *func, int line, const char *fmt, ...)
{
    if (!__rsc_dbg) {
        return;
    }
    va_list args;
    fprintf(stderr, "DBG %s:%d ", func, line);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}
