#include "utils.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

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

void padded_copy(unsigned char *dst, const char *src, size_t dst_size)
{
    memset(dst, ' ', dst_size);
    size_t src_len = strlen(src);
    if (src_len > dst_size) {
        memcpy(dst, src, dst_size);
    } else {
        memcpy(dst, src, src_len);
    }
}
