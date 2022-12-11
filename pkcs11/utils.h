#pragma once

#include <stdbool.h>

#define UNUSED(x) (void)(x)

extern bool __rsc_dbg;
void debug(const char *func, int line, const char *fmt, ...);
#define DBG(fmt, ...) debug(__func__, __LINE__, fmt, ##__VA_ARGS__)
