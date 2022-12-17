#pragma once

#include <stdbool.h>
#include <stddef.h>

#define UNUSED(x) (void)(x)
#define DBG(fmt, ...) debug(__func__, __LINE__, fmt, ##__VA_ARGS__)

struct rsc_config {
    char *addr;
    char *fingerprint;
    char *secret;
};

extern bool __rsc_dbg;

void debug(const char *func, int line, const char *fmt, ...);
void padded_copy(unsigned char *dst, const char *src, size_t dst_size);
struct rsc_config *parse_config();
void free_config(struct rsc_config *cfg);
