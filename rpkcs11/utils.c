#include "utils.h"

#include <json-c/json.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CFG_PATH "~/.config/remotesc.json"
#define DEFAULT_ADDR "127.0.0.1:44555"

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

struct rsc_config *parse_config()
{
    const char *cfg_path = getenv("REMOTESC_CONFIG");
    if (cfg_path == NULL) {
        cfg_path = DEFAULT_CFG_PATH;
    }

    const char *addr = getenv("REMOTESC_ADDR");
    const char *fingerprint = getenv("REMOTESC_FINGERPRINT");
    const char *secret = getenv("REMOTESC_SECRET");

    json_object *root = json_object_from_file(cfg_path);
    if (root != NULL) {
        json_object *obj;
        if (addr == NULL && json_object_object_get_ex(root, "addr", &obj)) {
            addr = json_object_get_string(obj);
        }
        if (fingerprint == NULL && json_object_object_get_ex(root, "fingerprint", &obj)) {
            fingerprint = json_object_get_string(obj);
        }
        if (secret == NULL && json_object_object_get_ex(root, "secret", &obj)) {
            secret = json_object_get_string(obj);
        }
    }

    if (addr == NULL) {
        addr = DEFAULT_ADDR;
    }
    if (fingerprint == NULL) {
        DBG("fingerprint not configured");
        return NULL;
    }
    if (secret == NULL) {
        DBG("shared secret not configured");
        return NULL;
    }

    struct rsc_config *cfg = malloc(sizeof(*cfg));
    cfg->addr = strdup(addr);
    cfg->fingerprint = strdup(fingerprint);
    cfg->secret = strdup(secret);
    return cfg;
}

void free_config(struct rsc_config *cfg)
{
    if (cfg == NULL) {
        return;
    }
    free(cfg->addr);
    free(cfg->fingerprint);
    free(cfg->secret);
    free(cfg);
}
