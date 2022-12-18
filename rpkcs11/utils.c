#include "utils.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CFG_PATH "~/.config/remotesc.json"
#define DEFAULT_ADDR "127.0.0.1:44555"

bool __rsc_dbg = false;

static cJSON *read_file(const char *fname);

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
    struct rsc_config *cfg = NULL;
    const char *cfg_path = getenv("REMOTESC_CONFIG");
    if (cfg_path == NULL) {
        cfg_path = DEFAULT_CFG_PATH;
    }

    const char *addr = getenv("REMOTESC_ADDR");
    const char *fingerprint = getenv("REMOTESC_FINGERPRINT");
    const char *secret = getenv("REMOTESC_SECRET");

    cJSON *root = read_file(cfg_path);
    if (cJSON_IsObject(root)) {
        cJSON *obj;
        obj = cJSON_GetObjectItem(root, "addr");
        if (addr == NULL && cJSON_IsString(obj)) {
            addr = obj->string;
        }
        obj = cJSON_GetObjectItem(root, "fingerprint");
        if (fingerprint == NULL && cJSON_IsString(obj)) {
            fingerprint = obj->string;
        }
        obj = cJSON_GetObjectItem(root, "secret");
        if (secret == NULL && cJSON_IsString(obj)) {
            secret = obj->string;
        }
    }

    if (addr == NULL) {
        addr = DEFAULT_ADDR;
    }
    if (fingerprint == NULL) {
        DBG("fingerprint not configured");
        goto out;
    }
    if (secret == NULL) {
        DBG("shared secret not configured");
        goto out;
    }

    cfg = malloc(sizeof(*cfg));
    cfg->addr = strdup(addr);
    cfg->fingerprint = strdup(fingerprint);
    cfg->secret = strdup(secret);
out:
    cJSON_Delete(root);
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

static cJSON *read_file(const char *fname)
{
    FILE *file = fopen(fname, "rb");
    if (file == NULL) {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size_t length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = malloc(length);
    size_t n = fread(content, sizeof(char), length, file);
    fclose(file);

    cJSON *json = cJSON_ParseWithLength(content, n);
    free(content);
    return json;
}
