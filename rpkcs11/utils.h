#pragma once

#include "pkcs11.h"

#include <cjson/cJSON.h>
#include <stdbool.h>
#include <stddef.h>

#define UNUSED(x) (void)(x)
#define DBG(fmt, ...) debug(__func__, __LINE__, fmt, ##__VA_ARGS__)
#define MAX_CRYPTO_OBJ_SIZE 4096

#define FILL_STRING_BY_JSON(json, key, str)                  \
    do {                                                     \
        cJSON *obj = cJSON_GetObjectItem(json, key);         \
        if (cJSON_IsString(obj))                             \
            padded_copy(str, obj->valuestring, sizeof(str)); \
        else                                                 \
            memset(str, ' ', sizeof(str));                   \
    } while (0)
#define FILL_INT_BY_JSON(json, key, val)                               \
    do {                                                               \
        cJSON *obj = cJSON_GetObjectItem(json, key);                   \
        val = cJSON_IsNumber(obj) ? (typeof(val))obj->valuedouble : 0; \
    } while (0)
#define FILL_INT_BY_JSON_UNAVAIL(json, key, val) \
    do {                                         \
        FILL_INT_BY_JSON(json, key, val);        \
        val = ntohUnavail(val);                  \
    } while (0)
#define FILL_VERSION_BY_JSON(json, key, ver)              \
    do {                                                  \
        cJSON *verObj = cJSON_GetObjectItem(json, key);   \
        ver.major = 0;                                    \
        ver.minor = 0;                                    \
        if (cJSON_IsObject(verObj)) {                     \
            FILL_INT_BY_JSON(verObj, "major", ver.major); \
            FILL_INT_BY_JSON(verObj, "minor", ver.minor); \
        }                                                 \
    } while (0)

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
CK_ULONG ntohUnavail(CK_ULONG v);
cJSON *wrapAttributeArr(CK_ATTRIBUTE_PTR attrs, CK_ULONG count, bool getter);
bool unwrapAttributeArr(cJSON *objs, CK_ATTRIBUTE_PTR attrs, CK_ULONG count);
