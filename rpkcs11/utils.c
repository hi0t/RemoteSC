#include "utils.h"

#include <arpa/inet.h>
#include <mbedtls/base64.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_PORT "25519"
#define DEFAULT_GATE "<default>"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define HOST_ULONG_LEN sizeof(CK_ULONG)
#define NET_ULONG_LEN 4
#define NET_UNAVAIL 0xffffffff

bool __rsc_dbg = false;

static cJSON *read_file(const char *fname);
static char *format_addr(const char *addr);

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
    const char *addr = getenv("REMOTESC_ADDR");
    const char *fingerprint = getenv("REMOTESC_FINGERPRINT");
    const char *secret = getenv("REMOTESC_SECRET");

    cJSON *root = read_file(cfg_path);
    if (cJSON_IsObject(root)) {
        cJSON *obj;
        obj = cJSON_GetObjectItem(root, "addr");
        if (addr == NULL && cJSON_IsString(obj)) {
            addr = obj->valuestring;
        }
        obj = cJSON_GetObjectItem(root, "fingerprint");
        if (fingerprint == NULL && cJSON_IsString(obj)) {
            fingerprint = obj->valuestring;
        }
        obj = cJSON_GetObjectItem(root, "secret");
        if (secret == NULL && cJSON_IsString(obj)) {
            secret = obj->valuestring;
        }
    }
    if (addr == NULL) {
        addr = DEFAULT_GATE;
    }
    if (fingerprint == NULL) {
        DBG("fingerprint not configured");
        goto out;
    }
    if (secret == NULL) {
        DBG("shared secret not configured");
        goto out;
    }

    char *formatted_addr = format_addr(addr);
    if (formatted_addr == NULL) {
        DBG("invalid address %s", addr);
        goto out;
    }

    cfg = malloc(sizeof(*cfg));
    cfg->addr = formatted_addr;
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

CK_ULONG ntohUnavail(CK_ULONG v)
{
    if (v == NET_UNAVAIL) {
        return CK_UNAVAILABLE_INFORMATION;
    }
    return v;
}

cJSON *wrapAttributeArr(CK_ATTRIBUTE_PTR attrs, CK_ULONG count, bool getter)
{
    char buf[MAX_CRYPTO_OBJ_SIZE];
    cJSON *objs = cJSON_CreateArray();
    size_t str_len;

    for (CK_ULONG i = 0; i < count; i++) {
        cJSON *tmp = cJSON_CreateObject();
        cJSON_AddItemToArray(objs, tmp);

        cJSON_AddNumberToObject(tmp, "type", attrs[i].type);
        // request length
        if (attrs[i].pValue == NULL) {
            continue;
        }

        CK_ULONG len = attrs[i].ulValueLen;
        switch (attrs[i].type) {
        case CKA_CLASS:
        case CKA_CERTIFICATE_TYPE:
        case CKA_KEY_TYPE:
        case CKA_MODULUS_BITS:
            len = MIN(len, NET_ULONG_LEN);
        }

        if (!getter) {
            if (mbedtls_base64_encode((unsigned char *)buf, sizeof(buf), &str_len, attrs[i].pValue, len) != 0) {
                DBG("buffer too small");
                cJSON_Delete(objs);
                return NULL;
            }
            buf[str_len] = '\0';
            cJSON_AddStringToObject(tmp, "value", buf);
        }
        cJSON_AddNumberToObject(tmp, "valueLen", len);
    }
    return objs;
}

bool unwrapAttributeArr(cJSON *objs, CK_ATTRIBUTE_PTR attrs, CK_ULONG count)
{
    unsigned char buf[MAX_CRYPTO_OBJ_SIZE];
    int sz = cJSON_GetArraySize(objs);
    CK_ULONG len, dummy;

    for (int i = 0; i < sz; i++) {
        if (i >= (int)count) {
            return false;
        }
        cJSON *tmp = cJSON_GetArrayItem(objs, i);

        FILL_INT_BY_JSON(tmp, "type", attrs[i].type);
        FILL_INT_BY_JSON(tmp, "valueLen", len);

        if (len == 0) {
            continue;
        }

        if (len == NET_UNAVAIL) {
            attrs[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            continue;
        }

        switch (attrs[i].type) {
        case CKA_CLASS:
        case CKA_CERTIFICATE_TYPE:
        case CKA_KEY_TYPE:
        case CKA_MODULUS_BITS:
            len = MAX(len, HOST_ULONG_LEN);
        }

        cJSON *val = cJSON_GetObjectItem(tmp, "value");
        if (!cJSON_IsString(val)) {
            // return length
            attrs[i].ulValueLen = len;
            continue;
        }

        if (len > attrs[i].ulValueLen) {
            return false;
        }

        memset(buf, 0, len);
        if (mbedtls_base64_decode(buf, sizeof(buf), &dummy, (unsigned char *)val->valuestring, strlen(val->valuestring)) != 0) {
            DBG("buffer too small");
            return false;
        }
        memcpy(attrs[i].pValue, buf, len);

        attrs[i].ulValueLen = len;
    }
    return true;
}

static const char *default_config_location()
{
    static char path[PATH_MAX];
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL) {
        return path;
    }
    snprintf(path, sizeof(path), "%s/.config/remotesc.json", pw->pw_dir);
    return path;
}

static cJSON *read_file(const char *fname)
{
    if (fname == NULL) {
        fname = default_config_location();
    }
    FILE *f = fopen(fname, "rb");
    if (f == NULL) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    size_t length = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = malloc(length);
    size_t n = fread(content, sizeof(char), length, f);
    fclose(f);

    cJSON *json = cJSON_ParseWithLength(content, n);
    if (json == NULL) {
        DBG("invalid json format: %s", fname);
    }
    free(content);
    return json;
}

static const char *default_gateway()
{
    unsigned long destination, gateway;
    char line[1024];
    static char addr[INET_ADDRSTRLEN];
    FILE *f;

    f = fopen("/proc/net/route", "r");
    if (!f) {
        DBG("can not open /proc/net/route");
        return NULL;
    }

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%*s %lx %lx", &destination, &gateway) == 2) {
            if (destination == 0) {
                inet_ntop(AF_INET, &gateway, addr, sizeof(addr));
                fclose(f);
                return addr;
            }
        }
    }

    fclose(f);
    DBG("can not find default route");
    return NULL;
}

static char *format_addr(const char *addr)
{
    char buf[256];

    char *sep = strrchr(addr, ':');
    if (sep != NULL) {
        char *v6 = strrchr(addr, ']');
        if (sep < v6) {
            sep = NULL;
        }
    }
    if (strncmp(addr, DEFAULT_GATE, strlen(DEFAULT_GATE)) == 0) {
        addr = default_gateway();
        if (addr == NULL) {
            return NULL;
        }
        if (sep != NULL) {
            if (snprintf(buf, sizeof(buf), "%s%s", addr, sep) < 0) {
                return NULL;
            }
            return strdup(buf);
        }
    }
    if (sep == NULL) {
        if (snprintf(buf, sizeof(buf), "%s:%s", addr, DEFAULT_PORT) < 0) {
            return NULL;
        }
        return strdup(buf);
    }
    return strdup(addr);
}
