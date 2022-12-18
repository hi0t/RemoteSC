#pragma once

#include "pkcs11.h"

#include <cjson/cJSON.h>
#include <stdbool.h>

struct http;

struct http *http_init(const char *addr, const char *fingerprint, const char *shared_secret);
void http_cleanup(struct http *h);
CK_RV http_invoke(struct http *h, const char *method, cJSON *args, cJSON **ret, bool sanitize);
