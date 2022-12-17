#pragma once

#include "pkcs11.h"

#include <json-c/json.h>
#include <stdbool.h>

struct http;

struct http *http_init(const char *addr, const char *fingerprint, const char *shared_secret);
void http_cleanup(struct http *h);
CK_RV http_invoke(struct http *h, const char *method, json_object *args, json_object **ret, bool sanitize);
