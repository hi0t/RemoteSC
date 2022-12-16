#pragma once

#include "pkcs11.h"

#include <json-c/json.h>

struct http;

struct http *http_init(const char *addr);
void http_cleanup(struct http *h);
CK_RV http_invoke(struct http *h, const char *method, json_object *args, json_object **ret);
