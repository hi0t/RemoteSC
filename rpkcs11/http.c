#include "http.h"
#include "utils.h"

#include <curl/curl.h>
#include <curl/mprintf.h>
#include <stdlib.h>
#include <string.h>

struct http {
    CURL *curl;
    struct curl_slist *headers;
};

struct curl_resp {
    char *buf;
    size_t size;
};

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp);

struct http *http_init(const char *addr)
{
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        return NULL;
    }

    struct http *h = malloc(sizeof(*h));
    h->curl = curl;

    char *url = curl_maprintf("http://%s", addr);
    curl_easy_setopt(h->curl, CURLOPT_URL, url);
    curl_free(url);

    h->headers = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, h->headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, NULL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    return h;
}

void http_cleanup(struct http *h)
{
    if (h == NULL) {
        return;
    }
    curl_slist_free_all(h->headers);
    curl_easy_cleanup(h->curl);
    free(h);
}

CK_RV http_invoke(struct http *h, const char *method, json_object *args, json_object **ret, bool sanitize)
{
    struct curl_resp raw_resp = { 0 };
    char curl_errbuf[CURL_ERROR_SIZE];
    json_object *resp = NULL, *req = NULL;
    CK_RV rv;

    if (strlen(method) > 2 && method[0] == 'C' && method[1] == '_') {
        method += 2;
    }

    req = json_object_new_object();
    json_object_object_add(req, "method", json_object_new_string(method));
    json_object_object_add(req, "args", args);

    const char *raw_req = json_object_to_json_string_ext(req, JSON_C_TO_STRING_PLAIN);
    size_t req_len = strlen(raw_req);
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDS, raw_req);
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE, req_len);
    curl_easy_setopt(h->curl, CURLOPT_WRITEDATA, &raw_resp);
    curl_easy_setopt(h->curl, CURLOPT_ERRORBUFFER, curl_errbuf);

    DBG("req: %s", method);
    CURLcode cerr = curl_easy_perform(h->curl);

    if (sanitize) {
        memset((char *)raw_req, '*', req_len);
    }

    if (cerr != CURLE_OK) {
        DBG("http err: (%d) %s", cerr, curl_errbuf);
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    long resp_code = 0;
    curl_easy_getinfo(h->curl, CURLINFO_RESPONSE_CODE, &resp_code);
    if (resp_code != 200) {
        DBG("resp %d err: %s", resp_code, raw_resp.buf);
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    rv = CKR_OK;
    resp = json_tokener_parse(raw_resp.buf);
    json_object *err;
    if (json_object_object_get_ex(resp, "err", &err)) {
        rv = json_object_get_uint64(err);
    }

    if (rv != CKR_OK) {
        json_object *errDesc;
        if (json_object_object_get_ex(resp, "errDescription", &errDesc)) {
            DBG("error description: %s", json_object_get_string(errDesc));
        }
        goto out;
    }

    if (ret != NULL && json_object_object_get_ex(resp, "ret", &*ret)) {
        json_object_get(*ret);
    }
out:
    json_object_get(args);
    json_object_put(req);
    json_object_put(resp);
    free(raw_resp.buf);
    return rv;
}

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct curl_resp *mem = (struct curl_resp *)userp;

    char *ptr = realloc(mem->buf, mem->size + realsize + 1);
    if (!ptr) {
        DBG("not enough memory");
        return 0;
    }

    mem->buf = ptr;
    memcpy(&(mem->buf[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->buf[mem->size] = 0;

    return realsize;
}
