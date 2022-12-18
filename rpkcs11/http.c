#include "http.h"
#include "utils.h"

#include <curl/curl.h>
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

struct http *http_init(const char *addr, const char *fingerprint, const char *shared_secret)
{
    char str[1024];
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        return NULL;
    }

    struct http *h = malloc(sizeof(*h));
    h->curl = curl;

    snprintf(str, sizeof(str), "https://%s", addr);
    curl_easy_setopt(h->curl, CURLOPT_URL, str);

    snprintf(str, sizeof(str), "sha256//%s", fingerprint);
    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, str);

    h->headers = curl_slist_append(NULL, "Content-Type: application/json; charset=utf-8");
    snprintf(str, sizeof(str), "Authorization: Bearer %s", shared_secret);
    h->headers = curl_slist_append(h->headers, str);

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

CK_RV http_invoke(struct http *h, const char *method, cJSON *args, cJSON **ret, bool sanitize)
{
    struct curl_resp raw_resp = { 0 };
    char curl_errbuf[CURL_ERROR_SIZE];
    cJSON *resp = NULL, *req = NULL;
    CK_RV rv;

    if (strlen(method) > 2 && method[0] == 'C' && method[1] == '_') {
        method += 2;
    }

    req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "method", method);
    cJSON_AddItemReferenceToObject(req, "args", args);

    char *raw_req = cJSON_PrintUnformatted(req);
    size_t req_len = strlen(raw_req);
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDS, raw_req);
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE, req_len);
    curl_easy_setopt(h->curl, CURLOPT_WRITEDATA, &raw_resp);
    curl_easy_setopt(h->curl, CURLOPT_ERRORBUFFER, curl_errbuf);

    DBG("req: %s", method);
    CURLcode cerr = curl_easy_perform(h->curl);

    if (sanitize) {
        memset(raw_req, '*', req_len);
    }

    if (cerr != CURLE_OK) {
        size_t len = strlen(curl_errbuf);
        if (len == 0) {
            DBG("http err: (%d) %s", cerr, curl_easy_strerror(cerr));
        } else {
            DBG("http err: (%d) %s", cerr, curl_errbuf);
        }
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
    resp = cJSON_Parse(raw_resp.buf);

    cJSON *err = cJSON_GetObjectItem(resp, "err");
    if (cJSON_IsNumber(err)) {
        rv = (CK_RV)err->valuedouble;
    }

    if (rv != CKR_OK) {
        cJSON *errDesc = cJSON_GetObjectItem(resp, "errDescription");
        if (cJSON_IsString(errDesc)) {
            DBG("error description: %s", errDesc->valuestring);
        }
        goto out;
    }

    if (ret != NULL) {
        *ret = cJSON_DetachItemFromObject(resp, "ret");
    }
out:
    cJSON_Delete(req);
    cJSON_Delete(resp);
    free(raw_req);
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
