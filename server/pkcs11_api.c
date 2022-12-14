#include "pkcs11_api.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
struct pkcs11_ctx {
    HMODULE handle;
    CK_FUNCTION_LIST_PTR f;
};

struct pkcs11_ctx *open(const char *module)
{
    CK_C_GetFunctionList list;
    struct pkcs11_ctx *ctx = malloc(sizeof(*ctx));
    ctx->handle = LoadLibrary(module);
    if (ctx->handle == NULL) {
        close(ctx);
        return NULL;
    }
    CK_C_GetFunctionList getfunctionlist = (CK_C_GetFunctionList)GetProcAddress(ctx->handle, "C_GetFunctionList");
    if (getfunctionlist == NULL) {
        close(ctx);
        return NULL;
    }
    if (getfunctionlist(&ctx->f) != CKR_OK) {
        close(ctx);
        return NULL;
    }
    return ctx;
}

void close(struct pkcs11_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->handle != NULL) {
        FreeLibrary(ctx->handle);
    }
    free(ctx);
}
#else
#include <dlfcn.h>
struct pkcs11_ctx {
    void *handle;
    CK_FUNCTION_LIST_PTR f;
};

struct pkcs11_ctx *openPKCS11(const char *module)
{
    CK_C_GetFunctionList list;
    struct pkcs11_ctx *ctx = malloc(sizeof(*ctx));
    ctx->handle = dlopen(module, RTLD_LAZY);
    if (ctx->handle == NULL) {
        closePKCS11(ctx);
        return NULL;
    }
    CK_C_GetFunctionList getfunctionlist = dlsym(ctx->handle, "C_GetFunctionList");
    if (getfunctionlist == NULL) {
        closePKCS11(ctx);
        return NULL;
    }
    if (getfunctionlist(&ctx->f) != CKR_OK) {
        closePKCS11(ctx);
        return NULL;
    }
    return ctx;
}

void closePKCS11(struct pkcs11_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->handle != NULL) {
        dlclose(ctx->handle);
    }
    free(ctx);
}
#endif

CK_RV Initialize(struct pkcs11_ctx *ctx)
{
    return ctx->f->C_Initialize(NULL);
}

CK_RV Finalize(struct pkcs11_ctx *ctx)
{
    return ctx->f->C_Finalize(NULL);
}

CK_RV GetInfo(struct pkcs11_ctx *ctx, struct unpackedInfo *uInfo)
{
    CK_INFO pInfo;
    CK_RV rv = ctx->f->C_GetInfo(&pInfo);
    if (rv != CKR_OK) {
        return rv;
    }
    uInfo->cryptokiVersion = pInfo.cryptokiVersion;
    memcpy(uInfo->manufacturerID, pInfo.manufacturerID, sizeof(pInfo.manufacturerID));
    uInfo->flags = pInfo.flags;
    memcpy(uInfo->libraryDescription, pInfo.libraryDescription, sizeof(pInfo.libraryDescription));
    uInfo->libraryVersion = pInfo.libraryVersion;
    return rv;
}
