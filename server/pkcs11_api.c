#include "pkcs11_api.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
struct rsc_ctx {
    HMODULE handle;
    CK_FUNCTION_LIST_PTR f;
};

struct rsc_ctx *rsc_open(const char *module)
{
    CK_C_GetFunctionList list;
    struct rsc_ctx *ctx = malloc(sizeof(*ctx));
    ctx->handle = LoadLibrary(module);
    if (ctx->handle == NULL) {
        rsc_close(ctx);
        return NULL;
    }
    CK_C_GetFunctionList getfunctionlist = (CK_C_GetFunctionList)GetProcAddress(ctx->handle, "C_GetFunctionList");
    if (getfunctionlist == NULL) {
        rsc_close(ctx);
        return NULL;
    }
    if (getfunctionlist(&ctx->f) != CKR_OK) {
        rsc_close(ctx);
        return NULL;
    }
    return ctx;
}

void rsc_close(struct rsc_ctx *ctx)
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
struct rsc_ctx {
    void *handle;
    CK_FUNCTION_LIST_PTR f;
};

struct rsc_ctx *rsc_open(const char *module)
{
    CK_C_GetFunctionList list;
    struct rsc_ctx *ctx = malloc(sizeof(*ctx));
    ctx->handle = dlopen(module, RTLD_LAZY);
    if (ctx->handle == NULL) {
        rsc_close(ctx);
        return NULL;
    }
    CK_C_GetFunctionList getfunctionlist = dlsym(ctx->handle, "C_GetFunctionList");
    if (getfunctionlist == NULL) {
        rsc_close(ctx);
        return NULL;
    }
    if (getfunctionlist(&ctx->f) != CKR_OK) {
        rsc_close(ctx);
        return NULL;
    }
    return ctx;
}

void rsc_close(struct rsc_ctx *ctx)
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

CK_RV rsc_Initialize(struct rsc_ctx *ctx)
{
    return ctx->f->C_Initialize(NULL);
}

CK_RV rsc_Finalize(struct rsc_ctx *ctx)
{
    return ctx->f->C_Finalize(NULL);
}

CK_RV rsc_GetInfo(struct rsc_ctx *ctx, struct rsc_unpacked_info *uInfo)
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

CK_RV rsc_GetSlotList(struct rsc_ctx *ctx, CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    return ctx->f->C_GetSlotList(tokenPresent, pSlotList, pulCount);
}

CK_RV rsc_GetSlotInfo(struct rsc_ctx *ctx, CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    return ctx->f->C_GetSlotInfo(slotID, pInfo);
}

CK_RV rsc_GetTokenInfo(struct rsc_ctx *ctx, CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    return ctx->f->C_GetTokenInfo(slotID, pInfo);
}

CK_RV rsc_OpenSession(struct rsc_ctx *ctx, CK_SLOT_ID slotID, CK_FLAGS flags, CK_SESSION_HANDLE_PTR phSession)
{
    return ctx->f->C_OpenSession(slotID, flags, NULL, NULL, phSession);
}

CK_RV rsc_CloseSession(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession)
{
    return ctx->f->C_CloseSession(hSession);
}

CK_RV rsc_CloseAllSessions(struct rsc_ctx *ctx, CK_SLOT_ID slotID)
{
    return ctx->f->C_CloseAllSessions(slotID);
}

CK_RV rsc_GetAttributeValue(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    for (CK_ULONG i = 0; i < ulCount; i++) {
        if (pTemplate[i].ulValueLen > 0) {
            pTemplate[i].pValue = malloc(pTemplate[i].ulValueLen);
        }
    }
    return ctx->f->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
}

CK_RV rsc_FindObjectsInit(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    return ctx->f->C_FindObjectsInit(hSession, pTemplate, ulCount);
}

CK_RV rsc_FindObjects(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    return ctx->f->C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

CK_RV rsc_FindObjectsFinal(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession)
{
    return ctx->f->C_FindObjectsFinal(hSession);
}

CK_RV rsc_Login(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, char *pPin, CK_ULONG ulPinLen)
{
    return ctx->f->C_Login(hSession, userType, (CK_UTF8CHAR_PTR)pPin, ulPinLen);
}

CK_RV rsc_Logout(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession)
{
    return ctx->f->C_Logout(hSession);
}
