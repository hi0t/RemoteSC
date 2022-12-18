#include "pkcs11_api.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
struct rsc_ctx {
    HMODULE handle;
    CK_FUNCTION_LIST_PTR f;
};

static char *errMessage()
{
    static char buf[1024];
    DWORD len = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, GetLastError(), MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
        buf, sizeof(buf), NULL);

    if (len == 0) {
        return NULL;
    }

    char *end = buf + len;
    while (isspace(*--end))
        ;
    *(end + 1) = '\0';
    return buf;
}

rsc_ctx *rsc_open(const char *module, char **err)
{
    CK_C_GetFunctionList list;
    struct rsc_ctx *ctx = malloc(sizeof(*ctx));
    ctx->handle = LoadLibrary(module);
    if (ctx->handle == NULL) {
        *err = errMessage();
        rsc_close(ctx);
        return NULL;
    }
    CK_C_GetFunctionList getfunctionlist = (CK_C_GetFunctionList)GetProcAddress(ctx->handle, "C_GetFunctionList");
    if (getfunctionlist == NULL) {
        *err = errMessage();
        rsc_close(ctx);
        return NULL;
    }
    if (getfunctionlist(&ctx->f) != CKR_OK) {
        *err = "C_GetFunctionList failed";
        rsc_close(ctx);
        return NULL;
    }
    return ctx;
}

void rsc_close(rsc_ctx *ctx)
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

rsc_ctx *rsc_open(const char *module, char **err)
{
    CK_C_GetFunctionList list;
    struct rsc_ctx *ctx = malloc(sizeof(*ctx));
    ctx->handle = dlopen(module, RTLD_LAZY);
    if (ctx->handle == NULL) {
        *err = dlerror();
        rsc_close(ctx);
        return NULL;
    }
    CK_C_GetFunctionList getfunctionlist = dlsym(ctx->handle, "C_GetFunctionList");
    if (getfunctionlist == NULL) {
        *err = dlerror();
        rsc_close(ctx);
        return NULL;
    }
    if (getfunctionlist(&ctx->f) != CKR_OK) {
        *err = "C_GetFunctionList failed";
        rsc_close(ctx);
        return NULL;
    }
    return ctx;
}

void rsc_close(rsc_ctx *ctx)
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

CK_RV rsc_Initialize(rsc_ctx *ctx)
{
    return ctx->f->C_Initialize(NULL);
}

CK_RV rsc_Finalize(rsc_ctx *ctx)
{
    return ctx->f->C_Finalize(NULL);
}

CK_RV rsc_GetInfo(rsc_ctx *ctx, CK_INFO_PTR pInfo)
{
    return ctx->f->C_GetInfo(pInfo);
}

CK_RV rsc_GetSlotList(rsc_ctx *ctx, CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    return ctx->f->C_GetSlotList(tokenPresent, pSlotList, pulCount);
}

CK_RV rsc_GetSlotInfo(rsc_ctx *ctx, CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    return ctx->f->C_GetSlotInfo(slotID, pInfo);
}

CK_RV rsc_GetTokenInfo(rsc_ctx *ctx, CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    return ctx->f->C_GetTokenInfo(slotID, pInfo);
}

CK_RV rsc_OpenSession(rsc_ctx *ctx, CK_SLOT_ID slotID, CK_FLAGS flags, CK_SESSION_HANDLE_PTR phSession)
{
    return ctx->f->C_OpenSession(slotID, flags, NULL, NULL, phSession);
}

CK_RV rsc_CloseSession(rsc_ctx *ctx, CK_SESSION_HANDLE hSession)
{
    return ctx->f->C_CloseSession(hSession);
}

CK_RV rsc_CloseAllSessions(rsc_ctx *ctx, CK_SLOT_ID slotID)
{
    return ctx->f->C_CloseAllSessions(slotID);
}

CK_RV rsc_Login(rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, char *pPin, CK_ULONG ulPinLen)
{
    CK_RV rv = ctx->f->C_Login(hSession, userType, (CK_UTF8CHAR_PTR)pPin, ulPinLen);
    memset(pPin, '*', ulPinLen);
    return rv;
}

CK_RV rsc_Logout(rsc_ctx *ctx, CK_SESSION_HANDLE hSession)
{
    return ctx->f->C_Logout(hSession);
}

CK_RV rsc_GetAttributeValue(rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    return ctx->f->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
}

CK_RV rsc_FindObjectsInit(rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    return ctx->f->C_FindObjectsInit(hSession, pTemplate, ulCount);
}

CK_RV rsc_FindObjects(rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    return ctx->f->C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
}

CK_RV rsc_FindObjectsFinal(rsc_ctx *ctx, CK_SESSION_HANDLE hSession)
{
    return ctx->f->C_FindObjectsFinal(hSession);
}

CK_RV rsc_SignInit(rsc_ctx *ctx, CK_SESSION_HANDLE hSession, rsc_unpacked_mechanism *uMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_MECHANISM pMechanism = {
        .mechanism = uMechanism->mechanism,
        .pParameter = uMechanism->pParameter,
        .ulParameterLen = uMechanism->ulParameterLen
    };

    CK_RV rv = ctx->f->C_SignInit(hSession, &pMechanism, hKey);

    uMechanism->mechanism = pMechanism.mechanism;
    uMechanism->pParameter = pMechanism.pParameter;
    uMechanism->ulParameterLen = pMechanism.ulParameterLen;
    return rv;
}

CK_RV rsc_Sign(rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return ctx->f->C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
}

CK_RV rsc_SignUpdate(rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    return ctx->f->C_SignUpdate(hSession, pPart, ulPartLen);
}

CK_RV rsc_SignFinal(rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    return ctx->f->C_SignFinal(hSession, pSignature, pulSignatureLen);
}
