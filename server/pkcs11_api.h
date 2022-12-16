#pragma once

#include <pkcs11.h>

struct rsc_ctx;

struct rsc_unpacked_info {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
};

struct rsc_ctx *rsc_open(const char *module);
void rsc_close(struct rsc_ctx *ctx);

CK_RV rsc_Initialize(struct rsc_ctx *ctx);
CK_RV rsc_Finalize(struct rsc_ctx *ctx);
CK_RV rsc_GetInfo(struct rsc_ctx *ctx, struct rsc_unpacked_info *uInfo);
CK_RV rsc_GetSlotList(struct rsc_ctx *ctx, CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
CK_RV rsc_GetSlotInfo(struct rsc_ctx *ctx, CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
CK_RV rsc_GetTokenInfo(struct rsc_ctx *ctx, CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
CK_RV rsc_OpenSession(struct rsc_ctx *ctx, CK_SLOT_ID slotID, CK_FLAGS flags, CK_SESSION_HANDLE_PTR phSession);
CK_RV rsc_CloseSession(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession);
CK_RV rsc_CloseAllSessions(struct rsc_ctx *ctx, CK_SLOT_ID slotID);
CK_RV rsc_Login(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, char *pPin, CK_ULONG ulPinLen);
CK_RV rsc_Logout(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession);
CK_RV rsc_GetAttributeValue(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV rsc_FindObjectsInit(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV rsc_FindObjects(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
CK_RV rsc_FindObjectsFinal(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession);
CK_RV rsc_SignInit(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
CK_RV rsc_Sign(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
CK_RV rsc_SignUpdate(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV rsc_SignFinal(struct rsc_ctx *ctx, CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
