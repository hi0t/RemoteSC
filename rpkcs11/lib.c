#include "http.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

#define DEFAULT_ADDR "127.0.0.1:44555"

#define INVOKE(args, ret) http_invoke(client, __func__, args, ret)
#define FILL_STRING_BY_JSON(json, str)                     \
    do {                                                   \
        cJSON *j = json;                                   \
        if (cJSON_IsString(j)) {                           \
            padded_copy(str, j->valuestring, sizeof(str)); \
        } else {                                           \
            memset(str, ' ', sizeof(str));                 \
        }                                                  \
    } while (0)
#define FILL_INT_BY_JSON(json, val)                                \
    do {                                                           \
        cJSON *j = json;                                           \
        val = cJSON_IsNumber(j) ? (typeof(val))j->valuedouble : 0; \
    } while (0)
#define FILL_VERSION_BY_JSON(json, ver)                                 \
    do {                                                                \
        cJSON *j = json;                                                \
        if (cJSON_IsObject(j)) {                                        \
            cJSON *major = cJSON_GetObjectItem(j, "major");             \
            cJSON *minor = cJSON_GetObjectItem(j, "minor");             \
            ver.major = cJSON_IsNumber(major) ? major->valuedouble : 0; \
            ver.minor = cJSON_IsNumber(minor) ? minor->valuedouble : 0; \
        } else {                                                        \
            ver.major = 0;                                              \
            ver.minor = 0;                                              \
        }                                                               \
    } while (0)

static CK_FUNCTION_LIST function_list;
static struct http *client;

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
#ifdef NDEBUG
    __rsc_dbg = getenv("REMOTESC_DBG") ? true : false;
#else
    __rsc_dbg = true;
#endif
    UNUSED(pInitArgs);

    const char *addr = getenv("REMOTESC_ADDR");
    if (addr == NULL) {
        addr = DEFAULT_ADDR;
    }

    client = http_init(addr);
    if (client == NULL) {
        return CKR_FUNCTION_FAILED;
    }
    return INVOKE(NULL, NULL);
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    UNUSED(pReserved);

    CK_RV rv = INVOKE(NULL, NULL);
    http_cleanup(client);
    return rv;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    cJSON *ret = NULL;
    CK_RV rv;

    if ((rv = INVOKE(NULL, &ret)) != CKR_OK) {
        return rv;
    }

    FILL_VERSION_BY_JSON(cJSON_GetObjectItem(ret, "cryptokiVersion"), pInfo->cryptokiVersion);
    FILL_STRING_BY_JSON(cJSON_GetObjectItem(ret, "manufacturerID"), pInfo->manufacturerID);
    FILL_INT_BY_JSON(cJSON_GetObjectItem(ret, "flags"), pInfo->flags);
    FILL_STRING_BY_JSON(cJSON_GetObjectItem(ret, "libraryDescription"), pInfo->libraryDescription);
    FILL_VERSION_BY_JSON(cJSON_GetObjectItem(ret, "libraryVersion"), pInfo->libraryVersion);
    cJSON_Delete(ret);

    return rv;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *ppFunctionList = &function_list;
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    UNUSED(tokenPresent);
    UNUSED(pSlotList);
    UNUSED(pulCount);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    UNUSED(slotID);
    UNUSED(pInfo);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    UNUSED(slotID);
    UNUSED(pInfo);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    UNUSED(flags);
    UNUSED(pSlot);
    UNUSED(pReserved);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    UNUSED(slotID);
    UNUSED(pMechanismList);
    UNUSED(pulCount);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    UNUSED(slotID);
    UNUSED(type);
    UNUSED(pInfo);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
    UNUSED(slotID);
    UNUSED(pPin);
    UNUSED(ulPinLen);
    UNUSED(pLabel);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    UNUSED(hSession);
    UNUSED(pPin);
    UNUSED(ulPinLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
    UNUSED(hSession);
    UNUSED(pOldPin);
    UNUSED(ulOldLen);
    UNUSED(pNewPin);
    UNUSED(ulNewLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
    UNUSED(slotID);
    UNUSED(flags);
    UNUSED(pApplication);
    UNUSED(Notify);
    UNUSED(phSession);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    UNUSED(hSession);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    UNUSED(slotID);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    UNUSED(hSession);
    UNUSED(pInfo);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
    UNUSED(hSession);
    UNUSED(pOperationState);
    UNUSED(pulOperationStateLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pOperationState,
    CK_ULONG ulOperationStateLen,
    CK_OBJECT_HANDLE hEncryptionKey,
    CK_OBJECT_HANDLE hAuthenticationKey)
{
    UNUSED(hSession);
    UNUSED(pOperationState);
    UNUSED(ulOperationStateLen);
    UNUSED(hEncryptionKey);
    UNUSED(hAuthenticationKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    UNUSED(hSession);
    UNUSED(userType);
    UNUSED(pPin);
    UNUSED(ulPinLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    UNUSED(hSession);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
    UNUSED(hSession);
    UNUSED(pTemplate);
    UNUSED(ulCount);
    UNUSED(phObject);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
    UNUSED(hSession);
    UNUSED(hObject);
    UNUSED(pTemplate);
    UNUSED(ulCount);
    UNUSED(phNewObject);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    UNUSED(hSession);
    UNUSED(hObject);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    UNUSED(hSession);
    UNUSED(hObject);
    UNUSED(pulSize);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    UNUSED(hSession);
    UNUSED(hObject);
    UNUSED(pTemplate);
    UNUSED(ulCount);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    UNUSED(hSession);
    UNUSED(hObject);
    UNUSED(pTemplate);
    UNUSED(ulCount);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    UNUSED(hSession);
    UNUSED(pTemplate);
    UNUSED(ulCount);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    UNUSED(hSession);
    UNUSED(phObject);
    UNUSED(ulMaxObjectCount);
    UNUSED(pulObjectCount);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    UNUSED(hSession);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(hKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    UNUSED(hSession);
    UNUSED(pData);
    UNUSED(ulDataLen);
    UNUSED(pEncryptedData);
    UNUSED(pulEncryptedDataLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
    UNUSED(hSession);
    UNUSED(pPart);
    UNUSED(ulPartLen);
    UNUSED(pEncryptedPart);
    UNUSED(pulEncryptedPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
    UNUSED(hSession);
    UNUSED(pLastEncryptedPart);
    UNUSED(pulLastEncryptedPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(hKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    UNUSED(hSession);
    UNUSED(pEncryptedData);
    UNUSED(ulEncryptedDataLen);
    UNUSED(pData);
    UNUSED(pulDataLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
    UNUSED(hSession);
    UNUSED(pEncryptedPart);
    UNUSED(ulEncryptedPartLen);
    UNUSED(pPart);
    UNUSED(pulPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    UNUSED(hSession);
    UNUSED(pLastPart);
    UNUSED(pulLastPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    UNUSED(hSession);
    UNUSED(pData);
    UNUSED(ulDataLen);
    UNUSED(pDigest);
    UNUSED(pulDigestLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    UNUSED(hSession);
    UNUSED(pPart);
    UNUSED(ulPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
    UNUSED(hSession);
    UNUSED(hKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    UNUSED(hSession);
    UNUSED(pDigest);
    UNUSED(pulDigestLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(hKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    UNUSED(hSession);
    UNUSED(pData);
    UNUSED(ulDataLen);
    UNUSED(pSignature);
    UNUSED(pulSignatureLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    UNUSED(hSession);
    UNUSED(pPart);
    UNUSED(ulPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    UNUSED(hSession);
    UNUSED(pSignature);
    UNUSED(pulSignatureLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(hKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    UNUSED(hSession);
    UNUSED(pData);
    UNUSED(ulDataLen);
    UNUSED(pSignature);
    UNUSED(pulSignatureLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(hKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    UNUSED(hSession);
    UNUSED(pData);
    UNUSED(ulDataLen);
    UNUSED(pSignature);
    UNUSED(ulSignatureLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    UNUSED(hSession);
    UNUSED(pPart);
    UNUSED(ulPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    UNUSED(hSession);
    UNUSED(pSignature);
    UNUSED(ulSignatureLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(hKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen,
    CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen)
{
    UNUSED(hSession);
    UNUSED(pSignature);
    UNUSED(ulSignatureLen);
    UNUSED(pData);
    UNUSED(pulDataLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
    UNUSED(hSession);
    UNUSED(pPart);
    UNUSED(ulPartLen);
    UNUSED(pEncryptedPart);
    UNUSED(pulEncryptedPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{
    UNUSED(hSession);
    UNUSED(pEncryptedPart);
    UNUSED(ulEncryptedPartLen);
    UNUSED(pPart);
    UNUSED(pulPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen)
{
    UNUSED(hSession);
    UNUSED(pPart);
    UNUSED(ulPartLen);
    UNUSED(pEncryptedPart);
    UNUSED(pulEncryptedPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen)
{
    UNUSED(hSession);
    UNUSED(pEncryptedPart);
    UNUSED(ulEncryptedPartLen);
    UNUSED(pPart);
    UNUSED(pulPartLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phKey)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(pTemplate);
    UNUSED(ulCount);
    UNUSED(phKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(pPublicKeyTemplate);
    UNUSED(ulPublicKeyAttributeCount);
    UNUSED(pPrivateKeyTemplate);
    UNUSED(ulPrivateKeyAttributeCount);
    UNUSED(phPublicKey);
    UNUSED(phPrivateKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey,
    CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey,
    CK_ULONG_PTR pulWrappedKeyLen)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(hWrappingKey);
    UNUSED(hKey);
    UNUSED(pWrappedKey);
    UNUSED(pulWrappedKeyLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey,
    CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(hUnwrappingKey);
    UNUSED(pWrappedKey);
    UNUSED(ulWrappedKeyLen);
    UNUSED(pTemplate);
    UNUSED(ulAttributeCount);
    UNUSED(phKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey)
{
    UNUSED(hSession);
    UNUSED(pMechanism);
    UNUSED(hBaseKey);
    UNUSED(pTemplate);
    UNUSED(ulAttributeCount);
    UNUSED(phKey);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
    UNUSED(hSession);
    UNUSED(pSeed);
    UNUSED(ulSeedLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
    UNUSED(hSession);
    UNUSED(pRandomData);
    UNUSED(ulRandomLen);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
    UNUSED(hSession);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
    UNUSED(hSession);
    DBG("%s not supported", __func__);
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_FUNCTION_LIST function_list = {
    { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
};
