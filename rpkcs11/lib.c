#include "http.h"
#include "utils.h"

#include <mbedtls/base64.h>
#include <stdlib.h>
#include <string.h>

#define INVOKE(args, ret) http_invoke(client, __func__, args, ret, false)
#define INVOKE_SAFE(args, ret) http_invoke(client, __func__, args, ret, true)

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
    CK_RV rv;

    struct rsc_config *cfg = parse_config();
    if (cfg == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    client = http_init(cfg->addr, cfg->fingerprint, cfg->secret);
    if (client == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }
    rv = INVOKE(NULL, NULL);
out:
    free_config(cfg);
    return rv;
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

    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((rv = INVOKE(NULL, &ret)) != CKR_OK) {
        return rv;
    }

    FILL_VERSION_BY_JSON(ret, "cryptokiVersion", pInfo->cryptokiVersion);
    FILL_STRING_BY_JSON(ret, "manufacturerID", pInfo->manufacturerID);
    FILL_INT_BY_JSON(ret, "flags", pInfo->flags);
    FILL_STRING_BY_JSON(ret, "libraryDescription", pInfo->libraryDescription);
    FILL_VERSION_BY_JSON(ret, "libraryVersion", pInfo->libraryVersion);
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
    cJSON *args = NULL, *ret = NULL;
    CK_RV rv;

    if (pulCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateBool(tokenPresent));
    if (pSlotList == NULL) {
        cJSON_AddItemToArray(args, cJSON_CreateNumber(0));
    } else {
        cJSON_AddItemToArray(args, cJSON_CreateNumber(*pulCount));
    }

    rv = INVOKE(args, &ret);

    if (!cJSON_IsObject(ret)) {
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    CK_ULONG start_count = *pulCount;
    FILL_INT_BY_JSON(ret, "cnt", *pulCount);

    if (pSlotList != NULL) {
        cJSON *list = cJSON_GetObjectItem(ret, "list");
        cJSON *id;
        size_t i = 0;
        cJSON_ArrayForEach(id, list)
        {
            if (cJSON_IsNumber(id)) {
                if (i >= start_count) {
                    rv = CKR_BUFFER_TOO_SMALL;
                    goto out;
                }
                pSlotList[i++] = id->valuedouble;
            }
        }
    }
out:
    cJSON_Delete(args);
    cJSON_Delete(ret);
    return rv;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    cJSON *args = NULL, *ret = NULL;
    CK_RV rv;

    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(slotID));

    if ((rv = INVOKE(args, &ret)) != CKR_OK) {
        goto out;
    }

    FILL_STRING_BY_JSON(ret, "slotDescription", pInfo->slotDescription);
    FILL_STRING_BY_JSON(ret, "manufacturerID", pInfo->manufacturerID);
    FILL_INT_BY_JSON(ret, "flags", pInfo->flags);
    FILL_VERSION_BY_JSON(ret, "hardwareVersion", pInfo->hardwareVersion);
    FILL_VERSION_BY_JSON(ret, "firmwareVersion", pInfo->firmwareVersion);
out:
    cJSON_Delete(args);
    cJSON_Delete(ret);
    return rv;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    cJSON *args = NULL, *ret = NULL;
    CK_RV rv;

    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(slotID));

    if ((rv = INVOKE(args, &ret)) != CKR_OK) {
        goto out;
    }

    FILL_STRING_BY_JSON(ret, "label", pInfo->label);
    FILL_STRING_BY_JSON(ret, "manufacturerID", pInfo->manufacturerID);
    FILL_STRING_BY_JSON(ret, "model", pInfo->model);
    FILL_STRING_BY_JSON(ret, "serialNumber", pInfo->serialNumber);
    FILL_INT_BY_JSON(ret, "flags", pInfo->flags);
    FILL_INT_BY_JSON(ret, "maxSessionCount", pInfo->ulMaxSessionCount);
    FILL_INT_BY_JSON(ret, "sessionCount", pInfo->ulSessionCount);
    FILL_INT_BY_JSON(ret, "maxRwSessionCount", pInfo->ulMaxRwSessionCount);
    FILL_INT_BY_JSON(ret, "rwSessionCount", pInfo->ulRwSessionCount);
    FILL_INT_BY_JSON(ret, "maxPinLen", pInfo->ulMaxPinLen);
    FILL_INT_BY_JSON(ret, "minPinLen", pInfo->ulMinPinLen);
    FILL_INT_BY_JSON(ret, "totalPublicMemory", pInfo->ulTotalPublicMemory);
    FILL_INT_BY_JSON(ret, "freePublicMemory", pInfo->ulFreePublicMemory);
    FILL_INT_BY_JSON(ret, "totalPrivateMemory", pInfo->ulTotalPrivateMemory);
    FILL_INT_BY_JSON(ret, "freePrivateMemory", pInfo->ulFreePrivateMemory);
    FILL_VERSION_BY_JSON(ret, "hardwareVersion", pInfo->hardwareVersion);
    FILL_VERSION_BY_JSON(ret, "firmwareVersion", pInfo->firmwareVersion);
    FILL_STRING_BY_JSON(ret, "utcTime", pInfo->utcTime);
out:
    cJSON_Delete(args);
    cJSON_Delete(ret);
    return rv;
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
    UNUSED(pApplication);
    UNUSED(Notify);
    cJSON *args = NULL, *ret = NULL;
    CK_RV rv;

    if (phSession == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(slotID));
    cJSON_AddItemToArray(args, cJSON_CreateNumber(flags));

    if ((rv = INVOKE(args, &ret)) != CKR_OK) {
        goto out;
    }

    if (cJSON_IsNumber(ret)) {
        *phSession = ret->valuedouble;
    } else {
        rv = CKR_FUNCTION_FAILED;
    }
out:
    cJSON_Delete(args);
    cJSON_Delete(ret);
    return rv;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    cJSON *args = NULL;
    CK_RV rv;

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));

    rv = INVOKE(args, NULL);
    cJSON_Delete(args);
    return rv;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    cJSON *args = NULL;
    CK_RV rv;

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(slotID));

    rv = INVOKE(args, NULL);
    cJSON_Delete(args);
    return rv;
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
    cJSON *args = NULL;
    CK_RV rv;
    char *pin = strndup((char *)pPin, ulPinLen);

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));
    cJSON_AddItemToArray(args, cJSON_CreateNumber(userType));
    cJSON_AddItemToArray(args, cJSON_CreateStringReference(pin));

    rv = INVOKE_SAFE(args, NULL);

    memset(pin, '*', ulPinLen);
    cJSON_Delete(args);
    return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    cJSON *args = NULL;
    CK_RV rv;

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));

    rv = INVOKE(args, NULL);
    cJSON_Delete(args);
    return rv;
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
    cJSON *args = NULL, *ret = NULL;
    CK_RV rv;

    if (pTemplate == NULL || ulCount == 0) {
        return CKR_ARGUMENTS_BAD;
    }

    cJSON *attrs = wrapAttributeArr(pTemplate, ulCount, true);
    if (attrs == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hObject));
    cJSON_AddItemToArray(args, attrs);

    rv = INVOKE(args, &ret);

    if (!unwrapAttributeArr(ret, pTemplate, ulCount)) {
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }
out:
    cJSON_Delete(args);
    cJSON_Delete(ret);
    return rv;
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
    cJSON *args = NULL;
    CK_RV rv;

    if (ulCount != 0 && pTemplate == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    cJSON *attrs = wrapAttributeArr(pTemplate, ulCount, false);
    if (attrs == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));
    cJSON_AddItemToArray(args, attrs);

    rv = INVOKE(args, NULL);
out:
    cJSON_Delete(args);
    return rv;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    cJSON *args = NULL, *ret = NULL;
    CK_RV rv;

    if (phObject == NULL || ulMaxObjectCount == 0 || pulObjectCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));
    cJSON_AddItemToArray(args, cJSON_CreateNumber(ulMaxObjectCount));

    if ((rv = INVOKE(args, &ret)) != CKR_OK) {
        goto out;
    }

    *pulObjectCount = 0;
    cJSON *id;
    cJSON_ArrayForEach(id, ret)
    {
        if (cJSON_IsNumber(id)) {
            phObject[(*pulObjectCount)++] = id->valuedouble;
        }
    }
    DBG("Returning %lu objects", *pulObjectCount);
out:
    cJSON_Delete(args);
    cJSON_Delete(ret);
    return rv;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    cJSON *args = NULL;
    CK_RV rv;

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));

    rv = INVOKE(args, NULL);

    cJSON_Delete(args);
    return rv;
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
    cJSON *args = NULL;
    char buf[MAX_CRYPTO_OBJ_SIZE];
    size_t str_len;
    CK_RV rv;

    if (pMechanism == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    cJSON *mech = cJSON_CreateObject();
    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));
    cJSON_AddItemToArray(args, mech);
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hKey));

    cJSON_AddNumberToObject(mech, "mechanism", pMechanism->mechanism);
    if (mbedtls_base64_encode((unsigned char *)buf, sizeof(buf), &str_len, pMechanism->pParameter, pMechanism->ulParameterLen) != 0) {
        DBG("buffer too small");
        rv = CKR_FUNCTION_FAILED;
        goto out;
    } else {
        buf[str_len] = '\0';
        cJSON_AddStringToObject(mech, "parameter", buf);
    }

    rv = INVOKE(args, NULL);
out:
    cJSON_Delete(args);
    return rv;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    cJSON *args = NULL, *ret = NULL;
    char buf[MAX_CRYPTO_OBJ_SIZE];
    size_t str_len;
    CK_ULONG new_len, dummy;
    CK_RV rv;

    if (mbedtls_base64_encode((unsigned char *)buf, sizeof(buf), &str_len, pData, ulDataLen) != 0) {
        DBG("buffer too small");
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }
    buf[str_len] = '\0';

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));
    cJSON_AddItemToArray(args, cJSON_CreateString(buf));
    cJSON_AddItemToArray(args, cJSON_CreateNumber(*pulSignatureLen));

    rv = INVOKE(args, &ret);

    FILL_INT_BY_JSON(ret, "signLen", new_len);

    cJSON *sign = cJSON_GetObjectItem(ret, "sign");
    if (cJSON_IsString(sign)) {
        mbedtls_base64_decode(
            pSignature,
            *pulSignatureLen,
            &dummy,
            (unsigned char *)sign->valuestring,
            strlen(sign->valuestring));
    }
    *pulSignatureLen = new_len;
out:
    cJSON_Delete(args);
    cJSON_Delete(ret);
    return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    cJSON *args = NULL;
    char buf[MAX_CRYPTO_OBJ_SIZE];
    size_t str_len;
    CK_RV rv;

    if (mbedtls_base64_encode((unsigned char *)buf, sizeof(buf), &str_len, pPart, ulPartLen) != 0) {
        DBG("buffer too small");
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }
    buf[str_len] = '\0';

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));
    cJSON_AddItemToArray(args, cJSON_CreateString(buf));

    rv = INVOKE(args, NULL);
out:
    cJSON_Delete(args);
    return rv;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    cJSON *args = NULL, *ret = NULL;
    CK_ULONG new_len, dummy;
    CK_RV rv;

    args = cJSON_CreateArray();
    cJSON_AddItemToArray(args, cJSON_CreateNumber(hSession));

    rv = INVOKE(args, &ret);

    FILL_INT_BY_JSON(ret, "signLen", new_len);

    cJSON *sign = cJSON_GetObjectItem(ret, "sign");
    if (cJSON_IsString(sign)) {
        mbedtls_base64_decode(
            pSignature,
            *pulSignatureLen,
            &dummy,
            (unsigned char *)sign->valuestring,
            strlen(sign->valuestring));
    }
    *pulSignatureLen = new_len;

    cJSON_Delete(args);
    cJSON_Delete(ret);
    return rv;
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
