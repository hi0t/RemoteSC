#include "http.h"
#include "utils.h"

#include <mbedtls/base64.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CRYPTO_OBJ_SIZE 4096

#define INVOKE(args, ret) http_invoke(client, __func__, args, ret, false)
#define INVOKE_SAFE(args, ret) http_invoke(client, __func__, args, ret, true)
#define FILL_STRING_BY_JSON(json, key, str)                             \
    do {                                                                \
        json_object *j = json;                                          \
        json_object *obj;                                               \
        if (json_object_object_get_ex(j, key, &obj))                    \
            padded_copy(str, json_object_get_string(obj), sizeof(str)); \
        else                                                            \
            memset(str, ' ', sizeof(str));                              \
    } while (0)
#define FILL_INT_BY_JSON(json, key, val)                    \
    do {                                                    \
        json_object *j = json;                              \
        json_object *obj;                                   \
        val = 0;                                            \
        if (json_object_object_get_ex(j, key, &obj))        \
            val = (typeof(val))json_object_get_uint64(obj); \
    } while (0)
#define FILL_VERSION_BY_JSON(json, key, ver)           \
    do {                                               \
        json_object *j = json;                         \
        json_object *obj;                              \
        ver.major = 0;                                 \
        ver.minor = 0;                                 \
        if (json_object_object_get_ex(j, key, &obj)) { \
            FILL_INT_BY_JSON(obj, "major", ver.major); \
            FILL_INT_BY_JSON(obj, "minor", ver.minor); \
        }                                              \
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
    json_object *ret = NULL;
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
    json_object_put(ret);

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
    json_object *args = NULL, *ret = NULL;
    CK_RV rv;

    if (pulCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_boolean(tokenPresent));
    if (pSlotList == NULL) {
        json_object_array_add(args, json_object_new_uint64(0));
    } else {
        json_object_array_add(args, json_object_new_uint64(*pulCount));
    }

    rv = INVOKE(args, &ret);

    if (!json_object_is_type(ret, json_type_object)) {
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    json_object *jcnt;
    if (json_object_object_get_ex(ret, "cnt", &jcnt)) {
        *pulCount = json_object_get_uint64(jcnt);
    }

    json_object *list;
    if (!json_object_object_get_ex(ret, "list", &list)) {
        goto out;
    }

    if (pSlotList != NULL) {
        size_t len = json_object_array_length(list);
        for (size_t i = 0; i < len; i++) {
            json_object *id = json_object_array_get_idx(list, i);
            pSlotList[i] = json_object_get_uint64(id);
        }
    }
out:
    json_object_put(args);
    json_object_put(ret);
    return rv;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    json_object *args = NULL, *ret = NULL;
    CK_RV rv;

    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(slotID));

    if ((rv = INVOKE(args, &ret)) != CKR_OK) {
        goto out;
    }

    FILL_STRING_BY_JSON(ret, "slotDescription", pInfo->slotDescription);
    FILL_STRING_BY_JSON(ret, "manufacturerID", pInfo->manufacturerID);
    FILL_INT_BY_JSON(ret, "flags", pInfo->flags);
    FILL_VERSION_BY_JSON(ret, "hardwareVersion", pInfo->hardwareVersion);
    FILL_VERSION_BY_JSON(ret, "firmwareVersion", pInfo->firmwareVersion);
out:
    json_object_put(args);
    json_object_put(ret);
    return rv;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    json_object *args = NULL, *ret = NULL;
    CK_RV rv;

    if (pInfo == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(slotID));

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
    json_object_put(args);
    json_object_put(ret);
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
    json_object *args = NULL, *ret = NULL;
    CK_RV rv;

    if (phSession == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(slotID));
    json_object_array_add(args, json_object_new_uint64(flags));

    if ((rv = INVOKE(args, &ret)) != CKR_OK) {
        goto out;
    }
    *phSession = json_object_get_uint64(ret);
out:
    json_object_put(args);
    json_object_put(ret);
    return rv;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    json_object *args = NULL;
    CK_RV rv;

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));

    rv = INVOKE(args, NULL);
    json_object_put(args);
    return rv;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    json_object *args = NULL;
    CK_RV rv;

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(slotID));

    rv = INVOKE(args, NULL);
    json_object_put(args);
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
    json_object *args = NULL;
    CK_RV rv;
    json_object *pin = json_object_new_string_len((char *)pPin, ulPinLen);

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));
    json_object_array_add(args, json_object_new_uint64(userType));
    json_object_array_add(args, pin);

    rv = INVOKE_SAFE(args, NULL);

    memset((char *)json_object_get_string(pin), '*', json_object_get_string_len(pin));
    json_object_put(args);
    return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    json_object *args = NULL;
    CK_RV rv;

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));

    rv = INVOKE(args, NULL);
    json_object_put(args);
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
    json_object *args = NULL, *ret = NULL;
    CK_RV rv;

    if (pTemplate == NULL || ulCount == 0) {
        return CKR_ARGUMENTS_BAD;
    }

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));
    json_object_array_add(args, json_object_new_uint64(hObject));

    json_object *objs = json_object_new_array();
    json_object_array_add(args, objs);
    for (CK_ULONG i = 0; i < ulCount; i++) {
        json_object *tmp = json_object_new_object();
        json_object_object_add(tmp, "type", json_object_new_uint64(pTemplate[i].type));
        if (pTemplate[i].pValue == NULL) {
            json_object_object_add(tmp, "valueLen", json_object_new_uint64(0));
        } else {
            json_object_object_add(tmp, "valueLen", json_object_new_uint64(pTemplate[i].ulValueLen));
        }
        json_object_array_add(objs, tmp);
    }

    rv = INVOKE(args, &ret);

    if (!json_object_is_type(ret, json_type_array)) {
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    size_t len = json_object_array_length(ret);
    for (size_t i = 0; i < len; i++) {
        CK_ULONG new_len, dummy;
        json_object *str;

        json_object *tmp = json_object_array_get_idx(ret, i);
        FILL_INT_BY_JSON(tmp, "type", pTemplate[i].type);
        FILL_INT_BY_JSON(tmp, "valueLen", new_len);

        // just request length
        if (!json_object_object_get_ex(tmp, "value", &str)) {
            pTemplate[i].ulValueLen = new_len;
            continue;
        }
        if (new_len > pTemplate[i].ulValueLen) {
            continue;
        }
        mbedtls_base64_decode(
            pTemplate[i].pValue,
            pTemplate[i].ulValueLen,
            &dummy,
            (unsigned char *)json_object_get_string(str),
            json_object_get_string_len(str));
        pTemplate[i].ulValueLen = new_len;
    }
out:
    json_object_put(args);
    json_object_put(ret);
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
    json_object *args = NULL;
    CK_RV rv;
    char buf[MAX_CRYPTO_OBJ_SIZE];
    size_t str_len;

    if (ulCount != 0 && pTemplate == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));

    json_object *objs = json_object_new_array();
    json_object_array_add(args, objs);
    for (CK_ULONG i = 0; i < ulCount; i++) {
        if (mbedtls_base64_encode((unsigned char *)buf, sizeof(buf), &str_len, pTemplate[i].pValue, pTemplate[i].ulValueLen) != 0) {
            DBG("buffer too small");
            rv = CKR_FUNCTION_FAILED;
            goto out;
        }
        json_object *tmp = json_object_new_object();
        json_object_object_add(tmp, "type", json_object_new_uint64(pTemplate[i].type));
        json_object_object_add(tmp, "value", json_object_new_string_len(buf, str_len));
        json_object_object_add(tmp, "valueLen", json_object_new_uint64(pTemplate[i].ulValueLen));
        json_object_array_add(objs, tmp);
    }

    rv = INVOKE(args, NULL);
out:
    json_object_put(args);
    return rv;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
    json_object *args = NULL, *ret = NULL;
    CK_RV rv;

    if (phObject == NULL || ulMaxObjectCount == 0 || pulObjectCount == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));
    json_object_array_add(args, json_object_new_uint64(ulMaxObjectCount));

    if ((rv = INVOKE(args, &ret)) != CKR_OK) {
        goto out;
    }

    *pulObjectCount = json_object_array_length(ret);
    for (CK_ULONG i = 0; i < *pulObjectCount; i++) {
        json_object *id = json_object_array_get_idx(ret, i);
        phObject[i] = json_object_get_uint64(id);
    }
out:
    json_object_put(args);
    json_object_put(ret);
    return rv;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    json_object *args = NULL;
    CK_RV rv;

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));

    rv = INVOKE(args, NULL);

    json_object_put(args);
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
    json_object *args = NULL;
    char buf[MAX_CRYPTO_OBJ_SIZE];
    size_t str_len;
    CK_RV rv;

    if (pMechanism == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    json_object *mech = json_object_new_object();
    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));
    json_object_array_add(args, mech);
    json_object_array_add(args, json_object_new_uint64(hKey));

    json_object_object_add(mech, "mechanism", json_object_new_uint64(pMechanism->mechanism));
    if (mbedtls_base64_encode((unsigned char *)buf, sizeof(buf), &str_len, pMechanism->pParameter, pMechanism->ulParameterLen) != 0) {
        DBG("buffer too small");
        rv = CKR_FUNCTION_FAILED;
        goto out;
    } else {
        json_object_object_add(mech, "parameter", json_object_new_string_len(buf, str_len));
    }

    rv = INVOKE(args, NULL);
out:
    json_object_put(args);
    return rv;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    json_object *args = NULL, *ret = NULL, *str;
    char buf[MAX_CRYPTO_OBJ_SIZE];
    size_t str_len;
    CK_ULONG new_len, dummy;
    CK_RV rv;

    if (mbedtls_base64_encode((unsigned char *)buf, sizeof(buf), &str_len, pData, ulDataLen) != 0) {
        DBG("buffer too small");
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));
    json_object_array_add(args, json_object_new_string_len(buf, str_len));
    json_object_array_add(args, json_object_new_uint64(*pulSignatureLen));

    rv = INVOKE(args, &ret);

    FILL_INT_BY_JSON(ret, "signLen", new_len);

    // just request length
    if (!json_object_object_get_ex(ret, "sign", &str)) {
        *pulSignatureLen = new_len;
        goto out;
    }
    if (new_len > *pulSignatureLen) {
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }
    if (mbedtls_base64_decode(
            pSignature,
            *pulSignatureLen,
            &dummy,
            (unsigned char *)json_object_get_string(str),
            json_object_get_string_len(str))
        != 0) {
        rv = CKR_BUFFER_TOO_SMALL;
    }
    *pulSignatureLen = new_len;
out:
    json_object_put(args);
    json_object_put(ret);
    return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    json_object *args = NULL;
    char buf[MAX_CRYPTO_OBJ_SIZE];
    size_t str_len;
    CK_RV rv;

    if (mbedtls_base64_encode((unsigned char *)buf, sizeof(buf), &str_len, pPart, ulPartLen) != 0) {
        DBG("buffer too small");
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));
    json_object_array_add(args, json_object_new_string_len(buf, str_len));

    rv = INVOKE(args, NULL);
out:
    json_object_put(args);
    return rv;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    json_object *args = NULL, *ret = NULL, *str;
    CK_ULONG new_len, dummy;
    CK_RV rv;

    args = json_object_new_array();
    json_object_array_add(args, json_object_new_uint64(hSession));

    rv = INVOKE(args, &ret);

    FILL_INT_BY_JSON(ret, "signLen", new_len);

    // just request length
    if (!json_object_object_get_ex(ret, "sign", &str)) {
        *pulSignatureLen = new_len;
        goto out;
    }
    if (new_len > *pulSignatureLen) {
        rv = CKR_BUFFER_TOO_SMALL;
        goto out;
    }
    if (mbedtls_base64_decode(
            pSignature,
            *pulSignatureLen,
            &dummy,
            (unsigned char *)json_object_get_string(str),
            json_object_get_string_len(str))
        != 0) {
        rv = CKR_BUFFER_TOO_SMALL;
    }
    *pulSignatureLen = new_len;
out:
    json_object_put(args);
    json_object_put(ret);
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
