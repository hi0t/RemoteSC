package server

/*
#include "pkcs11_api.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

const (
	CKR_OK                           = C.CKR_OK
	CKR_GENERAL_ERROR                = C.CKR_GENERAL_ERROR
	CKR_FUNCTION_FAILED              = C.CKR_FUNCTION_FAILED
	CKR_CRYPTOKI_NOT_INITIALIZED     = C.CKR_CRYPTOKI_NOT_INITIALIZED
	CKR_CRYPTOKI_ALREADY_INITIALIZED = C.CKR_CRYPTOKI_ALREADY_INITIALIZED
)

type pkcs11_err uint
type ckSessionHandle uint
type ckObjectHandle uint

type ckVersion struct {
	Major byte `json:"major"`
	Minor byte `json:"minor"`
}

type ckInfo struct {
	CryptokiVersion    ckVersion `json:"cryptokiVersion"`
	ManufacturerID     string    `json:"manufacturerID"`
	Flags              uint      `json:"flags"`
	LibraryDescription string    `json:"libraryDescription"`
	LibraryVersion     ckVersion `json:"libraryVersion"`
}

type ckSlotList struct {
	List []uint `json:"list"`
	Cnt  uint   `json:"cnt"`
}

type ckSlotInfo struct {
	SlotDescription string    `json:"slotDescription"`
	ManufacturerID  string    `json:"manufacturerID"`
	Flags           uint      `json:"flags"`
	HardwareVersion ckVersion `json:"hardwareVersion"`
	FirmwareVersion ckVersion `json:"firmwareVersion"`
}

type ckTokenInfo struct {
	Label              string    `json:"label"`
	ManufacturerID     string    `json:"manufacturerID"`
	Model              string    `json:"model"`
	SerialNumber       string    `json:"serialNumber"`
	Flags              uint      `json:"flags"`
	MaxSessionCount    uint      `json:"maxSessionCount"`
	SessionCount       uint      `json:"sessionCount"`
	MaxRwSessionCount  uint      `json:"maxRwSessionCount"`
	RwSessionCount     uint      `json:"rwSessionCount"`
	MaxPinLen          uint      `json:"maxPinLen"`
	MinPinLen          uint      `json:"minPinLen"`
	TotalPublicMemory  uint      `json:"totalPublicMemory"`
	FreePublicMemory   uint      `json:"freePublicMemory"`
	TotalPrivateMemory uint      `json:"totalPrivateMemory"`
	FreePrivateMemory  uint      `json:"freePrivateMemory"`
	HardwareVersion    ckVersion `json:"hardwareVersion"`
	FirmwareVersion    ckVersion `json:"firmwareVersion"`
	UTCTime            string    `json:"utcTime"`
}

type ckAttribute struct {
	Type     uint   `json:"type"`
	Value    []byte `json:"value,omitempty"`
	ValueLen uint   `json:"valueLen"`
}

func (e pkcs11_err) Error() string {
	return fmt.Sprintf("pkcs11 error: 0x%X", uint(e))
}

func wrapError(rv C.CK_RV) error {
	if rv == C.CKR_OK {
		return nil
	}
	return pkcs11_err(rv)
}

func wrapVersion(version C.CK_VERSION) ckVersion {
	return ckVersion{byte(version.major), byte(version.minor)}
}

func wrapBool(x bool) C.CK_BBOOL {
	if x {
		return C.CK_TRUE
	}
	return C.CK_FALSE
}

func wrapAttributeArr(arr []ckAttribute) (func(), C.CK_ATTRIBUTE_PTR, C.CK_ULONG) {
	if len(arr) == 0 {
		return func() {}, nil, 0
	}
	pArr := make([]C.CK_ATTRIBUTE, len(arr))
	ptrs := make([]unsafe.Pointer, len(arr))
	for i, a := range arr {
		pArr[i]._type = C.CK_ATTRIBUTE_TYPE(a.Type)
		if len(a.Value) > 0 {
			ptrs[i] = C.CBytes(a.Value)
			pArr[i].pValue = ptrs[i]
			pArr[i].ulValueLen = C.CK_ULONG(len(a.Value))
		}
	}
	return func() {
			for _, p := range ptrs {
				C.free(p)
			}
		},
		&pArr[0], C.CK_ULONG(len(arr))
}
