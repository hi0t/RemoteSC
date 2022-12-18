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

	hostUlongLen = uint(C.sizeof_CK_ULONG)
	netUlongLen  = uint(4)
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

type ckMechanism struct {
	Mechanism uint   `json:"mechanism"`
	Parameter []byte `json:"parameter"`
}

type ckSignData struct {
	Sign    []byte `json:"sign,omitempty"`
	SignLen uint   `json:"signLen"`
}

type integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

func min[T integer](a, b T) T {
	if a < b {
		return a
	} else {
		return b
	}
}

func max[T integer](a, b T) T {
	if a > b {
		return a
	} else {
		return b
	}
}

func (e pkcs11_err) Error() string {
	return fmt.Sprintf("pkcs11 error: 0x%X", uint(e))
}

func unwrapError(rv C.CK_RV) error {
	if rv == C.CKR_OK {
		return nil
	}
	return pkcs11_err(rv)
}

func unwrapVersion(version C.CK_VERSION) ckVersion {
	return ckVersion{byte(version.major), byte(version.minor)}
}

func wrapBool(x bool) C.CK_BBOOL {
	if x {
		return C.CK_TRUE
	}
	return C.CK_FALSE
}

func allocAttributeArr(nattr []ckAttribute) (func(), []C.CK_ATTRIBUTE) {
	hattr := make([]C.CK_ATTRIBUTE, len(nattr))
	for i, a := range nattr {
		hattr[i]._type = C.CK_ATTRIBUTE_TYPE(a.Type)
		len := a.ValueLen

		if len == 0 {
			continue
		}

		switch hattr[i]._type {
		case C.CKA_CLASS:
		case C.CKA_CERTIFICATE_TYPE:
		case C.CKA_KEY_TYPE:
		case C.CKA_MODULUS_BITS:
			len = max(len, hostUlongLen)
		}

		C.rsc_set_attribute_value(&hattr[i], C.CK_VOID_PTR(C.malloc(C.size_t(len))))
		hattr[i].ulValueLen = C.CK_ULONG(len)
	}
	return func() {
			for _, a := range hattr {
				C.free(unsafe.Pointer(C.rsc_get_attribute_value(&a)))
			}
		},
		hattr
}

func wrapAttributeArr(nattr []ckAttribute) (func(), []C.CK_ATTRIBUTE) {
	hattr := make([]C.CK_ATTRIBUTE, len(nattr))
	for i, a := range nattr {
		hattr[i]._type = C.CK_ATTRIBUTE_TYPE(a.Type)
		len := a.ValueLen

		if len == 0 {
			continue
		}

		switch hattr[i]._type {
		case C.CKA_CLASS:
		case C.CKA_CERTIFICATE_TYPE:
		case C.CKA_KEY_TYPE:
		case C.CKA_MODULUS_BITS:
			len = max(len, hostUlongLen)
		}

		C.rsc_set_attribute_value(&hattr[i], C.CK_VOID_PTR(C.CBytes(a.Value[:len])))
		hattr[i].ulValueLen = C.CK_ULONG(len)
	}
	return func() {
			for _, a := range hattr {
				C.free(unsafe.Pointer(C.rsc_get_attribute_value(&a)))
			}
		},
		hattr
}

func unWrapAttributeArr(hattr []C.CK_ATTRIBUTE) []ckAttribute {
	nattr := make([]ckAttribute, len(hattr))
	for i, a := range hattr {
		nattr[i].Type = uint(a._type)
		len := uint(a.ulValueLen)

		if len == 0 {
			continue
		}

		switch a._type {
		case C.CKA_CLASS:
		case C.CKA_CERTIFICATE_TYPE:
		case C.CKA_KEY_TYPE:
		case C.CKA_MODULUS_BITS:
			len = min(len, netUlongLen)
		}

		nattr[i].Value = C.GoBytes(unsafe.Pointer(C.rsc_get_attribute_value(&a)), C.int(len))
		nattr[i].ValueLen = len
	}
	return nattr
}
