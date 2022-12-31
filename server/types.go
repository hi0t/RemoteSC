package server

/*
#include "pkcs11_api.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"strings"
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
	netUnavail   = uint(0xffffffff)
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
	ValueLen uint   `json:"valueLen,omitempty"`
}

type ckMechanism struct {
	Mechanism uint   `json:"mechanism"`
	Parameter []byte `json:"parameter,omitempty"`
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

func unwrapString(s C.CK_UTF8CHAR_PTR, len int) string {
	return strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(s)), C.int(len)), " ")
}

func htonUnavail(v C.CK_ULONG) uint {
	if v == C.CK_UNAVAILABLE_INFORMATION {
		return netUnavail
	}
	return uint(v)
}

func wrapBool(x bool) C.CK_BBOOL {
	if x {
		return C.CK_TRUE
	}
	return C.CK_FALSE
}

func wrapAttributeArr(netAttr []ckAttribute) (func(), []C.CK_ATTRIBUTE) {
	hostAttr := make([]C.CK_ATTRIBUTE, len(netAttr))
	for i, a := range netAttr {
		hostAttr[i]._type = C.CK_ATTRIBUTE_TYPE(a.Type)
		outLen := a.ValueLen

		// request length
		if outLen == 0 {
			continue
		}

		switch hostAttr[i]._type {
		case C.CKA_CLASS, C.CKA_CERTIFICATE_TYPE, C.CKA_KEY_TYPE, C.CKA_MODULUS_BITS:
			outLen = max(outLen, hostUlongLen)
		}

		if a.Value == nil {
			// attribute get request
			C.rsc_set_attribute_value(&hostAttr[i], C.CK_VOID_PTR(C.malloc(C.size_t(outLen))))
		} else {
			hostVal := a.Value
			if outLen > uint(len(hostVal)) {
				hostVal = make([]byte, outLen)
				copy(hostVal, a.Value)
			}
			C.rsc_set_attribute_value(&hostAttr[i], C.CK_VOID_PTR(C.CBytes(hostVal)))
		}
		hostAttr[i].ulValueLen = C.CK_ULONG(outLen)
	}
	return func() {
		for _, a := range hostAttr {
			C.free(unsafe.Pointer(C.rsc_get_attribute_value(&a)))
		}
	}, hostAttr
}

func unWrapAttributeArr(hostAttr []C.CK_ATTRIBUTE) []ckAttribute {
	netAttr := make([]ckAttribute, len(hostAttr))
	for i, a := range hostAttr {
		netAttr[i].Type = uint(a._type)
		outLen := uint(a.ulValueLen)

		if outLen == 0 {
			continue
		}

		if outLen == C.CK_UNAVAILABLE_INFORMATION {
			netAttr[i].ValueLen = netUnavail
			continue
		}

		switch a._type {
		case C.CKA_CLASS, C.CKA_CERTIFICATE_TYPE, C.CKA_KEY_TYPE, C.CKA_MODULUS_BITS:
			outLen = min(uint(a.ulValueLen), netUlongLen)
		}
		val := C.rsc_get_attribute_value(&a)
		if val != nil {
			netAttr[i].Value = C.GoBytes(unsafe.Pointer(val), C.int(outLen))
		}
		netAttr[i].ValueLen = outLen
	}
	return netAttr
}
