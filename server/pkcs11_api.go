package server

/*
#cgo CFLAGS: -I../rpkcs11

#include "pkcs11_api.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"strings"
	"unsafe"
)

type pkcs11_ctx struct {
	ctx *C.struct_rsc_ctx
}

func OpenPKCS11(module string) (*pkcs11_ctx, error) {
	mod := C.CString(module)
	defer C.free(unsafe.Pointer(mod))

	c := C.rsc_open(mod)
	if c == nil {
		return nil, fmt.Errorf("'%s' module load error", module)
	}
	return &pkcs11_ctx{c}, nil
}

func (c *pkcs11_ctx) Close() {
	C.rsc_close(c.ctx)
}

func (c *pkcs11_ctx) Initialize() error {
	return wrapError(C.rsc_Initialize(c.ctx))
}

func (c *pkcs11_ctx) Finalize() error {
	return wrapError(C.rsc_Finalize(c.ctx))
}

func (c *pkcs11_ctx) GetInfo() (ckInfo, error) {
	var info C.struct_rsc_unpacked_info
	rv := C.rsc_GetInfo(c.ctx, &info)
	return ckInfo{
		CryptokiVersion:    wrapVersion(info.cryptokiVersion),
		ManufacturerID:     strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.manufacturerID[0])), 32), " "),
		Flags:              uint(info.flags),
		LibraryDescription: strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.libraryDescription[0])), 32), " "),
		LibraryVersion:     wrapVersion(info.libraryVersion),
	}, wrapError(rv)
}

func (c *pkcs11_ctx) GetSlotList(tokenPresent bool, cnt uint) (ckSlotList, error) {
	var pSlotList C.CK_SLOT_ID_PTR
	ccnt := C.CK_ULONG(cnt)

	if cnt > 0 {
		pSlotList = C.CK_SLOT_ID_PTR(C.calloc(C.CK_ULONG(cnt), C.sizeof_CK_SLOT_ID))
	}

	rv := C.rsc_GetSlotList(c.ctx, wrapBool(tokenPresent), pSlotList, &ccnt)

	res := ckSlotList{Cnt: uint(ccnt)}
	if pSlotList != nil {
		res.List = make([]uint, uint(ccnt))
		ul := unsafe.Slice(pSlotList, uint(ccnt))
		for i := range ul {
			res.List[i] = uint(ul[i])
		}
		C.free(unsafe.Pointer(pSlotList))
	}
	return res, wrapError(rv)
}

func (c *pkcs11_ctx) GetSlotInfo(slotID uint) (ckSlotInfo, error) {
	var info C.CK_SLOT_INFO
	rv := C.rsc_GetSlotInfo(c.ctx, C.CK_ULONG(slotID), &info)
	return ckSlotInfo{
		SlotDescription: strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.slotDescription[0])), 64), " "),
		ManufacturerID:  strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.manufacturerID[0])), 32), " "),
		Flags:           uint(info.flags),
		HardwareVersion: wrapVersion(info.hardwareVersion),
		FirmwareVersion: wrapVersion(info.firmwareVersion),
	}, wrapError(rv)
}

func (c *pkcs11_ctx) GetTokenInfo(slotID uint) (ckTokenInfo, error) {
	var info C.CK_TOKEN_INFO
	rv := C.rsc_GetTokenInfo(c.ctx, C.CK_ULONG(slotID), &info)
	return ckTokenInfo{
		Label:              strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.label[0])), 32), " "),
		ManufacturerID:     strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.manufacturerID[0])), 32), " "),
		Model:              strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.model[0])), 16), " "),
		SerialNumber:       strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.serialNumber[0])), 16), " "),
		Flags:              uint(info.flags),
		MaxSessionCount:    uint(info.ulMaxSessionCount),
		SessionCount:       uint(info.ulSessionCount),
		MaxRwSessionCount:  uint(info.ulMaxRwSessionCount),
		RwSessionCount:     uint(info.ulRwSessionCount),
		MaxPinLen:          uint(info.ulMaxPinLen),
		MinPinLen:          uint(info.ulMinPinLen),
		TotalPublicMemory:  uint(info.ulTotalPublicMemory),
		FreePublicMemory:   uint(info.ulFreePublicMemory),
		TotalPrivateMemory: uint(info.ulTotalPrivateMemory),
		FreePrivateMemory:  uint(info.ulFreePrivateMemory),
		HardwareVersion:    wrapVersion(info.hardwareVersion),
		FirmwareVersion:    wrapVersion(info.firmwareVersion),
		UTCTime:            strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.utcTime[0])), 16), " "),
	}, wrapError(rv)
}

func (c *pkcs11_ctx) OpenSession(slotID uint, flags uint) (ckSessionHandle, error) {
	var phSession C.CK_SESSION_HANDLE
	rv := C.rsc_OpenSession(c.ctx, C.CK_SLOT_ID(slotID), C.CK_FLAGS(flags), C.CK_SESSION_HANDLE_PTR(&phSession))
	return ckSessionHandle(phSession), wrapError(rv)
}

func (c *pkcs11_ctx) CloseSession(sess ckSessionHandle) error {
	return wrapError(C.rsc_CloseSession(c.ctx, C.CK_SESSION_HANDLE(sess)))
}

func (c *pkcs11_ctx) CloseAllSessions(slotID uint) error {
	return wrapError(C.rsc_CloseAllSessions(c.ctx, C.CK_SLOT_ID(slotID)))
}

func (c *pkcs11_ctx) Login(sess ckSessionHandle, userType uint, pin string) error {
	cpin := C.CString(pin)
	defer C.free(unsafe.Pointer(cpin))
	return wrapError(C.rsc_Login(c.ctx, C.CK_SESSION_HANDLE(sess), C.CK_USER_TYPE(userType), cpin, C.CK_ULONG(len(pin))))
}

func (c *pkcs11_ctx) Logout(sess ckSessionHandle) error {
	return wrapError(C.rsc_Logout(c.ctx, C.CK_SESSION_HANDLE(sess)))
}

func (c *pkcs11_ctx) GetAttributeValue(sess ckSessionHandle, obj ckObjectHandle, attr []ckAttribute) ([]ckAttribute, error) {
	cattr := make([]C.CK_ATTRIBUTE, len(attr))
	for i, a := range attr {
		cattr[i]._type = C.CK_ATTRIBUTE_TYPE(a.Type)
		cattr[i].ulValueLen = C.CK_ULONG(a.ValueLen)
		if a.ValueLen > 0 {
			cattr[i].pValue = C.calloc(C.CK_ULONG(a.ValueLen), C.sizeof_CK_BYTE)
		}
	}

	rv := C.rsc_GetAttributeValue(c.ctx, C.CK_SESSION_HANDLE(sess), C.CK_OBJECT_HANDLE(obj), &cattr[0], C.CK_ULONG(len(cattr)))

	res := make([]ckAttribute, len(cattr))
	for i, a := range cattr {
		res[i].Type = uint(a._type)
		res[i].ValueLen = uint(a.ulValueLen)
		if a.pValue != nil {
			res[i].Value = C.GoBytes(a.pValue, C.int(a.ulValueLen))
			C.free(a.pValue)
		}
	}
	return res, wrapError(rv)
}

func (c *pkcs11_ctx) FindObjectsInit(sess ckSessionHandle, pTemplate []ckAttribute) error {
	gc, tmp, cnt := wrapAttributeArr(pTemplate)
	defer gc()
	return wrapError(C.rsc_FindObjectsInit(c.ctx, C.CK_SESSION_HANDLE(sess), tmp, cnt))
}

func (c *pkcs11_ctx) FindObjects(sess ckSessionHandle, maxObjs uint) ([]ckObjectHandle, error) {
	var count C.CK_ULONG
	obj := C.CK_OBJECT_HANDLE_PTR(C.calloc(C.CK_ULONG(maxObjs), C.sizeof_CK_OBJECT_HANDLE))

	rv := C.rsc_FindObjects(c.ctx, C.CK_SESSION_HANDLE(sess), obj, C.CK_ULONG(maxObjs), &count)
	if rv != C.CKR_OK {
		return nil, wrapError(rv)
	}

	ul := unsafe.Slice(obj, count)
	l := make([]ckObjectHandle, count)
	for i := range ul {
		l[i] = ckObjectHandle(ul[i])
	}
	C.free(unsafe.Pointer(obj))

	return l, nil
}

func (c *pkcs11_ctx) FindObjectsFinal(sess ckSessionHandle) error {
	return wrapError(C.rsc_FindObjectsFinal(c.ctx, C.CK_SESSION_HANDLE(sess)))
}

func (c *pkcs11_ctx) SignInit(sess ckSessionHandle, mech ckMechanism, key ckObjectHandle) error {
	cmech := &C.CK_MECHANISM{
		mechanism:      C.CK_MECHANISM_TYPE(mech.Mechanism),
		pParameter:     C.CBytes(mech.Parameter),
		ulParameterLen: C.CK_ULONG(len(mech.Parameter)),
	}
	defer C.free(cmech.pParameter)
	return wrapError(C.rsc_SignInit(c.ctx, C.CK_SESSION_HANDLE(sess), cmech, C.CK_OBJECT_HANDLE(key)))
}

func (c *pkcs11_ctx) Sign(sess ckSessionHandle, msg []byte, signLen uint) (ckSignData, error) {
	var sign unsafe.Pointer
	cSignLen := C.CK_ULONG(signLen)

	cmsg := C.CBytes(msg)
	defer C.free(cmsg)

	if signLen > 0 {
		sign = C.malloc(C.CK_ULONG(signLen))
		defer C.free(sign)
	}
	rv := C.rsc_Sign(c.ctx, C.CK_SESSION_HANDLE(sess), C.CK_BYTE_PTR(cmsg), C.CK_ULONG(len(msg)), C.CK_BYTE_PTR(sign), &cSignLen)

	return ckSignData{Sign: C.GoBytes(sign, C.int(cSignLen)), SignLen: uint(cSignLen)}, wrapError(rv)
}

func (c *pkcs11_ctx) SignUpdate(sess ckSessionHandle, msg []byte) error {
	cmsg := C.CBytes(msg)
	defer C.free(cmsg)
	return wrapError(C.rsc_SignUpdate(c.ctx, C.CK_SESSION_HANDLE(sess), C.CK_BYTE_PTR(cmsg), C.CK_ULONG(len(msg))))
}

func (c *pkcs11_ctx) SignFinal(sess ckSessionHandle, signLen uint) (ckSignData, error) {
	var sign unsafe.Pointer
	cSignLen := C.CK_ULONG(signLen)

	if signLen > 0 {
		sign = C.malloc(C.CK_ULONG(signLen))
		defer C.free(sign)
	}
	rv := C.rsc_SignFinal(c.ctx, C.CK_SESSION_HANDLE(sess), C.CK_BYTE_PTR(sign), &cSignLen)

	return ckSignData{Sign: C.GoBytes(sign, C.int(cSignLen)), SignLen: uint(cSignLen)}, wrapError(rv)
}
