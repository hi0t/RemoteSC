package server

/*
#cgo CFLAGS: -I${SRCDIR}/../rpkcs11

#include "pkcs11_api.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type pkcs11_ctx struct {
	ctx *C.rsc_ctx
}

func OpenPKCS11(module string) (*pkcs11_ctx, error) {
	mod := C.CString(module)
	defer C.free(unsafe.Pointer(mod))
	var cerr *C.char

	c := C.rsc_open(mod, &cerr)
	if c == nil {
		return nil, fmt.Errorf("module load error: %s", C.GoString(cerr))
	}
	return &pkcs11_ctx{c}, nil
}

func (c *pkcs11_ctx) Close() {
	C.rsc_close(c.ctx)
}

func (c *pkcs11_ctx) Initialize() error {
	return unwrapError(C.rsc_Initialize(c.ctx))
}

func (c *pkcs11_ctx) Finalize() error {
	return unwrapError(C.rsc_Finalize(c.ctx))
}

func (c *pkcs11_ctx) GetInfo() (ckInfo, error) {
	var info C.CK_INFO
	rv := C.rsc_GetInfo(c.ctx, &info)
	return ckInfo{
		CryptokiVersion:    unwrapVersion(info.cryptokiVersion),
		ManufacturerID:     unwrapString(&info.manufacturerID[0], 32),
		Flags:              uint(C.rsc_get_info_flags(&info)),
		LibraryDescription: unwrapString(&info.libraryDescription[0], 32),
		LibraryVersion:     unwrapVersion(info.libraryVersion),
	}, unwrapError(rv)
}

func (c *pkcs11_ctx) GetSlotList(tokenPresent bool, cnt uint) (ckSlotList, error) {
	var pSlotList C.CK_SLOT_ID_PTR
	ccnt := C.CK_ULONG(cnt)

	if cnt > 0 {
		pSlotList = C.CK_SLOT_ID_PTR(C.malloc(C.size_t(cnt) * C.sizeof_CK_SLOT_ID))
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
	return res, unwrapError(rv)
}

func (c *pkcs11_ctx) GetSlotInfo(slotID uint) (ckSlotInfo, error) {
	var info C.CK_SLOT_INFO
	rv := C.rsc_GetSlotInfo(c.ctx, C.CK_ULONG(slotID), &info)
	return ckSlotInfo{
		SlotDescription: unwrapString(&info.slotDescription[0], 64),
		ManufacturerID:  unwrapString(&info.manufacturerID[0], 32),
		Flags:           uint(info.flags),
		HardwareVersion: unwrapVersion(info.hardwareVersion),
		FirmwareVersion: unwrapVersion(info.firmwareVersion),
	}, unwrapError(rv)
}

func (c *pkcs11_ctx) GetTokenInfo(slotID uint) (ckTokenInfo, error) {
	var info C.CK_TOKEN_INFO
	rv := C.rsc_GetTokenInfo(c.ctx, C.CK_ULONG(slotID), &info)
	return ckTokenInfo{
		Label:              unwrapString(&info.label[0], 32),
		ManufacturerID:     unwrapString(&info.manufacturerID[0], 32),
		Model:              unwrapString(&info.model[0], 16),
		SerialNumber:       unwrapString(&info.serialNumber[0], 16),
		Flags:              uint(info.flags),
		MaxSessionCount:    htonUnavail(info.ulMaxSessionCount),
		SessionCount:       htonUnavail(info.ulSessionCount),
		MaxRwSessionCount:  htonUnavail(info.ulMaxRwSessionCount),
		RwSessionCount:     htonUnavail(info.ulRwSessionCount),
		MaxPinLen:          uint(info.ulMaxPinLen),
		MinPinLen:          uint(info.ulMinPinLen),
		TotalPublicMemory:  htonUnavail(info.ulTotalPublicMemory),
		FreePublicMemory:   htonUnavail(info.ulFreePublicMemory),
		TotalPrivateMemory: htonUnavail(info.ulTotalPrivateMemory),
		FreePrivateMemory:  htonUnavail(info.ulFreePrivateMemory),
		HardwareVersion:    unwrapVersion(info.hardwareVersion),
		FirmwareVersion:    unwrapVersion(info.firmwareVersion),
		UTCTime:            unwrapString(&info.utcTime[0], 16),
	}, unwrapError(rv)
}

func (c *pkcs11_ctx) OpenSession(slotID uint, flags uint) (ckSessionHandle, error) {
	var phSession C.CK_SESSION_HANDLE
	rv := C.rsc_OpenSession(c.ctx, C.CK_SLOT_ID(slotID), C.CK_FLAGS(flags), C.CK_SESSION_HANDLE_PTR(&phSession))
	return ckSessionHandle(phSession), unwrapError(rv)
}

func (c *pkcs11_ctx) CloseSession(sess ckSessionHandle) error {
	return unwrapError(C.rsc_CloseSession(c.ctx, C.CK_SESSION_HANDLE(sess)))
}

func (c *pkcs11_ctx) CloseAllSessions(slotID uint) error {
	return unwrapError(C.rsc_CloseAllSessions(c.ctx, C.CK_SLOT_ID(slotID)))
}

func (c *pkcs11_ctx) Login(sess ckSessionHandle, userType uint, pin string) error {
	cpin := C.CString(pin)
	defer C.free(unsafe.Pointer(cpin))
	return unwrapError(C.rsc_Login(c.ctx, C.CK_SESSION_HANDLE(sess), C.CK_USER_TYPE(userType), cpin, C.CK_ULONG(len(pin))))
}

func (c *pkcs11_ctx) Logout(sess ckSessionHandle) error {
	return unwrapError(C.rsc_Logout(c.ctx, C.CK_SESSION_HANDLE(sess)))
}

func (c *pkcs11_ctx) GetAttributeValue(sess ckSessionHandle, obj ckObjectHandle, attrs []ckAttribute) ([]ckAttribute, error) {
	gc, tmp := wrapAttributeArr(attrs)
	defer gc()

	rv := C.rsc_GetAttributeValue(c.ctx, C.CK_SESSION_HANDLE(sess), C.CK_OBJECT_HANDLE(obj), &tmp[0], C.CK_ULONG(len(attrs)))
	return unWrapAttributeArr(tmp), unwrapError(rv)
}

func (c *pkcs11_ctx) FindObjectsInit(sess ckSessionHandle, attrs []ckAttribute) error {
	gc, tmp := wrapAttributeArr(attrs)
	defer gc()

	return unwrapError(C.rsc_FindObjectsInit(c.ctx, C.CK_SESSION_HANDLE(sess), &tmp[0], C.CK_ULONG(len(attrs))))
}

func (c *pkcs11_ctx) FindObjects(sess ckSessionHandle, maxObjs uint) ([]ckObjectHandle, error) {
	var count C.CK_ULONG
	obj := C.CK_OBJECT_HANDLE_PTR(C.malloc(C.size_t(maxObjs) * C.sizeof_CK_OBJECT_HANDLE))

	rv := C.rsc_FindObjects(c.ctx, C.CK_SESSION_HANDLE(sess), obj, C.CK_ULONG(maxObjs), &count)

	ul := unsafe.Slice(obj, count)
	l := make([]ckObjectHandle, count)
	for i := range ul {
		l[i] = ckObjectHandle(ul[i])
	}
	C.free(unsafe.Pointer(obj))

	return l, unwrapError(rv)
}

func (c *pkcs11_ctx) FindObjectsFinal(sess ckSessionHandle) error {
	return unwrapError(C.rsc_FindObjectsFinal(c.ctx, C.CK_SESSION_HANDLE(sess)))
}

func (c *pkcs11_ctx) SignInit(sess ckSessionHandle, mech ckMechanism, key ckObjectHandle) error {
	cmech := C.CK_MECHANISM{mechanism: C.CK_MECHANISM_TYPE(mech.Mechanism)}
	// TODO handle special mechanism parameters
	return unwrapError(C.rsc_SignInit(c.ctx, C.CK_SESSION_HANDLE(sess), &cmech, C.CK_OBJECT_HANDLE(key)))
}

func (c *pkcs11_ctx) Sign(sess ckSessionHandle, msg []byte, signLen uint) (ckSignData, error) {
	var sign unsafe.Pointer
	cSignLen := C.CK_ULONG(signLen)

	cmsg := C.CBytes(msg)
	defer C.free(cmsg)

	if signLen > 0 {
		sign = C.malloc(C.size_t(signLen))
		defer C.free(sign)
	}
	rv := C.rsc_Sign(c.ctx, C.CK_SESSION_HANDLE(sess), C.CK_BYTE_PTR(cmsg), C.CK_ULONG(len(msg)), C.CK_BYTE_PTR(sign), &cSignLen)

	return ckSignData{Sign: C.GoBytes(sign, C.int(cSignLen)), SignLen: uint(cSignLen)}, unwrapError(rv)
}

func (c *pkcs11_ctx) SignUpdate(sess ckSessionHandle, msg []byte) error {
	cmsg := C.CBytes(msg)
	defer C.free(cmsg)
	return unwrapError(C.rsc_SignUpdate(c.ctx, C.CK_SESSION_HANDLE(sess), C.CK_BYTE_PTR(cmsg), C.CK_ULONG(len(msg))))
}

func (c *pkcs11_ctx) SignFinal(sess ckSessionHandle, signLen uint) (ckSignData, error) {
	var sign unsafe.Pointer
	cSignLen := C.CK_ULONG(signLen)

	if signLen > 0 {
		sign = C.malloc(C.size_t(signLen))
		defer C.free(sign)
	}
	rv := C.rsc_SignFinal(c.ctx, C.CK_SESSION_HANDLE(sess), C.CK_BYTE_PTR(sign), &cSignLen)

	return ckSignData{Sign: C.GoBytes(sign, C.int(cSignLen)), SignLen: uint(cSignLen)}, unwrapError(rv)
}
