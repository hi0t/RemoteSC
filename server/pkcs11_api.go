package server

/*
#cgo CFLAGS: -I../rpkcs11

#include "pkcs11_api.h"

#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"strings"
	"unsafe"
)

var ErrLoadModule = errors.New("module loading error")

type pkcs11_ctx struct {
	ctx *C.struct_pkcs11_ctx
}

func OpenPKCS11(module string) (*pkcs11_ctx, error) {
	mod := C.CString(module)
	defer C.free(unsafe.Pointer(mod))

	c := C.openPKCS11(mod)
	if c == nil {
		return nil, ErrLoadModule
	}
	return &pkcs11_ctx{c}, nil
}

func (c *pkcs11_ctx) Close() {
	C.closePKCS11(c.ctx)
}

func (c *pkcs11_ctx) Initialize() error {
	return wrapError(C.Initialize(c.ctx))
}

func (c *pkcs11_ctx) Finalize() error {
	return wrapError(C.Finalize(c.ctx))
}

func (c *pkcs11_ctx) GetInfo() (ckInfo, error) {
	var info C.struct_unpackedInfo
	rv := C.GetInfo(c.ctx, &info)
	return ckInfo{
		CryptokiVersion:    wrapVersion(info.cryptokiVersion),
		ManufacturerID:     strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.manufacturerID[0])), 32), " "),
		Flags:              uint(info.flags),
		LibraryDescription: strings.TrimRight(C.GoStringN((*C.char)(unsafe.Pointer(&info.libraryDescription[0])), 32), " "),
		LibraryVersion:     wrapVersion(info.libraryVersion),
	}, wrapError(rv)
}
