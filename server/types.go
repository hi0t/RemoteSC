package server

/*
#include "pkcs11_api.h"
*/
import "C"
import "fmt"

const (
	CKR_OK                           = C.CKR_OK
	CKR_GENERAL_ERROR                = C.CKR_GENERAL_ERROR
	CKR_FUNCTION_FAILED              = C.CKR_FUNCTION_FAILED
	CKR_CRYPTOKI_NOT_INITIALIZED     = C.CKR_CRYPTOKI_NOT_INITIALIZED
	CKR_CRYPTOKI_ALREADY_INITIALIZED = C.CKR_CRYPTOKI_ALREADY_INITIALIZED
)

type pkcs11_err uint

func (e pkcs11_err) Error() string {
	return fmt.Sprintf("pkcs11 error: 0x%X", uint(e))
}

func wrapError(err C.CK_RV) error {
	if err == C.CKR_OK {
		return nil
	}
	return pkcs11_err(err)
}

type ckVersion struct {
	Major byte
	Minor byte
}

func wrapVersion(version C.CK_VERSION) ckVersion {
	return ckVersion{byte(version.major), byte(version.minor)}
}

type ckInfo struct {
	CryptokiVersion    ckVersion `json:"cryptokiVersion"`
	ManufacturerID     string    `json:"manufacturerID"`
	Flags              uint      `json:"flags"`
	LibraryDescription string    `json:"libraryDescription"`
	LibraryVersion     ckVersion `json:"libraryVersion"`
}
