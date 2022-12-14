#pragma once

#include <pkcs11.h>

struct pkcs11_ctx;

struct unpackedInfo {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
};

struct pkcs11_ctx *openPKCS11(const char *module);
void closePKCS11(struct pkcs11_ctx *ctx);

CK_RV Initialize(struct pkcs11_ctx *ctx);
CK_RV Finalize(struct pkcs11_ctx *ctx);
CK_RV GetInfo(struct pkcs11_ctx *ctx, struct unpackedInfo *uInfo);
