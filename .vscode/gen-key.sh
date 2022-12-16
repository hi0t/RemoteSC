#!/bin/bash

wd="$(dirname -- "$(readlink -f -- "$0";)";)"
keysd="$wd/keys"
export SOFTHSM2_CONF="$keysd/softhsm2.conf"

rm -rf "$keysd"
mkdir -p "$keysd"

echo "log.level = INFO" > "$SOFTHSM2_CONF"
echo "objectstore.backend = file" >> "$SOFTHSM2_CONF"
echo "directories.tokendir = "$keysd"" >> "$SOFTHSM2_CONF"

slotid=`softhsm2-util --init-token --label s10-token --pin 123456 --so-pin 123456 --free | grep -oP 'is reassigned to slot \K\d+'`

pkcs11-tool --module=/usr/lib/softhsm/libsofthsm2.so --login --pin 123456 --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:secp384r1 --usage-sign --label root --id 0

echo -e "\nssh key:"
pkcs11-tool --module=/usr/lib/softhsm/libsofthsm2.so --slot $slotid --read-object --type pubkey --id 0 | \
    openssl ec -pubin -inform DER -outform PEM 2>/dev/null | \
    ssh-keygen -if /dev/stdin -mPKCS8
