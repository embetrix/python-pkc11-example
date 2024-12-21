#!/bin/sh -e
#
# Copyright (c) 2024
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com

export PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
export PIN="12345"
export SO_PIN="1234"
export SOFTHSM2_CONF=$PWD/.softhsm/softhsm2.conf
export TOKEN_NAME="token0"

rm -rf .softhsm
mkdir -p .softhsm/tokens
echo "directories.tokendir = $PWD/.softhsm/tokens" > .softhsm/softhsm2.conf
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --slot-index=0 --init-token --label=$TOKEN_NAME --so-pin $SO_PIN --init-pin 
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --keypairgen --key-type EC:prime256v1 --id 66 --label "testkeyECp256"
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --keygen     --key-type aes:32 --id 67 --label "testkeyAES256"

p11tool --list-all --login --provider=$PKCS11_MODULE_PATH --set-pin=$PIN

./pkcs11-test.py
