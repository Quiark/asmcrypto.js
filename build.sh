#!/bin/sh
cat src/errors.js src/utils.js src/origin.js src/exports.js src/globals.js src/aes/aes.asm.js src/aes/aes.js src/aes/ecb/ecb.js src/aes/ecb/exports.js src/aes/cbc/cbc.js src/aes/exports.js  src/aes/cbc/exports.js > build/asmcrypto.js
