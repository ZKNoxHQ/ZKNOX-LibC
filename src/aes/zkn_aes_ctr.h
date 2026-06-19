// zkn_aes_ctr.h — AES-256-CTR using BOLOS cx_aes_iv_*
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#ifndef _ZKN_AES_CTR_H
#define _ZKN_AES_CTR_H

#include <stdint.h>
#include <stddef.h>

// AES-256-CTR encrypt `in_len` bytes of `in` into `out` using `key32` and
// initial counter `iv16`. NIST SP 800-38A counter convention: the IV is
// treated as a 128-bit big-endian counter that increments by 1 per AES
// block (16 B). Matches Node's `createCipheriv('aes-256-ctr', key, iv)`
// — same convention the Railgun engine uses (utils/encryption/aes.ts).
//
// Used to encrypt the V2 annotationData under the sender's viewing
// private key. Returns 0 on success, non-zero on SDK failure.
int zkn_aes256_ctr_encrypt(const uint8_t *key32,
                           const uint8_t *iv16,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out);

#endif
