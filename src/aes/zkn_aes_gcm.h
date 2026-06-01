// zkn_aes_gcm.h — AES-256-GCM (Ledger backend, BOLOS cx_aes_gcm_*).
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// Thin wrapper around BOLOS cx_aes_gcm_* (lib_cxng). Built only when
// WITH_KEYS=1, since it needs the Ledger SDK.

#ifndef ZKN_AES_GCM_H
#define ZKN_AES_GCM_H

#include <stdint.h>
#include <stddef.h>

// Encrypt under AES-256-GCM with no AAD and a 16-byte IV.
// @return 0 on success, nonzero on error.
int zkn_aes256_gcm_encrypt(const uint8_t *key32,
                           const uint8_t *iv16,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext,
                           uint8_t *tag16);

#endif // ZKN_AES_GCM_H
