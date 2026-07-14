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


// AES-256-GCM with AAD (12-byte nonce), used for DKG share transport.
// Matches curves-lite vss-dkg.ts encryptSharesAESGCMWithAAD / decryptShareAESGCMWithAAD.
int zkn_aes256_gcm_encrypt_aad(const uint8_t *key32,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *plaintext, size_t plaintext_len,
                               uint8_t *ciphertext,
                               uint8_t *tag16);

// Returns 0 if the tag verifies, -1 on authentication failure (plaintext zeroed).
int zkn_aes256_gcm_decrypt_aad(const uint8_t *key32,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               const uint8_t *tag16,
                               uint8_t *plaintext);

#endif // ZKN_AES_GCM_H
