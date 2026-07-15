// zkn_aes_gcm.c — AES-256-GCM wrapper using BOLOS cx_aes_gcm_*
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifndef ZKN_HOST_BUILD /* device build: BOLOS cx_* syscalls */

#include "os.h"
#include "cx.h"
#include "zkn_aes_gcm.h"

int zkn_aes256_gcm_encrypt(const uint8_t *key32,
                           const uint8_t *iv16,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext,
                           uint8_t *tag16)
{
    cx_aes_gcm_context_t ctx;
    int rc = -1;

    cx_aes_gcm_init(&ctx);
    if (cx_aes_gcm_set_key(&ctx, key32, 32) != CX_OK) goto out;

    // cx_aes_gcm_encrypt_and_tag takes `in` as non-const (it may operate
    // in-place); copy to a scratch buffer so we keep the const-correct API.
    // RAILGUN V2 transact-note plaintext is up to 96 B (note) + 32 B (memo)
    // = 128 B when the memo path is exercised (engine concatenates the
    // encoded memo onto the GCM input as a 4th block).
    uint8_t scratch[128];
    if (plaintext_len > sizeof(scratch)) goto out;
    memcpy(scratch, plaintext, plaintext_len);

    if (cx_aes_gcm_encrypt_and_tag(&ctx,
                                   scratch, plaintext_len,
                                   iv16, 16,
                                   NULL, 0,
                                   ciphertext,
                                   tag16, 16) != CX_OK) goto out;

    rc = 0;
out:
    explicit_bzero(&ctx, sizeof(ctx));
    return rc;
}

#endif /* !ZKN_HOST_BUILD */
