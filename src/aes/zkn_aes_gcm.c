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

#if defined(ZKN_AES_GCM_OVER_CX_AES)

/* The LNS cxng (Nano S, API_LEVEL_LNS) ships no cx_aes_gcm_*, only the AES
 * block primitive. Same three entry points, same argument checks and limits
 * as the cx_aes_gcm_* versions below: the block cipher is cx_aes_enc_block,
 * the mode comes from zkn_gcm_ct.c. */
#include "zkn_gcm_ct.h"

#define ZKN_GCM_MAX_LEN 128 /* the scratch size of the cx_aes_gcm_* versions */

static int zkn_gcm_cx_block(void *ctx, const uint8_t in[16], uint8_t out[16])
{
    return cx_aes_enc_block((const cx_aes_key_t *)ctx, in, out) == CX_OK ? 0 : -1;
}

static int zkn_gcm_cx(const uint8_t *key32,
                      const uint8_t *iv, size_t iv_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *in, size_t in_len,
                      uint8_t *out, uint8_t *tag16, int encrypt)
{
    cx_aes_key_t key;
    int rc = -1;

    if (cx_aes_init_key_no_throw(key32, 32, &key) == CX_OK)
        rc = zkn_gcm_ct_crypt(zkn_gcm_cx_block, &key, iv, iv_len, aad, aad_len,
                              in, in_len, out, tag16, encrypt);
    explicit_bzero(&key, sizeof(key));
    return rc;
}

int zkn_aes256_gcm_encrypt(const uint8_t *key32,
                           const uint8_t *iv16,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext,
                           uint8_t *tag16)
{
    if (!key32 || !iv16 || !tag16) return -1;
    if (plaintext_len > ZKN_GCM_MAX_LEN) return -1;
    if (plaintext_len && (!plaintext || !ciphertext)) return -1;

    return zkn_gcm_cx(key32, iv16, 16, NULL, 0, plaintext, plaintext_len, ciphertext, tag16, 1);
}

int zkn_aes256_gcm_encrypt_aad(const uint8_t *key32,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *plaintext, size_t plaintext_len,
                               uint8_t *ciphertext,
                               uint8_t *tag16)
{
    if (!key32 || !nonce || !tag16 || nonce_len == 0) return -1;
    if (aad_len && !aad) return -1;
    if (plaintext_len > ZKN_GCM_MAX_LEN) return -1;
    if (plaintext_len && (!plaintext || !ciphertext)) return -1;

    return zkn_gcm_cx(key32, nonce, nonce_len, aad, aad_len,
                      plaintext, plaintext_len, ciphertext, tag16, 1);
}

// Returns 0 if the tag verifies, -1 otherwise (plaintext zeroed on failure).
int zkn_aes256_gcm_decrypt_aad(const uint8_t *key32,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               const uint8_t *tag16,
                               uint8_t *plaintext)
{
    uint8_t tag[16];
    int rc;

    if (!key32 || !nonce || !tag16 || nonce_len == 0) return -1;
    if (aad_len && !aad) return -1;
    if (ciphertext_len > ZKN_GCM_MAX_LEN) return -1;
    if (ciphertext_len && (!ciphertext || !plaintext)) return -1;

    rc = zkn_gcm_cx(key32, nonce, nonce_len, aad, aad_len,
                    ciphertext, ciphertext_len, plaintext, tag, 0);
    if (rc == 0 && zkn_gcm_ct_tag_diff(tag, tag16) != 0) rc = -1;
    if (rc != 0 && plaintext && ciphertext_len) explicit_bzero(plaintext, ciphertext_len);
    explicit_bzero(tag, sizeof(tag));
    return rc;
}

#else /* cx_aes_gcm_* from the SDK */

int zkn_aes256_gcm_encrypt(const uint8_t *key32,
                           const uint8_t *iv16,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext,
                           uint8_t *tag16)
{
    cx_aes_gcm_context_t ctx;
    // cx_aes_gcm_encrypt_and_tag takes `in` as non-const (it may operate
    // in-place); copy to a scratch buffer so we keep the const-correct API.
    // RAILGUN V2 transact-note plaintext is up to 96 B (note) + 32 B (memo)
    // = 128 B when the memo path is exercised (engine concatenates the
    // encoded memo onto the GCM input as a 4th block).
    uint8_t scratch[128];
    int rc = -1;

    if (!key32 || !iv16 || !tag16) return -1;
    if (plaintext_len > sizeof(scratch)) return -1;
    if (plaintext_len && (!plaintext || !ciphertext)) return -1;

    cx_aes_gcm_init(&ctx);
    if (cx_aes_gcm_set_key(&ctx, key32, 32) != CX_OK) goto out;

    if (plaintext_len) memcpy(scratch, plaintext, plaintext_len);

    if (cx_aes_gcm_encrypt_and_tag(&ctx,
                                   scratch, plaintext_len,
                                   iv16, 16,
                                   NULL, 0,
                                   ciphertext,
                                   tag16, 16) != CX_OK) goto out;

    rc = 0;
out:
    // scratch held the note plaintext; it used to be left on the stack.
    explicit_bzero(scratch, sizeof(scratch));
    explicit_bzero(&ctx, sizeof(ctx));
    return rc;
}


// AES-256-GCM with AAD — used for DKG share transport (12-byte nonce).
// Mirrors the SW backend (src/aes/zkn_aes_gcm_sw_backend.c) so host and
// device agree bit-for-bit; cross-checked by js/frost-tests/enc_interop.mjs.
int zkn_aes256_gcm_encrypt_aad(const uint8_t *key32,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *plaintext, size_t plaintext_len,
                               uint8_t *ciphertext,
                               uint8_t *tag16)
{
    cx_aes_gcm_context_t ctx;
    uint8_t scratch[128];
    int rc = -1;

    if (!key32 || !nonce || !tag16 || nonce_len == 0) return -1;
    if (aad_len && !aad) return -1;
    if (plaintext_len > sizeof(scratch)) return -1;
    if (plaintext_len && (!plaintext || !ciphertext)) return -1;

    cx_aes_gcm_init(&ctx);
    if (cx_aes_gcm_set_key(&ctx, key32, 32) != CX_OK) goto out;
    // `in` is non-const (may operate in-place); keep the const-correct API.
    if (plaintext_len) memcpy(scratch, plaintext, plaintext_len);
    if (cx_aes_gcm_encrypt_and_tag(&ctx,
                                   scratch, plaintext_len,
                                   nonce, nonce_len,
                                   aad, aad_len,
                                   ciphertext,
                                   tag16, 16) != CX_OK) goto out;
    rc = 0;
out:
    explicit_bzero(scratch, sizeof(scratch));
    explicit_bzero(&ctx, sizeof(ctx));
    return rc;
}

// Returns 0 if the tag verifies, -1 otherwise (plaintext zeroed on failure).
int zkn_aes256_gcm_decrypt_aad(const uint8_t *key32,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               const uint8_t *tag16,
                               uint8_t *plaintext)
{
    cx_aes_gcm_context_t ctx;
    uint8_t scratch[128];
    int rc = -1;

    if (!key32 || !nonce || !tag16 || nonce_len == 0) return -1;
    if (aad_len && !aad) return -1;
    if (ciphertext_len > sizeof(scratch)) return -1;
    if (ciphertext_len && (!ciphertext || !plaintext)) return -1;

    cx_aes_gcm_init(&ctx);
    if (cx_aes_gcm_set_key(&ctx, key32, 32) != CX_OK) goto out;
    if (ciphertext_len) memcpy(scratch, ciphertext, ciphertext_len);
    // decrypt_and_auth checks the tag itself; any non-CX_OK is a rejection.
    if (cx_aes_gcm_decrypt_and_auth(&ctx,
                                    scratch, ciphertext_len,
                                    nonce, nonce_len,
                                    aad, aad_len,
                                    plaintext,
                                    tag16, 16) != CX_OK) goto out;
    rc = 0;
out:
    if (rc != 0 && plaintext && ciphertext_len) explicit_bzero(plaintext, ciphertext_len);
    explicit_bzero(scratch, sizeof(scratch));
    explicit_bzero(&ctx, sizeof(ctx));
    return rc;
}

#endif /* ZKN_AES_GCM_OVER_CX_AES */
#endif /* !ZKN_HOST_BUILD */
