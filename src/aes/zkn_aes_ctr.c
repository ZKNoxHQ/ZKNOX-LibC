// zkn_aes_ctr.c — AES-256-CTR using BOLOS cx_aes_iv_*
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// BOLOS exposes `cx_aes_iv_no_throw` for CBC/CTR/CFB/OFB via the
// CX_CHAIN_* flag bits in the mode word. AES-256-CTR with a 16-byte IV
// matches the Railgun engine's `crypto.createCipheriv('aes-256-ctr', …)`
// — NIST SP 800-38A counter form, IV interpreted as a 128-bit BE counter
// that increments by 1 per 16-byte AES block.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(ZKN_BN_BACKEND_LEDGER) /* Ledger backend only */

#include "os.h"
#include "cx.h"
#include "zkn_aes_ctr.h"

int zkn_aes256_ctr_encrypt(const uint8_t *key32,
                           const uint8_t *iv16,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out)
{
    cx_aes_key_t key;
    int rc = -1;

    if (cx_aes_init_key_no_throw(key32, 32, &key) != CX_OK) goto out;

    // CX_CHAIN_CTR | CX_ENCRYPT | CX_LAST: single-shot full message,
    // counter starts at iv16. The SDK handles the per-block counter
    // increment for us. iv16 is read by the SDK; we pass a writable
    // copy so it can be used as the running counter state.
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv16, 16);

    size_t out_len = in_len;
    // cx_aes_iv_no_throw expects (key, mode, iv, iv_len, in, in_len, out, &out_len).
    if (cx_aes_iv_no_throw(&key,
                           CX_CHAIN_CTR | CX_ENCRYPT | CX_LAST,
                           iv_copy, 16,
                           in, in_len,
                           out, &out_len) != CX_OK) goto out;

    if (out_len != in_len) goto out;
    rc = 0;
out:
    explicit_bzero(&key, sizeof(key));
    explicit_bzero(iv_copy, sizeof(iv_copy));
    return rc;
}

#endif /* ZKN_BN_BACKEND_LEDGER */
