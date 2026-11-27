// zkn_gcm_ct.h — GCM mode over a caller-supplied 128-bit block cipher.
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// For targets whose SDK has an AES block primitive but no GCM (the Ledger
// LNS cxng). The block cipher stays the platform's; this file adds the
// counter mode and GHASH. GHASH is bitwise with masks: no table, no branch
// and no memory access that depends on the hash key or the data.
//
// Compiled on host builds (for the tests) and on device builds that define
// ZKN_AES_GCM_OVER_CX_AES.

#ifndef ZKN_GCM_CT_H
#define ZKN_GCM_CT_H

#include <stdint.h>
#include <stddef.h>

// Encrypts one 16-byte block. `in` and `out` never alias. Returns 0 on success.
typedef int (*zkn_gcm_block_fn)(void *cipher_ctx, const uint8_t in[16], uint8_t out[16]);

// GCM as in NIST SP 800-38D, 128-bit tag.
//   encrypt != 0 : in = plaintext,  out = ciphertext
//   encrypt == 0 : in = ciphertext, out = plaintext (the caller compares `tag`)
// `in` and `out` may be the same buffer. iv_len > 0; a 12-byte IV takes the
// short path. Returns 0 on success, -1 on a bad argument or a cipher failure.
int zkn_gcm_ct_crypt(zkn_gcm_block_fn block, void *cipher_ctx,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out,
                     uint8_t tag[16],
                     int encrypt);

// 0 iff the two 16-byte tags are equal. Constant time.
int zkn_gcm_ct_tag_diff(const uint8_t a[16], const uint8_t b[16]);

#endif // ZKN_GCM_CT_H
