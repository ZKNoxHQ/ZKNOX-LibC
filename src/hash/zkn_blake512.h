// copyright, zknox, 2025
//
// zkn_blake512.h — BLAKE-512 (original, SHA-3 candidate)
//
// This is the BLAKE hash used by circomlib's eddsa-babyjubjub via the
// 'blake-hash' / 'blake' npm package: createBlakeHash('blake512').
// It is NOT blake2b.
//
// Reference: J.-P. Aumasson, L. Henzen, W. Meier, R. C.-W. Phan,
//            "SHA-3 proposal BLAKE", 2010

#ifndef _ZKN_BLAKE512_H
#define _ZKN_BLAKE512_H

#include <stdint.h>
#include <stddef.h>

#include "zkn_errors.h"

#define ZKN_BLAKE512_BLOCK_SIZE   128
#define ZKN_BLAKE512_DIGEST_SIZE   64

typedef struct {
    uint64_t h[8];                          // chaining value (SHA-512 IV)
    uint64_t s[4];                          // salt (default 0)
    uint64_t t[2];                          // bit counter [lo, hi]
    uint8_t  buf[ZKN_BLAKE512_BLOCK_SIZE];  // partial block buffer
    size_t   buflen;                        // bytes currently in buf
    uint8_t  nullt;                         // null-counter flag for padding
} zkn_blake512_ctx_t;

/**
 * Initialize a BLAKE-512 context (no salt).
 *
 * @param[out] ctx  Stack-allocated context.
 * @return ZKN_OK on success, ZKN_ERR_INVALID_PARAM if ctx is NULL.
 */
zkn_error_t zkn_blake512_init(zkn_blake512_ctx_t *ctx);

/**
 * Initialize a BLAKE-512 context with a 32-byte salt.
 *
 * @param[out] ctx   Stack-allocated context.
 * @param[in]  salt  32 bytes (4 × uint64 big-endian), or NULL for no salt.
 * @return ZKN_OK on success.
 */
zkn_error_t zkn_blake512_init_with_salt(zkn_blake512_ctx_t *ctx, const uint8_t salt[32]);

/**
 * Feed data into an ongoing BLAKE-512 hash.
 *
 * @param[in,out] ctx     Initialized context.
 * @param[in]     data    Input bytes (may be NULL if datalen == 0).
 * @param[in]     datalen Length in bytes.
 * @return ZKN_OK on success.
 */
zkn_error_t zkn_blake512_update(zkn_blake512_ctx_t *ctx, const uint8_t *data, size_t datalen);

/**
 * Finalize and output the 64-byte BLAKE-512 digest.
 *
 * Context is wiped after this call and must not be reused.
 *
 * @param[in,out] ctx  Initialized + updated context.
 * @param[out]    out  64-byte output buffer.
 * @return ZKN_OK on success.
 */
zkn_error_t zkn_blake512_final(zkn_blake512_ctx_t *ctx, uint8_t out[ZKN_BLAKE512_DIGEST_SIZE]);

/**
 * One-shot BLAKE-512 hash (init + update + final).
 *
 * @param[in]  data    Input bytes.
 * @param[in]  datalen Length in bytes.
 * @param[out] out     64-byte output buffer.
 * @return ZKN_OK on success.
 */
zkn_error_t zkn_blake512(const uint8_t *data, size_t datalen, uint8_t out[ZKN_BLAKE512_DIGEST_SIZE]);

#endif
