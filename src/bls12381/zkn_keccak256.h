/*
 * zkn_keccak256.h — Keccak-256 hash (pre-NIST, 0x01 padding)
 *
 * This is the original Keccak-256, NOT SHA-3-256 (which uses 0x06 padding).
 * Matches the variant used by Ethereum and snarkjs (js-sha3 keccak256).
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_KECCAK256_H
#define ZKN_KECCAK256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One-shot Keccak-256: hash `inlen` bytes from `in`, write 32 bytes to `out`. */
void zkn_keccak256(uint8_t out[32], const uint8_t *in, size_t inlen);

/* Incremental API */
typedef struct {
    uint64_t state[25];
    uint8_t  buf[136];       /* rate = 1088 bits = 136 bytes for Keccak-256 */
    size_t   buf_len;
} zkn_keccak256_ctx_t;

void zkn_keccak256_init(zkn_keccak256_ctx_t *ctx);
void zkn_keccak256_update(zkn_keccak256_ctx_t *ctx, const uint8_t *data, size_t len);
void zkn_keccak256_final(zkn_keccak256_ctx_t *ctx, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_KECCAK256_H */
