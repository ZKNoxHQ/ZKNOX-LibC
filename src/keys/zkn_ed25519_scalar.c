// zkn_ed25519_scalar.c — Ed25519 EdDSA scalar derivation
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "zkn_ed25519_scalar.h"

// Ed25519 subgroup order L = 2^252 + 27742317777372353535851937790883648493,
// as 32 bytes big-endian.
static const uint8_t L_BE[32] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
    0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
};

int zkn_ed25519_scalar_from_seed(const uint8_t *seed32, uint8_t *scalar_out)
{
    uint8_t hash[64];
    uint8_t reversed_be[32];
    cx_bn_t bn_scalar, bn_L, bn_result;
    int rc = -1;
    bool bn_locked = false;

    // SHA-512(seed)
    if (cx_hash_sha512(seed32, 32, hash, 64) != 64) goto out;

    // adjustBytes25519 on lower half (RFC 8032 §5.1.5)
    hash[0] &= 0xF8;
    hash[31] &= 0x7F;
    hash[31] |= 0x40;

    // RFC 8032 interprets head as little-endian. Convert to big-endian
    // storage for cx_bn (which treats input as BE).
    for (int i = 0; i < 32; i++) reversed_be[i] = hash[31 - i];

    // Reduce mod L.
    if (cx_bn_lock(32, 0) != CX_OK) goto out;
    bn_locked = true;

    if (cx_bn_alloc_init(&bn_scalar, 32, reversed_be, 32) != CX_OK) goto out;
    if (cx_bn_alloc_init(&bn_L,      32, L_BE,        32) != CX_OK) goto out;
    if (cx_bn_alloc(&bn_result, 32) != CX_OK) goto out;
    if (cx_bn_reduce(bn_result, bn_scalar, bn_L) != CX_OK) goto out;
    if (cx_bn_export(bn_result, scalar_out, 32) != CX_OK) goto out;

    rc = 0;
out:
    /* cx_bn_unlock erases the whole pool, so per-handle cx_bn_destroy
     * calls are redundant on success — and destroying a half-written
     * handle on the failure path (cx_bn_alloc_init may write the
     * out-handle before deciding to fail) corrupts the pool. Let the
     * unlock be the single source of truth — same idiom as
     * zkn_poseidon.c::zkn_poseidon_hash. */
    if (bn_locked) (void)cx_bn_unlock();
    explicit_bzero(hash, sizeof(hash));
    explicit_bzero(reversed_be, sizeof(reversed_be));
    return rc;
}
