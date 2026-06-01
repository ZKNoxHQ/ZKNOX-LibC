// zkn_ed25519_scalar.h — Ed25519 EdDSA scalar derivation
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// Derives the Ed25519 "signing scalar" from a 32-byte seed (private key),
// matching the standard EdDSA-Ed25519 procedure (RFC 8032 §5.1.5):
//
//   h      = SHA-512(seed)         // 64 bytes
//   head   = h[0..32]
//   head[0]  &= 0xF8
//   head[31] &= 0x7F
//   head[31] |= 0x40
//   scalar = LE-decode(head) mod L  // L = Ed25519 subgroup order
//
// Output is the scalar as 32 bytes big-endian — suitable for cx_bn_init /
// cx_ecpoint_scalarmul_bn. This is the scalar RAILGUN uses for
// viewing-key ECDH ([scalar]·VKpub_recipient → shared point → SHA-256 →
// AES key).

#ifndef ZKN_ED25519_SCALAR_H
#define ZKN_ED25519_SCALAR_H

#include <stdint.h>
#include <stddef.h>

// Derive the Ed25519 signing scalar from a 32-byte seed.
//
// @param seed32       32-byte private key seed (e.g. from SLIP-0010 derivation)
// @param scalar_out   output buffer, 32 bytes big-endian
// @return 0 on success, nonzero on error
int zkn_ed25519_scalar_from_seed(const uint8_t *seed32, uint8_t *scalar_out);

#endif // ZKN_ED25519_SCALAR_H
