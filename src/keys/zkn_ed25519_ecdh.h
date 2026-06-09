// zkn_ed25519_ecdh.h — Ed25519 scalar multiplication + ECDH-KDF
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// Helpers for RAILGUN note encryption on Ed25519:
//   - Multiply a host-provided compressed Ed25519 point by a scalar
//     (used for Blind1 = [random]·VKpub_sender and Blind2 = [random]·VKpub_recipient,
//     where the 16-byte note `random` doubles as the blinding scalar).
//   - Derive the AES-256 key for note encryption from the ECDH shared point
//     (RAILGUN KDF: AES_KEY = SHA-256(compressed shared)).
//
// All compressed Ed25519 points use RFC 8032 §5.1.2 format: 32 bytes,
// y-coordinate little-endian, sign of x in the MSB of the last byte.

#ifndef ZKN_ED25519_ECDH_H
#define ZKN_ED25519_ECDH_H

#include <stdint.h>
#include <stddef.h>

// Compute [scalar]·P on Ed25519.
//
// @param scalar_be32    32-byte big-endian scalar (already reduced mod L)
// @param compressed_in  32-byte RFC 8032 compressed input point
// @param compressed_out 32-byte RFC 8032 compressed output point
// @return 0 on success, nonzero on error
int zkn_ed25519_scalarmul_compressed(const uint8_t *scalar_be32,
                                     const uint8_t *compressed_in,
                                     uint8_t *compressed_out);

// ECDH-KDF for RAILGUN notes: AES_KEY = SHA-256(compressed [scalar]·VK).
//
// @param scalar_be32   32-byte big-endian sender scalar
// @param VK_compressed 32-byte compressed Ed25519 point (recipient's VK or
//                      a blinded point Blind2)
// @param aes_key_out   32-byte output, the AES-256 key
// @return 0 on success, nonzero on error
int zkn_ed25519_ecdh_kdf(const uint8_t *scalar_be32,
                         const uint8_t *VK_compressed,
                         uint8_t *aes_key_out);

#endif // ZKN_ED25519_ECDH_H
