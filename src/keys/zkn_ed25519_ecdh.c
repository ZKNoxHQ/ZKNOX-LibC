// zkn_ed25519_ecdh.c — Ed25519 scalar multiplication + ECDH-KDF
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(ZKN_BN_BACKEND_LEDGER) /* Ledger backend only */

#include "os.h"
#include "cx.h"
#include "zkn_ed25519_ecdh.h"

// Compress a 65-byte uncompressed Ed25519 point (BOLOS format: 04||X_BE||Y_BE)
// into the 32-byte RFC 8032 form (y little-endian + sign of x in MSB of byte 31).
// Mirrors derive_pubkey_ed25519's manual compression in zkn_keyderivation.c.
static void compress_rfc(const uint8_t W[65], uint8_t out32[32])
{
    // Y is at W[33..65] big-endian. Reverse to little-endian.
    for (int i = 0; i < 32; i++) out32[i] = W[64 - i];
    // X is at W[1..33] big-endian; LSB of X = W[32]. Branchless: the parity
    // of X is a one-bit function of the shared secret point (scalar × VK)
    // in the ECDH-KDF caller, so a conditional branch here would leak that
    // bit through instruction-timing / DPA. The keyderivation.c sibling
    // can keep the branch because its parity ends up in the public output.
    out32[31] |= (uint8_t)((W[32] & 1u) << 7);
}

int zkn_ed25519_scalarmul_compressed(const uint8_t *scalar_be32,
                                     const uint8_t *compressed_in,
                                     uint8_t *compressed_out)
{
    // BOLOS Edwards point buffer:
    //   - On input to decompress: P[0]=0x02, P[1..33] = compressed bytes.
    //   - On output: P[0]=0x04, P[1..33]=X(BE), P[33..65]=Y(BE).
    uint8_t P[65];
    int rc = -1;

    P[0] = 0x02;
    memcpy(P + 1, compressed_in, 32);
    memset(P + 33, 0, 32);

    if (cx_edwards_decompress_point_no_throw(CX_CURVE_Ed25519, P, sizeof(P)) != CX_OK)
        goto out;

    if (cx_ecfp_scalar_mult_no_throw(CX_CURVE_Ed25519, P, scalar_be32, 32) != CX_OK)
        goto out;

    // Compress manually to guarantee RFC 8032 output (independent of whatever
    // format cx_edwards_compress_point_no_throw produces).
    compress_rfc(P, compressed_out);
    rc = 0;
out:
    explicit_bzero(P, sizeof(P));
    return rc;
}

int zkn_ed25519_ecdh_kdf(const uint8_t *scalar_be32,
                         const uint8_t *VK_compressed,
                         uint8_t *aes_key_out)
{
    uint8_t shared_compressed[32];
    int rc;

    rc = zkn_ed25519_scalarmul_compressed(scalar_be32, VK_compressed, shared_compressed);
    if (rc != 0) return rc;

    // AES_KEY = SHA-256(compressed shared point bytes). RAILGUN KDF.
    cx_sha256_t sha;
    cx_sha256_init(&sha);
    if (cx_hash_no_throw((cx_hash_t *)&sha, CX_LAST,
                         shared_compressed, sizeof(shared_compressed),
                         aes_key_out, 32) != CX_OK) {
        explicit_bzero(shared_compressed, sizeof(shared_compressed));
        return -1;
    }
    explicit_bzero(shared_compressed, sizeof(shared_compressed));
    return 0;
}

#endif /* ZKN_BN_BACKEND_LEDGER */
