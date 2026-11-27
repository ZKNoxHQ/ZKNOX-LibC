// zkn_gcm_ct.c — GCM mode over a caller-supplied 128-bit block cipher.
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#if defined(ZKN_HOST_BUILD) || defined(ZKN_AES_GCM_OVER_CX_AES)

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "zkn_gcm_ct.h"

/* GHASH works on the 128-bit state as four big-endian 32-bit words:
 * w[0] holds bits 0..31 of the block in GCM's bit numbering (bit 0 first). */
typedef struct
{
    uint32_t h[4]; /* hash key H = E_K(0) */
    uint32_t y[4]; /* running digest */
} ghash_t;

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* y <- y * h in GF(2^128), right-shift algorithm of SP 800-38D 6.3.
 * 128 iterations whatever the operands; bits are consumed through masks. */
static void ghash_mul(ghash_t *g)
{
    uint32_t z[4] = {0, 0, 0, 0};
    uint32_t v[4] = {g->h[0], g->h[1], g->h[2], g->h[3]};

    for (unsigned i = 0; i < 128; i++)
    {
        uint32_t xbit = (g->y[i >> 5] >> (31u - (i & 31u))) & 1u;
        uint32_t mx = 0u - xbit; /* all ones iff bit i of y is set */
        z[0] ^= v[0] & mx;
        z[1] ^= v[1] & mx;
        z[2] ^= v[2] & mx;
        z[3] ^= v[3] & mx;

        uint32_t mr = 0u - (v[3] & 1u); /* all ones iff the bit shifted out is set */
        v[3] = (v[3] >> 1) | (v[2] << 31);
        v[2] = (v[2] >> 1) | (v[1] << 31);
        v[1] = (v[1] >> 1) | (v[0] << 31);
        v[0] = (v[0] >> 1) ^ (0xE1000000u & mr);
    }

    g->y[0] = z[0];
    g->y[1] = z[1];
    g->y[2] = z[2];
    g->y[3] = z[3];
    explicit_bzero(z, sizeof(z));
    explicit_bzero(v, sizeof(v));
}

/* Absorb `len` bytes, the last block zero-padded. */
static void ghash_update(ghash_t *g, const uint8_t *data, size_t len)
{
    uint8_t blk[16];

    while (len > 0)
    {
        size_t n = len < 16 ? len : 16;
        memset(blk, 0, sizeof(blk));
        memcpy(blk, data, n);
        g->y[0] ^= load_be32(blk);
        g->y[1] ^= load_be32(blk + 4);
        g->y[2] ^= load_be32(blk + 8);
        g->y[3] ^= load_be32(blk + 12);
        ghash_mul(g);
        data += n;
        len -= n;
    }
    explicit_bzero(blk, sizeof(blk));
}

/* Absorb the closing block [a_bits]_64 || [b_bits]_64. Lengths fit 32 bits
 * of bytes here, so the bit counts fit 35 bits. */
static void ghash_lengths(ghash_t *g, size_t a_len, size_t b_len)
{
    g->y[0] ^= (uint32_t)((uint64_t)a_len >> 29);
    g->y[1] ^= (uint32_t)((uint64_t)a_len << 3);
    g->y[2] ^= (uint32_t)((uint64_t)b_len >> 29);
    g->y[3] ^= (uint32_t)((uint64_t)b_len << 3);
    ghash_mul(g);
}

static void inc32(uint8_t ctr[16])
{
    for (int i = 15; i >= 12; i--)
    {
        if (++ctr[i] != 0) break;
    }
}

int zkn_gcm_ct_crypt(zkn_gcm_block_fn block, void *cipher_ctx,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out,
                     uint8_t tag[16],
                     int encrypt)
{
    ghash_t g;
    uint8_t j0[16], ctr[16], ks[16], zero[16];
    int rc = -1;

    if (block == NULL || iv == NULL || iv_len == 0 || tag == NULL) return -1;
    if (aad_len != 0 && aad == NULL) return -1;
    if (in_len != 0 && (in == NULL || out == NULL)) return -1;

    /* H = E_K(0^128) */
    memset(zero, 0, sizeof(zero));
    if (block(cipher_ctx, zero, ks) != 0) goto end;
    g.h[0] = load_be32(ks);
    g.h[1] = load_be32(ks + 4);
    g.h[2] = load_be32(ks + 8);
    g.h[3] = load_be32(ks + 12);

    /* J0 */
    if (iv_len == 12)
    {
        memcpy(j0, iv, 12);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;
    }
    else
    {
        memset(g.y, 0, sizeof(g.y));
        ghash_update(&g, iv, iv_len);
        ghash_lengths(&g, 0, iv_len);
        store_be32(j0, g.y[0]);
        store_be32(j0 + 4, g.y[1]);
        store_be32(j0 + 8, g.y[2]);
        store_be32(j0 + 12, g.y[3]);
    }

    /* S = GHASH(A || pad || C || pad || lengths). C is the ciphertext in both
     * directions: hash it before decrypting, after encrypting, block by block
     * so that in == out works. */
    memset(g.y, 0, sizeof(g.y));
    ghash_update(&g, aad, aad_len);

    memcpy(ctr, j0, 16);
    for (size_t off = 0; off < in_len; off += 16)
    {
        size_t n = in_len - off < 16 ? in_len - off : 16;

        if (!encrypt) ghash_update(&g, in + off, n);

        inc32(ctr);
        if (block(cipher_ctx, ctr, ks) != 0) goto end;
        for (size_t j = 0; j < n; j++) out[off + j] = (uint8_t)(in[off + j] ^ ks[j]);

        if (encrypt) ghash_update(&g, out + off, n);
    }
    ghash_lengths(&g, aad_len, in_len);

    /* T = E_K(J0) xor S */
    if (block(cipher_ctx, j0, ks) != 0) goto end;
    store_be32(tag, g.y[0] ^ load_be32(ks));
    store_be32(tag + 4, g.y[1] ^ load_be32(ks + 4));
    store_be32(tag + 8, g.y[2] ^ load_be32(ks + 8));
    store_be32(tag + 12, g.y[3] ^ load_be32(ks + 12));
    rc = 0;

end:
    /* H, the keystream and E_K(J0) are key material. */
    explicit_bzero(&g, sizeof(g));
    explicit_bzero(ks, sizeof(ks));
    explicit_bzero(ctr, sizeof(ctr));
    explicit_bzero(j0, sizeof(j0));
    if (rc != 0)
    {
        if (in_len != 0 && out != NULL) explicit_bzero(out, in_len);
        explicit_bzero(tag, 16);
    }
    return rc;
}

int zkn_gcm_ct_tag_diff(const uint8_t a[16], const uint8_t b[16])
{
    uint8_t d = 0;
    for (size_t i = 0; i < 16; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d;
}

#endif /* ZKN_HOST_BUILD || ZKN_AES_GCM_OVER_CX_AES */
