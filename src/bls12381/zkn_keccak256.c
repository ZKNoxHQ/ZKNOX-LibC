/*
 * zkn_keccak256.c — Keccak-256 hash (pre-NIST, 0x01 padding)
 *
 * Keccak-f[1600] with 24 rounds, rate = 136 bytes, capacity = 64 bytes.
 * Padding: original Keccak multi-rate padding (0x01...0x80), NOT SHA-3.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include <string.h>
#include "zkn_keccak256.h"

/* ══════════════════════════════════════════════════════════════════════
 *  Keccak-f[1600] permutation
 * ══════════════════════════════════════════════════════════════════════ */

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int KECCAK_ROT[24] = {
     1,  3,  6, 10, 15, 21, 28, 36,
    45, 55,  2, 14, 27, 41, 56,  8,
    25, 43, 62, 18, 39, 61, 20, 44,
};

static const int KECCAK_PI[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,
     8, 21, 24,  4, 15, 23, 19, 13,
    12,  2, 20, 14, 22,  9,  6,  1,
};

#define ROT64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static void keccak_f1600(uint64_t st[25])
{
    for (int round = 0; round < 24; round++) {
        uint64_t bc[5];

        /* θ step */
        for (int i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        for (int i = 0; i < 5; i++) {
            uint64_t t = bc[(i + 4) % 5] ^ ROT64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        /* ρ and π steps */
        uint64_t t = st[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAK_PI[i];
            uint64_t tmp = st[j];
            st[j] = ROT64(t, KECCAK_ROT[i]);
            t = tmp;
        }

        /* χ step */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (int i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        /* ι step */
        st[0] ^= KECCAK_RC[round];
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  XOR a block of `rate` bytes into the state (as little-endian u64s)
 * ══════════════════════════════════════════════════════════════════════ */

#define KECCAK256_RATE 136   /* (1600 - 2*256) / 8 */

static void xor_block(uint64_t st[25], const uint8_t *block, size_t len)
{
    for (size_t i = 0; i < len / 8; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++)
            v |= (uint64_t)block[i * 8 + j] << (8 * j);
        st[i] ^= v;
    }
    /* Handle any trailing bytes (< 8) */
    if (len % 8) {
        uint64_t v = 0;
        size_t base = (len / 8) * 8;
        for (size_t j = 0; j < len % 8; j++)
            v |= (uint64_t)block[base + j] << (8 * j);
        st[len / 8] ^= v;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Incremental API
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_keccak256_init(zkn_keccak256_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void zkn_keccak256_update(zkn_keccak256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t off = 0;

    /* Fill partial buffer */
    if (ctx->buf_len > 0) {
        size_t need = KECCAK256_RATE - ctx->buf_len;
        if (len < need) {
            memcpy(ctx->buf + ctx->buf_len, data, len);
            ctx->buf_len += len;
            return;
        }
        memcpy(ctx->buf + ctx->buf_len, data, need);
        xor_block(ctx->state, ctx->buf, KECCAK256_RATE);
        keccak_f1600(ctx->state);
        ctx->buf_len = 0;
        off = need;
    }

    /* Process full blocks */
    while (off + KECCAK256_RATE <= len) {
        xor_block(ctx->state, data + off, KECCAK256_RATE);
        keccak_f1600(ctx->state);
        off += KECCAK256_RATE;
    }

    /* Save remainder */
    size_t rem = len - off;
    if (rem > 0) {
        memcpy(ctx->buf, data + off, rem);
        ctx->buf_len = rem;
    }
}

void zkn_keccak256_final(zkn_keccak256_ctx_t *ctx, uint8_t out[32])
{
    /* Keccak padding: 0x01 || 0x00...0x00 || 0x80
     * NOTE: NOT SHA-3 which uses 0x06 instead of 0x01 */
    memset(ctx->buf + ctx->buf_len, 0, KECCAK256_RATE - ctx->buf_len);
    ctx->buf[ctx->buf_len] = 0x01;
    ctx->buf[KECCAK256_RATE - 1] |= 0x80;

    xor_block(ctx->state, ctx->buf, KECCAK256_RATE);
    keccak_f1600(ctx->state);

    /* Extract 256 bits = 32 bytes from state in little-endian */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (uint8_t)(ctx->state[i] >> (8 * j));
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  One-shot API
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_keccak256(uint8_t out[32], const uint8_t *in, size_t inlen)
{
    zkn_keccak256_ctx_t ctx;
    zkn_keccak256_init(&ctx);
    zkn_keccak256_update(&ctx, in, inlen);
    zkn_keccak256_final(&ctx, out);
}
