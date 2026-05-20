// copyright, zknox, 2025
//
// zkn_blake512.c — BLAKE-512 (original, SHA-3 candidate)
//
// This is the BLAKE hash used by circomlib's eddsa-babyjubjub via the
// 'blake-hash' / 'blake' npm package: createBlakeHash('blake512').
// It is NOT blake2b.
//
// Key differences with BLAKE2b-512:
//   - 16 rounds (vs 12)
//   - G function XORs message words with pi-derived constants (cross-indexed)
//   - SHA-512 IV as initial chaining value
//   - MD-strengthening padding with 128-bit bit counter
//   - Salt XORed into IV and finalization
//
// Reference: J.-P. Aumasson, L. Henzen, W. Meier, R. C.-W. Phan,
//            "SHA-3 proposal BLAKE", v1.4, 2010
//
// Memory budget:
//   Context struct:  ~250 bytes (stack)
//   compress():      ~256 bytes additional (v[16] + m[16])
//   No heap allocation.
//   Constants are 'static const' → flash on Ledger.

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "zkn_errors.h"
#include "zkn_blake512.h"

// =========================================================================
// Constants
// =========================================================================

// SHA-512 initial vector — used as BLAKE-512 chaining value seed
static const uint64_t blake512_iv[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

// First digits of π as 16 × 64-bit words
static const uint64_t blake512_cst[16] = {
    0x243F6A8885A308D3ULL, 0x13198A2E03707344ULL,
    0xA4093822299F31D0ULL, 0x082EFA98EC4E6C89ULL,
    0x452821E638D01377ULL, 0xBE5466CF34E90C6CULL,
    0xC0AC29B7C97C50DDULL, 0x3F84D5B5B5470917ULL,
    0x9216D5D98979FB1BULL, 0xD1310BA698DFB5ACULL,
    0x2FFD72DBD01ADFB7ULL, 0xB8E1AFED6A267E96ULL,
    0xBA7C9045F12C7F99ULL, 0x24A19947B3916CF7ULL,
    0x0801F2E2858EFC16ULL, 0x636920D871574E69ULL
};

// σ permutations — 10 rows cycled for rounds 10–15 via r % 10
static const uint8_t blake512_sigma[10][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
    { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
    { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
    {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
    {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0}
};

// =========================================================================
// Big-endian load / store (BLAKE-512 is internally big-endian)
// =========================================================================

static inline uint64_t load64_be(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] <<  8) | ((uint64_t)p[7]);
}

static inline void store64_be(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);  p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);  p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);  p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >>  8);  p[7] = (uint8_t)(v);
}

// =========================================================================
// G mixing function and block compression
// =========================================================================

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// BLAKE-512 G function (note cross-indexed constant XOR):
//   a += b + (m_j ⊕ c_k)      d = (d ⊕ a) >>> 32
//   c += d                      b = (b ⊕ c) >>> 25
//   a += b + (m_k ⊕ c_j)      d = (d ⊕ a) >>> 16
//   c += d                      b = (b ⊕ c) >>> 11
#define BLAKE512_G(a, b, c, d, mj, mk, cj, ck) do { \
    (a) += (b) + ((mj) ^ (ck));                      \
    (d)  = ROTR64((d) ^ (a), 32);                    \
    (c) += (d);                                       \
    (b)  = ROTR64((b) ^ (c), 25);                    \
    (a) += (b) + ((mk) ^ (cj));                      \
    (d)  = ROTR64((d) ^ (a), 16);                    \
    (c) += (d);                                       \
    (b)  = ROTR64((b) ^ (c), 11);                    \
} while (0)

static void blake512_compress(zkn_blake512_ctx_t *ctx, const uint8_t block[128])
{
    uint64_t v[16];
    uint64_t m[16];
    int r;

    // --- Load 128-byte block as 16 big-endian uint64 words ---
    for (int i = 0; i < 16; i++) {
        m[i] = load64_be(block + i * 8);
    }

    // --- Init working vector ---
    v[ 0] = ctx->h[0];                     v[ 1] = ctx->h[1];
    v[ 2] = ctx->h[2];                     v[ 3] = ctx->h[3];
    v[ 4] = ctx->h[4];                     v[ 5] = ctx->h[5];
    v[ 6] = ctx->h[6];                     v[ 7] = ctx->h[7];
    v[ 8] = ctx->s[0] ^ blake512_cst[0];   v[ 9] = ctx->s[1] ^ blake512_cst[1];
    v[10] = ctx->s[2] ^ blake512_cst[2];   v[11] = ctx->s[3] ^ blake512_cst[3];
    v[12] = blake512_cst[4];               v[13] = blake512_cst[5];
    v[14] = blake512_cst[6];               v[15] = blake512_cst[7];

    // Counter injection (skipped for padding-only blocks via nullt flag)
    if (!ctx->nullt) {
        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[0];
        v[14] ^= ctx->t[1];
        v[15] ^= ctx->t[1];
    }

    // --- 16 rounds ---
    for (r = 0; r < 16; r++) {
        const uint8_t *s = blake512_sigma[r % 10];

        // Column step
        BLAKE512_G(v[ 0], v[ 4], v[ 8], v[12],
                   m[s[ 0]], m[s[ 1]], blake512_cst[s[ 0]], blake512_cst[s[ 1]]);
        BLAKE512_G(v[ 1], v[ 5], v[ 9], v[13],
                   m[s[ 2]], m[s[ 3]], blake512_cst[s[ 2]], blake512_cst[s[ 3]]);
        BLAKE512_G(v[ 2], v[ 6], v[10], v[14],
                   m[s[ 4]], m[s[ 5]], blake512_cst[s[ 4]], blake512_cst[s[ 5]]);
        BLAKE512_G(v[ 3], v[ 7], v[11], v[15],
                   m[s[ 6]], m[s[ 7]], blake512_cst[s[ 6]], blake512_cst[s[ 7]]);

        // Diagonal step
        BLAKE512_G(v[ 0], v[ 5], v[10], v[15],
                   m[s[ 8]], m[s[ 9]], blake512_cst[s[ 8]], blake512_cst[s[ 9]]);
        BLAKE512_G(v[ 1], v[ 6], v[11], v[12],
                   m[s[10]], m[s[11]], blake512_cst[s[10]], blake512_cst[s[11]]);
        BLAKE512_G(v[ 2], v[ 7], v[ 8], v[13],
                   m[s[12]], m[s[13]], blake512_cst[s[12]], blake512_cst[s[13]]);
        BLAKE512_G(v[ 3], v[ 4], v[ 9], v[14],
                   m[s[14]], m[s[15]], blake512_cst[s[14]], blake512_cst[s[15]]);
    }

    // --- Finalize: h[i] ^= s[i%4] ^ v[i] ^ v[i+8] ---
    for (int i = 0; i < 8; i++) {
        ctx->h[i] ^= ctx->s[i % 4] ^ v[i] ^ v[i + 8];
    }
}

// =========================================================================
// Public API
// =========================================================================

zkn_error_t zkn_blake512_init(zkn_blake512_ctx_t *ctx)
{
    if (ctx == NULL) {
        return ZKN_ERR_INVALID_PARAM;
    }

    for (int i = 0; i < 8; i++) ctx->h[i] = blake512_iv[i];
    memset(ctx->s, 0, sizeof(ctx->s));
    ctx->t[0]  = 0;
    ctx->t[1]  = 0;
    ctx->buflen = 0;
    ctx->nullt  = 0;

    return ZKN_OK;
}

zkn_error_t zkn_blake512_init_with_salt(zkn_blake512_ctx_t *ctx, const uint8_t salt[32])
{
    zkn_error_t err = zkn_blake512_init(ctx);
    if (err) return err;

    if (salt != NULL) {
        ctx->s[0] = load64_be(salt);
        ctx->s[1] = load64_be(salt +  8);
        ctx->s[2] = load64_be(salt + 16);
        ctx->s[3] = load64_be(salt + 24);
        // Salt is XORed into the first 4 IV words
        ctx->h[0] ^= ctx->s[0];
        ctx->h[1] ^= ctx->s[1];
        ctx->h[2] ^= ctx->s[2];
        ctx->h[3] ^= ctx->s[3];
    }

    return ZKN_OK;
}

zkn_error_t zkn_blake512_update(zkn_blake512_ctx_t *ctx, const uint8_t *data, size_t datalen)
{
    if (ctx == NULL) return ZKN_ERR_INVALID_PARAM;
    if (datalen == 0) return ZKN_OK;
    if (data == NULL)  return ZKN_ERR_INVALID_PARAM;

    size_t left = ctx->buflen;
    size_t fill = ZKN_BLAKE512_BLOCK_SIZE - left;

    // Complete a pending partial block
    if (left > 0 && datalen >= fill) {
        memcpy(ctx->buf + left, data, fill);
        ctx->t[0] += 1024;                         // 128 bytes = 1024 bits
        if (ctx->t[0] < 1024) ctx->t[1]++;         // overflow
        blake512_compress(ctx, ctx->buf);
        data    += fill;
        datalen -= fill;
        left     = 0;
    }

    // Process full blocks straight from input pointer
    while (datalen >= ZKN_BLAKE512_BLOCK_SIZE) {
        ctx->t[0] += 1024;
        if (ctx->t[0] < 1024) ctx->t[1]++;
        blake512_compress(ctx, data);
        data    += ZKN_BLAKE512_BLOCK_SIZE;
        datalen -= ZKN_BLAKE512_BLOCK_SIZE;
    }

    // Buffer remaining bytes
    if (datalen > 0) {
        memcpy(ctx->buf + left, data, datalen);
    }
    ctx->buflen = left + datalen;

    return ZKN_OK;
}

// -------------------------------------------------------------------------
// Finalization — BLAKE-512 MD-strengthening padding
//
// Layout of the final block(s):
//   [message remainder] [0x80] [0x00 ...] [0x01] [128-bit bitcount BE]
//                                          ^pos 111  ^pos 112..127
//
// Three cases:
//   buflen == 111 → merge 0x80|0x01 = 0x81 at position 111
//   buflen <  111 → pad fits in current block
//   buflen >  111 → overflow into a second block
// -------------------------------------------------------------------------

zkn_error_t zkn_blake512_final(zkn_blake512_ctx_t *ctx, uint8_t out[ZKN_BLAKE512_DIGEST_SIZE])
{
    if (ctx == NULL || out == NULL) {
        return ZKN_ERR_INVALID_PARAM;
    }

    // --- Total message length in bits (before padding) ---
    uint64_t lo = ctx->t[0] + ((uint64_t)ctx->buflen << 3);
    uint64_t hi = ctx->t[1];
    if (lo < ctx->t[0]) hi++;

    // Encode as big-endian 128-bit
    uint8_t msglen[16];
    store64_be(msglen,     hi);
    store64_be(msglen + 8, lo);

    // --- Case 1: buflen == 111 — exact fit, merged pad byte ---
    if (ctx->buflen == 111) {
        ctx->t[0] = lo;
        ctx->t[1] = hi;

        ctx->buf[111] = 0x81;                      // 0x80 | 0x01
        memcpy(ctx->buf + 112, msglen, 16);
        blake512_compress(ctx, ctx->buf);
    }
    // --- Case 2: buflen < 111 — padding fits in one block ---
    else if (ctx->buflen < 111) {
        // If buffer is empty, this entire block is padding (no message bits)
        if (ctx->buflen == 0) ctx->nullt = 1;

        // Set counter to total message bit count for this compress
        ctx->t[0] = lo;
        ctx->t[1] = hi;

        // [0x80] [zeros ...] [0x01 at pos 111] [16-byte bitcount]
        ctx->buf[ctx->buflen] = 0x80;
        memset(ctx->buf + ctx->buflen + 1, 0, 110 - ctx->buflen);
        ctx->buf[111] = 0x01;
        memcpy(ctx->buf + 112, msglen, 16);
        blake512_compress(ctx, ctx->buf);
    }
    // --- Case 3: buflen > 111 — need two blocks ---
    else {
        // Block 1: message tail + 0x80 + zeros
        ctx->t[0] = lo;
        ctx->t[1] = hi;

        ctx->buf[ctx->buflen] = 0x80;
        memset(ctx->buf + ctx->buflen + 1, 0,
               ZKN_BLAKE512_BLOCK_SIZE - ctx->buflen - 1);
        blake512_compress(ctx, ctx->buf);

        // Block 2: all padding, no message bits → nullt
        ctx->t[0] = 0;
        ctx->t[1] = 0;
        ctx->nullt = 1;

        memset(ctx->buf, 0, 111);
        ctx->buf[111] = 0x01;
        memcpy(ctx->buf + 112, msglen, 16);
        blake512_compress(ctx, ctx->buf);
    }

    // --- Output chaining value as big-endian bytes ---
    for (int i = 0; i < 8; i++) {
        store64_be(out + i * 8, ctx->h[i]);
    }

    // Wipe context (sensitive: may contain key material in eddsa usage)
    explicit_bzero(ctx, sizeof(zkn_blake512_ctx_t));

    return ZKN_OK;
}

// --- One-shot convenience ---

zkn_error_t zkn_blake512(const uint8_t *data, size_t datalen, uint8_t out[ZKN_BLAKE512_DIGEST_SIZE])
{
    zkn_blake512_ctx_t ctx;
    ZKN_ERROR_INIT();

    ZKN_CHECK(zkn_blake512_init(&ctx));
    ZKN_CHECK(zkn_blake512_update(&ctx, data, datalen));
    ZKN_CHECK(zkn_blake512_final(&ctx, out));

    ZKN_ERROR_CLOSE();
}
