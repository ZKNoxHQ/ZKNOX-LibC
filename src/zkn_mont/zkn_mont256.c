/*
 * zkn_mont256.c — Portable C implementation of 256-bit Montgomery arithmetic
 *
 * CIOS (Coarsely Integrated Operand Scanning) method for Montgomery
 * multiplication, targeting 32-bit ARM but portable to any platform.
 *
 * All functions are constant-time: no secret-dependent branches or indexing.
 *
 * When ZKN_MONT256_ASM is defined, the core functions (mul, sqr, add, sub,
 * from_mont) are provided by zkn_mont256_arm32.S instead.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_mont256.h"
#include <string.h>

#define N ZKN_MONT_NLIMBS  /* 8 */

/* ══════════════════════════════════════════════════════════════════════
 *  Internal helpers
 * ══════════════════════════════════════════════════════════════════════ */

/*
 * Constant-time conditional subtraction.
 * Computes r = t - p if t >= p, otherwise r = t.
 * t has N+1 limbs (t[N] is 0 or 1 overflow).
 */
static void ct_final_sub(zkn_limb_t r[N],
                         const zkn_limb_t t[N + 1],
                         const zkn_limb_t p[N])
{
    zkn_limb_t tmp[N];
    zkn_limb_t borrow = 0;

    for (int i = 0; i < N; i++) {
        zkn_dlimb_t d = (zkn_dlimb_t)t[i] - p[i] - borrow;
        tmp[i] = (zkn_limb_t)d;
        borrow = (zkn_limb_t)(d >> 63);
    }

    zkn_limb_t underflow = (zkn_limb_t)(t[N] < borrow);
    zkn_limb_t mask = (zkn_limb_t)0 - underflow;

    for (int i = 0; i < N; i++) {
        r[i] = (tmp[i] & ~mask) | (t[i] & mask);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Core arithmetic — guarded by ZKN_MONT256_ASM
 * ══════════════════════════════════════════════════════════════════════ */

#if !defined(ZKN_MONT256_ASM)

void zkn_mul_mont_256(zkn_fe256_t r,
                      const zkn_fe256_t a,
                      const zkn_fe256_t b,
                      const zkn_fe256_t p,
                      zkn_limb_t n0)
{
    zkn_limb_t t[N + 1];
    memset(t, 0, sizeof(t));

    for (int i = 0; i < N; i++) {
        zkn_dlimb_t carry = 0;
        zkn_limb_t bi = b[i];

        for (int j = 0; j < N; j++) {
            carry += (zkn_dlimb_t)a[j] * bi + t[j];
            t[j] = (zkn_limb_t)carry;
            carry >>= 32;
        }
        zkn_dlimb_t carry2 = (zkn_dlimb_t)t[N] + carry;
        t[N] = (zkn_limb_t)carry2;
        zkn_limb_t overflow = (zkn_limb_t)(carry2 >> 32);

        zkn_limb_t m = t[0] * n0;
        carry = 0;

        carry = (zkn_dlimb_t)t[0] + (zkn_dlimb_t)m * p[0];
        carry >>= 32;

        for (int j = 1; j < N; j++) {
            carry += (zkn_dlimb_t)t[j] + (zkn_dlimb_t)m * p[j];
            t[j - 1] = (zkn_limb_t)carry;
            carry >>= 32;
        }

        carry += (zkn_dlimb_t)t[N];
        t[N - 1] = (zkn_limb_t)carry;
        t[N] = (zkn_limb_t)(carry >> 32) + overflow;
    }

    ct_final_sub(r, t, p);
}

void zkn_sqr_mont_256(zkn_fe256_t r,
                      const zkn_fe256_t a,
                      const zkn_fe256_t p,
                      zkn_limb_t n0)
{
    zkn_mul_mont_256(r, a, a, p, n0);
}

void zkn_add_mod_256(zkn_fe256_t r,
                     const zkn_fe256_t a,
                     const zkn_fe256_t b,
                     const zkn_fe256_t p)
{
    zkn_limb_t t[N + 1];
    zkn_dlimb_t carry = 0;

    for (int i = 0; i < N; i++) {
        carry += (zkn_dlimb_t)a[i] + b[i];
        t[i] = (zkn_limb_t)carry;
        carry >>= 32;
    }
    t[N] = (zkn_limb_t)carry;

    ct_final_sub(r, t, p);
}

void zkn_sub_mod_256(zkn_fe256_t r,
                     const zkn_fe256_t a,
                     const zkn_fe256_t b,
                     const zkn_fe256_t p)
{
    zkn_limb_t t[N];
    zkn_limb_t borrow = 0;

    for (int i = 0; i < N; i++) {
        zkn_dlimb_t d = (zkn_dlimb_t)a[i] - b[i] - borrow;
        t[i] = (zkn_limb_t)d;
        borrow = (zkn_limb_t)(d >> 63);
    }

    zkn_limb_t mask = (zkn_limb_t)0 - borrow;
    zkn_dlimb_t carry = 0;

    for (int i = 0; i < N; i++) {
        carry += (zkn_dlimb_t)t[i] + (p[i] & mask);
        r[i] = (zkn_limb_t)carry;
        carry >>= 32;
    }
}

void zkn_from_mont_256(zkn_fe256_t r,
                       const zkn_fe256_t a,
                       const zkn_fe256_t p,
                       zkn_limb_t n0)
{
    zkn_wide256_t wide;
    memset(wide, 0, sizeof(wide));
    memcpy(wide, a, N * sizeof(zkn_limb_t));
    zkn_redc_mont_256(r, wide, p, n0);
}

#endif /* !ZKN_MONT256_ASM */

/* ── redc is always compiled from C (no ASM version) ───────────────── */

void zkn_redc_mont_256(zkn_fe256_t r,
                       const zkn_wide256_t a,
                       const zkn_fe256_t p,
                       zkn_limb_t n0)
{
    zkn_limb_t t[2 * N + 1];
    memcpy(t, a, 2 * N * sizeof(zkn_limb_t));
    t[2 * N] = 0;

    for (int i = 0; i < N; i++) {
        zkn_limb_t m = t[i] * n0;
        zkn_dlimb_t carry = 0;

        for (int j = 0; j < N; j++) {
            carry += (zkn_dlimb_t)t[i + j] + (zkn_dlimb_t)m * p[j];
            t[i + j] = (zkn_limb_t)carry;
            carry >>= 32;
        }

        for (int j = N + i; carry && j <= 2 * N; j++) {
            carry += (zkn_dlimb_t)t[j];
            t[j] = (zkn_limb_t)carry;
            carry >>= 32;
        }
    }

    zkn_limb_t result[N + 1];
    memcpy(result, &t[N], N * sizeof(zkn_limb_t));
    result[N] = t[2 * N];

    ct_final_sub(r, result, p);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Context initialization
 * ══════════════════════════════════════════════════════════════════════ */

zkn_limb_t zkn_mont_compute_n0(zkn_limb_t p0)
{
    zkn_limb_t x = 1;
    for (int i = 0; i < 5; i++) {
        x *= 2 - p0 * x;
    }
    return (zkn_limb_t)0 - x;
}

void zkn_mont_ctx_init(zkn_mont_ctx256_t *ctx, const zkn_fe256_t p)
{
    memcpy(ctx->p, p, sizeof(zkn_fe256_t));
    ctx->n0 = zkn_mont_compute_n0(p[0]);

    /* R mod p = 2^256 mod p, via 256 doublings of 1 */
    {
        zkn_fe256_t x = {1, 0, 0, 0, 0, 0, 0, 0};
        for (int i = 0; i < 256; i++) {
            zkn_add_mod_256(x, x, x, p);
        }
        memcpy(ctx->one, x, sizeof(zkn_fe256_t));
    }

    /* R^2 mod p, via 256 doublings of R mod p */
    {
        zkn_fe256_t acc;
        memcpy(acc, ctx->one, sizeof(zkn_fe256_t));
        for (int i = 0; i < 256; i++) {
            zkn_add_mod_256(acc, acc, acc, p);
        }
        memcpy(ctx->R2, acc, sizeof(zkn_fe256_t));
    }
}

void zkn_to_mont_256(zkn_fe256_t r,
                     const zkn_fe256_t a,
                     const zkn_mont_ctx256_t *ctx)
{
    zkn_mul_mont_256(r, a, ctx->R2, ctx->p, ctx->n0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Serialization
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fe256_from_be(zkn_fe256_t r, const uint8_t src[ZKN_MONT_BYTES])
{
    for (int i = 0; i < N; i++) {
        int base = ZKN_MONT_BYTES - 4 - i * 4;
        r[i] = ((zkn_limb_t)src[base]     << 24) |
               ((zkn_limb_t)src[base + 1] << 16) |
               ((zkn_limb_t)src[base + 2] <<  8) |
               ((zkn_limb_t)src[base + 3]);
    }
}

void zkn_fe256_to_be(uint8_t dst[ZKN_MONT_BYTES], const zkn_fe256_t a)
{
    for (int i = 0; i < N; i++) {
        int base = ZKN_MONT_BYTES - 4 - i * 4;
        dst[base]     = (uint8_t)(a[i] >> 24);
        dst[base + 1] = (uint8_t)(a[i] >> 16);
        dst[base + 2] = (uint8_t)(a[i] >>  8);
        dst[base + 3] = (uint8_t)(a[i]);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Utility
 * ══════════════════════════════════════════════════════════════════════ */

int zkn_fe256_eq(const zkn_fe256_t a, const zkn_fe256_t b)
{
    zkn_limb_t diff = 0;
    for (int i = 0; i < N; i++) {
        diff |= a[i] ^ b[i];
    }
    return (int)(1 ^ ((diff | ((zkn_limb_t)0 - diff)) >> 31));
}

void zkn_fe256_zero(zkn_fe256_t r)
{
    memset(r, 0, N * sizeof(zkn_limb_t));
}

void zkn_fe256_cmov(zkn_fe256_t r, const zkn_fe256_t a, zkn_limb_t flag)
{
    zkn_limb_t mask = (zkn_limb_t)0 - flag;
    for (int i = 0; i < N; i++) {
        r[i] ^= mask & (r[i] ^ a[i]);
    }
}

void zkn_neg_mod_256(zkn_fe256_t r,
                     const zkn_fe256_t a,
                     const zkn_fe256_t p)
{
    /* r = p - a, but if a == 0 then r = 0 (constant-time) */
    zkn_limb_t is_nonzero = 0;
    for (int i = 0; i < N; i++) is_nonzero |= a[i];

    /* mask = 0xFFFFFFFF if a != 0, 0 if a == 0 */
    zkn_limb_t mask = (zkn_limb_t)0 - (zkn_limb_t)(is_nonzero != 0);

    zkn_dlimb_t borrow = 0;
    for (int i = 0; i < N; i++) {
        zkn_dlimb_t d = (zkn_dlimb_t)p[i] - a[i] - borrow;
        r[i] = (zkn_limb_t)d & mask;
        borrow = (zkn_limb_t)(d >> 63);
    }
}

void zkn_exp_mont_256(zkn_fe256_t r,
                      const zkn_fe256_t base,
                      const uint8_t *exp_be,
                      int exp_len,
                      const zkn_mont_ctx256_t *ctx)
{
    /*
     * Left-to-right binary square-and-multiply.
     * Constant-time: always compute both sqr and mul, use cmov to select.
     */
    zkn_fe256_t acc, tmp;
    memcpy(acc, ctx->one, sizeof(zkn_fe256_t));

    for (int i = 0; i < exp_len; i++) {
        uint8_t byte = exp_be[i];
        for (int bit = 7; bit >= 0; bit--) {
            zkn_sqr_mont_256(acc, acc, ctx->p, ctx->n0);
            zkn_mul_mont_256(tmp, acc, base, ctx->p, ctx->n0);
            zkn_fe256_cmov(acc, tmp, (byte >> bit) & 1);
        }
    }

    memcpy(r, acc, sizeof(zkn_fe256_t));
}

void zkn_inv_mont_256(zkn_fe256_t r,
                      const zkn_fe256_t a,
                      const zkn_mont_ctx256_t *ctx)
{
    /* a^{-1} = a^{p-2} mod p  (Fermat's little theorem) */
    zkn_fe256_t pm2;
    zkn_fe256_t two = {2, 0, 0, 0, 0, 0, 0, 0};

    /* pm2 = p - 2 (plain subtraction, p > 2 guaranteed) */
    zkn_dlimb_t borrow = 0;
    for (int i = 0; i < N; i++) {
        zkn_dlimb_t d = (zkn_dlimb_t)ctx->p[i] - two[i] - borrow;
        pm2[i] = (zkn_limb_t)d;
        borrow = (zkn_limb_t)(d >> 63);
    }

    uint8_t pm2_be[ZKN_MONT_BYTES];
    zkn_fe256_to_be(pm2_be, pm2);

    zkn_exp_mont_256(r, a, pm2_be, ZKN_MONT_BYTES, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  BabyJubjub precomputed context
 * ══════════════════════════════════════════════════════════════════════ */

static const zkn_fe256_t BABYJUBJUB_P = {
    0xf0000001u, 0x43e1f593u, 0x79b97091u, 0x2833e848u,
    0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u
};

static zkn_mont_ctx256_t _bjj_ctx;
static int _bjj_ctx_initialized = 0;

const zkn_mont_ctx256_t *zkn_babyjubjub_ctx(void)
{
    if (!_bjj_ctx_initialized) {
        zkn_mont_ctx_init(&_bjj_ctx, BABYJUBJUB_P);
        _bjj_ctx_initialized = 1;
    }
    return &_bjj_ctx;
}
