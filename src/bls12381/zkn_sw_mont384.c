/*
 * zkn_sw_mont384.c — Portable C implementation of 384-bit Montgomery arithmetic
 *
 * CIOS (Coarsely Integrated Operand Scanning) for 12 × 32-bit limbs.
 * Same structure as zkn_mont256.c, extended for 384-bit primes (BLS12-381).
 *
 * When ZKN_SW_MONT384_ASM is defined, the core functions (mul, sqr, add, sub,
 * from_mont) are provided by zkn_sw_mont384_arm32.S instead.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_sw_mont384.h"
#include <string.h>

#define N ZKN_SW_MONT384_NLIMBS  /* 12 */

/* ══════════════════════════════════════════════════════════════════════
 *  Internal helpers
 * ══════════════════════════════════════════════════════════════════════ */

static void ct_final_sub(zkn_sw_limb_t r[N],
                         const zkn_sw_limb_t t[N + 1],
                         const zkn_sw_limb_t p[N])
{
    zkn_sw_limb_t tmp[N];
    zkn_sw_limb_t borrow = 0;

    for (int i = 0; i < N; i++) {
        zkn_sw_dlimb_t d = (zkn_sw_dlimb_t)t[i] - p[i] - borrow;
        tmp[i] = (zkn_sw_limb_t)d;
        borrow = (zkn_sw_limb_t)(d >> 63);
    }

    zkn_sw_limb_t underflow = (zkn_sw_limb_t)(t[N] < borrow);
    zkn_sw_limb_t mask = (zkn_sw_limb_t)0 - underflow;  /* 0 or 0xFFFFFFFF */

    for (int i = 0; i < N; i++)
        r[i] = (tmp[i] & ~mask) | (t[i] & mask);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Core arithmetic — disabled when ASM is used
 * ══════════════════════════════════════════════════════════════════════ */

#ifndef ZKN_SW_MONT384_ASM

void zkn_sw_mul_mont_384(zkn_sw_fe384_t r,
                      const zkn_sw_fe384_t a,
                      const zkn_sw_fe384_t b,
                      const zkn_sw_fe384_t p,
                      zkn_sw_limb_t n0)
{
    zkn_sw_limb_t t[N + 1];
    memset(t, 0, sizeof(t));

    for (int i = 0; i < N; i++) {
        zkn_sw_dlimb_t carry = 0;
        zkn_sw_limb_t bi = b[i];

        for (int j = 0; j < N; j++) {
            carry += (zkn_sw_dlimb_t)a[j] * bi + t[j];
            t[j] = (zkn_sw_limb_t)carry;
            carry >>= 32;
        }
        zkn_sw_dlimb_t carry2 = (zkn_sw_dlimb_t)t[N] + carry;
        t[N] = (zkn_sw_limb_t)carry2;
        zkn_sw_limb_t overflow = (zkn_sw_limb_t)(carry2 >> 32);

        zkn_sw_limb_t m = t[0] * n0;
        carry = 0;

        carry = (zkn_sw_dlimb_t)t[0] + (zkn_sw_dlimb_t)m * p[0];
        carry >>= 32;

        for (int j = 1; j < N; j++) {
            carry += (zkn_sw_dlimb_t)t[j] + (zkn_sw_dlimb_t)m * p[j];
            t[j - 1] = (zkn_sw_limb_t)carry;
            carry >>= 32;
        }

        carry += (zkn_sw_dlimb_t)t[N];
        t[N - 1] = (zkn_sw_limb_t)carry;
        t[N] = (zkn_sw_limb_t)(carry >> 32) + overflow;
    }

    ct_final_sub(r, t, p);
}

void zkn_sw_sqr_mont_384(zkn_sw_fe384_t r,
                      const zkn_sw_fe384_t a,
                      const zkn_sw_fe384_t p,
                      zkn_sw_limb_t n0)
{
    zkn_sw_mul_mont_384(r, a, a, p, n0);
}

void zkn_sw_add_mod_384(zkn_sw_fe384_t r,
                     const zkn_sw_fe384_t a,
                     const zkn_sw_fe384_t b,
                     const zkn_sw_fe384_t p)
{
    zkn_sw_limb_t t[N + 1];
    zkn_sw_dlimb_t carry = 0;
    for (int i = 0; i < N; i++) {
        carry += (zkn_sw_dlimb_t)a[i] + b[i];
        t[i] = (zkn_sw_limb_t)carry;
        carry >>= 32;
    }
    t[N] = (zkn_sw_limb_t)carry;
    ct_final_sub(r, t, p);
}

void zkn_sw_sub_mod_384(zkn_sw_fe384_t r,
                     const zkn_sw_fe384_t a,
                     const zkn_sw_fe384_t b,
                     const zkn_sw_fe384_t p)
{
    zkn_sw_limb_t borrow = 0;
    for (int i = 0; i < N; i++) {
        zkn_sw_dlimb_t d = (zkn_sw_dlimb_t)a[i] - b[i] - borrow;
        r[i] = (zkn_sw_limb_t)d;
        borrow = (zkn_sw_limb_t)(d >> 63);
    }

    /* If borrow, add p back (constant-time) */
    zkn_sw_limb_t mask = (zkn_sw_limb_t)(0u - borrow);  /* -1 if borrow, 0 otherwise */
    zkn_sw_dlimb_t carry = 0;
    for (int i = 0; i < N; i++) {
        carry += (zkn_sw_dlimb_t)r[i] + (p[i] & mask);
        r[i] = (zkn_sw_limb_t)carry;
        carry >>= 32;
    }
}

void zkn_sw_from_mont_384(zkn_sw_fe384_t r,
                       const zkn_sw_fe384_t a,
                       const zkn_sw_fe384_t p,
                       zkn_sw_limb_t n0)
{
    zkn_sw_fe384_t one = {1};
    zkn_sw_mul_mont_384(r, a, one, p, n0);
}

#endif /* !ZKN_SW_MONT384_ASM */

/* ══════════════════════════════════════════════════════════════════════
 *  Reduction of a 768-bit value (always C, not perf-critical)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_sw_redc_mont_384(zkn_sw_fe384_t r,
                       const zkn_sw_wide384_t a,
                       const zkn_sw_fe384_t p,
                       zkn_sw_limb_t n0)
{
    zkn_sw_limb_t t[2 * N + 1];
    memcpy(t, a, sizeof(zkn_sw_wide384_t));
    t[2 * N] = 0;

    for (int i = 0; i < N; i++) {
        zkn_sw_limb_t m = t[i] * n0;
        zkn_sw_dlimb_t carry = 0;
        for (int j = 0; j < N; j++) {
            carry += (zkn_sw_dlimb_t)t[i + j] + (zkn_sw_dlimb_t)m * p[j];
            t[i + j] = (zkn_sw_limb_t)carry;
            carry >>= 32;
        }
        for (int j = N; i + j <= 2 * N; j++) {
            carry += t[i + j];
            t[i + j] = (zkn_sw_limb_t)carry;
            carry >>= 32;
        }
    }

    zkn_sw_limb_t tN[N + 1];
    memcpy(tN, t + N, (N + 1) * sizeof(zkn_sw_limb_t));
    ct_final_sub(r, tN, p);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Context / helpers (always C)
 * ══════════════════════════════════════════════════════════════════════ */

zkn_sw_limb_t zkn_sw_mont384_compute_n0(zkn_sw_limb_t p0)
{
    zkn_sw_limb_t x = p0;
    for (int i = 0; i < 5; i++)
        x *= 2 - p0 * x;
    return (zkn_sw_limb_t)(0u - x);
}

void zkn_sw_mont_ctx384_init(zkn_sw_mont_ctx384_t *ctx, const zkn_sw_fe384_t p)
{
    memcpy(ctx->p, p, sizeof(zkn_sw_fe384_t));
    ctx->n0 = zkn_sw_mont384_compute_n0(p[0]);

    /* Compute R mod p  (R = 2^384) via repeated doubling of 1 */
    memset(ctx->one, 0, sizeof(zkn_sw_fe384_t));
    zkn_sw_fe384_t acc = {1};
    for (int i = 0; i < 384; i++)
        zkn_sw_add_mod_384(acc, acc, acc, p);
    memcpy(ctx->one, acc, sizeof(zkn_sw_fe384_t));

    /* R^2 mod p = to_mont(R mod p) */
    zkn_sw_fe384_t r2 = {0};
    memcpy(r2, ctx->one, sizeof(zkn_sw_fe384_t));
    for (int i = 0; i < 384; i++)
        zkn_sw_add_mod_384(r2, r2, r2, p);
    memcpy(ctx->R2, r2, sizeof(zkn_sw_fe384_t));
}

void zkn_sw_to_mont_384(zkn_sw_fe384_t r,
                     const zkn_sw_fe384_t a,
                     const zkn_sw_mont_ctx384_t *ctx)
{
    zkn_sw_mul_mont_384(r, a, ctx->R2, ctx->p, ctx->n0);
}

void zkn_sw_fe384_from_be(zkn_sw_fe384_t r, const uint8_t src[ZKN_SW_MONT384_BYTES])
{
    for (int i = 0; i < ZKN_SW_MONT384_NLIMBS; i++) {
        int base = ZKN_SW_MONT384_BYTES - 4 * (i + 1);
        r[i] = ((uint32_t)src[base]     << 24) |
               ((uint32_t)src[base + 1] << 16) |
               ((uint32_t)src[base + 2] <<  8) |
               ((uint32_t)src[base + 3]);
    }
}

void zkn_sw_fe384_to_be(uint8_t dst[ZKN_SW_MONT384_BYTES], const zkn_sw_fe384_t a)
{
    for (int i = 0; i < ZKN_SW_MONT384_NLIMBS; i++) {
        int base = ZKN_SW_MONT384_BYTES - 4 * (i + 1);
        dst[base]     = (uint8_t)(a[i] >> 24);
        dst[base + 1] = (uint8_t)(a[i] >> 16);
        dst[base + 2] = (uint8_t)(a[i] >>  8);
        dst[base + 3] = (uint8_t)(a[i]);
    }
}

int zkn_sw_fe384_eq(const zkn_sw_fe384_t a, const zkn_sw_fe384_t b)
{
    zkn_sw_limb_t diff = 0;
    for (int i = 0; i < N; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

void zkn_sw_fe384_zero(zkn_sw_fe384_t r)
{
    memset(r, 0, sizeof(zkn_sw_fe384_t));
}

void zkn_sw_fe384_cmov(zkn_sw_fe384_t r, const zkn_sw_fe384_t a, zkn_sw_limb_t flag)
{
    zkn_sw_limb_t mask = (zkn_sw_limb_t)(0u - flag);
    for (int i = 0; i < N; i++)
        r[i] ^= mask & (r[i] ^ a[i]);
}

void zkn_sw_neg_mod_384(zkn_sw_fe384_t r,
                     const zkn_sw_fe384_t a,
                     const zkn_sw_fe384_t p)
{
    zkn_sw_fe384_t zero = {0};
    zkn_sw_sub_mod_384(r, zero, a, p);
}

void zkn_sw_exp_mont_384(zkn_sw_fe384_t r,
                      const zkn_sw_fe384_t base,
                      const uint8_t *exp_be,
                      int exp_len,
                      const zkn_sw_mont_ctx384_t *ctx)
{
    memcpy(r, ctx->one, sizeof(zkn_sw_fe384_t));
    int started = 0;

    for (int i = 0; i < exp_len; i++) {
        uint8_t byte = exp_be[i];
        for (int bit = 7; bit >= 0; bit--) {
            if (started)
                zkn_sw_sqr_mont_384(r, r, ctx->p, ctx->n0);
            if ((byte >> bit) & 1) {
                if (started)
                    zkn_sw_mul_mont_384(r, r, base, ctx->p, ctx->n0);
                else {
                    memcpy(r, base, sizeof(zkn_sw_fe384_t));
                    started = 1;
                }
            }
        }
    }
}

void zkn_sw_inv_mont_384(zkn_sw_fe384_t r,
                      const zkn_sw_fe384_t a,
                      const zkn_sw_mont_ctx384_t *ctx)
{
    /* Fermat: a^{-1} = a^{p-2} mod p */
    zkn_sw_fe384_t pm2;
    memcpy(pm2, ctx->p, sizeof(zkn_sw_fe384_t));
    /* p - 2 */
    zkn_sw_dlimb_t borrow = 2;
    for (int i = 0; i < N; i++) {
        zkn_sw_dlimb_t d = (zkn_sw_dlimb_t)pm2[i] - (borrow & 0xFFFFFFFF);
        pm2[i] = (zkn_sw_limb_t)d;
        borrow = (d >> 63);
    }

    uint8_t exp_be[ZKN_SW_MONT384_BYTES];
    zkn_sw_fe384_to_be(exp_be, pm2);
    zkn_sw_exp_mont_384(r, a, exp_be, ZKN_SW_MONT384_BYTES, ctx);
}

/* ── BLS12-381 base field convenience ──────────────────────────────── */

static const zkn_sw_fe384_t BLS12_381_P = {
    0xffffaaabu, 0xb9feffffu, 0xb153ffffu, 0x1eabfffeu,
    0xf6b0f624u, 0x6730d2a0u, 0xf38512bfu, 0x64774b84u,
    0x434bacd7u, 0x4b1ba7b6u, 0x397fe69au, 0x1a0111eau
};

const zkn_sw_mont_ctx384_t *zkn_sw_bls12381_ctx(void)
{
    static zkn_sw_mont_ctx384_t ctx;
    static int ready = 0;
    if (!ready) {
        zkn_sw_mont_ctx384_init(&ctx, BLS12_381_P);
        ready = 1;
    }
    return &ctx;
}
