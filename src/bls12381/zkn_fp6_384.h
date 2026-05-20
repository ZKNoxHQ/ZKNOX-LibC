/*
 * zkn_fp6_384.h — Fp6 = Fp2[v] / (v³ − ξ) arithmetic for BLS12-381
 *
 * Cubic extension of Fp2 with ξ = 1 + u (the Fp2 non-residue).
 * Elements are triples (c0 + c1·v + c2·v²) stored in Montgomery form.
 *
 * Tower: Fp → Fp2 = Fp[u]/(u²+1) → Fp6 = Fp2[v]/(v³ − ξ)
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_FP6_384_H
#define ZKN_FP6_384_H

#include "zkn_fp2_384.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Types ─────────────────────────────────────────────────────────── */

typedef struct {
    zkn_fp2_384_t c0;   /* constant coefficient   */
    zkn_fp2_384_t c1;   /* coefficient of v       */
    zkn_fp2_384_t c2;   /* coefficient of v²      */
} zkn_fp6_384_t;

/* ── Constructors / comparison ─────────────────────────────────────── */

void zkn_fp6_384_zero(zkn_fp6_384_t *r);
void zkn_fp6_384_one(zkn_fp6_384_t *r, const zkn_mont_ctx384_t *ctx);
void zkn_fp6_384_copy(zkn_fp6_384_t *r, const zkn_fp6_384_t *a);
int  zkn_fp6_384_eq(const zkn_fp6_384_t *a, const zkn_fp6_384_t *b);

/* ── Addition / subtraction / negation ─────────────────────────────── */

void zkn_fp6_384_add(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_fp6_384_t *b,
                     const zkn_mont_ctx384_t *ctx);

void zkn_fp6_384_sub(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_fp6_384_t *b,
                     const zkn_mont_ctx384_t *ctx);

void zkn_fp6_384_neg(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_mont_ctx384_t *ctx);

/* ── Multiplication ────────────────────────────────────────────────── */

/**
 * Full multiplication (Karatsuba): 6 Fp2 mul + 2 mul_by_xi + ~9 Fp2 add/sub.
 */
void zkn_fp6_384_mul(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_fp6_384_t *b,
                     const zkn_mont_ctx384_t *ctx);

/**
 * Squaring: 2 Fp2 mul + 3 Fp2 sqr + 2 mul_by_xi + ~8 Fp2 add/sub.
 */
void zkn_fp6_384_sqr(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_mont_ctx384_t *ctx);

/**
 * Sparse mul by (b0 + b1·v + 0·v²).
 * Used in Miller loop line evaluations.
 * Cost: 5 Fp2 mul + 1 mul_by_xi + ~4 Fp2 add/sub.
 */
void zkn_fp6_384_mul_by_01(zkn_fp6_384_t *r,
                           const zkn_fp6_384_t *a,
                           const zkn_fp2_384_t *b0,
                           const zkn_fp2_384_t *b1,
                           const zkn_mont_ctx384_t *ctx);

/**
 * Sparse mul by (0 + b1·v + 0·v²).
 * Cost: 3 Fp2 mul + 1 mul_by_xi + ~0 Fp2 add/sub.
 */
void zkn_fp6_384_mul_by_1(zkn_fp6_384_t *r,
                          const zkn_fp6_384_t *a,
                          const zkn_fp2_384_t *b1,
                          const zkn_mont_ctx384_t *ctx);

/**
 * Multiply by non-residue: r = a · v  (shift components).
 * (c0 + c1·v + c2·v²) · v = ξ·c2 + c0·v + c1·v²
 */
void zkn_fp6_384_mul_by_v(zkn_fp6_384_t *r,
                          const zkn_fp6_384_t *a,
                          const zkn_mont_ctx384_t *ctx);

/**
 * Scale all components by an Fp2 element.
 */
void zkn_fp6_384_mul_by_fp2(zkn_fp6_384_t *r,
                            const zkn_fp6_384_t *a,
                            const zkn_fp2_384_t *s,
                            const zkn_mont_ctx384_t *ctx);

/* ── Inversion ─────────────────────────────────────────────────────── */

/**
 * Inversion via cofactor / norm reduction to Fp2.
 * Cost: 3 Fp2 sqr + 9 Fp2 mul + 3 mul_by_xi + 1 Fp2 inv.
 */
void zkn_fp6_384_inv(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_mont_ctx384_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_FP6_384_H */
