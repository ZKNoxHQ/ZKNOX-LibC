/*
 * zkn_fp2_384.h — Fp2 = Fp[u] / (u² + 1) arithmetic for BLS12-381
 *
 * Quadratic extension of Fp using the irreducible polynomial u² + 1.
 * All elements are pairs (c0 + c1·u) stored in Montgomery form.
 *
 * Used as the base of the tower Fp → Fp2 → Fp6 → Fp12 for BLS12-381 pairings.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_FP2_384_H
#define ZKN_FP2_384_H

#include "zkn_mont384.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Types ─────────────────────────────────────────────────────────── */

typedef struct {
    zkn_fe384_t c0;
    zkn_fe384_t c1;
} zkn_fp2_384_t;

/* ── Constructors / comparison ─────────────────────────────────────── */

void zkn_fp2_384_zero(zkn_fp2_384_t *r);
void zkn_fp2_384_one(zkn_fp2_384_t *r, const zkn_mont_ctx384_t *ctx);
void zkn_fp2_384_copy(zkn_fp2_384_t *r, const zkn_fp2_384_t *a);
int  zkn_fp2_384_eq(const zkn_fp2_384_t *a, const zkn_fp2_384_t *b);

void zkn_fp2_384_set(zkn_fp2_384_t *r,
                     const zkn_fe384_t c0,
                     const zkn_fe384_t c1);

/* ── Arithmetic ────────────────────────────────────────────────────── */

void zkn_fp2_384_add(zkn_fp2_384_t *r, const zkn_fp2_384_t *a, const zkn_fp2_384_t *b,
                     const zkn_mont_ctx384_t *ctx);

void zkn_fp2_384_sub(zkn_fp2_384_t *r, const zkn_fp2_384_t *a, const zkn_fp2_384_t *b,
                     const zkn_mont_ctx384_t *ctx);

void zkn_fp2_384_neg(zkn_fp2_384_t *r, const zkn_fp2_384_t *a,
                     const zkn_mont_ctx384_t *ctx);

void zkn_fp2_384_conjugate(zkn_fp2_384_t *r, const zkn_fp2_384_t *a,
                           const zkn_mont_ctx384_t *ctx);

/**
 * Karatsuba multiplication: 3 Fp mul + 2 Fp add + 2 Fp sub.
 */
void zkn_fp2_384_mul(zkn_fp2_384_t *r, const zkn_fp2_384_t *a, const zkn_fp2_384_t *b,
                     const zkn_mont_ctx384_t *ctx);

/**
 * Squaring: 2 Fp mul + 2 Fp add/sub.
 */
void zkn_fp2_384_sqr(zkn_fp2_384_t *r, const zkn_fp2_384_t *a,
                     const zkn_mont_ctx384_t *ctx);

/**
 * Inversion: a^{-1} = conj(a) / norm(a).
 */
void zkn_fp2_384_inv(zkn_fp2_384_t *r, const zkn_fp2_384_t *a,
                     const zkn_mont_ctx384_t *ctx);

/**
 * Multiply by the Fp6 non-residue ξ = 1 + u (BLS12-381-specific).
 * (a0+a1·u)(1+u) = (a0 - a1) + (a0 + a1)·u
 * Cost: 1 Fp add + 1 Fp sub.
 */
void zkn_fp2_384_mul_by_xi(zkn_fp2_384_t *r, const zkn_fp2_384_t *a,
                           const zkn_mont_ctx384_t *ctx);

/**
 * Multiply Fp2 element by an Fp scalar: r = (a0·s, a1·s).
 * s is a 384-bit Montgomery field element.
 * Cost: 2 Fp mul.
 *
 * Used by Miller loop line functions to inject G1 affine coordinates
 * (xP, yP ∈ Fp) into line coefficients (∈ Fp2).
 */
void zkn_fp2_384_mul_by_fp(zkn_fp2_384_t *r,
                           const zkn_fp2_384_t *a,
                           const zkn_fe384_t s,
                           const zkn_mont_ctx384_t *ctx);

/**
 * Norm: a0² + a1² (Fp element).
 */
void zkn_fp2_384_norm(zkn_fe384_t r, const zkn_fp2_384_t *a,
                      const zkn_mont_ctx384_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_FP2_384_H */
