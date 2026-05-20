/*
 * zkn_fp2.h — Fp2 = Fp[u] / (u² + 1) arithmetic for BN254
 *
 * Quadratic extension of Fp using the irreducible polynomial u² + 1.
 * All elements are pairs (c0 + c1·u) stored in Montgomery form.
 *
 * Used as the base of the tower Fp → Fp2 → Fp6 → Fp12 for BN254 pairings.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_FP2_H
#define ZKN_FP2_H

#include "zkn_mont256.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Types ─────────────────────────────────────────────────────────── */

/**
 * Element of Fp2 = Fp[u] / (u² + 1).
 * Stored as (c0, c1) representing c0 + c1·u.
 * Both components are in Montgomery form.
 */
typedef struct {
    zkn_fe256_t c0;   /* real part       */
    zkn_fe256_t c1;   /* coefficient of u */
} zkn_fp2_t;

/* ── Constructors / comparison ─────────────────────────────────────── */

void zkn_fp2_zero(zkn_fp2_t *r);
void zkn_fp2_one(zkn_fp2_t *r, const zkn_mont_ctx256_t *ctx);
void zkn_fp2_copy(zkn_fp2_t *r, const zkn_fp2_t *a);
int  zkn_fp2_eq(const zkn_fp2_t *a, const zkn_fp2_t *b);

/** Set from two Fp elements (already in Montgomery form). */
void zkn_fp2_set(zkn_fp2_t *r,
                 const zkn_fe256_t c0,
                 const zkn_fe256_t c1);

/* ── Arithmetic ────────────────────────────────────────────────────── */

void zkn_fp2_add(zkn_fp2_t *r, const zkn_fp2_t *a, const zkn_fp2_t *b,
                 const zkn_mont_ctx256_t *ctx);

void zkn_fp2_sub(zkn_fp2_t *r, const zkn_fp2_t *a, const zkn_fp2_t *b,
                 const zkn_mont_ctx256_t *ctx);

void zkn_fp2_neg(zkn_fp2_t *r, const zkn_fp2_t *a,
                 const zkn_mont_ctx256_t *ctx);

/** Conjugate: (a0, a1) → (a0, -a1). */
void zkn_fp2_conjugate(zkn_fp2_t *r, const zkn_fp2_t *a,
                       const zkn_mont_ctx256_t *ctx);

/**
 * Multiplication using Karatsuba: 3 Fp mul + 2 Fp add + 2 Fp sub.
 * (a0+a1·u)(b0+b1·u) = (a0·b0 - a1·b1) + ((a0+a1)(b0+b1) - a0·b0 - a1·b1)·u
 */
void zkn_fp2_mul(zkn_fp2_t *r, const zkn_fp2_t *a, const zkn_fp2_t *b,
                 const zkn_mont_ctx256_t *ctx);

/**
 * Squaring: 2 Fp mul + 2 Fp add/sub.
 * (a0+a1·u)² = (a0+a1)(a0-a1) + 2·a0·a1·u
 */
void zkn_fp2_sqr(zkn_fp2_t *r, const zkn_fp2_t *a,
                 const zkn_mont_ctx256_t *ctx);

/**
 * Inversion: a^{-1} = conj(a) / norm(a), where norm = a0² + a1².
 * Cost: 1 Fp inv + 2 Fp sqr + 1 Fp add + 2 Fp mul + 1 Fp neg.
 */
void zkn_fp2_inv(zkn_fp2_t *r, const zkn_fp2_t *a,
                 const zkn_mont_ctx256_t *ctx);

/**
 * Multiply by the Fp6 non-residue ξ = 9 + u (BN254-specific).
 * (a0+a1·u)(9+u) = (9·a0 - a1) + (a0 + 9·a1)·u
 * Cost: 8 Fp add + 1 Fp sub (no Fp mul).
 */
void zkn_fp2_mul_by_xi(zkn_fp2_t *r, const zkn_fp2_t *a,
                       const zkn_mont_ctx256_t *ctx);

/**
 * Norm: returns a0² + a1² as an Fp element.
 * Used internally for inversion; exposed for testing.
 */
void zkn_fp2_norm(zkn_fe256_t r, const zkn_fp2_t *a,
                  const zkn_mont_ctx256_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_FP2_H */
