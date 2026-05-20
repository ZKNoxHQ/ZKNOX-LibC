/*
 * zkn_fp4_384.h — Fp4 = Fp2[y] / (y² − ξ) arithmetic for BLS12-381
 *
 * Quadratic extension of Fp2 using the irreducible polynomial y² − ξ,
 * where ξ = 1 + u is the BLS12-381 Fp6 non-residue.
 *
 * Elements: c0 + c1·y  (c0, c1 ∈ Fp2, Montgomery form)
 *
 * This layer is NOT part of the standard BLS12-381 tower (Fp→Fp2→Fp6→Fp12)
 * but is introduced as an intermediate to implement efficient cyclotomic
 * squaring in Fp12, following the Granger–Scott approach.
 *
 * Fp12 cyclotomic element reorganised as 3 Fp4 pairs:
 *   pair 0: (a[0][0], a[1][1])
 *   pair 1: (a[1][0], a[0][2])
 *   pair 2: (a[0][1], a[1][2])
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_FP4_384_H
#define ZKN_FP4_384_H

#include "zkn_fp2_384.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Type ──────────────────────────────────────────────────────────── */

/**
 * Element of Fp4 = Fp2[y] / (y² − ξ).
 * Stored as (c0, c1) representing c0 + c1·y.
 */
typedef struct {
    zkn_fp2_384_t c0;
    zkn_fp2_384_t c1;
} zkn_fp4_384_t;

/* ── Constructors ──────────────────────────────────────────────────── */

void zkn_fp4_384_zero(zkn_fp4_384_t *r);
void zkn_fp4_384_copy(zkn_fp4_384_t *r, const zkn_fp4_384_t *a);

/* ── Arithmetic ────────────────────────────────────────────────────── */

void zkn_fp4_384_add(zkn_fp4_384_t *r,
                     const zkn_fp4_384_t *a, const zkn_fp4_384_t *b,
                     const zkn_mont_ctx384_t *ctx);

void zkn_fp4_384_sub(zkn_fp4_384_t *r,
                     const zkn_fp4_384_t *a, const zkn_fp4_384_t *b,
                     const zkn_mont_ctx384_t *ctx);

/**
 * Multiplication (Karatsuba): 3 Fp2_mul + 4 Fp2_add/sub.
 * (c0 + c1·y)(d0 + d1·y) = (c0·d0 + ξ·c1·d1) + ((c0+c1)(d0+d1) − c0·d0 − c1·d1)·y
 */
void zkn_fp4_384_mul(zkn_fp4_384_t *r,
                     const zkn_fp4_384_t *a, const zkn_fp4_384_t *b,
                     const zkn_mont_ctx384_t *ctx);

/**
 * Squaring: 2 Fp2_sqr + 1 Fp2_mul_by_xi + 3 Fp2_add/sub.
 * (c0 + c1·y)² = (c0² + ξ·c1²) + ((c0+c1)² − c0² − c1²)·y
 *              = (c0² + ξ·c1²) + 2·c0·c1·y
 *
 * This is the key primitive for cyclotomic squaring in Fp12.
 */
void zkn_fp4_384_sqr(zkn_fp4_384_t *r, const zkn_fp4_384_t *a,
                     const zkn_mont_ctx384_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_FP4_384_H */
