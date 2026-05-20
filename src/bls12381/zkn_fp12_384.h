/*
 * zkn_fp12_384.h — Fp12 = Fp6[w] / (w² − v) arithmetic for BLS12-381
 *
 * Quadratic extension of Fp6 with w² = v (the Fp6 indeterminate).
 * Elements are pairs (c0 + c1·w) stored in Montgomery form.
 *
 * Tower: Fp → Fp2 → Fp6 = Fp2[v]/(v³−ξ) → Fp12 = Fp6[w]/(w²−v)
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_FP12_384_H
#define ZKN_FP12_384_H

#include "zkn_fp6_384.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Types ─────────────────────────────────────────────────────────── */

typedef struct {
    zkn_fp6_384_t c0;   /* constant coefficient   */
    zkn_fp6_384_t c1;   /* coefficient of w       */
} zkn_fp12_384_t;

/* ── Constructors / comparison ─────────────────────────────────────── */

void zkn_fp12_384_zero(zkn_fp12_384_t *r);
void zkn_fp12_384_one(zkn_fp12_384_t *r, const zkn_mont_ctx384_t *ctx);
void zkn_fp12_384_copy(zkn_fp12_384_t *r, const zkn_fp12_384_t *a);
int  zkn_fp12_384_eq(const zkn_fp12_384_t *a, const zkn_fp12_384_t *b);

/* ── Addition / subtraction / negation ─────────────────────────────── */

void zkn_fp12_384_add(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_fp12_384_t *b,
                      const zkn_mont_ctx384_t *ctx);

void zkn_fp12_384_sub(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_fp12_384_t *b,
                      const zkn_mont_ctx384_t *ctx);

void zkn_fp12_384_neg(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_mont_ctx384_t *ctx);

/* ── Conjugation (w ↦ −w) ─────────────────────────────────────────── */

/**
 * conj(c0 + c1·w) = c0 − c1·w.
 * For elements in the cyclotomic subgroup, conj(a) = a^{−1}.
 * Used in final exponentiation easy part: f^{p^6−1} = conj(f) · f^{−1}.
 */
void zkn_fp12_384_conjugate(zkn_fp12_384_t *r,
                            const zkn_fp12_384_t *a,
                            const zkn_mont_ctx384_t *ctx);

/* ── Multiplication ────────────────────────────────────────────────── */

/**
 * Full multiplication (Karatsuba): 3 Fp6 mul + 1 mul_by_v.
 */
void zkn_fp12_384_mul(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_fp12_384_t *b,
                      const zkn_mont_ctx384_t *ctx);

/**
 * Squaring: 3 Fp6 sqr + 1 mul_by_v.
 * Uses Karatsuba variant: cheaper than mul since Fp6 sqr < Fp6 mul.
 */
void zkn_fp12_384_sqr(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_mont_ctx384_t *ctx);

/**
 * Sparse multiplication by a Miller loop line evaluation.
 *
 * The line function produces Fp12 elements with non-zero Fp2 coefficients
 * only at positions 0, 1, 4 (in the 6-Fp2 decomposition of Fp12):
 *
 *   b = (b0 + b1·v + 0·v², 0 + b4·v + 0·v²) in Fp6×Fp6
 *     i.e.  b.c0 = (b0, b1, 0)   [sparse Fp6]
 *           b.c1 = (0,  b4, 0)   [sparse Fp6]
 *
 * Cost: 2 × Fp6 mul_by_01 + 1 × Fp6 mul_by_1 + 1 × mul_by_v + adds.
 */
void zkn_fp12_384_mul_by_014(zkn_fp12_384_t *r,
                             const zkn_fp12_384_t *a,
                             const zkn_fp2_384_t *b0,
                             const zkn_fp2_384_t *b1,
                             const zkn_fp2_384_t *b4,
                             const zkn_mont_ctx384_t *ctx);

/* ── Inversion ─────────────────────────────────────────────────────── */

/**
 * Inversion via conjugate/norm reduction to Fp6.
 *   norm = c0² − v·c1²   (Fp6 element)
 *   a^{−1} = conj(a) / norm
 * Cost: 2 Fp6 sqr + 1 Fp6 mul_by_v + 1 Fp6 sub + 1 Fp6 inv + 2 Fp6 mul.
 */
void zkn_fp12_384_inv(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_mont_ctx384_t *ctx);

/**
 * Unitary inverse: for elements in the cyclotomic subgroup (norm = 1),
 * a^{−1} = conj(a). Just an alias for conjugate.
 */
void zkn_fp12_384_unitary_inv(zkn_fp12_384_t *r,
                              const zkn_fp12_384_t *a,
                              const zkn_mont_ctx384_t *ctx);

/* ── Frobenius map ─────────────────────────────────────────────────── */

/**
 * Frobenius endomorphism φ_{p^k} on Fp12.
 *
 * Acts on the 6-Fp2 decomposition {1, v, v², w, vw, v²w}:
 *   - Conjugate each Fp2 component (if k is odd)
 *   - Multiply position j by γ_j = ξ^{j·(p^k−1)/6}
 *
 * Frobenius constants are computed once at first call (lazy init).
 *
 * @param r     Output element
 * @param a     Input element
 * @param power Frobenius power k (1, 2, or 3)
 * @param ctx   Montgomery context for BLS12-381 Fp
 */
void zkn_fp12_384_frobenius_map(zkn_fp12_384_t *r,
                                const zkn_fp12_384_t *a,
                                int power,
                                const zkn_mont_ctx384_t *ctx);

/* ── Cyclotomic squaring ───────────────────────────────────────────── */

/**
 * Optimized squaring for elements in the cyclotomic subgroup GΦ₆(Fp12).
 *
 * An element f is cyclotomic iff f · conj(f) = 1, which holds for any
 * element f^{p^6−1}·f^{p^2−1} (i.e. after the easy part of final exp).
 *
 * Uses the Granger–Scott 2010 decomposition into 3 Fp4 "lines":
 *   Pairs: (c0.c0, c1.c1), (c0.c1, c1.c2), (c0.c2, c1.c0)
 *   Each Fp4 squaring: 3 Fp2 sqr + 1 mul_by_xi + adds.
 *   Total: 9 Fp2 sqr + 3 mul_by_xi  (~30% cheaper than generic sqr).
 *
 * Called ~65 times in raise_to_z during final exponentiation.
 *
 * @param r   Output element (may alias a)
 * @param a   Input cyclotomic element
 * @param ctx Montgomery context
 */
void zkn_fp12_384_cyclotomic_sqr(zkn_fp12_384_t *r,
                                 const zkn_fp12_384_t *a,
                                 const zkn_mont_ctx384_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_FP12_384_H */
