/*
 * zkn_fp6_384.c — Fp6 = Fp2[v] / (v³ − ξ) arithmetic for BLS12-381
 *
 * Cubic extension of Fp2 where ξ = 1 + u ∈ Fp2 is the non-residue.
 * v³ = ξ is the relation used for reduction.
 *
 * Multiplication uses Karatsuba (6 Fp2 mul, same as Chung-Hasan SQR3).
 * Squaring uses the CH-SQR2 formula (2 Fp2 mul + 3 Fp2 sqr).
 * Inversion uses cofactor method (reduces to Fp2 inversion).
 *
 * Aliasing: all functions support r aliased to any input operand.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_fp6_384.h"
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 *  Constructors / comparison
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp6_384_zero(zkn_fp6_384_t *r)
{
    zkn_fp2_384_zero(&r->c0);
    zkn_fp2_384_zero(&r->c1);
    zkn_fp2_384_zero(&r->c2);
}

void zkn_fp6_384_one(zkn_fp6_384_t *r, const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_one(&r->c0, ctx);
    zkn_fp2_384_zero(&r->c1);
    zkn_fp2_384_zero(&r->c2);
}

void zkn_fp6_384_copy(zkn_fp6_384_t *r, const zkn_fp6_384_t *a)
{
    memcpy(r, a, sizeof(zkn_fp6_384_t));
}

int zkn_fp6_384_eq(const zkn_fp6_384_t *a, const zkn_fp6_384_t *b)
{
    return zkn_fp2_384_eq(&a->c0, &b->c0) &
           zkn_fp2_384_eq(&a->c1, &b->c1) &
           zkn_fp2_384_eq(&a->c2, &b->c2);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Addition / subtraction / negation
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp6_384_add(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_fp6_384_t *b,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_add(&r->c0, &a->c0, &b->c0, ctx);
    zkn_fp2_384_add(&r->c1, &a->c1, &b->c1, ctx);
    zkn_fp2_384_add(&r->c2, &a->c2, &b->c2, ctx);
}

void zkn_fp6_384_sub(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_fp6_384_t *b,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_sub(&r->c0, &a->c0, &b->c0, ctx);
    zkn_fp2_384_sub(&r->c1, &a->c1, &b->c1, ctx);
    zkn_fp2_384_sub(&r->c2, &a->c2, &b->c2, ctx);
}

void zkn_fp6_384_neg(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_neg(&r->c0, &a->c0, ctx);
    zkn_fp2_384_neg(&r->c1, &a->c1, ctx);
    zkn_fp2_384_neg(&r->c2, &a->c2, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Multiplication — Karatsuba (6 Fp2 mul)
 *
 *  a = a0 + a1·v + a2·v²
 *  b = b0 + b1·v + b2·v²
 *  v³ = ξ
 *
 *  v0 = a0·b0,  v1 = a1·b1,  v2 = a2·b2
 *
 *  c0 = v0 + ξ·((a1+a2)(b1+b2) - v1 - v2)
 *  c1 = (a0+a1)(b0+b1) - v0 - v1 + ξ·v2
 *  c2 = (a0+a2)(b0+b2) - v0 - v2 + v1
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp6_384_mul(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_fp6_384_t *b,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t v0, v1, v2;

    /* v0 = a0·b0,  v1 = a1·b1,  v2 = a2·b2 */
    zkn_fp2_384_mul(&v0, &a->c0, &b->c0, ctx);
    zkn_fp2_384_mul(&v1, &a->c1, &b->c1, ctx);
    zkn_fp2_384_mul(&v2, &a->c2, &b->c2, ctx);

    zkn_fp2_384_t t0, t1, s0, s1;

    /* c0 = v0 + ξ·((a1+a2)(b1+b2) - v1 - v2) */
    zkn_fp2_384_add(&t0, &a->c1, &a->c2, ctx);
    zkn_fp2_384_add(&t1, &b->c1, &b->c2, ctx);
    zkn_fp2_384_mul(&s0, &t0, &t1, ctx);
    zkn_fp2_384_sub(&s0, &s0, &v1, ctx);
    zkn_fp2_384_sub(&s0, &s0, &v2, ctx);
    zkn_fp2_384_mul_by_xi(&s0, &s0, ctx);    /* ξ·(...) */
    zkn_fp2_384_add(&s0, &s0, &v0, ctx);     /* + v0 → c0 */

    /* c1 = (a0+a1)(b0+b1) - v0 - v1 + ξ·v2 */
    zkn_fp2_384_add(&t0, &a->c0, &a->c1, ctx);
    zkn_fp2_384_add(&t1, &b->c0, &b->c1, ctx);
    zkn_fp2_384_mul(&s1, &t0, &t1, ctx);
    zkn_fp2_384_sub(&s1, &s1, &v0, ctx);
    zkn_fp2_384_sub(&s1, &s1, &v1, ctx);
    zkn_fp2_384_t xi_v2;
    zkn_fp2_384_mul_by_xi(&xi_v2, &v2, ctx);
    zkn_fp2_384_add(&s1, &s1, &xi_v2, ctx);  /* → c1 */

    /* c2 = (a0+a2)(b0+b2) - v0 - v2 + v1 */
    zkn_fp2_384_add(&t0, &a->c0, &a->c2, ctx);
    zkn_fp2_384_add(&t1, &b->c0, &b->c2, ctx);
    zkn_fp2_384_mul(&r->c2, &t0, &t1, ctx);
    zkn_fp2_384_sub(&r->c2, &r->c2, &v0, ctx);
    zkn_fp2_384_sub(&r->c2, &r->c2, &v2, ctx);
    zkn_fp2_384_add(&r->c2, &r->c2, &v1, ctx);

    /* Commit c0, c1 (after c2 is computed, safe for aliasing) */
    zkn_fp2_384_copy(&r->c0, &s0);
    zkn_fp2_384_copy(&r->c1, &s1);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Squaring — CH-SQR2 (2 Fp2 mul + 3 Fp2 sqr)
 *
 *  s0 = a0²
 *  ab = a0·a1,    s1 = 2·ab
 *  t  = a0-a1+a2, s2 = t²
 *  bc = a1·a2,    s3 = 2·bc
 *  s4 = a2²
 *
 *  c0 = s0 + ξ·s3
 *  c1 = s1 + ξ·s4
 *  c2 = s1 + s2 + s3 - s0 - s4
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp6_384_sqr(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t s0, s1, s2, s3, s4;
    zkn_fp2_384_t ab, bc, t;

    /* s0 = a0² */
    zkn_fp2_384_sqr(&s0, &a->c0, ctx);

    /* ab = a0·a1,  s1 = 2·ab */
    zkn_fp2_384_mul(&ab, &a->c0, &a->c1, ctx);
    zkn_fp2_384_add(&s1, &ab, &ab, ctx);

    /* s2 = (a0 - a1 + a2)² */
    zkn_fp2_384_sub(&t, &a->c0, &a->c1, ctx);
    zkn_fp2_384_add(&t, &t, &a->c2, ctx);
    zkn_fp2_384_sqr(&s2, &t, ctx);

    /* bc = a1·a2,  s3 = 2·bc */
    zkn_fp2_384_mul(&bc, &a->c1, &a->c2, ctx);
    zkn_fp2_384_add(&s3, &bc, &bc, ctx);

    /* s4 = a2² */
    zkn_fp2_384_sqr(&s4, &a->c2, ctx);

    /* c0 = s0 + ξ·s3 */
    zkn_fp2_384_t xi_s3;
    zkn_fp2_384_mul_by_xi(&xi_s3, &s3, ctx);
    zkn_fp2_384_add(&r->c0, &s0, &xi_s3, ctx);

    /* c1 = s1 + ξ·s4 */
    zkn_fp2_384_t xi_s4;
    zkn_fp2_384_mul_by_xi(&xi_s4, &s4, ctx);
    zkn_fp2_384_add(&r->c1, &s1, &xi_s4, ctx);

    /* c2 = s1 + s2 + s3 - s0 - s4 */
    zkn_fp2_384_add(&r->c2, &s1, &s2, ctx);
    zkn_fp2_384_add(&r->c2, &r->c2, &s3, ctx);
    zkn_fp2_384_sub(&r->c2, &r->c2, &s0, ctx);
    zkn_fp2_384_sub(&r->c2, &r->c2, &s4, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Sparse mul by (b0 + b1·v + 0·v²) — for Miller loop
 *
 *  Direct expansion with b2 = 0:
 *    c0 = a0·b0 + ξ·a2·b1
 *    c1 = a1·b0 + a0·b1     ← Karatsuba: (a0+a1)(b0+b1) - a0b0 - a1b1
 *    c2 = a2·b0 + a1·b1
 *
 *  Using Karatsuba for c1:
 *    v0 = a0·b0               1 mul
 *    v1 = a1·b1               1 mul
 *    c0 = v0 + ξ·(a2·b1)     1 mul + 1 mul_by_xi
 *    c1 = (a0+a1)(b0+b1) - v0 - v1    1 mul
 *    c2 = a2·b0 + v1          1 mul
 *  Total: 5 Fp2 mul + 1 mul_by_xi
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp6_384_mul_by_01(zkn_fp6_384_t *r,
                           const zkn_fp6_384_t *a,
                           const zkn_fp2_384_t *b0,
                           const zkn_fp2_384_t *b1,
                           const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t v0, v1;

    /* v0 = a0·b0 */
    zkn_fp2_384_mul(&v0, &a->c0, b0, ctx);

    /* v1 = a1·b1 */
    zkn_fp2_384_mul(&v1, &a->c1, b1, ctx);

    /* c0 = v0 + ξ·(a2·b1) */
    zkn_fp2_384_t t;
    zkn_fp2_384_mul(&t, &a->c2, b1, ctx);
    zkn_fp2_384_mul_by_xi(&t, &t, ctx);
    zkn_fp2_384_t c0;
    zkn_fp2_384_add(&c0, &v0, &t, ctx);

    /* c1 = (a0+a1)(b0+b1) - v0 - v1 */
    zkn_fp2_384_t sa, sb;
    zkn_fp2_384_add(&sa, &a->c0, &a->c1, ctx);
    zkn_fp2_384_add(&sb, b0, b1, ctx);
    zkn_fp2_384_t c1;
    zkn_fp2_384_mul(&c1, &sa, &sb, ctx);
    zkn_fp2_384_sub(&c1, &c1, &v0, ctx);
    zkn_fp2_384_sub(&c1, &c1, &v1, ctx);

    /* c2 = a2·b0 + v1 */
    zkn_fp2_384_mul(&r->c2, &a->c2, b0, ctx);
    zkn_fp2_384_add(&r->c2, &r->c2, &v1, ctx);

    zkn_fp2_384_copy(&r->c0, &c0);
    zkn_fp2_384_copy(&r->c1, &c1);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Sparse mul by (0 + b1·v + 0·v²)
 *
 *  c0 = ξ·a2·b1
 *  c1 = a0·b1
 *  c2 = a1·b1
 *
 *  Total: 3 Fp2 mul + 1 mul_by_xi
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp6_384_mul_by_1(zkn_fp6_384_t *r,
                          const zkn_fp6_384_t *a,
                          const zkn_fp2_384_t *b1,
                          const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t c0, c1;

    /* c0 = ξ·a2·b1 */
    zkn_fp2_384_mul(&c0, &a->c2, b1, ctx);
    zkn_fp2_384_mul_by_xi(&c0, &c0, ctx);

    /* c1 = a0·b1 */
    zkn_fp2_384_mul(&c1, &a->c0, b1, ctx);

    /* c2 = a1·b1 */
    zkn_fp2_384_mul(&r->c2, &a->c1, b1, ctx);

    zkn_fp2_384_copy(&r->c0, &c0);
    zkn_fp2_384_copy(&r->c1, &c1);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Multiply by v (shift components)
 *
 *  (c0 + c1·v + c2·v²) · v = c0·v + c1·v² + c2·v³
 *                           = ξ·c2 + c0·v + c1·v²
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp6_384_mul_by_v(zkn_fp6_384_t *r,
                          const zkn_fp6_384_t *a,
                          const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t new_c0;
    zkn_fp2_384_mul_by_xi(&new_c0, &a->c2, ctx);

    zkn_fp2_384_copy(&r->c2, &a->c1);
    zkn_fp2_384_copy(&r->c1, &a->c0);
    zkn_fp2_384_copy(&r->c0, &new_c0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Scale by Fp2 element
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp6_384_mul_by_fp2(zkn_fp6_384_t *r,
                            const zkn_fp6_384_t *a,
                            const zkn_fp2_384_t *s,
                            const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_mul(&r->c0, &a->c0, s, ctx);
    zkn_fp2_384_mul(&r->c1, &a->c1, s, ctx);
    zkn_fp2_384_mul(&r->c2, &a->c2, s, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Inversion via cofactor reduction to Fp2
 *
 *  Given a = c0 + c1·v + c2·v²,  compute a⁻¹:
 *
 *  Step 1 — Cofactors (in Fp2):
 *    A = c0² − ξ·c1·c2
 *    B = ξ·c2² − c0·c1
 *    C = c1² − c0·c2
 *
 *  Step 2 — Norm (Fp2 element):
 *    N = c0·A + ξ·(c2·B + c1·C)
 *
 *  Step 3 — Scale cofactors by N⁻¹:
 *    a⁻¹ = (A/N) + (B/N)·v + (C/N)·v²
 *
 *  Cost: 3 Fp2 sqr + 9 Fp2 mul + 3 mul_by_xi + 1 Fp2 inv + add/sub.
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp6_384_inv(zkn_fp6_384_t *r,
                     const zkn_fp6_384_t *a,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t t0, t1, t2, t3, t4, t5;

    /* Squared terms */
    zkn_fp2_384_sqr(&t0, &a->c0, ctx);   /* t0 = c0² */
    zkn_fp2_384_sqr(&t1, &a->c1, ctx);   /* t1 = c1² */
    zkn_fp2_384_sqr(&t2, &a->c2, ctx);   /* t2 = c2² */

    /* Cross products */
    zkn_fp2_384_mul(&t3, &a->c0, &a->c1, ctx);   /* t3 = c0·c1 */
    zkn_fp2_384_mul(&t4, &a->c0, &a->c2, ctx);   /* t4 = c0·c2 */
    zkn_fp2_384_mul(&t5, &a->c1, &a->c2, ctx);   /* t5 = c1·c2 */

    /* Cofactors */
    zkn_fp2_384_t cof_a, cof_b, cof_c;

    /* A = c0² − ξ·(c1·c2) = t0 − ξ·t5 */
    zkn_fp2_384_mul_by_xi(&cof_a, &t5, ctx);
    zkn_fp2_384_sub(&cof_a, &t0, &cof_a, ctx);

    /* B = ξ·c2² − c0·c1 = ξ·t2 − t3 */
    zkn_fp2_384_mul_by_xi(&cof_b, &t2, ctx);
    zkn_fp2_384_sub(&cof_b, &cof_b, &t3, ctx);

    /* C = c1² − c0·c2 = t1 − t4 */
    zkn_fp2_384_sub(&cof_c, &t1, &t4, ctx);

    /* Norm = c0·A + ξ·(c2·B + c1·C) */
    zkn_fp2_384_t norm, s1, s2;
    zkn_fp2_384_mul(&norm, &a->c0, &cof_a, ctx);
    zkn_fp2_384_mul(&s1, &a->c2, &cof_b, ctx);
    zkn_fp2_384_mul(&s2, &a->c1, &cof_c, ctx);
    zkn_fp2_384_add(&s1, &s1, &s2, ctx);
    zkn_fp2_384_mul_by_xi(&s1, &s1, ctx);
    zkn_fp2_384_add(&norm, &norm, &s1, ctx);

    /* Invert norm in Fp2 */
    zkn_fp2_384_t inv_norm;
    zkn_fp2_384_inv(&inv_norm, &norm, ctx);

    /* Result: cofactors scaled by inv_norm */
    zkn_fp2_384_mul(&r->c0, &cof_a, &inv_norm, ctx);
    zkn_fp2_384_mul(&r->c1, &cof_b, &inv_norm, ctx);
    zkn_fp2_384_mul(&r->c2, &cof_c, &inv_norm, ctx);
}
