/*
 * zkn_fp4_384.c — Fp4 = Fp2[y] / (y² − ξ) arithmetic for BLS12-381
 *
 * Non-residue: ξ = 1 + u  (BLS12-381 Fp6 tower non-residue)
 * Multiplication by ξ is therefore a zkn_fp2_384_mul_by_xi call.
 *
 * Aliasing: all functions support r == a or r == b (temporaries used).
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_fp4_384.h"
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 *  Constructors
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp4_384_zero(zkn_fp4_384_t *r)
{
    zkn_fp2_384_zero(&r->c0);
    zkn_fp2_384_zero(&r->c1);
}

void zkn_fp4_384_copy(zkn_fp4_384_t *r, const zkn_fp4_384_t *a)
{
    memcpy(r, a, sizeof(zkn_fp4_384_t));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Addition / subtraction
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp4_384_add(zkn_fp4_384_t *r,
                     const zkn_fp4_384_t *a, const zkn_fp4_384_t *b,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_add(&r->c0, &a->c0, &b->c0, ctx);
    zkn_fp2_384_add(&r->c1, &a->c1, &b->c1, ctx);
}

void zkn_fp4_384_sub(zkn_fp4_384_t *r,
                     const zkn_fp4_384_t *a, const zkn_fp4_384_t *b,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_sub(&r->c0, &a->c0, &b->c0, ctx);
    zkn_fp2_384_sub(&r->c1, &a->c1, &b->c1, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Multiplication (Karatsuba, 3 Fp2 mul)
 *
 *  Let a = a0 + a1·y,  b = b0 + b1·y
 *  v0 = a0·b0
 *  v1 = a1·b1
 *  r0 = v0 + ξ·v1
 *  r1 = (a0+a1)(b0+b1) − v0 − v1
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp4_384_mul(zkn_fp4_384_t *r,
                     const zkn_fp4_384_t *a, const zkn_fp4_384_t *b,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t v0, v1, sa, sb, t, xi_v1;

    /* v0 = a0·b0,  v1 = a1·b1 */
    zkn_fp2_384_mul(&v0, &a->c0, &b->c0, ctx);
    zkn_fp2_384_mul(&v1, &a->c1, &b->c1, ctx);

    /* t = (a0+a1)·(b0+b1) */
    zkn_fp2_384_add(&sa, &a->c0, &a->c1, ctx);
    zkn_fp2_384_add(&sb, &b->c0, &b->c1, ctx);
    zkn_fp2_384_mul(&t, &sa, &sb, ctx);

    /* r1 = t − v0 − v1 */
    zkn_fp2_384_sub(&r->c1, &t,    &v0, ctx);
    zkn_fp2_384_sub(&r->c1, &r->c1, &v1, ctx);

    /* r0 = v0 + ξ·v1  (ξ = 1+u) */
    zkn_fp2_384_mul_by_xi(&xi_v1, &v1, ctx);
    zkn_fp2_384_add(&r->c0, &v0, &xi_v1, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Squaring (2 Fp2 sqr + 1 mul_by_xi + 3 Fp2 add/sub)
 *
 *  Let a = c0 + c1·y
 *  t0 = c0²
 *  t1 = c1²
 *  r0 = t0 + ξ·t1
 *  r1 = (c0+c1)² − t0 − t1  =  2·c0·c1
 *
 *  Saves 1 Fp2_mul vs generic multiplication.
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp4_384_sqr(zkn_fp4_384_t *r, const zkn_fp4_384_t *a,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t t0, t1, t2, xi_t1;

    /* t0 = c0²,  t1 = c1² */
    zkn_fp2_384_sqr(&t0, &a->c0, ctx);
    zkn_fp2_384_sqr(&t1, &a->c1, ctx);

    /* t2 = (c0+c1)²  →  r1 = t2 − t0 − t1  =  2·c0·c1 */
    zkn_fp2_384_add(&t2, &a->c0, &a->c1, ctx);
    zkn_fp2_384_sqr(&t2, &t2, ctx);
    zkn_fp2_384_sub(&r->c1, &t2, &t0, ctx);
    zkn_fp2_384_sub(&r->c1, &r->c1, &t1, ctx);

    /* r0 = t0 + ξ·t1  (ξ = 1+u) */
    zkn_fp2_384_mul_by_xi(&xi_t1, &t1, ctx);
    zkn_fp2_384_add(&r->c0, &t0, &xi_t1, ctx);
}
