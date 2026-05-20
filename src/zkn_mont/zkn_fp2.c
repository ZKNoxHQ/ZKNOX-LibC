/*
 * zkn_fp2.c — Fp2 = Fp[u] / (u² + 1) arithmetic for BN254
 *
 * All operations are in Montgomery form. The hot path (Fp multiplications)
 * is accelerated by ARM Thumb-2 assembly when ZKN_MONT256_ASM is defined.
 *
 * Aliasing: all functions support r == a or r == b (in-place operation).
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_fp2.h"
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 *  Constructors / comparison
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_zero(zkn_fp2_t *r)
{
    zkn_fe256_zero(r->c0);
    zkn_fe256_zero(r->c1);
}

void zkn_fp2_one(zkn_fp2_t *r, const zkn_mont_ctx256_t *ctx)
{
    memcpy(r->c0, ctx->one, sizeof(zkn_fe256_t));
    zkn_fe256_zero(r->c1);
}

void zkn_fp2_copy(zkn_fp2_t *r, const zkn_fp2_t *a)
{
    memcpy(r, a, sizeof(zkn_fp2_t));
}

int zkn_fp2_eq(const zkn_fp2_t *a, const zkn_fp2_t *b)
{
    return zkn_fe256_eq(a->c0, b->c0) & zkn_fe256_eq(a->c1, b->c1);
}

void zkn_fp2_set(zkn_fp2_t *r,
                 const zkn_fe256_t c0,
                 const zkn_fe256_t c1)
{
    memcpy(r->c0, c0, sizeof(zkn_fe256_t));
    memcpy(r->c1, c1, sizeof(zkn_fe256_t));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Addition / subtraction / negation
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_add(zkn_fp2_t *r, const zkn_fp2_t *a, const zkn_fp2_t *b,
                 const zkn_mont_ctx256_t *ctx)
{
    zkn_add_mod_256(r->c0, a->c0, b->c0, ctx->p);
    zkn_add_mod_256(r->c1, a->c1, b->c1, ctx->p);
}

void zkn_fp2_sub(zkn_fp2_t *r, const zkn_fp2_t *a, const zkn_fp2_t *b,
                 const zkn_mont_ctx256_t *ctx)
{
    zkn_sub_mod_256(r->c0, a->c0, b->c0, ctx->p);
    zkn_sub_mod_256(r->c1, a->c1, b->c1, ctx->p);
}

void zkn_fp2_neg(zkn_fp2_t *r, const zkn_fp2_t *a,
                 const zkn_mont_ctx256_t *ctx)
{
    zkn_neg_mod_256(r->c0, a->c0, ctx->p);
    zkn_neg_mod_256(r->c1, a->c1, ctx->p);
}

void zkn_fp2_conjugate(zkn_fp2_t *r, const zkn_fp2_t *a,
                       const zkn_mont_ctx256_t *ctx)
{
    memcpy(r->c0, a->c0, sizeof(zkn_fe256_t));
    zkn_neg_mod_256(r->c1, a->c1, ctx->p);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Multiplication (Karatsuba, 3 Fp mul)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_mul(zkn_fp2_t *r, const zkn_fp2_t *a, const zkn_fp2_t *b,
                 const zkn_mont_ctx256_t *ctx)
{
    /*
     * (a0 + a1·u)(b0 + b1·u) = (a0·b0 - a1·b1) + ((a0+a1)(b0+b1) - a0·b0 - a1·b1)·u
     *
     * Karatsuba saves one Fp mul vs naive (3 instead of 4).
     */
    zkn_fe256_t v0, v1, s_a, s_b, t;

    zkn_mul_mont_256(v0, a->c0, b->c0, ctx->p, ctx->n0);  /* v0 = a0·b0 */
    zkn_mul_mont_256(v1, a->c1, b->c1, ctx->p, ctx->n0);  /* v1 = a1·b1 */

    zkn_add_mod_256(s_a, a->c0, a->c1, ctx->p);            /* s_a = a0+a1 */
    zkn_add_mod_256(s_b, b->c0, b->c1, ctx->p);            /* s_b = b0+b1 */
    zkn_mul_mont_256(t, s_a, s_b, ctx->p, ctx->n0);        /* t = (a0+a1)(b0+b1) */

    /* c0 = v0 - v1 */
    zkn_sub_mod_256(r->c0, v0, v1, ctx->p);

    /* c1 = t - v0 - v1 */
    zkn_sub_mod_256(t, t, v0, ctx->p);
    zkn_sub_mod_256(r->c1, t, v1, ctx->p);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Squaring (2 Fp mul)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_sqr(zkn_fp2_t *r, const zkn_fp2_t *a,
                 const zkn_mont_ctx256_t *ctx)
{
    /*
     * (a0 + a1·u)² = a0² - a1² + 2·a0·a1·u
     *
     * Optimized:
     *   c0 = (a0 + a1)(a0 - a1)     1 Fp mul
     *   c1 = 2 · a0 · a1            1 Fp mul + 1 Fp add
     */
    zkn_fe256_t sum, diff, prod;

    zkn_add_mod_256(sum, a->c0, a->c1, ctx->p);
    zkn_sub_mod_256(diff, a->c0, a->c1, ctx->p);
    zkn_mul_mont_256(prod, a->c0, a->c1, ctx->p, ctx->n0);

    zkn_mul_mont_256(r->c0, sum, diff, ctx->p, ctx->n0);
    zkn_add_mod_256(r->c1, prod, prod, ctx->p);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Norm and inversion
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_norm(zkn_fe256_t r, const zkn_fp2_t *a,
                  const zkn_mont_ctx256_t *ctx)
{
    /* norm(a0 + a1·u) = a0² + a1²   (since u² = -1) */
    zkn_fe256_t t0, t1;
    zkn_sqr_mont_256(t0, a->c0, ctx->p, ctx->n0);
    zkn_sqr_mont_256(t1, a->c1, ctx->p, ctx->n0);
    zkn_add_mod_256(r, t0, t1, ctx->p);
}

void zkn_fp2_inv(zkn_fp2_t *r, const zkn_fp2_t *a,
                 const zkn_mont_ctx256_t *ctx)
{
    /*
     * (a0 + a1·u)⁻¹ = (a0 - a1·u) / (a0² + a1²)
     *
     * 1. norm = a0² + a1²
     * 2. inv_norm = norm⁻¹  (Fp inversion via Fermat)
     * 3. c0 = a0 · inv_norm
     * 4. c1 = -a1 · inv_norm
     */
    zkn_fe256_t norm, inv_norm, neg_a1;

    zkn_fp2_norm(norm, a, ctx);
    zkn_inv_mont_256(inv_norm, norm, ctx);

    zkn_neg_mod_256(neg_a1, a->c1, ctx->p);

    zkn_mul_mont_256(r->c0, a->c0, inv_norm, ctx->p, ctx->n0);
    zkn_mul_mont_256(r->c1, neg_a1, inv_norm, ctx->p, ctx->n0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Multiply by non-residue ξ = 9 + u (BN254 Fp6 tower)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_mul_by_xi(zkn_fp2_t *r, const zkn_fp2_t *a,
                       const zkn_mont_ctx256_t *ctx)
{
    /*
     * (a0 + a1·u)(9 + u) = (9·a0 - a1) + (a0 + 9·a1)·u
     *
     * 9x via 4 additions: x→2x→4x→8x→9x.  Cheaper than one Fp mul.
     */
    zkn_fe256_t a0x9, a1x9, t, c0, c1;

    /* a0 × 9 */
    zkn_add_mod_256(t, a->c0, a->c0, ctx->p);     /* 2 */
    zkn_add_mod_256(t, t, t, ctx->p);               /* 4 */
    zkn_add_mod_256(t, t, t, ctx->p);               /* 8 */
    zkn_add_mod_256(a0x9, t, a->c0, ctx->p);        /* 9 */

    /* a1 × 9 */
    zkn_add_mod_256(t, a->c1, a->c1, ctx->p);
    zkn_add_mod_256(t, t, t, ctx->p);
    zkn_add_mod_256(t, t, t, ctx->p);
    zkn_add_mod_256(a1x9, t, a->c1, ctx->p);

    /* c0 = 9·a0 - a1,  c1 = a0 + 9·a1 */
    zkn_sub_mod_256(c0, a0x9, a->c1, ctx->p);
    zkn_add_mod_256(c1, a->c0, a1x9, ctx->p);

    memcpy(r->c0, c0, sizeof(zkn_fe256_t));
    memcpy(r->c1, c1, sizeof(zkn_fe256_t));
}
