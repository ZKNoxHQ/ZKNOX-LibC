/*
 * zkn_fp2_384.c — Fp2 = Fp[u] / (u² + 1) arithmetic for BLS12-381
 *
 * All operations are in Montgomery form. Same algorithms as zkn_fp2.c
 * (BN254 version) but over 384-bit field elements.
 *
 * Key difference from BN254: the Fp6 non-residue is ξ = 1+u (not 9+u),
 * making mul_by_xi much cheaper (1 add + 1 sub vs 8 add + 1 sub).
 *
 * Aliasing: all functions support r == a or r == b (in-place operation).
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_fp2_384.h"
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 *  Constructors / comparison
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_384_zero(zkn_fp2_384_t *r)
{
    zkn_fe384_zero(r->c0);
    zkn_fe384_zero(r->c1);
}

void zkn_fp2_384_one(zkn_fp2_384_t *r, const zkn_mont_ctx384_t *ctx)
{
    memcpy(r->c0, ctx->one, sizeof(zkn_fe384_t));
    zkn_fe384_zero(r->c1);
}

void zkn_fp2_384_copy(zkn_fp2_384_t *r, const zkn_fp2_384_t *a)
{
    memcpy(r, a, sizeof(zkn_fp2_384_t));
}

int zkn_fp2_384_eq(const zkn_fp2_384_t *a, const zkn_fp2_384_t *b)
{
    return zkn_fe384_eq(a->c0, b->c0) & zkn_fe384_eq(a->c1, b->c1);
}

void zkn_fp2_384_set(zkn_fp2_384_t *r,
                     const zkn_fe384_t c0,
                     const zkn_fe384_t c1)
{
    memcpy(r->c0, c0, sizeof(zkn_fe384_t));
    memcpy(r->c1, c1, sizeof(zkn_fe384_t));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Addition / subtraction / negation
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_384_add(zkn_fp2_384_t *r, const zkn_fp2_384_t *a, const zkn_fp2_384_t *b,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_add_mod_384(r->c0, a->c0, b->c0, ctx->p);
    zkn_add_mod_384(r->c1, a->c1, b->c1, ctx->p);
}

void zkn_fp2_384_sub(zkn_fp2_384_t *r, const zkn_fp2_384_t *a, const zkn_fp2_384_t *b,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_sub_mod_384(r->c0, a->c0, b->c0, ctx->p);
    zkn_sub_mod_384(r->c1, a->c1, b->c1, ctx->p);
}

void zkn_fp2_384_neg(zkn_fp2_384_t *r, const zkn_fp2_384_t *a,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_neg_mod_384(r->c0, a->c0, ctx->p);
    zkn_neg_mod_384(r->c1, a->c1, ctx->p);
}

void zkn_fp2_384_conjugate(zkn_fp2_384_t *r, const zkn_fp2_384_t *a,
                           const zkn_mont_ctx384_t *ctx)
{
    memcpy(r->c0, a->c0, sizeof(zkn_fe384_t));
    zkn_neg_mod_384(r->c1, a->c1, ctx->p);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Multiplication (Karatsuba, 3 Fp mul)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_384_mul(zkn_fp2_384_t *r, const zkn_fp2_384_t *a, const zkn_fp2_384_t *b,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t v0, v1, s_a, s_b, t;

    zkn_mul_mont_384(v0, a->c0, b->c0, ctx->p, ctx->n0);
    zkn_mul_mont_384(v1, a->c1, b->c1, ctx->p, ctx->n0);

    zkn_add_mod_384(s_a, a->c0, a->c1, ctx->p);
    zkn_add_mod_384(s_b, b->c0, b->c1, ctx->p);
    zkn_mul_mont_384(t, s_a, s_b, ctx->p, ctx->n0);

    /* c0 = v0 - v1 */
    zkn_sub_mod_384(r->c0, v0, v1, ctx->p);

    /* c1 = t - v0 - v1 */
    zkn_sub_mod_384(t, t, v0, ctx->p);
    zkn_sub_mod_384(r->c1, t, v1, ctx->p);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Squaring (2 Fp mul)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_384_sqr(zkn_fp2_384_t *r, const zkn_fp2_384_t *a,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t sum, diff, prod;

    zkn_add_mod_384(sum, a->c0, a->c1, ctx->p);
    zkn_sub_mod_384(diff, a->c0, a->c1, ctx->p);
    zkn_mul_mont_384(prod, a->c0, a->c1, ctx->p, ctx->n0);

    zkn_mul_mont_384(r->c0, sum, diff, ctx->p, ctx->n0);
    zkn_add_mod_384(r->c1, prod, prod, ctx->p);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Norm and inversion
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_384_norm(zkn_fe384_t r, const zkn_fp2_384_t *a,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t t0, t1;
    zkn_sqr_mont_384(t0, a->c0, ctx->p, ctx->n0);
    zkn_sqr_mont_384(t1, a->c1, ctx->p, ctx->n0);
    zkn_add_mod_384(r, t0, t1, ctx->p);
}

void zkn_fp2_384_inv(zkn_fp2_384_t *r, const zkn_fp2_384_t *a,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t norm, inv_norm, neg_a1;

    zkn_fp2_384_norm(norm, a, ctx);
    zkn_inv_mont_384(inv_norm, norm, ctx);

    zkn_neg_mod_384(neg_a1, a->c1, ctx->p);

    zkn_mul_mont_384(r->c0, a->c0, inv_norm, ctx->p, ctx->n0);
    zkn_mul_mont_384(r->c1, neg_a1, inv_norm, ctx->p, ctx->n0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Multiply by non-residue ξ = 1 + u (BLS12-381 Fp6 tower)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp2_384_mul_by_xi(zkn_fp2_384_t *r, const zkn_fp2_384_t *a,
                           const zkn_mont_ctx384_t *ctx)
{
    /*
     * (a0 + a1·u)(1 + u) = (a0 - a1) + (a0 + a1)·u
     *
     * Only 1 Fp add + 1 Fp sub. Much cheaper than BN254's ξ=9+u.
     */
    zkn_fe384_t c0, c1;

    zkn_sub_mod_384(c0, a->c0, a->c1, ctx->p);
    zkn_add_mod_384(c1, a->c0, a->c1, ctx->p);

    memcpy(r->c0, c0, sizeof(zkn_fe384_t));
    memcpy(r->c1, c1, sizeof(zkn_fe384_t));
}
