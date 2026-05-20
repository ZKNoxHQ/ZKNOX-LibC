/*
 * zkn_final_exp_384.c — Final exponentiation for BLS12-381 ate pairing
 *
 * Direct translation of blst final_exp() using zkn_fp12_384 primitives.
 * Reference: https://github.com/supranational/blst  (Apache-2.0)
 *
 * BLS12-381: z = -0xd201000000010000  (negative)
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_final_exp_384.h"

/* ══════════════════════════════════════════════════════════════════════
 *  Raise-to-z helpers
 *
 *  |z|   = 0xd201000000010000
 *  |z|/2 = 0x6900800000008000
 *
 *  Chain: 0x2 → 0xc → 0x68 → 0xd200 → 0xd20100000000 → 0xd201000000010000
 * ══════════════════════════════════════════════════════════════════════ */

static void mul_n_sqr(zkn_fp12_384_t          *ret,
                      const zkn_fp12_384_t    *a,
                      int                      n,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_mul(ret, ret, a, ctx);
    while (n--)
        zkn_fp12_384_cyclotomic_sqr(ret, ret, ctx);
}

static void raise_to_z_div_by_2(zkn_fp12_384_t          *ret,
                                 const zkn_fp12_384_t    *a,
                                 const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_cyclotomic_sqr(ret, a,   ctx);  /* 0x2                   */
    mul_n_sqr(ret, a,  2,                 ctx);  /* ..0xc                 */
    mul_n_sqr(ret, a,  3,                 ctx);  /* ..0x68                */
    mul_n_sqr(ret, a,  9,                 ctx);  /* ..0xd200              */
    mul_n_sqr(ret, a, 32,                 ctx);  /* ..0xd20100000000      */
    mul_n_sqr(ret, a, 15,                 ctx);  /* ..0x6900800000008000  */
    zkn_fp12_384_conjugate(ret, ret,      ctx);  /* z < 0                */
}

static void raise_to_z(zkn_fp12_384_t          *ret,
                        const zkn_fp12_384_t    *a,
                        const zkn_mont_ctx384_t *ctx)
{
    raise_to_z_div_by_2(ret, a, ctx);
    zkn_fp12_384_cyclotomic_sqr(ret, ret, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Easy part: f^{(p^6 − 1)(p^2 + 1)}
 * ══════════════════════════════════════════════════════════════════════ */

static void easy_part(zkn_fp12_384_t          *ret,
                      const zkn_fp12_384_t    *f,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t y1, y2;

    zkn_fp12_384_copy(&y1, f);
    zkn_fp12_384_conjugate(&y1, &y1, ctx);   /* y1 = conj(f) = f^{p^6}  */
    zkn_fp12_384_inv(&y2, f, ctx);            /* y2 = f^{-1}             */
    zkn_fp12_384_mul(ret, &y1, &y2, ctx);     /* ret = f^{p^6 - 1}       */
    zkn_fp12_384_frobenius_map(&y2, ret, 2, ctx);
    zkn_fp12_384_mul(ret, ret, &y2, ctx);     /* ret = f^{(p^6-1)(p^2+1)} */
}

/* ══════════════════════════════════════════════════════════════════════
 *  Hard part (blst/zkcrypto decomposition)
 *  Input f must be in the cyclotomic subgroup (output of easy_part).
 * ══════════════════════════════════════════════════════════════════════ */

static void hard_part(zkn_fp12_384_t          *ret,
                      const zkn_fp12_384_t    *f,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t y0, y1, y2, y3;

    zkn_fp12_384_cyclotomic_sqr(&y0, f,    ctx);
    raise_to_z             (&y1, &y0,      ctx);
    raise_to_z_div_by_2    (&y2, &y1,      ctx);

    zkn_fp12_384_copy      (&y3, f            );
    zkn_fp12_384_conjugate (&y3, &y3,      ctx);

    zkn_fp12_384_mul       (&y1, &y1, &y3, ctx);
    zkn_fp12_384_conjugate (&y1, &y1,      ctx);
    zkn_fp12_384_mul       (&y1, &y1, &y2, ctx);

    raise_to_z             (&y2, &y1,      ctx);
    raise_to_z             (&y3, &y2,      ctx);

    zkn_fp12_384_conjugate (&y1, &y1,      ctx);
    zkn_fp12_384_mul       (&y3, &y3, &y1, ctx);
    zkn_fp12_384_conjugate (&y1, &y1,      ctx);

    zkn_fp12_384_frobenius_map(&y1, &y1, 3, ctx);
    zkn_fp12_384_frobenius_map(&y2, &y2, 2, ctx);
    zkn_fp12_384_mul       (&y1, &y1, &y2, ctx);

    raise_to_z             (&y2, &y3,      ctx);
    zkn_fp12_384_mul       (&y2, &y2, &y0, ctx);
    zkn_fp12_384_mul       (&y2, &y2,  f,  ctx);

    zkn_fp12_384_mul       (&y1, &y1, &y2, ctx);

    zkn_fp12_384_frobenius_map(&y2, &y3, 1, ctx);
    zkn_fp12_384_mul       (ret, &y1, &y2, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Public API
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_final_exp(zkn_fp12_384_t          *r,
                   const zkn_fp12_384_t    *f,
                   const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t tmp;
    easy_part(&tmp, f,    ctx);
    hard_part(r,   &tmp, ctx);
}

void zkn_pairing(zkn_fp12_384_t          *r,
                 const zkn_g1_384_t      *P,
                 const zkn_g2_384_t      *Q,
                 const zkn_mont_ctx384_t *ctx)
{
    zkn_miller_loop(r, P, Q, ctx);
    zkn_final_exp(r, r, ctx);
}
