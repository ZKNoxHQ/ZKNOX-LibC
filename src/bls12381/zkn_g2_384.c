/*
 * zkn_g2_384.c — G2 curve arithmetic for BLS12-381
 *
 * E'(Fp2): y² = x³ + 4(1+u),  a = 0, b' = 4·ξ = 4(1+u).
 * Same algorithms as G1 but all Fp operations become Fp2 operations.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_g2_384.h"
#include <string.h>

/* ── BLS12-381 G2 generator (affine, big-endian) ──────────────────── */

static const uint8_t G2_GEN_X0_BE[48] = {
    0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,
    0x26,0x08,0x05,0x27,0x2d,0xc5,0x10,0x51,
    0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
    0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,
    0x0b,0xac,0x03,0x26,0xa8,0x05,0xbb,0xef,
    0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
};
static const uint8_t G2_GEN_X1_BE[48] = {
    0x13,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,
    0x7d,0xac,0xd3,0xa0,0x88,0x27,0x4f,0x65,
    0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
    0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,
    0x33,0x4c,0xf1,0x12,0x13,0x94,0x5d,0x57,
    0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e
};
static const uint8_t G2_GEN_Y0_BE[48] = {
    0x0c,0xe5,0xd5,0x27,0x72,0x7d,0x6e,0x11,
    0x8c,0xc9,0xcd,0xc6,0xda,0x2e,0x35,0x1a,
    0xad,0xfd,0x9b,0xaa,0x8c,0xbd,0xd3,0xa7,
    0x6d,0x42,0x9a,0x69,0x51,0x60,0xd1,0x2c,
    0x92,0x3a,0xc9,0xcc,0x3b,0xac,0xa2,0x89,
    0xe1,0x93,0x54,0x86,0x08,0xb8,0x28,0x01
};
static const uint8_t G2_GEN_Y1_BE[48] = {
    0x06,0x06,0xc4,0xa0,0x2e,0xa7,0x34,0xcc,
    0x32,0xac,0xd2,0xb0,0x2b,0xc2,0x8b,0x99,
    0xcb,0x3e,0x28,0x7e,0x85,0xa7,0x63,0xaf,
    0x26,0x74,0x92,0xab,0x57,0x2e,0x99,0xab,
    0x3f,0x37,0x0d,0x27,0x5c,0xec,0x1d,0xa1,
    0xaa,0xa9,0x07,0x5f,0xf0,0x5f,0x79,0xbe
};

/* Fp2 zero check helper */
static int fp2_is_zero(const zkn_fp2_384_t *a)
{
    zkn_fe384_t zero = {0};
    return zkn_fe384_eq(a->c0, zero) & zkn_fe384_eq(a->c1, zero);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Constructors
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g2_384_zero(zkn_g2_384_t *r)
{
    zkn_fp2_384_zero(&r->X);
    zkn_fp2_384_zero(&r->Y);
    r->Y.c0[0] = 1;  /* (0:1:0) */
    zkn_fp2_384_zero(&r->Z);
}

void zkn_g2_384_copy(zkn_g2_384_t *r, const zkn_g2_384_t *a)
{
    memcpy(r, a, sizeof(zkn_g2_384_t));
}

int zkn_g2_384_is_zero(const zkn_g2_384_t *a)
{
    return fp2_is_zero(&a->Z);
}

void zkn_g2_384_generator(zkn_g2_384_t *r, const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t gx, gy;

    /* Deserialise big-endian → normal limbs (from_affine converts to Mont) */
    zkn_fe384_from_be(gx.c0, G2_GEN_X0_BE);
    zkn_fe384_from_be(gx.c1, G2_GEN_X1_BE);
    zkn_fe384_from_be(gy.c0, G2_GEN_Y0_BE);
    zkn_fe384_from_be(gy.c1, G2_GEN_Y1_BE);

    zkn_g2_384_from_affine(r, &gx, &gy, ctx);
}

void zkn_g2_384_from_affine(zkn_g2_384_t *r,
                            const zkn_fp2_384_t *x,
                            const zkn_fp2_384_t *y,
                            const zkn_mont_ctx384_t *ctx)
{
    /* Convert from normal form to Montgomery (same contract as G1). */
    zkn_to_mont_384(r->X.c0, x->c0, ctx);
    zkn_to_mont_384(r->X.c1, x->c1, ctx);
    zkn_to_mont_384(r->Y.c0, y->c0, ctx);
    zkn_to_mont_384(r->Y.c1, y->c1, ctx);
    zkn_fp2_384_one(&r->Z, ctx);  /* Z = 1 in Montgomery */
}

void zkn_g2_384_to_affine(zkn_fp2_384_t *r_x, zkn_fp2_384_t *r_y,
                          const zkn_g2_384_t *p,
                          const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t z_inv, z_inv2, z_inv3, mx, my;

    zkn_fp2_384_inv(&z_inv, &p->Z, ctx);
    zkn_fp2_384_sqr(&z_inv2, &z_inv, ctx);
    zkn_fp2_384_mul(&z_inv3, &z_inv2, &z_inv, ctx);

    zkn_fp2_384_mul(&mx, &p->X, &z_inv2, ctx);
    zkn_fp2_384_mul(&my, &p->Y, &z_inv3, ctx);

    /* Convert from Montgomery to normal (same contract as G1) */
    zkn_from_mont_384(r_x->c0, mx.c0, ctx->p, ctx->n0);
    zkn_from_mont_384(r_x->c1, mx.c1, ctx->p, ctx->n0);
    zkn_from_mont_384(r_y->c0, my.c0, ctx->p, ctx->n0);
    zkn_from_mont_384(r_y->c1, my.c1, ctx->p, ctx->n0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Comparison / validation
 * ══════════════════════════════════════════════════════════════════════ */

int zkn_g2_384_eq(const zkn_g2_384_t *a, const zkn_g2_384_t *b,
                  const zkn_mont_ctx384_t *ctx)
{
    int a_zero = zkn_g2_384_is_zero(a);
    int b_zero = zkn_g2_384_is_zero(b);
    if (a_zero && b_zero) return 1;
    if (a_zero || b_zero) return 0;

    zkn_fp2_384_t z1sq, z2sq, z1cb, z2cb;
    zkn_fp2_384_sqr(&z1sq, &a->Z, ctx);
    zkn_fp2_384_sqr(&z2sq, &b->Z, ctx);
    zkn_fp2_384_mul(&z1cb, &z1sq, &a->Z, ctx);
    zkn_fp2_384_mul(&z2cb, &z2sq, &b->Z, ctx);

    zkn_fp2_384_t lx, rx, ly, ry;
    zkn_fp2_384_mul(&lx, &a->X, &z2sq, ctx);
    zkn_fp2_384_mul(&rx, &b->X, &z1sq, ctx);
    zkn_fp2_384_mul(&ly, &a->Y, &z2cb, ctx);
    zkn_fp2_384_mul(&ry, &b->Y, &z1cb, ctx);

    return zkn_fp2_384_eq(&lx, &rx) & zkn_fp2_384_eq(&ly, &ry);
}

int zkn_g2_384_on_curve(const zkn_g2_384_t *p,
                        const zkn_mont_ctx384_t *ctx)
{
    if (zkn_g2_384_is_zero(p)) return 1;

    /* Check Y² == X³ + b'·Z⁶  where b' = 4(1+u) */
    zkn_fp2_384_t y2, x2, x3, z2, z4, z6, bz6, rhs;

    zkn_fp2_384_sqr(&y2, &p->Y, ctx);
    zkn_fp2_384_sqr(&x2, &p->X, ctx);
    zkn_fp2_384_mul(&x3, &x2, &p->X, ctx);

    zkn_fp2_384_sqr(&z2, &p->Z, ctx);
    zkn_fp2_384_sqr(&z4, &z2, ctx);
    zkn_fp2_384_mul(&z6, &z4, &z2, ctx);

    /* b' = 4(1+u):  bz6 = 4·(1+u)·Z⁶ */
    /* First: ξ·Z⁶ = (1+u)·Z⁶ via mul_by_xi */
    zkn_fp2_384_mul_by_xi(&bz6, &z6, ctx);
    /* Then ×4 */
    zkn_fp2_384_t t;
    zkn_fp2_384_add(&t, &bz6, &bz6, ctx);
    zkn_fp2_384_add(&bz6, &t, &t, ctx);

    zkn_fp2_384_add(&rhs, &x3, &bz6, ctx);

    return zkn_fp2_384_eq(&y2, &rhs);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Negation
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g2_384_neg(zkn_g2_384_t *r, const zkn_g2_384_t *a,
                    const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_copy(&r->X, &a->X);
    zkn_fp2_384_neg(&r->Y, &a->Y, ctx);
    zkn_fp2_384_copy(&r->Z, &a->Z);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Doubling (a = 0)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g2_384_dbl(zkn_g2_384_t *r, const zkn_g2_384_t *a,
                    const zkn_mont_ctx384_t *ctx)
{
    if (zkn_g2_384_is_zero(a)) {
        zkn_g2_384_zero(r);
        return;
    }

    zkn_fp2_384_t A, B, C, D, t;

    zkn_fp2_384_sqr(&A, &a->Y, ctx);

    zkn_fp2_384_mul(&B, &a->X, &A, ctx);
    zkn_fp2_384_add(&B, &B, &B, ctx);
    zkn_fp2_384_add(&B, &B, &B, ctx);

    zkn_fp2_384_sqr(&C, &A, ctx);
    zkn_fp2_384_add(&C, &C, &C, ctx);
    zkn_fp2_384_add(&C, &C, &C, ctx);
    zkn_fp2_384_add(&C, &C, &C, ctx);

    zkn_fp2_384_sqr(&D, &a->X, ctx);
    zkn_fp2_384_add(&t, &D, &D, ctx);
    zkn_fp2_384_add(&D, &t, &D, ctx);

    zkn_fp2_384_mul(&r->Z, &a->Y, &a->Z, ctx);
    zkn_fp2_384_add(&r->Z, &r->Z, &r->Z, ctx);

    zkn_fp2_384_sqr(&r->X, &D, ctx);
    zkn_fp2_384_sub(&r->X, &r->X, &B, ctx);
    zkn_fp2_384_sub(&r->X, &r->X, &B, ctx);

    zkn_fp2_384_sub(&t, &B, &r->X, ctx);
    zkn_fp2_384_mul(&r->Y, &D, &t, ctx);
    zkn_fp2_384_sub(&r->Y, &r->Y, &C, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Addition (general Jacobian over Fp2)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g2_384_add(zkn_g2_384_t *r,
                    const zkn_g2_384_t *a,
                    const zkn_g2_384_t *b,
                    const zkn_mont_ctx384_t *ctx)
{
    if (zkn_g2_384_is_zero(a)) { zkn_g2_384_copy(r, b); return; }
    if (zkn_g2_384_is_zero(b)) { zkn_g2_384_copy(r, a); return; }

    zkn_fp2_384_t z1sq, z2sq, z1cb, z2cb;
    zkn_fp2_384_sqr(&z1sq, &a->Z, ctx);
    zkn_fp2_384_sqr(&z2sq, &b->Z, ctx);
    zkn_fp2_384_mul(&z1cb, &z1sq, &a->Z, ctx);
    zkn_fp2_384_mul(&z2cb, &z2sq, &b->Z, ctx);

    zkn_fp2_384_t U1, U2, S1, S2;
    zkn_fp2_384_mul(&U1, &a->X, &z2sq, ctx);
    zkn_fp2_384_mul(&U2, &b->X, &z1sq, ctx);
    zkn_fp2_384_mul(&S1, &a->Y, &z2cb, ctx);
    zkn_fp2_384_mul(&S2, &b->Y, &z1cb, ctx);

    zkn_fp2_384_t H, R;
    zkn_fp2_384_sub(&H, &U2, &U1, ctx);
    zkn_fp2_384_sub(&R, &S2, &S1, ctx);

    if (fp2_is_zero(&H)) {
        if (fp2_is_zero(&R)) {
            zkn_g2_384_dbl(r, a, ctx);
        } else {
            zkn_g2_384_zero(r);
        }
        return;
    }

    zkn_fp2_384_t H2, H3, U1H2, t;

    zkn_fp2_384_sqr(&H2, &H, ctx);
    zkn_fp2_384_mul(&H3, &H2, &H, ctx);
    zkn_fp2_384_mul(&U1H2, &U1, &H2, ctx);

    zkn_fp2_384_sqr(&r->X, &R, ctx);
    zkn_fp2_384_sub(&r->X, &r->X, &H3, ctx);
    zkn_fp2_384_sub(&r->X, &r->X, &U1H2, ctx);
    zkn_fp2_384_sub(&r->X, &r->X, &U1H2, ctx);

    zkn_fp2_384_sub(&t, &U1H2, &r->X, ctx);
    zkn_fp2_384_mul(&r->Y, &R, &t, ctx);
    zkn_fp2_384_mul(&t, &S1, &H3, ctx);
    zkn_fp2_384_sub(&r->Y, &r->Y, &t, ctx);

    zkn_fp2_384_mul(&r->Z, &H, &a->Z, ctx);
    zkn_fp2_384_mul(&r->Z, &r->Z, &b->Z, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Mixed addition (b is affine: b.Z = 1)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g2_384_add_mixed(zkn_g2_384_t *r,
                          const zkn_g2_384_t *a,
                          const zkn_g2_384_t *b,
                          const zkn_mont_ctx384_t *ctx)
{
    if (zkn_g2_384_is_zero(a)) { zkn_g2_384_copy(r, b); return; }
    if (zkn_g2_384_is_zero(b)) { zkn_g2_384_copy(r, a); return; }

    zkn_fp2_384_t z1sq, z1cb;
    zkn_fp2_384_sqr(&z1sq, &a->Z, ctx);
    zkn_fp2_384_mul(&z1cb, &z1sq, &a->Z, ctx);

    zkn_fp2_384_t U2, S2, H, R;
    zkn_fp2_384_mul(&U2, &b->X, &z1sq, ctx);
    zkn_fp2_384_mul(&S2, &b->Y, &z1cb, ctx);

    zkn_fp2_384_sub(&H, &U2, &a->X, ctx);
    zkn_fp2_384_sub(&R, &S2, &a->Y, ctx);

    if (fp2_is_zero(&H)) {
        if (fp2_is_zero(&R)) {
            zkn_g2_384_dbl(r, a, ctx);
        } else {
            zkn_g2_384_zero(r);
        }
        return;
    }

    zkn_fp2_384_t H2, H3, U1H2, t;

    zkn_fp2_384_sqr(&H2, &H, ctx);
    zkn_fp2_384_mul(&H3, &H2, &H, ctx);
    zkn_fp2_384_mul(&U1H2, &a->X, &H2, ctx);

    zkn_fp2_384_sqr(&r->X, &R, ctx);
    zkn_fp2_384_sub(&r->X, &r->X, &H3, ctx);
    zkn_fp2_384_sub(&r->X, &r->X, &U1H2, ctx);
    zkn_fp2_384_sub(&r->X, &r->X, &U1H2, ctx);

    zkn_fp2_384_sub(&t, &U1H2, &r->X, ctx);
    zkn_fp2_384_mul(&r->Y, &R, &t, ctx);
    zkn_fp2_384_mul(&t, &a->Y, &H3, ctx);
    zkn_fp2_384_sub(&r->Y, &r->Y, &t, ctx);

    zkn_fp2_384_mul(&r->Z, &H, &a->Z, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Scalar multiplication
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g2_384_mul(zkn_g2_384_t *r,
                    const zkn_g2_384_t *p,
                    const uint8_t *scalar_be,
                    int scalar_len,
                    const zkn_mont_ctx384_t *ctx)
{
    zkn_g2_384_zero(r);
    int started = 0;

    for (int i = 0; i < scalar_len; i++) {
        uint8_t byte = scalar_be[i];
        for (int bit = 7; bit >= 0; bit--) {
            if (started)
                zkn_g2_384_dbl(r, r, ctx);
            if ((byte >> bit) & 1) {
                if (started)
                    zkn_g2_384_add(r, r, p, ctx);
                else {
                    zkn_g2_384_copy(r, p);
                    started = 1;
                }
            }
        }
    }
}
