/*
 * zkn_g1_384.c — G1 curve arithmetic for BLS12-381
 *
 * E(Fp): y² = x³ + 4,  a = 0, b = 4.
 * Jacobian coordinates: (X : Y : Z) represents affine (X/Z², Y/Z³).
 * Point at infinity: Z = 0.
 *
 * Doubling uses the a=0 shortcut (saves one mul).
 * Addition handles all degenerate cases (infinity, equal, inverse).
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_g1_384.h"
#include <string.h>

/* ── BLS12-381 G1 generator (affine, big-endian) ──────────────────── */

static const uint8_t G1_GEN_X_BE[48] = {
    0x17,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,
    0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
    0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
    0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
    0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,
    0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
};

static const uint8_t G1_GEN_Y_BE[48] = {
    0x08,0xb3,0xf4,0x81,0xe3,0xaa,0xa0,0xf1,
    0xa0,0x9e,0x30,0xed,0x74,0x1d,0x8a,0xe4,
    0xfc,0xf5,0xe0,0x95,0xd5,0xd0,0x0a,0xf6,
    0x00,0xdb,0x18,0xcb,0x2c,0x04,0xb3,0xed,
    0xd0,0x3c,0xc7,0x44,0xa2,0x88,0x8a,0xe4,
    0x0c,0xaa,0x23,0x29,0x46,0xc5,0xe7,0xe1
};

/* ══════════════════════════════════════════════════════════════════════
 *  Constructors
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g1_384_zero(zkn_g1_384_t *r)
{
    zkn_fe384_zero(r->X);
    /* Convention: (0 : 1 : 0) — standard projective identity */
    zkn_fe384_zero(r->Y);
    r->Y[0] = 1;
    zkn_fe384_zero(r->Z);
}

void zkn_g1_384_copy(zkn_g1_384_t *r, const zkn_g1_384_t *a)
{
    memcpy(r, a, sizeof(zkn_g1_384_t));
}

int zkn_g1_384_is_zero(const zkn_g1_384_t *a)
{
    zkn_fe384_t zero = {0};
    return zkn_fe384_eq(a->Z, zero);
}

void zkn_g1_384_generator(zkn_g1_384_t *r, const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t gx, gy;
    zkn_fe384_from_be(gx, G1_GEN_X_BE);
    zkn_fe384_from_be(gy, G1_GEN_Y_BE);
    zkn_g1_384_from_affine(r, gx, gy, ctx);
}

void zkn_g1_384_from_affine(zkn_g1_384_t *r,
                            const zkn_fe384_t x,
                            const zkn_fe384_t y,
                            const zkn_mont_ctx384_t *ctx)
{
    zkn_to_mont_384(r->X, x, ctx);
    zkn_to_mont_384(r->Y, y, ctx);
    memcpy(r->Z, ctx->one, sizeof(zkn_fe384_t));  /* Z = R mod p (= mont(1)) */
}

void zkn_g1_384_to_affine(zkn_fe384_t r_x, zkn_fe384_t r_y,
                          const zkn_g1_384_t *p,
                          const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t z_inv, z_inv2, z_inv3;

    zkn_inv_mont_384(z_inv, p->Z, ctx);
    zkn_sqr_mont_384(z_inv2, z_inv, ctx->p, ctx->n0);
    zkn_mul_mont_384(z_inv3, z_inv2, z_inv, ctx->p, ctx->n0);

    zkn_fe384_t x_mont, y_mont;
    zkn_mul_mont_384(x_mont, p->X, z_inv2, ctx->p, ctx->n0);
    zkn_mul_mont_384(y_mont, p->Y, z_inv3, ctx->p, ctx->n0);

    zkn_from_mont_384(r_x, x_mont, ctx->p, ctx->n0);
    zkn_from_mont_384(r_y, y_mont, ctx->p, ctx->n0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Comparison / validation
 * ══════════════════════════════════════════════════════════════════════ */

int zkn_g1_384_eq(const zkn_g1_384_t *a, const zkn_g1_384_t *b,
                  const zkn_mont_ctx384_t *ctx)
{
    int a_zero = zkn_g1_384_is_zero(a);
    int b_zero = zkn_g1_384_is_zero(b);
    if (a_zero && b_zero) return 1;
    if (a_zero || b_zero) return 0;

    /* X1·Z2² == X2·Z1² and Y1·Z2³ == Y2·Z1³ */
    zkn_fe384_t z1sq, z2sq, z1cb, z2cb;
    zkn_sqr_mont_384(z1sq, a->Z, ctx->p, ctx->n0);
    zkn_sqr_mont_384(z2sq, b->Z, ctx->p, ctx->n0);
    zkn_mul_mont_384(z1cb, z1sq, a->Z, ctx->p, ctx->n0);
    zkn_mul_mont_384(z2cb, z2sq, b->Z, ctx->p, ctx->n0);

    zkn_fe384_t lx, rx, ly, ry;
    zkn_mul_mont_384(lx, a->X, z2sq, ctx->p, ctx->n0);
    zkn_mul_mont_384(rx, b->X, z1sq, ctx->p, ctx->n0);
    zkn_mul_mont_384(ly, a->Y, z2cb, ctx->p, ctx->n0);
    zkn_mul_mont_384(ry, b->Y, z1cb, ctx->p, ctx->n0);

    return zkn_fe384_eq(lx, rx) & zkn_fe384_eq(ly, ry);
}

int zkn_g1_384_on_curve(const zkn_g1_384_t *p,
                        const zkn_mont_ctx384_t *ctx)
{
    if (zkn_g1_384_is_zero(p)) return 1;

    /* Check Y² == X³ + 4·Z⁶ */
    zkn_fe384_t y2, x2, x3, z2, z4, z6, bz6, rhs;

    zkn_sqr_mont_384(y2, p->Y, ctx->p, ctx->n0);
    zkn_sqr_mont_384(x2, p->X, ctx->p, ctx->n0);
    zkn_mul_mont_384(x3, x2, p->X, ctx->p, ctx->n0);

    zkn_sqr_mont_384(z2, p->Z, ctx->p, ctx->n0);
    zkn_sqr_mont_384(z4, z2, ctx->p, ctx->n0);
    zkn_mul_mont_384(z6, z4, z2, ctx->p, ctx->n0);

    /* 4·Z⁶ = Z⁶ + Z⁶ + Z⁶ + Z⁶ */
    zkn_fe384_t t;
    zkn_add_mod_384(t, z6, z6, ctx->p);
    zkn_add_mod_384(bz6, t, t, ctx->p);

    zkn_add_mod_384(rhs, x3, bz6, ctx->p);

    return zkn_fe384_eq(y2, rhs);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Negation
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g1_384_neg(zkn_g1_384_t *r, const zkn_g1_384_t *a,
                    const zkn_mont_ctx384_t *ctx)
{
    memcpy(r->X, a->X, sizeof(zkn_fe384_t));
    zkn_neg_mod_384(r->Y, a->Y, ctx->p);
    memcpy(r->Z, a->Z, sizeof(zkn_fe384_t));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Doubling (a = 0 shortcut)
 *
 *  A = Y²           S
 *  B = 4·X·A        S = 4·X·Y²
 *  C = 8·A²         8·Y⁴
 *  D = 3·X²         M (since a=0)
 *  X' = D² - 2·B
 *  Y' = D·(B - X') - C
 *  Z' = 2·Y·Z
 *
 *  Cost: 1S(Y) + 1S(X) + 1M(X,A) + 1S(A) + 1S(D) + 1M(D,...) + 1M(Y,Z)
 *      = 4M + 4S (counting sqr as separate)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g1_384_dbl(zkn_g1_384_t *r, const zkn_g1_384_t *a,
                    const zkn_mont_ctx384_t *ctx)
{
    if (zkn_g1_384_is_zero(a)) {
        zkn_g1_384_zero(r);
        return;
    }

    zkn_fe384_t A, B, C, D, t;

    /* A = Y² */
    zkn_sqr_mont_384(A, a->Y, ctx->p, ctx->n0);

    /* B = 4·X·A */
    zkn_mul_mont_384(B, a->X, A, ctx->p, ctx->n0);
    zkn_add_mod_384(B, B, B, ctx->p);
    zkn_add_mod_384(B, B, B, ctx->p);

    /* C = 8·A² */
    zkn_sqr_mont_384(C, A, ctx->p, ctx->n0);
    zkn_add_mod_384(C, C, C, ctx->p);
    zkn_add_mod_384(C, C, C, ctx->p);
    zkn_add_mod_384(C, C, C, ctx->p);

    /* D = 3·X² */
    zkn_sqr_mont_384(D, a->X, ctx->p, ctx->n0);
    zkn_add_mod_384(t, D, D, ctx->p);
    zkn_add_mod_384(D, t, D, ctx->p);

    /* Z' = 2·Y·Z */
    zkn_mul_mont_384(r->Z, a->Y, a->Z, ctx->p, ctx->n0);
    zkn_add_mod_384(r->Z, r->Z, r->Z, ctx->p);

    /* X' = D² - 2·B */
    zkn_sqr_mont_384(r->X, D, ctx->p, ctx->n0);
    zkn_sub_mod_384(r->X, r->X, B, ctx->p);
    zkn_sub_mod_384(r->X, r->X, B, ctx->p);

    /* Y' = D·(B - X') - C */
    zkn_sub_mod_384(t, B, r->X, ctx->p);
    zkn_mul_mont_384(r->Y, D, t, ctx->p, ctx->n0);
    zkn_sub_mod_384(r->Y, r->Y, C, ctx->p);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Addition (general Jacobian)
 *
 *  U1 = X1·Z2², U2 = X2·Z1², S1 = Y1·Z2³, S2 = Y2·Z1³
 *  H = U2 − U1,  R = S2 − S1
 *  X3 = R² − H³ − 2·U1·H²
 *  Y3 = R·(U1·H² − X3) − S1·H³
 *  Z3 = H·Z1·Z2
 *
 *  Handles: infinity, equal (→ dbl), inverse (→ zero).
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g1_384_add(zkn_g1_384_t *r,
                    const zkn_g1_384_t *a,
                    const zkn_g1_384_t *b,
                    const zkn_mont_ctx384_t *ctx)
{
    if (zkn_g1_384_is_zero(a)) { zkn_g1_384_copy(r, b); return; }
    if (zkn_g1_384_is_zero(b)) { zkn_g1_384_copy(r, a); return; }

    zkn_fe384_t z1sq, z2sq, z1cb, z2cb;
    zkn_sqr_mont_384(z1sq, a->Z, ctx->p, ctx->n0);
    zkn_sqr_mont_384(z2sq, b->Z, ctx->p, ctx->n0);
    zkn_mul_mont_384(z1cb, z1sq, a->Z, ctx->p, ctx->n0);
    zkn_mul_mont_384(z2cb, z2sq, b->Z, ctx->p, ctx->n0);

    zkn_fe384_t U1, U2, S1, S2;
    zkn_mul_mont_384(U1, a->X, z2sq, ctx->p, ctx->n0);
    zkn_mul_mont_384(U2, b->X, z1sq, ctx->p, ctx->n0);
    zkn_mul_mont_384(S1, a->Y, z2cb, ctx->p, ctx->n0);
    zkn_mul_mont_384(S2, b->Y, z1cb, ctx->p, ctx->n0);

    zkn_fe384_t H, R;
    zkn_sub_mod_384(H, U2, U1, ctx->p);
    zkn_sub_mod_384(R, S2, S1, ctx->p);

    zkn_fe384_t zero = {0};
    if (zkn_fe384_eq(H, zero)) {
        if (zkn_fe384_eq(R, zero)) {
            zkn_g1_384_dbl(r, a, ctx);
        } else {
            zkn_g1_384_zero(r);
        }
        return;
    }

    zkn_fe384_t H2, H3, U1H2, t;

    zkn_sqr_mont_384(H2, H, ctx->p, ctx->n0);
    zkn_mul_mont_384(H3, H2, H, ctx->p, ctx->n0);
    zkn_mul_mont_384(U1H2, U1, H2, ctx->p, ctx->n0);

    /* X3 = R² - H³ - 2·U1·H² */
    zkn_sqr_mont_384(r->X, R, ctx->p, ctx->n0);
    zkn_sub_mod_384(r->X, r->X, H3, ctx->p);
    zkn_sub_mod_384(r->X, r->X, U1H2, ctx->p);
    zkn_sub_mod_384(r->X, r->X, U1H2, ctx->p);

    /* Y3 = R·(U1·H² - X3) - S1·H³ */
    zkn_sub_mod_384(t, U1H2, r->X, ctx->p);
    zkn_mul_mont_384(r->Y, R, t, ctx->p, ctx->n0);
    zkn_mul_mont_384(t, S1, H3, ctx->p, ctx->n0);
    zkn_sub_mod_384(r->Y, r->Y, t, ctx->p);

    /* Z3 = H·Z1·Z2  — compute Z1·Z2 first to avoid aliasing when r == b */
    zkn_fe384_t z1z2;
    zkn_mul_mont_384(z1z2, a->Z, b->Z, ctx->p, ctx->n0);
    zkn_mul_mont_384(r->Z, H, z1z2, ctx->p, ctx->n0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Mixed addition (b is affine: b.Z = mont(1))
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g1_384_add_mixed(zkn_g1_384_t *r,
                          const zkn_g1_384_t *a,
                          const zkn_g1_384_t *b,
                          const zkn_mont_ctx384_t *ctx)
{
    if (zkn_g1_384_is_zero(a)) { zkn_g1_384_copy(r, b); return; }
    if (zkn_g1_384_is_zero(b)) { zkn_g1_384_copy(r, a); return; }

    zkn_fe384_t z1sq, z1cb;
    zkn_sqr_mont_384(z1sq, a->Z, ctx->p, ctx->n0);
    zkn_mul_mont_384(z1cb, z1sq, a->Z, ctx->p, ctx->n0);

    /* U1 = X1 (since Z2=1), U2 = X2·Z1² */
    /* S1 = Y1 (since Z2=1), S2 = Y2·Z1³ */
    zkn_fe384_t U2, S2, H, R;
    zkn_mul_mont_384(U2, b->X, z1sq, ctx->p, ctx->n0);
    zkn_mul_mont_384(S2, b->Y, z1cb, ctx->p, ctx->n0);

    zkn_sub_mod_384(H, U2, a->X, ctx->p);
    zkn_sub_mod_384(R, S2, a->Y, ctx->p);

    zkn_fe384_t zero = {0};
    if (zkn_fe384_eq(H, zero)) {
        if (zkn_fe384_eq(R, zero)) {
            zkn_g1_384_dbl(r, a, ctx);
        } else {
            zkn_g1_384_zero(r);
        }
        return;
    }

    zkn_fe384_t H2, H3, U1H2, t;

    zkn_sqr_mont_384(H2, H, ctx->p, ctx->n0);
    zkn_mul_mont_384(H3, H2, H, ctx->p, ctx->n0);
    zkn_mul_mont_384(U1H2, a->X, H2, ctx->p, ctx->n0);

    zkn_sqr_mont_384(r->X, R, ctx->p, ctx->n0);
    zkn_sub_mod_384(r->X, r->X, H3, ctx->p);
    zkn_sub_mod_384(r->X, r->X, U1H2, ctx->p);
    zkn_sub_mod_384(r->X, r->X, U1H2, ctx->p);

    zkn_sub_mod_384(t, U1H2, r->X, ctx->p);
    zkn_mul_mont_384(r->Y, R, t, ctx->p, ctx->n0);
    zkn_mul_mont_384(t, a->Y, H3, ctx->p, ctx->n0);
    zkn_sub_mod_384(r->Y, r->Y, t, ctx->p);

    zkn_mul_mont_384(r->Z, H, a->Z, ctx->p, ctx->n0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Scalar multiplication (double-and-add, left-to-right)
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_g1_384_mul(zkn_g1_384_t *r,
                    const zkn_g1_384_t *p,
                    const uint8_t *scalar_be,
                    int scalar_len,
                    const zkn_mont_ctx384_t *ctx)
{
    zkn_g1_384_zero(r);
    int started = 0;

    for (int i = 0; i < scalar_len; i++) {
        uint8_t byte = scalar_be[i];
        for (int bit = 7; bit >= 0; bit--) {
            if (started)
                zkn_g1_384_dbl(r, r, ctx);
            if ((byte >> bit) & 1) {
                if (started)
                    zkn_g1_384_add(r, r, p, ctx);
                else {
                    zkn_g1_384_copy(r, p);
                    started = 1;
                }
            }
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Multi-scalar multiplication — Straus interleaving
 *
 *  Instead of k separate scalar muls (k × 256 doublings),
 *  we scan all scalars bit-by-bit simultaneously (1 × 256 doublings).
 *
 *  For k=2: table of 4 points  (576 bytes stack)
 *  For k=3: table of 8 points  (1152 bytes stack)
 * ══════════════════════════════════════════════════════════════════════ */

/** Extract bit j (0 = LSB) from a 32-byte big-endian scalar. */
static inline int scalar_bit(const uint8_t s[32], int j)
{
    return (s[31 - j / 8] >> (j % 8)) & 1;
}

void zkn_g1_384_msm2(zkn_g1_384_t *r,
                     const zkn_g1_384_t *P1, const uint8_t s1[32],
                     const zkn_g1_384_t *P2, const uint8_t s2[32],
                     const zkn_mont_ctx384_t *ctx)
{
    /* Precompute T[0..3] = {O, P1, P2, P1+P2} */
    zkn_g1_384_t T[4];
    zkn_g1_384_zero(&T[0]);
    zkn_g1_384_copy(&T[1], P1);
    zkn_g1_384_copy(&T[2], P2);
    zkn_g1_384_add(&T[3], P1, P2, ctx);

    zkn_g1_384_zero(r);
    int started = 0;

    for (int j = 255; j >= 0; j--) {
        if (started)
            zkn_g1_384_dbl(r, r, ctx);

        int idx = scalar_bit(s1, j) | (scalar_bit(s2, j) << 1);
        if (idx != 0) {
            if (started)
                zkn_g1_384_add(r, r, &T[idx], ctx);
            else {
                zkn_g1_384_copy(r, &T[idx]);
                started = 1;
            }
        }
    }
}

void zkn_g1_384_msm3(zkn_g1_384_t *r,
                     const zkn_g1_384_t *P1, const uint8_t s1[32],
                     const zkn_g1_384_t *P2, const uint8_t s2[32],
                     const zkn_g1_384_t *P3, const uint8_t s3[32],
                     const zkn_mont_ctx384_t *ctx)
{
    /* Precompute T[0..7] */
    zkn_g1_384_t T[8];
    zkn_g1_384_zero(&T[0]);
    zkn_g1_384_copy(&T[1], P1);                       /* 001 */
    zkn_g1_384_copy(&T[2], P2);                       /* 010 */
    zkn_g1_384_add(&T[3], P1, P2, ctx);               /* 011 */
    zkn_g1_384_copy(&T[4], P3);                       /* 100 */
    zkn_g1_384_add(&T[5], P1, P3, ctx);               /* 101 */
    zkn_g1_384_add(&T[6], P2, P3, ctx);               /* 110 */
    zkn_g1_384_add(&T[7], &T[3], P3, ctx);            /* 111 */

    zkn_g1_384_zero(r);
    int started = 0;

    for (int j = 255; j >= 0; j--) {
        if (started)
            zkn_g1_384_dbl(r, r, ctx);

        int idx = scalar_bit(s1, j)
                | (scalar_bit(s2, j) << 1)
                | (scalar_bit(s3, j) << 2);
        if (idx != 0) {
            if (started)
                zkn_g1_384_add(r, r, &T[idx], ctx);
            else {
                zkn_g1_384_copy(r, &T[idx]);
                started = 1;
            }
        }
    }
}

void zkn_g1_384_msm(zkn_g1_384_t *r,
                    const zkn_g1_384_t *points,
                    const uint8_t      *scalars,   /* k × 32 bytes BE */
                    int                 k,
                    const zkn_mont_ctx384_t *ctx)
{
    zkn_g1_384_zero(r);
    if (k <= 0) return;

    int i = 0;

    /* Process groups of 3 */
    while (i + 3 <= k) {
        zkn_g1_384_t partial;
        zkn_g1_384_msm3(&partial,
                        &points[i],   scalars + (i)   * 32,
                        &points[i+1], scalars + (i+1) * 32,
                        &points[i+2], scalars + (i+2) * 32,
                        ctx);
        zkn_g1_384_add(r, r, &partial, ctx);
        i += 3;
    }

    /* Remainder: 2 points */
    if (i + 2 <= k) {
        zkn_g1_384_t partial;
        zkn_g1_384_msm2(&partial,
                        &points[i],   scalars + (i)   * 32,
                        &points[i+1], scalars + (i+1) * 32,
                        ctx);
        zkn_g1_384_add(r, r, &partial, ctx);
        i += 2;
    }

    /* Remainder: 1 point */
    if (i < k) {
        zkn_g1_384_t partial;
        zkn_g1_384_mul(&partial, &points[i], scalars + i * 32, 32, ctx);
        zkn_g1_384_add(r, r, &partial, ctx);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Input validation (untrusted encodings)
 *
 *  Added by the security review: the verifiers deserialised proof points
 *  with from_affine() and nothing else, so off-curve points, points outside
 *  the prime-order subgroup and non-canonical coordinates (x and x + p) were
 *  all accepted, and public inputs >= r aliased to (input mod r).
 * ══════════════════════════════════════════════════════════════════════ */

/* p (base field) and r (scalar field / subgroup order), big-endian */
static const uint8_t BLS12_381_P_BE[48] = {
    0x1a,0x01,0x11,0xea,0x39,0x7f,0xe6,0x9a,0x4b,0x1b,0xa7,0xb6,0x43,0x4b,0xac,0xd7,
    0x64,0x77,0x4b,0x84,0xf3,0x85,0x12,0xbf,0x67,0x30,0xd2,0xa0,0xf6,0xb0,0xf6,0x24,
    0x1e,0xab,0xff,0xfe,0xb1,0x53,0xff,0xff,0xb9,0xfe,0xff,0xff,0xff,0xff,0xaa,0xab};
static const uint8_t BLS12_381_R_BE[32] = {
    0x73,0xed,0xa7,0x53,0x29,0x9d,0x7d,0x48,0x33,0x39,0xd8,0x08,0x09,0xa1,0xd8,0x05,
    0x53,0xbd,0xa4,0x02,0xff,0xfe,0x5b,0xfe,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01};

static int be_lt(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] < b[i]) return 1;
        if (a[i] > b[i]) return 0;
    }
    return 0;
}

static int all_zero(const uint8_t *a, size_t n)
{
    for (size_t i = 0; i < n; i++) if (a[i]) return 0;
    return 1;
}

int zkn_bls12381_fp_is_canonical(const uint8_t be[48])
{
    return be_lt(be, BLS12_381_P_BE, 48);
}

int zkn_bls12381_fr_is_canonical(const uint8_t be[32])
{
    return be_lt(be, BLS12_381_R_BE, 32);
}

const uint8_t *zkn_bls12381_r_be(void)
{
    return BLS12_381_R_BE;
}

int zkn_g1_384_in_subgroup(const zkn_g1_384_t *P, const zkn_mont_ctx384_t *ctx)
{
    zkn_g1_384_t T;
    zkn_g1_384_mul(&T, P, BLS12_381_R_BE, 32, ctx);
    return zkn_g1_384_is_zero(&T);
}

int zkn_g1_384_from_be_checked(zkn_g1_384_t *P, const uint8_t buf[96],
                               int allow_identity, int check_subgroup,
                               const zkn_mont_ctx384_t *ctx)
{
    if (all_zero(buf, 96)) {               /* snarkjs zeroAffine convention */
        if (!allow_identity) return -1;
        zkn_g1_384_zero(P);
        return 0;
    }
    if (!be_lt(buf, BLS12_381_P_BE, 48) || !be_lt(buf + 48, BLS12_381_P_BE, 48))
        return -1;
    zkn_fe384_t x, y;
    zkn_fe384_from_be(x, buf);
    zkn_fe384_from_be(y, buf + 48);
    zkn_g1_384_from_affine(P, x, y, ctx);
    if (!zkn_g1_384_on_curve(P, ctx)) return -1;
    if (check_subgroup && !zkn_g1_384_in_subgroup(P, ctx)) return -1;
    return 0;
}
