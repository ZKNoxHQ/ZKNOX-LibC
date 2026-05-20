/*
 * zkn_miller.c — Miller loop variants for BLS12-381 optimal ate pairing
 *
 * Montgomery convention (critical)
 * ─────────────────────────────────
 * zkn_g1_384_to_affine() returns coordinates in NORMAL form.
 * zkn_g2_384_to_affine() returns coordinates in NORMAL form.
 * zkn_fp2_384_mul_by_fp() calls zkn_mul_mont_384() which needs MONTGOMERY.
 * The static helpers g1_affine_to_mont() and g2_affine_to_mont() wrap both
 * calls and are the ONLY places where this conversion happens.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_miller.h"

/* BLS12-381 seed |u| = 0xd201000000010000 */
static const uint64_t BLS12_381_U = 0xd201000000010000ULL;

/* ══════════════════════════════════════════════════════════════════════
 *  G1 affine → Montgomery
 *  (to_affine gives normal form; mul_by_fp needs Montgomery)
 * ══════════════════════════════════════════════════════════════════════ */

static void g1_affine_to_mont(zkn_fe384_t              Px,
                               zkn_fe384_t              Py,
                               const zkn_g1_384_t      *P,
                               const zkn_mont_ctx384_t *ctx)
{
    zkn_g1_384_to_affine(Px, Py, P, ctx);
    zkn_to_mont_384(Px, Px, ctx);
    zkn_to_mont_384(Py, Py, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  G2 affine → Montgomery
 *  (to_affine gives normal form; Miller loop arithmetic needs Montgomery)
 * ══════════════════════════════════════════════════════════════════════ */

static void g2_affine_to_mont(zkn_fp2_384_t            *Qx,
                               zkn_fp2_384_t            *Qy,
                               const zkn_g2_384_t      *Q,
                               const zkn_mont_ctx384_t *ctx)
{
    zkn_g2_384_to_affine(Qx, Qy, Q, ctx);
    zkn_to_mont_384(Qx->c0, Qx->c0, ctx);
    zkn_to_mont_384(Qx->c1, Qx->c1, ctx);
    zkn_to_mont_384(Qy->c0, Qy->c0, ctx);
    zkn_to_mont_384(Qy->c1, Qy->c1, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Single-pair Miller loop
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_miller_loop(zkn_fp12_384_t          *f,
                     const zkn_g1_384_t      *P,
                     const zkn_g2_384_t      *Q,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t    Px, Py;
    zkn_fp2_384_t  Qx, Qy;
    zkn_g2_384_t   T;
    zkn_line_384_t line;
    int i;

    if (zkn_g1_384_is_identity(P) || zkn_g2_384_is_identity(Q)) {
        zkn_fp12_384_one(f, ctx);
        return;
    }

    g1_affine_to_mont(Px, Py, P, ctx);
    g2_affine_to_mont(&Qx, &Qy, Q, ctx);

    zkn_fp2_384_copy(&T.X, &Qx);
    zkn_fp2_384_copy(&T.Y, &Qy);
    zkn_fp2_384_one(&T.Z, ctx);

    zkn_fp12_384_one(f, ctx);

    for (i = 62; i >= 0; i--) {
        int bit = (int)((BLS12_381_U >> i) & 1);

        zkn_fp12_384_sqr(f, f, ctx);

        zkn_miller_doubling_step(&T, &line, Px, Py, ctx);
        zkn_fp12_384_mul_by_014(f, f, &line.c0, &line.c1, &line.c4, ctx);

        if (bit) {
            zkn_miller_addition_step(&T, &line, &Qx, &Qy, Px, Py, ctx);
            zkn_fp12_384_mul_by_014(f, f, &line.c0, &line.c1, &line.c4, ctx);
        }
    }

    zkn_fp12_384_conjugate(f, f, ctx);   /* u < 0 */
}

/* ══════════════════════════════════════════════════════════════════════
 *  Raw step helpers (no P — for precomputed-line API)
 * ══════════════════════════════════════════════════════════════════════ */

static void dbl_step_raw(zkn_g2_384_t         *T,
                         zkn_line_raw_384_t   *line,
                         const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t A, B, C, D, E, F, X1, Z1sq, tmp;

    zkn_fp2_384_copy(&X1, &T->X);
    zkn_fp2_384_sqr(&A,    &X1,   ctx);
    zkn_fp2_384_sqr(&B,    &T->Y, ctx);
    zkn_fp2_384_sqr(&C,    &B,    ctx);
    zkn_fp2_384_sqr(&Z1sq, &T->Z, ctx);

    zkn_fp2_384_add(&D, &X1, &B,  ctx);
    zkn_fp2_384_sqr(&D, &D,       ctx);
    zkn_fp2_384_sub(&D, &D,  &A,  ctx);
    zkn_fp2_384_sub(&D, &D,  &C,  ctx);
    zkn_fp2_384_add(&D, &D,  &D,  ctx);

    zkn_fp2_384_add(&E, &A, &A, ctx);
    zkn_fp2_384_add(&E, &E, &A, ctx);
    zkn_fp2_384_sqr(&F, &E, ctx);

    /* c0 = E·X1 − 2·B */
    zkn_fp2_384_mul(&line->c0, &E, &X1, ctx);
    zkn_fp2_384_add(&tmp, &B, &B, ctx);
    zkn_fp2_384_sub(&line->c0, &line->c0, &tmp, ctx);

    /* X3 = F − 2·D */
    zkn_fp2_384_add(&tmp, &D, &D, ctx);
    zkn_fp2_384_sub(&T->X, &F, &tmp, ctx);

    /* Z3 = (Y1+Z1)²−B−Z1² */
    zkn_fp2_384_add(&T->Z, &T->Y, &T->Z, ctx);
    zkn_fp2_384_sqr(&T->Z, &T->Z,        ctx);
    zkn_fp2_384_sub(&T->Z, &T->Z, &B,    ctx);
    zkn_fp2_384_sub(&T->Z, &T->Z, &Z1sq, ctx);

    /* Y3 = E·(D−X3)−8·C */
    zkn_fp2_384_sub(&T->Y, &D, &T->X, ctx);
    zkn_fp2_384_mul(&T->Y, &E, &T->Y, ctx);
    zkn_fp2_384_add(&C, &C, &C, ctx);
    zkn_fp2_384_add(&C, &C, &C, ctx);
    zkn_fp2_384_add(&C, &C, &C, ctx);
    zkn_fp2_384_sub(&T->Y, &T->Y, &C, ctx);

    /* c1 = −E·Z1²  (raw, ×xP applied later) */
    zkn_fp2_384_mul(&line->c1, &E, &Z1sq, ctx);
    zkn_fp2_384_neg(&line->c1, &line->c1, ctx);

    /* c4 = Z3·Z1²  (raw, ×yP applied later) */
    zkn_fp2_384_mul(&line->c4, &T->Z, &Z1sq, ctx);
}

static void add_step_raw(zkn_g2_384_t         *T,
                         zkn_line_raw_384_t   *line,
                         const zkn_fp2_384_t  *Q_x,
                         const zkn_fp2_384_t  *Q_y,
                         const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t ZZ, ZZZ, U2, S2, H, Hsq, I, J, rr, V, Y1, tmp;

    zkn_fp2_384_copy(&Y1, &T->Y);
    zkn_fp2_384_sqr(&ZZ,  &T->Z,        ctx);
    zkn_fp2_384_mul(&ZZZ, &ZZ,   &T->Z, ctx);
    zkn_fp2_384_mul(&U2,  Q_x,   &ZZ,   ctx);
    zkn_fp2_384_mul(&S2,  Q_y,   &ZZZ,  ctx);
    zkn_fp2_384_sub(&H,   &U2,   &T->X, ctx);
    zkn_fp2_384_sqr(&Hsq, &H,           ctx);
    zkn_fp2_384_add(&I,   &Hsq,  &Hsq,  ctx);
    zkn_fp2_384_add(&I,   &I,    &I,    ctx);
    zkn_fp2_384_mul(&J,   &H,    &I,    ctx);
    zkn_fp2_384_sub(&rr,  &S2,   &Y1,   ctx);
    zkn_fp2_384_add(&rr,  &rr,   &rr,   ctx);
    zkn_fp2_384_mul(&V,   &T->X, &I,    ctx);

    zkn_fp2_384_sqr(&T->X, &rr,          ctx);
    zkn_fp2_384_sub(&T->X, &T->X, &J,    ctx);
    zkn_fp2_384_add(&tmp,  &V,    &V,    ctx);
    zkn_fp2_384_sub(&T->X, &T->X, &tmp,  ctx);

    zkn_fp2_384_add(&T->Z, &T->Z, &H,    ctx);
    zkn_fp2_384_sqr(&T->Z, &T->Z,        ctx);
    zkn_fp2_384_sub(&T->Z, &T->Z, &ZZ,   ctx);
    zkn_fp2_384_sub(&T->Z, &T->Z, &Hsq,  ctx);

    zkn_fp2_384_sub(&tmp,  &V,    &T->X, ctx);
    zkn_fp2_384_mul(&T->Y, &rr,   &tmp,  ctx);
    zkn_fp2_384_mul(&tmp,  &Y1,   &J,    ctx);
    zkn_fp2_384_add(&tmp,  &tmp,  &tmp,  ctx);
    zkn_fp2_384_sub(&T->Y, &T->Y, &tmp,  ctx);

    /* c0 = rr·X_Q − Y_Q·Z3 */
    zkn_fp2_384_mul(&line->c0, &rr,  Q_x,   ctx);
    zkn_fp2_384_mul(&tmp,       Q_y, &T->Z, ctx);
    zkn_fp2_384_sub(&line->c0, &line->c0, &tmp, ctx);

    /* c1 = −rr  (raw) */
    zkn_fp2_384_neg(&line->c1, &rr, ctx);

    /* c4 = Z3   (raw) */
    zkn_fp2_384_copy(&line->c4, &T->Z);
}

/* Inject Montgomery xP/yP into raw coefficients */
static void apply_p_to_line(zkn_line_384_t           *out,
                             const zkn_line_raw_384_t *in,
                             const zkn_fe384_t         Px,
                             const zkn_fe384_t         Py,
                             const zkn_mont_ctx384_t  *ctx)
{
    zkn_fp2_384_copy(&out->c0, &in->c0);
    zkn_fp2_384_mul_by_fp(&out->c1, &in->c1, Px, ctx);
    zkn_fp2_384_mul_by_fp(&out->c4, &in->c4, Py, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Precomputed lines for fixed Q
 * ══════════════════════════════════════════════════════════════════════ */

static void pre_add_n_dbl(zkn_line_raw_384_t     **ptr,
                          zkn_g2_384_t            *T,
                          const zkn_fp2_384_t     *Qx,
                          const zkn_fp2_384_t     *Qy,
                          size_t                   n,
                          const zkn_mont_ctx384_t *ctx)
{
    add_step_raw(T, (*ptr)++, Qx, Qy, ctx);
    while (n--)
        dbl_step_raw(T, (*ptr)++, ctx);
}

void zkn_precompute_lines(zkn_line_raw_384_t    lines[68],
                          const zkn_g2_384_t   *Q,
                          const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t      Qx, Qy;
    zkn_g2_384_t       T;
    zkn_line_raw_384_t *p = lines;

    g2_affine_to_mont(&Qx, &Qy, Q, ctx);
    zkn_fp2_384_copy(&T.X, &Qx);
    zkn_fp2_384_copy(&T.Y, &Qy);
    zkn_fp2_384_one(&T.Z, ctx);

    dbl_step_raw(&T, p++, ctx);
    pre_add_n_dbl(&p, &T, &Qx, &Qy,  2, ctx);
    pre_add_n_dbl(&p, &T, &Qx, &Qy,  3, ctx);
    pre_add_n_dbl(&p, &T, &Qx, &Qy,  9, ctx);
    pre_add_n_dbl(&p, &T, &Qx, &Qy, 32, ctx);
    pre_add_n_dbl(&p, &T, &Qx, &Qy, 16, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Miller loop from precomputed lines
 * ══════════════════════════════════════════════════════════════════════ */

static void post_add_n_dbl(zkn_fp12_384_t               *f,
                            const zkn_line_raw_384_t    **ptr,
                            const zkn_fe384_t             Px,
                            const zkn_fe384_t             Py,
                            size_t                        n,
                            const zkn_mont_ctx384_t      *ctx)
{
    zkn_line_384_t line;

    apply_p_to_line(&line, (*ptr)++, Px, Py, ctx);
    zkn_fp12_384_mul_by_014(f, f, &line.c0, &line.c1, &line.c4, ctx);

    while (n--) {
        zkn_fp12_384_sqr(f, f, ctx);
        apply_p_to_line(&line, (*ptr)++, Px, Py, ctx);
        zkn_fp12_384_mul_by_014(f, f, &line.c0, &line.c1, &line.c4, ctx);
    }
}

void zkn_miller_loop_lines(zkn_fp12_384_t           *f,
                           const zkn_line_raw_384_t  lines[68],
                           const zkn_g1_384_t        *P,
                           const zkn_mont_ctx384_t   *ctx)
{
    zkn_fe384_t Px, Py;
    zkn_line_384_t line;
    const zkn_line_raw_384_t *p = lines;

    g1_affine_to_mont(Px, Py, P, ctx);   /* ← Montgomery fix */

    apply_p_to_line(&line, p++, Px, Py, ctx);
    zkn_fp12_384_one(f, ctx);
    zkn_fp12_384_mul_by_014(f, f, &line.c0, &line.c1, &line.c4, ctx);

    post_add_n_dbl(f, &p, Px, Py,  2, ctx);
    post_add_n_dbl(f, &p, Px, Py,  3, ctx);
    post_add_n_dbl(f, &p, Px, Py,  9, ctx);
    post_add_n_dbl(f, &p, Px, Py, 32, ctx);
    post_add_n_dbl(f, &p, Px, Py, 16, ctx);

    zkn_fp12_384_conjugate(f, f, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Batch Miller loop
 * ══════════════════════════════════════════════════════════════════════ */

/* Wrapper: avoids ISO C11 warnings on const array-pointer qualifiers */
typedef struct { zkn_fe384_t v; } zkn_fe384_wrap_t;

static void start_dbl_n(zkn_fp12_384_t          *f,
                        zkn_g2_384_t             T[],
                        const zkn_limb_t        *Px[],
                        const zkn_limb_t        *Py[],
                        size_t                   n,
                        const zkn_mont_ctx384_t *ctx)
{
    zkn_line_raw_384_t raw;
    zkn_line_384_t     line;
    size_t i;

    dbl_step_raw(&T[0], &raw, ctx);
    apply_p_to_line(&line, &raw, Px[0], Py[0], ctx);
    zkn_fp12_384_one(f, ctx);
    zkn_fp12_384_mul_by_014(f, f, &line.c0, &line.c1, &line.c4, ctx);

    for (i = 1; i < n; i++) {
        dbl_step_raw(&T[i], &raw, ctx);
        apply_p_to_line(&line, &raw, Px[i], Py[i], ctx);
        zkn_fp12_384_mul_by_014(f, f, &line.c0, &line.c1, &line.c4, ctx);
    }
}

static void add_n_dbl_n(zkn_fp12_384_t          *f,
                        zkn_g2_384_t             T[],
                        const zkn_fp2_384_t      Qx[],
                        const zkn_fp2_384_t      Qy[],
                        const zkn_limb_t        *Px[],
                        const zkn_limb_t        *Py[],
                        size_t                   n,
                        size_t                   k,
                        const zkn_mont_ctx384_t *ctx)
{
    zkn_line_raw_384_t raw;
    zkn_line_384_t     line;
    size_t i;

    for (i = 0; i < n; i++) {
        add_step_raw(&T[i], &raw, &Qx[i], &Qy[i], ctx);
        apply_p_to_line(&line, &raw, Px[i], Py[i], ctx);
        zkn_fp12_384_mul_by_014(f, f, &line.c0, &line.c1, &line.c4, ctx);
    }
    while (k--) {
        zkn_fp12_384_sqr(f, f, ctx);
        for (i = 0; i < n; i++) {
            dbl_step_raw(&T[i], &raw, ctx);
            apply_p_to_line(&line, &raw, Px[i], Py[i], ctx);
            zkn_fp12_384_mul_by_014(f, f, &line.c0, &line.c1, &line.c4, ctx);
        }
    }
}

void zkn_miller_loop_n(zkn_fp12_384_t          *f,
                       const zkn_g1_384_t *const Ps[],
                       const zkn_g2_384_t *const Qs[],
                       size_t                    n,
                       const zkn_mont_ctx384_t  *ctx)
{
#define MILLER_N_MAX 3   /* Groth16 max — Nano S+ budget (was 16, ~10.9 KB → ~2.1 KB) */
    zkn_g2_384_t     T[MILLER_N_MAX];
    zkn_fp2_384_t    Qx[MILLER_N_MAX];
    zkn_fp2_384_t    Qy[MILLER_N_MAX];
    zkn_fe384_wrap_t Px[MILLER_N_MAX];
    zkn_fe384_wrap_t Py[MILLER_N_MAX];
    const zkn_limb_t *pPx[MILLER_N_MAX];
    const zkn_limb_t *pPy[MILLER_N_MAX];
    size_t i, j;

    for (i = 0, j = 0; j < n; j++) {
        const zkn_g1_384_t *P = Ps[j];
        const zkn_g2_384_t *Q = Qs[j];

        if (zkn_g1_384_is_identity(P) || zkn_g2_384_is_identity(Q))
            continue;

        g1_affine_to_mont(Px[i].v, Py[i].v, P, ctx);   /* ← Montgomery fix */
        g2_affine_to_mont(&Qx[i], &Qy[i], Q, ctx);
        pPx[i] = Px[i].v;
        pPy[i] = Py[i].v;

        zkn_fp2_384_copy(&T[i].X, &Qx[i]);
        zkn_fp2_384_copy(&T[i].Y, &Qy[i]);
        zkn_fp2_384_one(&T[i].Z, ctx);

        if (++i == MILLER_N_MAX || j == n - 1) {
            zkn_fp12_384_t tmp;
            int first = (j < MILLER_N_MAX);
            zkn_fp12_384_t *ret = first ? f : &tmp;

            start_dbl_n(ret, T, pPx, pPy, i, ctx);
            add_n_dbl_n(ret, T, Qx, Qy, pPx, pPy, i,  2, ctx);
            add_n_dbl_n(ret, T, Qx, Qy, pPx, pPy, i,  3, ctx);
            add_n_dbl_n(ret, T, Qx, Qy, pPx, pPy, i,  9, ctx);
            add_n_dbl_n(ret, T, Qx, Qy, pPx, pPy, i, 32, ctx);
            add_n_dbl_n(ret, T, Qx, Qy, pPx, pPy, i, 16, ctx);
            zkn_fp12_384_conjugate(ret, ret, ctx);

            if (!first)
                zkn_fp12_384_mul(f, f, &tmp, ctx);
            i = 0;
        }
    }

    if (i == 0 && j == 0)
        zkn_fp12_384_one(f, ctx);
#undef MILLER_N_MAX
}
