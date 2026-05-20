/*
 * zkn_pairing_384.c — Line evaluation primitives for BLS12-381 ate pairing
 *
 * Implements fp2_mul_by_fp, doubling step, addition step.
 * All P coordinates received here are already in Montgomery form.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_pairing_384.h"

/* ══════════════════════════════════════════════════════════════════════
 *  Fp2 × Fp
 *
 *  When ZKN_FP2_384_MUL_BY_FP_STANDALONE is defined, this function is
 *  compiled from its own dedicated translation unit (zkn_fp2_384_mul_by_fp.c)
 *  and must NOT be emitted here to avoid a duplicate-symbol link error.
 * ══════════════════════════════════════════════════════════════════════ */

#ifndef ZKN_FP2_384_MUL_BY_FP_STANDALONE
void zkn_fp2_384_mul_by_fp(zkn_fp2_384_t       *r,
                           const zkn_fp2_384_t *a,
                           const zkn_fe384_t    s,
                           const zkn_mont_ctx384_t *ctx)
{
    zkn_mul_mont_384(r->c0, a->c0, s, ctx->p, ctx->n0);
    zkn_mul_mont_384(r->c1, a->c1, s, ctx->p, ctx->n0);
}
#endif /* !ZKN_FP2_384_MUL_BY_FP_STANDALONE */

/* ══════════════════════════════════════════════════════════════════════
 *  Doubling step
 *
 *  EFD dbl-2009-l adapted for a=0, Jacobian Fp2.
 *  Line (M-twist, slots 0/1/4):
 *    c0 = E·X1 − 2·B
 *    c1 = −E·Z1²·xP
 *    c4 = Z3·Z1²·yP
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_miller_doubling_step(zkn_g2_384_t       *T,
                              zkn_line_384_t     *line,
                              const zkn_fe384_t   P_x,
                              const zkn_fe384_t   P_y,
                              const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t A, B, C, D, E, F, X1, Z1sq, tmp;

    zkn_fp2_384_copy(&X1, &T->X);
    zkn_fp2_384_sqr(&A,    &X1,   ctx);
    zkn_fp2_384_sqr(&B,    &T->Y, ctx);
    zkn_fp2_384_sqr(&C,    &B,    ctx);
    zkn_fp2_384_sqr(&Z1sq, &T->Z, ctx);

    /* D = 4·X1·Y1² */
    zkn_fp2_384_add(&D, &X1, &B,  ctx);
    zkn_fp2_384_sqr(&D, &D,       ctx);
    zkn_fp2_384_sub(&D, &D,  &A,  ctx);
    zkn_fp2_384_sub(&D, &D,  &C,  ctx);
    zkn_fp2_384_add(&D, &D,  &D,  ctx);

    /* E = 3·A */
    zkn_fp2_384_add(&E, &A, &A, ctx);
    zkn_fp2_384_add(&E, &E, &A, ctx);

    /* F = E² */
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

    /* c4 = Z3·Z1²·yP */
    zkn_fp2_384_mul(&tmp, &T->Z, &Z1sq, ctx);
    zkn_fp2_384_mul_by_fp(&line->c4, &tmp, P_y, ctx);

    /* c1 = −E·Z1²·xP */
    zkn_fp2_384_mul(&tmp, &E, &Z1sq, ctx);
    zkn_fp2_384_neg(&tmp, &tmp, ctx);
    zkn_fp2_384_mul_by_fp(&line->c1, &tmp, P_x, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Addition step
 *
 *  madd-2007-bl adapted for Jacobian T + affine Q, Fp2.
 *  Line (M-twist, slots 0/1/4):
 *    c0 = rr·X_Q − Y_Q·Z3
 *    c1 = −rr·xP
 *    c4 = Z3·yP
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_miller_addition_step(zkn_g2_384_t         *T,
                              zkn_line_384_t        *line,
                              const zkn_fp2_384_t   *Q_x,
                              const zkn_fp2_384_t   *Q_y,
                              const zkn_fe384_t      P_x,
                              const zkn_fe384_t      P_y,
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

    /* X3 = rr²−J−2·V */
    zkn_fp2_384_sqr(&T->X, &rr,         ctx);
    zkn_fp2_384_sub(&T->X, &T->X, &J,   ctx);
    zkn_fp2_384_add(&tmp,  &V,    &V,   ctx);
    zkn_fp2_384_sub(&T->X, &T->X, &tmp, ctx);

    /* Z3 = (Z+H)²−ZZ−Hsq */
    zkn_fp2_384_add(&T->Z, &T->Z, &H,   ctx);
    zkn_fp2_384_sqr(&T->Z, &T->Z,       ctx);
    zkn_fp2_384_sub(&T->Z, &T->Z, &ZZ,  ctx);
    zkn_fp2_384_sub(&T->Z, &T->Z, &Hsq, ctx);

    /* Y3 = rr·(V−X3)−2·Y1·J */
    zkn_fp2_384_sub(&tmp,  &V,    &T->X, ctx);
    zkn_fp2_384_mul(&T->Y, &rr,   &tmp,  ctx);
    zkn_fp2_384_mul(&tmp,  &Y1,   &J,    ctx);
    zkn_fp2_384_add(&tmp,  &tmp,  &tmp,  ctx);
    zkn_fp2_384_sub(&T->Y, &T->Y, &tmp,  ctx);

    /* c0 = rr·X_Q − Y_Q·Z3 */
    zkn_fp2_384_mul(&line->c0, &rr,  Q_x,   ctx);
    zkn_fp2_384_mul(&tmp,       Q_y, &T->Z, ctx);
    zkn_fp2_384_sub(&line->c0, &line->c0, &tmp, ctx);

    /* c1 = −rr·xP */
    zkn_fp2_384_neg(&tmp, &rr, ctx);
    zkn_fp2_384_mul_by_fp(&line->c1, &tmp,  P_x, ctx);

    /* c4 = Z3·yP */
    zkn_fp2_384_mul_by_fp(&line->c4, &T->Z, P_y, ctx);
}
