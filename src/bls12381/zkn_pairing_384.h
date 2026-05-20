/*
 * zkn_pairing_384.h — Line evaluation primitives for BLS12-381 ate pairing
 *
 * Provides ONLY the low-level building blocks:
 *   - zkn_fp2_384_mul_by_fp    Fp2 × Fp scalar  (s must be Montgomery)
 *   - zkn_line_384_t           sparse Fp12 line coefficients (slots 0,1,4)
 *   - zkn_miller_doubling_step T ← 2T, tangent line at P
 *   - zkn_miller_addition_step T ← T+Q, secant line at P
 *
 * P_x / P_y passed to step functions MUST be in Montgomery form.
 * Montgomery conversion is the caller's responsibility (done in zkn_miller.c).
 *
 * Miller loop variants  → zkn_miller.h
 * Final exp + pairing   → zkn_final_exp_384.h
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_PAIRING_384_H
#define ZKN_PAIRING_384_H

#include "zkn_fp12_384.h"
#include "zkn_g1_384.h"
#include "zkn_g2_384.h"

#define zkn_g1_384_is_identity  zkn_g1_384_is_zero
#define zkn_g2_384_is_identity  zkn_g2_384_is_zero

#ifdef __cplusplus
extern "C" {
#endif

/* ── Fp2 × Fp scalar (s must be in Montgomery form) ────────────────── */

void zkn_fp2_384_mul_by_fp(zkn_fp2_384_t       *r,
                           const zkn_fp2_384_t *a,
                           const zkn_fe384_t    s,
                           const zkn_mont_ctx384_t *ctx);

/* ── Sparse line coefficients (slots 0, 1, 4 of Fp12) ──────────────── */

typedef struct {
    zkn_fp2_384_t c0;   /* no P factor                  */
    zkn_fp2_384_t c1;   /* multiplied by xP (Montgomery) */
    zkn_fp2_384_t c4;   /* multiplied by yP (Montgomery) */
} zkn_line_384_t;

/* ── Doubling step: T ← 2T, tangent at P (P_x/P_y in Montgomery) ───── */

void zkn_miller_doubling_step(zkn_g2_384_t       *T,
                              zkn_line_384_t     *line,
                              const zkn_fe384_t   P_x,
                              const zkn_fe384_t   P_y,
                              const zkn_mont_ctx384_t *ctx);

/* ── Addition step: T ← T+Q, secant at P (P_x/P_y in Montgomery) ───── */

void zkn_miller_addition_step(zkn_g2_384_t         *T,
                              zkn_line_384_t        *line,
                              const zkn_fp2_384_t   *Q_x,
                              const zkn_fp2_384_t   *Q_y,
                              const zkn_fe384_t      P_x,
                              const zkn_fe384_t      P_y,
                              const zkn_mont_ctx384_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_PAIRING_384_H */
