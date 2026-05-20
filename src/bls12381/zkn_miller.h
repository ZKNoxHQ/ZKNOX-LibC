/*
 * zkn_miller.h — Miller loop variants for BLS12-381 optimal ate pairing
 *
 * Three variants sharing the same NAF loop over |u| = 0xd201000000010000:
 *
 *   zkn_miller_loop        single pair (P, Q)
 *   zkn_miller_loop_lines  precomputed lines for fixed Q, variable P
 *   zkn_miller_loop_n      batch of n pairs
 *
 *   zkn_precompute_lines   precompute 68 raw lines for a fixed Q
 *
 * Montgomery conversion of G1 affine coordinates is handled internally.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_MILLER_H
#define ZKN_MILLER_H

#include "zkn_pairing_384.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════════════════════════════════
 *  Raw line coefficients for precomputed-line API
 *
 *  Same layout as zkn_line_384_t but c1/c4 are NOT yet scaled by xP/yP.
 *  P is injected at consumption time in zkn_miller_loop_lines.
 * ══════════════════════════════════════════════════════════════════════ */

typedef struct {
    zkn_fp2_384_t c0;
    zkn_fp2_384_t c1;   /* raw, multiply by xP_mont before use */
    zkn_fp2_384_t c4;   /* raw, multiply by yP_mont before use */
} zkn_line_raw_384_t;

/* ── Single-pair Miller loop ────────────────────────────────────────── */

void zkn_miller_loop(zkn_fp12_384_t      *f,
                     const zkn_g1_384_t  *P,
                     const zkn_g2_384_t  *Q,
                     const zkn_mont_ctx384_t *ctx);

/* ── Precompute 68 raw lines for fixed Q ────────────────────────────── */

void zkn_precompute_lines(zkn_line_raw_384_t    lines[68],
                          const zkn_g2_384_t   *Q,
                          const zkn_mont_ctx384_t *ctx);

/* ── Miller loop from precomputed lines (variable P, fixed Q) ────────── */

void zkn_miller_loop_lines(zkn_fp12_384_t           *f,
                           const zkn_line_raw_384_t  lines[68],
                           const zkn_g1_384_t        *P,
                           const zkn_mont_ctx384_t   *ctx);

/* ── Batch Miller loop: f = ∏ ML(Ps[i], Qs[i]) ─────────────────────── */

void zkn_miller_loop_n(zkn_fp12_384_t          *f,
                       const zkn_g1_384_t *const Ps[],
                       const zkn_g2_384_t *const Qs[],
                       size_t                    n,
                       const zkn_mont_ctx384_t  *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_MILLER_H */
