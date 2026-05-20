/*
 * zkn_g2_384.h — G2 curve arithmetic for BLS12-381
 *
 * Twist curve E'(Fp2): y² = x³ + 4(1+u)
 * Points in Jacobian coordinates over Fp2.
 * Point at infinity: Z = 0.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_G2_384_H
#define ZKN_G2_384_H

#include "zkn_fp2_384.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Types ─────────────────────────────────────────────────────────── */

typedef struct {
    zkn_fp2_384_t X;
    zkn_fp2_384_t Y;
    zkn_fp2_384_t Z;
} zkn_g2_384_t;

/* ── Constructors ──────────────────────────────────────────────────── */

void zkn_g2_384_zero(zkn_g2_384_t *r);
void zkn_g2_384_copy(zkn_g2_384_t *r, const zkn_g2_384_t *a);
int  zkn_g2_384_is_zero(const zkn_g2_384_t *a);

void zkn_g2_384_generator(zkn_g2_384_t *r, const zkn_mont_ctx384_t *ctx);

/** Set from affine Fp2 coordinates (converts to Jacobian/Montgomery). */
void zkn_g2_384_from_affine(zkn_g2_384_t *r,
                            const zkn_fp2_384_t *x,
                            const zkn_fp2_384_t *y,
                            const zkn_mont_ctx384_t *ctx);

/** Convert to affine. r_x, r_y receive normal (non-Montgomery) Fp2 values. */
void zkn_g2_384_to_affine(zkn_fp2_384_t *r_x, zkn_fp2_384_t *r_y,
                          const zkn_g2_384_t *p,
                          const zkn_mont_ctx384_t *ctx);

/* ── Comparison ────────────────────────────────────────────────────── */

int zkn_g2_384_eq(const zkn_g2_384_t *a, const zkn_g2_384_t *b,
                  const zkn_mont_ctx384_t *ctx);

int zkn_g2_384_on_curve(const zkn_g2_384_t *p,
                        const zkn_mont_ctx384_t *ctx);

/* ── Point arithmetic ──────────────────────────────────────────────── */

void zkn_g2_384_neg(zkn_g2_384_t *r, const zkn_g2_384_t *a,
                    const zkn_mont_ctx384_t *ctx);

void zkn_g2_384_dbl(zkn_g2_384_t *r, const zkn_g2_384_t *a,
                    const zkn_mont_ctx384_t *ctx);

void zkn_g2_384_add(zkn_g2_384_t *r,
                    const zkn_g2_384_t *a,
                    const zkn_g2_384_t *b,
                    const zkn_mont_ctx384_t *ctx);

void zkn_g2_384_add_mixed(zkn_g2_384_t *r,
                          const zkn_g2_384_t *a,
                          const zkn_g2_384_t *b,
                          const zkn_mont_ctx384_t *ctx);

void zkn_g2_384_mul(zkn_g2_384_t *r,
                    const zkn_g2_384_t *p,
                    const uint8_t *scalar_be,
                    int scalar_len,
                    const zkn_mont_ctx384_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_G2_384_H */
