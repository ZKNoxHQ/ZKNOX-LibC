/*
 * zkn_g1_384.h — G1 curve arithmetic for BLS12-381
 *
 * Curve E(Fp): y² = x³ + 4
 * Points in Jacobian coordinates (X : Y : Z), affine = (X/Z², Y/Z³).
 * Point at infinity: Z = 0.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_G1_384_H
#define ZKN_G1_384_H

#include "zkn_mont384.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Types ─────────────────────────────────────────────────────────── */

typedef struct {
    zkn_fe384_t X;
    zkn_fe384_t Y;
    zkn_fe384_t Z;
} zkn_g1_384_t;

/* ── Constructors ──────────────────────────────────────────────────── */

void zkn_g1_384_zero(zkn_g1_384_t *r);
void zkn_g1_384_copy(zkn_g1_384_t *r, const zkn_g1_384_t *a);
int  zkn_g1_384_is_zero(const zkn_g1_384_t *a);

/** Standard generator of G1. Returns point in Jacobian (Z = R mod p). */
void zkn_g1_384_generator(zkn_g1_384_t *r, const zkn_mont_ctx384_t *ctx);

/** Set from affine coordinates (converts to Jacobian/Montgomery). */
void zkn_g1_384_from_affine(zkn_g1_384_t *r,
                            const zkn_fe384_t x,
                            const zkn_fe384_t y,
                            const zkn_mont_ctx384_t *ctx);

/** Convert to affine. r_x, r_y receive normal (non-Montgomery) values. */
void zkn_g1_384_to_affine(zkn_fe384_t r_x, zkn_fe384_t r_y,
                          const zkn_g1_384_t *p,
                          const zkn_mont_ctx384_t *ctx);

/* ── Comparison ────────────────────────────────────────────────────── */

/** Jacobian equality: X1·Z2² = X2·Z1² and Y1·Z2³ = Y2·Z1³. */
int zkn_g1_384_eq(const zkn_g1_384_t *a, const zkn_g1_384_t *b,
                  const zkn_mont_ctx384_t *ctx);

/** Check Y² = X³ + 4·Z⁶ in Jacobian coordinates. */
int zkn_g1_384_on_curve(const zkn_g1_384_t *p,
                        const zkn_mont_ctx384_t *ctx);

/* ── Point arithmetic ──────────────────────────────────────────────── */

void zkn_g1_384_neg(zkn_g1_384_t *r, const zkn_g1_384_t *a,
                    const zkn_mont_ctx384_t *ctx);

/** Doubling (a=0 shortcut): ~4M + 4S. */
void zkn_g1_384_dbl(zkn_g1_384_t *r, const zkn_g1_384_t *a,
                    const zkn_mont_ctx384_t *ctx);

/** Full addition: ~12M + 4S. Handles all edge cases. */
void zkn_g1_384_add(zkn_g1_384_t *r,
                    const zkn_g1_384_t *a,
                    const zkn_g1_384_t *b,
                    const zkn_mont_ctx384_t *ctx);

/** Mixed addition (b.Z = 1): ~8M + 3S. */
void zkn_g1_384_add_mixed(zkn_g1_384_t *r,
                          const zkn_g1_384_t *a,
                          const zkn_g1_384_t *b,
                          const zkn_mont_ctx384_t *ctx);

/** Scalar multiplication (double-and-add, left-to-right). */
void zkn_g1_384_mul(zkn_g1_384_t *r,
                    const zkn_g1_384_t *p,
                    const uint8_t *scalar_be,
                    int scalar_len,
                    const zkn_mont_ctx384_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_G1_384_H */

/* ══════════════════════════════════════════════════════════════════════
 *  Multi-scalar multiplication (Straus interleaving)
 * ══════════════════════════════════════════════════════════════════════ */

/** 2-point MSM: r = s1·P1 + s2·P2  (Straus, 256 doublings). */
void zkn_g1_384_msm2(zkn_g1_384_t *r,
                     const zkn_g1_384_t *P1, const uint8_t s1_be[32],
                     const zkn_g1_384_t *P2, const uint8_t s2_be[32],
                     const zkn_mont_ctx384_t *ctx);

/** 3-point MSM: r = s1·P1 + s2·P2 + s3·P3  (Straus, 256 doublings). */
void zkn_g1_384_msm3(zkn_g1_384_t *r,
                     const zkn_g1_384_t *P1, const uint8_t s1_be[32],
                     const zkn_g1_384_t *P2, const uint8_t s2_be[32],
                     const zkn_g1_384_t *P3, const uint8_t s3_be[32],
                     const zkn_mont_ctx384_t *ctx);

/** Generic k-point MSM: r = Σ s[i]·P[i]  (split into Straus pairs).
 *  Scalars are 32-byte big-endian. */
void zkn_g1_384_msm(zkn_g1_384_t *r,
                    const zkn_g1_384_t *points,
                    const uint8_t      *scalars_be,  /* k × 32 bytes */
                    int                 k,
                    const zkn_mont_ctx384_t *ctx);
