/*
 * zkn_sw_mont384.h — 384-bit Montgomery arithmetic for ARM 32-bit
 *
 * Same architecture as zkn_mont256.h but for 384-bit primes (12 × uint32_t).
 * Primary target: BLS12-381 base field Fp.
 *
 * Number representation:
 *   384-bit integers as 12 × uint32_t limbs in LITTLE-ENDIAN order.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_SW_MONT384_H
#define ZKN_SW_MONT384_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Types ─────────────────────────────────────────────────────────── */

#define ZKN_SW_MONT384_NLIMBS  12
#define ZKN_SW_MONT384_BYTES   48

typedef uint32_t  zkn_sw_limb_t;
typedef uint64_t  zkn_sw_dlimb_t;

typedef zkn_sw_limb_t zkn_sw_fe384_t[ZKN_SW_MONT384_NLIMBS];
typedef zkn_sw_limb_t zkn_sw_wide384_t[2 * ZKN_SW_MONT384_NLIMBS];

typedef struct {
    zkn_sw_fe384_t p;
    zkn_sw_limb_t  n0;
    zkn_sw_fe384_t R2;
    zkn_sw_fe384_t one;
} zkn_sw_mont_ctx384_t;

/* ── Core arithmetic (constant-time) ───────────────────────────────── */

void zkn_sw_mul_mont_384(zkn_sw_fe384_t r,
                      const zkn_sw_fe384_t a,
                      const zkn_sw_fe384_t b,
                      const zkn_sw_fe384_t p,
                      zkn_sw_limb_t n0);

void zkn_sw_sqr_mont_384(zkn_sw_fe384_t r,
                      const zkn_sw_fe384_t a,
                      const zkn_sw_fe384_t p,
                      zkn_sw_limb_t n0);

void zkn_sw_add_mod_384(zkn_sw_fe384_t r,
                     const zkn_sw_fe384_t a,
                     const zkn_sw_fe384_t b,
                     const zkn_sw_fe384_t p);

void zkn_sw_sub_mod_384(zkn_sw_fe384_t r,
                     const zkn_sw_fe384_t a,
                     const zkn_sw_fe384_t b,
                     const zkn_sw_fe384_t p);

void zkn_sw_from_mont_384(zkn_sw_fe384_t r,
                       const zkn_sw_fe384_t a,
                       const zkn_sw_fe384_t p,
                       zkn_sw_limb_t n0);

void zkn_sw_redc_mont_384(zkn_sw_fe384_t r,
                       const zkn_sw_wide384_t a,
                       const zkn_sw_fe384_t p,
                       zkn_sw_limb_t n0);

/* ── Context / helpers ─────────────────────────────────────────────── */

zkn_sw_limb_t zkn_sw_mont384_compute_n0(zkn_sw_limb_t p0);
void zkn_sw_mont_ctx384_init(zkn_sw_mont_ctx384_t *ctx, const zkn_sw_fe384_t p);

void zkn_sw_to_mont_384(zkn_sw_fe384_t r,
                     const zkn_sw_fe384_t a,
                     const zkn_sw_mont_ctx384_t *ctx);

void zkn_sw_fe384_from_be(zkn_sw_fe384_t r, const uint8_t src[ZKN_SW_MONT384_BYTES]);
void zkn_sw_fe384_to_be(uint8_t dst[ZKN_SW_MONT384_BYTES], const zkn_sw_fe384_t a);

int  zkn_sw_fe384_eq(const zkn_sw_fe384_t a, const zkn_sw_fe384_t b);
void zkn_sw_fe384_zero(zkn_sw_fe384_t r);
void zkn_sw_fe384_cmov(zkn_sw_fe384_t r, const zkn_sw_fe384_t a, zkn_sw_limb_t flag);

void zkn_sw_neg_mod_384(zkn_sw_fe384_t r,
                     const zkn_sw_fe384_t a,
                     const zkn_sw_fe384_t p);

void zkn_sw_exp_mont_384(zkn_sw_fe384_t r,
                      const zkn_sw_fe384_t base,
                      const uint8_t *exp_be,
                      int exp_len,
                      const zkn_sw_mont_ctx384_t *ctx);

void zkn_sw_inv_mont_384(zkn_sw_fe384_t r,
                      const zkn_sw_fe384_t a,
                      const zkn_sw_mont_ctx384_t *ctx);

/* ── BLS12-381 convenience ─────────────────────────────────────────── */

const zkn_sw_mont_ctx384_t *zkn_sw_bls12381_ctx(void);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_SW_MONT384_H */
