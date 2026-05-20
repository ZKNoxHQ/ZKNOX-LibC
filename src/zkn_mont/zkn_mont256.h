/*
 * zkn_mont256.h — 256-bit Montgomery arithmetic for ARM 32-bit
 *
 * Pure software implementation targeting Ledger Nano (ARM SC300 / Cortex-M).
 * All operations are constant-time (no secret-dependent branches or memory access).
 *
 * Number representation:
 *   256-bit integers are stored as 8 × uint32_t limbs in LITTLE-ENDIAN order:
 *     a[0] is the least significant 32 bits, a[7] the most significant.
 *
 * Montgomery form:
 *   A value 'a' is represented as aR mod p, where R = 2^256.
 *   n0 = -p^{-1} mod 2^32  (single-limb Montgomery constant).
 *
 * Adapted from the blst library's approach for 64-bit, re-targeted to 32-bit
 * ARM with 8-limb representation and Thumb-2 umull/umlal.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_MONT256_H
#define ZKN_MONT256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Types ─────────────────────────────────────────────────────────── */

#define ZKN_MONT_NLIMBS  8
#define ZKN_MONT_BYTES   32

typedef uint32_t  zkn_limb_t;
typedef uint64_t  zkn_dlimb_t;

/* A 256-bit field element in Montgomery form (8 × 32-bit limbs, LE). */
typedef zkn_limb_t zkn_fe256_t[ZKN_MONT_NLIMBS];

/* A 512-bit intermediate (16 limbs), used by redc. */
typedef zkn_limb_t zkn_wide256_t[2 * ZKN_MONT_NLIMBS];

/* Montgomery context: prime + precomputed constants. */
typedef struct {
    zkn_fe256_t p;      /* The prime modulus                        */
    zkn_limb_t  n0;     /* -p^{-1} mod 2^32                        */
    zkn_fe256_t R2;     /* R^2 mod p, for converting to Montgomery  */
    zkn_fe256_t one;    /* R mod p = Montgomery(1)                  */
} zkn_mont_ctx256_t;

/* ── Core arithmetic (constant-time) ───────────────────────────────── */

/**
 * Montgomery multiplication: r = a * b * R^{-1} mod p
 * Uses CIOS (Coarsely Integrated Operand Scanning).
 */
void zkn_mul_mont_256(zkn_fe256_t r,
                      const zkn_fe256_t a,
                      const zkn_fe256_t b,
                      const zkn_fe256_t p,
                      zkn_limb_t n0);

/**
 * Montgomery squaring: r = a^2 * R^{-1} mod p
 */
void zkn_sqr_mont_256(zkn_fe256_t r,
                      const zkn_fe256_t a,
                      const zkn_fe256_t p,
                      zkn_limb_t n0);

/**
 * Modular addition: r = (a + b) mod p
 */
void zkn_add_mod_256(zkn_fe256_t r,
                     const zkn_fe256_t a,
                     const zkn_fe256_t b,
                     const zkn_fe256_t p);

/**
 * Modular subtraction: r = (a - b) mod p
 */
void zkn_sub_mod_256(zkn_fe256_t r,
                     const zkn_fe256_t a,
                     const zkn_fe256_t b,
                     const zkn_fe256_t p);

/**
 * Convert OUT of Montgomery: r = a * R^{-1} mod p
 */
void zkn_from_mont_256(zkn_fe256_t r,
                       const zkn_fe256_t a,
                       const zkn_fe256_t p,
                       zkn_limb_t n0);

/**
 * Montgomery reduction of a 512-bit value: r = a * R^{-1} mod p
 */
void zkn_redc_mont_256(zkn_fe256_t r,
                       const zkn_wide256_t a,
                       const zkn_fe256_t p,
                       zkn_limb_t n0);

/* ── Context / helpers ─────────────────────────────────────────────── */

/** Compute n0 = -p^{-1} mod 2^32 via Newton's method. */
zkn_limb_t zkn_mont_compute_n0(zkn_limb_t p0);

/** Initialize a Montgomery context (computes n0, R mod p, R^2 mod p). */
void zkn_mont_ctx_init(zkn_mont_ctx256_t *ctx, const zkn_fe256_t p);

/** Convert TO Montgomery: r = a * R mod p */
void zkn_to_mont_256(zkn_fe256_t r,
                     const zkn_fe256_t a,
                     const zkn_mont_ctx256_t *ctx);

/** Load a 256-bit big-endian byte array into limb representation. */
void zkn_fe256_from_be(zkn_fe256_t r, const uint8_t src[ZKN_MONT_BYTES]);

/** Export limb representation to a 256-bit big-endian byte array. */
void zkn_fe256_to_be(uint8_t dst[ZKN_MONT_BYTES], const zkn_fe256_t a);

/** Constant-time comparison: returns 1 if a == b, 0 otherwise. */
int zkn_fe256_eq(const zkn_fe256_t a, const zkn_fe256_t b);

/** Set r = 0. */
void zkn_fe256_zero(zkn_fe256_t r);

/** Constant-time conditional copy: r = flag ? a : r  (flag must be 0 or 1). */
void zkn_fe256_cmov(zkn_fe256_t r, const zkn_fe256_t a, zkn_limb_t flag);

/**
 * Modular negation: r = -a mod p = p - a (constant-time).
 */
void zkn_neg_mod_256(zkn_fe256_t r,
                     const zkn_fe256_t a,
                     const zkn_fe256_t p);

/**
 * Constant-time modular exponentiation in Montgomery form.
 * r = base^exp mod p, where base is in Montgomery form.
 * Result is in Montgomery form.
 * exp_be is the exponent as a big-endian byte array.
 */
void zkn_exp_mont_256(zkn_fe256_t r,
                      const zkn_fe256_t base,
                      const uint8_t *exp_be,
                      int exp_len,
                      const zkn_mont_ctx256_t *ctx);

/**
 * Modular inversion in Montgomery form via Fermat: r = a^{-1} mod p.
 * Input and output in Montgomery form.
 * Undefined if a = 0.
 */
void zkn_inv_mont_256(zkn_fe256_t r,
                      const zkn_fe256_t a,
                      const zkn_mont_ctx256_t *ctx);

/* ── BabyJubjub convenience ────────────────────────────────────────── */

/**
 * Pre-initialized context for BabyJubjub base field (= BN254 scalar field):
 *   p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 */
const zkn_mont_ctx256_t *zkn_babyjubjub_ctx(void);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_MONT256_H */
