/*
 * zkn_bn.h — Ledger cx_bn/cx_mont compatible API over zkn_mont256
 *
 * Drop-in replacement for the Ledger SDK big number / Montgomery API.
 * Replace cx_ with zkn_ in your code and link against this instead.
 *
 * Key difference from Ledger SDK:
 *   - cx_bn_t is a handle (uint32_t index) into a heap-allocated pool.
 *   - zkn_bn_t IS the data (uint32_t[8] on the stack).
 *   → alloc/lock/unlock/destroy become no-ops.
 *   → Structs containing zkn_bn_t are larger but self-contained.
 *
 * Return values: all functions return int (0 = ZKN_OK, nonzero = error).
 * Compatible with ZKN_CHECK() macro from zkn_errors.h.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_BN_SW_H
#define ZKN_BN_SW_H

#include <stdbool.h>
#include <stdint.h>
#include "zkn_mont256.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ───────────────────────────────────────────────────── */

#define ZKN_OK              0
#define ZKN_INVALID_PARAM  -1
#define ZKN_OVERFLOW        -2

/* ── Types ─────────────────────────────────────────────────────────── */

/**
 * Big number: 256-bit value stored inline (8 × uint32_t, LE).
 *
 * In Ledger SDK, cx_bn_t is a uint32_t handle into a pool.
 * Here, the data lives directly in the variable.
 * Array semantics: decays to pointer when passed to functions.
 */
typedef zkn_fe256_t zkn_bn_t;

/**
 * Montgomery context.
 *
 * Drop-in for cx_bn_mont_ctx_t. The member 'n' holds the modulus
 * (same role as cx_bn_mont_ctx_t.n in the Ledger SDK).
 */
typedef struct {
    zkn_bn_t    n;       /* modulus (accessible as ctx->n)         */
    zkn_limb_t  n0;      /* -n^{-1} mod 2^32                      */
    zkn_bn_t    R2;      /* R^2 mod n                              */
    zkn_bn_t    one;     /* R mod n = Montgomery(1)                */
} zkn_bn_mont_ctx_t;

/* ══════════════════════════════════════════════════════════════════════
 *  Lifecycle — no-ops (stack-based, no heap allocation)
 *
 *  These exist solely so that cx_bn_lock/unlock/alloc/destroy calls
 *  compile and succeed without modification.
 * ══════════════════════════════════════════════════════════════════════ */

/** No-op. Returns ZKN_OK. */
int zkn_bn_lock(size_t word_nbytes, uint32_t flags);

/** No-op. Returns ZKN_OK. */
int zkn_bn_unlock(void);

/** Zeroes *x. Returns ZKN_OK. */
int zkn_bn_alloc(zkn_bn_t *x, size_t nbytes);

/** Zeroes *x, then loads value (big-endian). Returns ZKN_OK. */
int zkn_bn_alloc_init(zkn_bn_t *x, size_t nbytes,
                      const uint8_t *value, size_t value_nbytes);

/** No-op. Returns ZKN_OK. */
int zkn_bn_destroy(zkn_bn_t *x);

/* ══════════════════════════════════════════════════════════════════════
 *  Init / copy / export
 * ══════════════════════════════════════════════════════════════════════ */

/** Load from big-endian bytes. */
int zkn_bn_init(zkn_bn_t x, const uint8_t *value, size_t value_nbytes);

/** Set from a uint32_t value. */
int zkn_bn_set_u32(zkn_bn_t x, uint32_t n);

/** Copy: a = b. */
int zkn_bn_copy(zkn_bn_t a, const zkn_bn_t b);

/** Export to big-endian bytes. */
int zkn_bn_export(const zkn_bn_t x, uint8_t *bytes, size_t nbytes);

/** Get size in bytes (always 32). */
int zkn_bn_nbytes(const zkn_bn_t x, size_t *nbytes);

/* ══════════════════════════════════════════════════════════════════════
 *  Modular arithmetic
 * ══════════════════════════════════════════════════════════════════════ */

/** r = (a + b) mod n */
int zkn_bn_mod_add(zkn_bn_t r, const zkn_bn_t a,
                   const zkn_bn_t b, const zkn_bn_t n);

/** r = (a - b) mod n */
int zkn_bn_mod_sub(zkn_bn_t r, const zkn_bn_t a,
                   const zkn_bn_t b, const zkn_bn_t n);

/* ══════════════════════════════════════════════════════════════════════
 *  Montgomery operations
 * ══════════════════════════════════════════════════════════════════════ */

/** No-op (context is stack-allocated). Returns ZKN_OK. */
int zkn_mont_alloc(zkn_bn_mont_ctx_t *ctx, size_t length);

/** Initialize Montgomery context from modulus n. */
int zkn_mont_init(zkn_bn_mont_ctx_t *ctx, const zkn_bn_t n);

/** Convert to Montgomery: x = z·R mod n. */
int zkn_mont_to_montgomery(zkn_bn_t x, const zkn_bn_t z,
                           const zkn_bn_mont_ctx_t *ctx);

/** Convert from Montgomery: z = x·R⁻¹ mod n. */
int zkn_mont_from_montgomery(zkn_bn_t z, const zkn_bn_t x,
                             const zkn_bn_mont_ctx_t *ctx);

/** Montgomery multiply: r = a·b·R⁻¹ mod n. */
int zkn_mont_mul(zkn_bn_t r, const zkn_bn_t a, const zkn_bn_t b,
                 const zkn_bn_mont_ctx_t *ctx);

/**
 * Montgomery power: r = x^exp mod n (in Montgomery form).
 * exp is a big-endian byte array of exp_len bytes.
 */
int zkn_mont_pow(zkn_bn_t r, const zkn_bn_t x,
                 const uint8_t *exp, uint32_t exp_len,
                 const zkn_bn_mont_ctx_t *ctx);



/* ══════════════════════════════════════════════════════════════════════
 * Functions added for compatibility with the Ledger SDK API surface
 * (used by zknox_1905 high-level code: ecc/, bls12381/).
 * ══════════════════════════════════════════════════════════════════════ */

/** Compare two big numbers: *diff = (a > b) ? +1 : (a < b) ? -1 : 0. */
int zkn_bn_cmp(const zkn_bn_t a, const zkn_bn_t b, int *diff);

/** Compare a big number with a 32-bit constant: *diff = sign(a - n). */
int zkn_bn_cmp_u32(const zkn_bn_t a, uint32_t n, int *diff);

/** Modular reduce: r = value mod modulus.
 *  Reduces a bignum (already 32 bytes wide). Result placed in r. */
int zkn_bn_reduce(zkn_bn_t r, const zkn_bn_t value, const zkn_bn_t modulus);

/** Test bit n of x: *set = (bit_n(x) != 0). */
int zkn_bn_tst_bit(const zkn_bn_t x, uint32_t n, bool *set);

/** Modular multiply: r = (a · b) mod modulus. */
int zkn_bn_mod_mul(zkn_bn_t r, const zkn_bn_t a,
                   const zkn_bn_t b, const zkn_bn_t modulus);

/** Modular inverse (n prime): r = a^{-1} mod n.
 *  Uses Fermat's little theorem: a^{n-2} mod n. */
int zkn_bn_mod_invert_nprime(zkn_bn_t r, const zkn_bn_t a, const zkn_bn_t n);

/** No-op destructor for Montgomery context (matches SDK API). */
int zkn_mont_destroy(zkn_bn_mont_ctx_t *ctx);

/** Montgomery inverse (n prime): r = a^{-1} mod ctx->n. */
int zkn_mont_invert_nprime(zkn_bn_t r, const zkn_bn_t a,
                           const zkn_bn_mont_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_BN_SW_H */
