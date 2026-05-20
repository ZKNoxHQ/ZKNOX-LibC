/*
 * zkn_bn.c — Ledger cx_bn/cx_mont compatible API over zkn_mont256
 *
 * Thin wrapper: all real work delegated to zkn_mont256 functions.
 * Lifecycle functions (lock/unlock/alloc/destroy) are no-ops since
 * data lives on the stack, not in a heap pool.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_bn_sw.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 *  Lifecycle — no-ops
 * ══════════════════════════════════════════════════════════════════════ */

int zkn_bn_lock(size_t word_nbytes, uint32_t flags)
{
    (void)word_nbytes;
    (void)flags;
    return ZKN_OK;
}

int zkn_bn_unlock(void)
{
    return ZKN_OK;
}

int zkn_bn_alloc(zkn_bn_t *x, size_t nbytes)
{
    (void)nbytes;
    zkn_fe256_zero(*x);
    return ZKN_OK;
}

int zkn_bn_alloc_init(zkn_bn_t *x, size_t nbytes,
                      const uint8_t *value, size_t value_nbytes)
{
    (void)nbytes;
    (void)value_nbytes;
    zkn_fe256_from_be(*x, value);
    return ZKN_OK;
}

int zkn_bn_destroy(zkn_bn_t *x)
{
    (void)x;
    return ZKN_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Init / copy / export
 * ══════════════════════════════════════════════════════════════════════ */

int zkn_bn_init(zkn_bn_t x, const uint8_t *value, size_t value_nbytes)
{
    (void)value_nbytes;
    zkn_fe256_from_be(x, value);
    return ZKN_OK;
}

int zkn_bn_set_u32(zkn_bn_t x, uint32_t n)
{
    zkn_fe256_zero(x);
    x[0] = n;
    return ZKN_OK;
}

int zkn_bn_copy(zkn_bn_t a, const zkn_bn_t b)
{
    memcpy(a, b, sizeof(zkn_fe256_t));
    return ZKN_OK;
}

int zkn_bn_export(const zkn_bn_t x, uint8_t *bytes, size_t nbytes)
{
    (void)nbytes;
    zkn_fe256_to_be(bytes, x);
    return ZKN_OK;
}

int zkn_bn_nbytes(const zkn_bn_t x, size_t *nbytes)
{
    (void)x;
    *nbytes = ZKN_MONT_BYTES;
    return ZKN_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Modular arithmetic
 * ══════════════════════════════════════════════════════════════════════ */

int zkn_bn_mod_add(zkn_bn_t r, const zkn_bn_t a,
                   const zkn_bn_t b, const zkn_bn_t n)
{
    zkn_add_mod_256(r, a, b, n);
    return ZKN_OK;
}

int zkn_bn_mod_sub(zkn_bn_t r, const zkn_bn_t a,
                   const zkn_bn_t b, const zkn_bn_t n)
{
    zkn_sub_mod_256(r, a, b, n);
    return ZKN_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Montgomery operations
 * ══════════════════════════════════════════════════════════════════════ */

int zkn_mont_alloc(zkn_bn_mont_ctx_t *ctx, size_t length)
{
    (void)ctx;
    (void)length;
    return ZKN_OK;
}

int zkn_mont_init(zkn_bn_mont_ctx_t *ctx, const zkn_bn_t n)
{
    /*
     * Reuse zkn_mont_ctx256_t init logic but map to our layout.
     * Our struct has the same fields, just named 'n' instead of 'p'.
     */
    zkn_mont_ctx256_t tmp;
    zkn_mont_ctx_init(&tmp, n);

    memcpy(ctx->n, tmp.p, sizeof(zkn_bn_t));
    ctx->n0 = tmp.n0;
    memcpy(ctx->R2, tmp.R2, sizeof(zkn_bn_t));
    memcpy(ctx->one, tmp.one, sizeof(zkn_bn_t));

    return ZKN_OK;
}

int zkn_mont_to_montgomery(zkn_bn_t x, const zkn_bn_t z,
                           const zkn_bn_mont_ctx_t *ctx)
{
    /* x = z * R^2 * R^{-1} = z * R mod n */
    zkn_mul_mont_256(x, z, ctx->R2, ctx->n, ctx->n0);
    return ZKN_OK;
}

int zkn_mont_from_montgomery(zkn_bn_t z, const zkn_bn_t x,
                             const zkn_bn_mont_ctx_t *ctx)
{
    zkn_from_mont_256(z, x, ctx->n, ctx->n0);
    return ZKN_OK;
}

int zkn_mont_mul(zkn_bn_t r, const zkn_bn_t a, const zkn_bn_t b,
                 const zkn_bn_mont_ctx_t *ctx)
{
    zkn_mul_mont_256(r, a, b, ctx->n, ctx->n0);
    return ZKN_OK;
}

int zkn_mont_pow(zkn_bn_t r, const zkn_bn_t x,
                 const uint8_t *exp, uint32_t exp_len,
                 const zkn_bn_mont_ctx_t *ctx)
{
    /* Map to zkn_exp_mont_256 which expects a full mont_ctx256_t.
     * Our layout is binary-compatible, cast through. */
    zkn_exp_mont_256(r, x, exp, (int)exp_len,
                     (const zkn_mont_ctx256_t *)ctx);
    return ZKN_OK;
}


/* ══════════════════════════════════════════════════════════════════════
 *  Functions added for compatibility with the Ledger SDK API surface
 *  (used by zknox_1905 high-level code).
 * ══════════════════════════════════════════════════════════════════════ */

int zkn_bn_cmp(const zkn_bn_t a, const zkn_bn_t b, int *diff)
{
    if (diff == NULL) return ZKN_INVALID_PARAM;
    /* Compare limb-by-limb from MSB (limb index NLIMBS-1) down to LSB. */
    for (int i = ZKN_MONT_NLIMBS - 1; i >= 0; i--) {
        if (a[i] > b[i]) { *diff =  1; return ZKN_OK; }
        if (a[i] < b[i]) { *diff = -1; return ZKN_OK; }
    }
    *diff = 0;
    return ZKN_OK;
}

int zkn_bn_cmp_u32(const zkn_bn_t a, uint32_t n, int *diff)
{
    if (diff == NULL) return ZKN_INVALID_PARAM;
    /* If any high limb is non-zero, a > n. */
    for (int i = ZKN_MONT_NLIMBS - 1; i >= 1; i--) {
        if (a[i] != 0) { *diff = 1; return ZKN_OK; }
    }
    if (a[0] > n)      *diff =  1;
    else if (a[0] < n) *diff = -1;
    else               *diff =  0;
    return ZKN_OK;
}

int zkn_bn_tst_bit(const zkn_bn_t x, uint32_t n, bool *set)
{
    if (set == NULL) return ZKN_INVALID_PARAM;
    if (n >= ZKN_MONT_NLIMBS * 32) {
        *set = false;
        return ZKN_OK;
    }
    uint32_t limb_idx = n / 32;
    uint32_t bit_idx  = n % 32;
    *set = ((x[limb_idx] >> bit_idx) & 1u) != 0;
    return ZKN_OK;
}

int zkn_bn_reduce(zkn_bn_t r, const zkn_bn_t value, const zkn_bn_t modulus)
{
    /* Copy value into r, then if r >= modulus subtract modulus once. */
    memcpy(r, value, sizeof(zkn_fe256_t));
    int diff = 0;
    zkn_bn_cmp(r, modulus, &diff);
    if (diff >= 0) {
        zkn_sub_mod_256(r, r, modulus, modulus);
    }
    return ZKN_OK;
}

int zkn_bn_mod_mul(zkn_bn_t r, const zkn_bn_t a,
                   const zkn_bn_t b, const zkn_bn_t modulus)
{
    /* Plain modular multiply (not Montgomery form): we do
     *   r_mont = to_mont(a) · to_mont(b) · R⁻¹  (= a·b·R in Mont form)
     *   r      = from_mont(r_mont)              (= a·b)
     * Build a temporary mont ctx on-the-fly from the modulus.
     */
    zkn_bn_mont_ctx_t ctx;
    int err = zkn_mont_init(&ctx, modulus);
    if (err != ZKN_OK) return err;

    zkn_bn_t am, bm, rm;
    zkn_mont_to_montgomery(am, a, &ctx);
    zkn_mont_to_montgomery(bm, b, &ctx);
    zkn_mont_mul(rm, am, bm, &ctx);
    zkn_mont_from_montgomery(r, rm, &ctx);
    return ZKN_OK;
}

int zkn_bn_mod_invert_nprime(zkn_bn_t r, const zkn_bn_t a, const zkn_bn_t n)
{
    /* Fermat's little theorem: a^{-1} = a^{n-2} mod n (n prime).
     * Compute n-2 as a big-endian byte array, then zkn_mont_pow. */
    zkn_bn_t nm2;
    zkn_bn_t two;
    zkn_bn_set_u32(two, 2);
    /* Modular subtraction would wrap; for n prime > 2, n-2 is well-defined. */
    /* Use raw 256-bit subtraction (no modulus reduction). */
    /* zkn_sub_mod_256(r, a, b, m): r = (a - b) mod m. We want n - 2 (no mod). */
    /* Trick: use n itself as modulus, n - 2 is < n so no reduction kicks in. */
    zkn_sub_mod_256(nm2, n, two, n);

    /* Serialize nm2 to big-endian bytes for zkn_mont_pow exponent input. */
    uint8_t exp_be[ZKN_MONT_BYTES];
    zkn_fe256_to_be(exp_be, nm2);

    /* Now compute a^{nm2} mod n via Montgomery exponentiation. */
    zkn_bn_mont_ctx_t ctx;
    int err = zkn_mont_init(&ctx, n);
    if (err != ZKN_OK) return err;

    zkn_bn_t am, rm;
    zkn_mont_to_montgomery(am, a, &ctx);
    zkn_mont_pow(rm, am, exp_be, ZKN_MONT_BYTES, &ctx);
    zkn_mont_from_montgomery(r, rm, &ctx);
    return ZKN_OK;
}

int zkn_mont_destroy(zkn_bn_mont_ctx_t *ctx)
{
    /* No-op: ctx lives on the stack of the caller, nothing to free. */
    (void)ctx;
    return ZKN_OK;
}

int zkn_mont_invert_nprime(zkn_bn_t r, const zkn_bn_t a,
                           const zkn_bn_mont_ctx_t *ctx)
{
    /* a is in Montgomery form. We want r = a^{-1} (still in Montgomery form).
     * Strategy: convert a out of Mont → x; invert x via Fermat → x^{-1};
     * convert x^{-1} back to Mont form. */
    zkn_bn_t x, x_inv;
    zkn_mont_from_montgomery(x, a, ctx);
    int err = zkn_bn_mod_invert_nprime(x_inv, x, ctx->n);
    if (err != ZKN_OK) return err;
    zkn_mont_to_montgomery(r, x_inv, ctx);
    return ZKN_OK;
}
