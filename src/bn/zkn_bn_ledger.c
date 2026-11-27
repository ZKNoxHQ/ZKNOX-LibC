/*
 * zkn_bn_ledger.c — Ledger-specific helper functions
 *
 * These helpers (zkn_montgomery_init / zkn_montgomery_export) use the
 * Ledger SDK cx_bn_* / cx_mont_* primitives directly. They have no
 * software-backend equivalent, so the entire file is conditionally
 * compiled only when ZKN_BN_BACKEND_LEDGER is defined.
 *
 * For consumers that need similar helpers in software mode, equivalent
 * functionality is available via the standard zkn_bn_* / zkn_mont_*
 * API (see zkn_bn_sw.h).
 */

#ifdef ZKN_BN_BACKEND_LEDGER

#include <stdint.h>  // uint*_t
#include <stdbool.h> // bool
#include <stddef.h>  // size_t
#include "os.h"
#include "cx.h"
#include "zkn_errors.h"
#include "zkn_bn.h"
/* import from  MSB hexa to Montgomery*/
/* out is already allocated*/
int zkn_montgomery_init(cx_bn_mont_ctx_t *mont, uint8_t *in, size_t len, cx_bn_t out)
{
    ZKN_ERROR_INIT();
    cx_bn_t tmp;
    ZKN_CHECK(cx_bn_alloc(&tmp, len));
    ZKN_CHECK(cx_bn_init(tmp, in, len));
    ZKN_CHECK(cx_mont_to_montgomery(tmp, out, mont));
    ZKN_CHECK(cx_bn_destroy(&tmp));
    ZKN_ERROR_CLOSE();
}
/* export from Montgomery to MSB hexa*/
int zkn_montgomery_export(cx_bn_mont_ctx_t *mont, cx_bn_t in, uint8_t *out, size_t len)
{
    ZKN_ERROR_INIT();
    cx_bn_t tmp;
    ZKN_CHECK(cx_bn_alloc(&tmp, len));
    ZKN_CHECK(cx_mont_from_montgomery(tmp, in, mont));
    ZKN_CHECK(cx_bn_export(tmp, out, len));
    ZKN_CHECK(cx_bn_destroy(&tmp));
    ZKN_ERROR_CLOSE();
}

#if defined(ZKN_CX_NO_ALIAS) || defined(ZKN_CX_UNREDUCED)
/* A fresh bignum of the size of `like`. */
static cx_err_t na_fresh(cx_bn_t *t, cx_bn_t like)
{
    size_t nbytes = 0;
    cx_err_t err = cx_bn_nbytes(like, &nbytes);
    if (err != CX_OK) {
        return err;
    }
    return cx_bn_alloc(t, nbytes);
}
#endif

#if defined(ZKN_CX_NO_ALIAS)
/* ──────────────────────────────────────────────────────────────────────
 * The primitives that accept a result bignum which is also an operand.
 * See zkn_bn.h for the fault this works around.
 *
 * Aliased call: the syscall writes into a fresh bignum, which is then copied
 * to the result and released. That bignum lives in the cx pool like every
 * other one, so cx_bn_unlock erases it with the rest.
 * ────────────────────────────────────────────────────────────────────── */

/* r = t if the computation succeeded; t is released either way. */
static cx_err_t na_commit(cx_bn_t r, cx_bn_t *t, cx_err_t err)
{
    cx_err_t err2;
    if (err == CX_OK) {
        err = cx_bn_copy(r, *t);
    }
    err2 = cx_bn_destroy(t);
    return (err != CX_OK) ? err : err2;
}

cx_err_t zkn_cx_bn_reduce(cx_bn_t r, const cx_bn_t d, const cx_bn_t n)
{
    cx_bn_t t;
    cx_err_t err;
    if (r != d) {
        return cx_bn_reduce(r, d, n);
    }
    err = na_fresh(&t, r);
    if (err != CX_OK) {
        return err;
    }
    return na_commit(r, &t, cx_bn_reduce(t, d, n));
}

cx_err_t zkn_cx_bn_mod_mul(cx_bn_t r, const cx_bn_t a, const cx_bn_t b, const cx_bn_t n)
{
    cx_bn_t t;
    cx_err_t err;
    if (r != a && r != b) {
        return cx_bn_mod_mul(r, a, b, n);
    }
    err = na_fresh(&t, r);
    if (err != CX_OK) {
        return err;
    }
    return na_commit(r, &t, cx_bn_mod_mul(t, a, b, n));
}

cx_err_t zkn_cx_mont_to_montgomery(cx_bn_t x, const cx_bn_t z, const cx_bn_mont_ctx_t *ctx)
{
    cx_bn_t t;
    cx_err_t err;
    if (x != z) {
        return cx_mont_to_montgomery(x, z, ctx);
    }
    err = na_fresh(&t, x);
    if (err != CX_OK) {
        return err;
    }
    return na_commit(x, &t, cx_mont_to_montgomery(t, z, ctx));
}

cx_err_t zkn_cx_mont_from_montgomery(cx_bn_t z, const cx_bn_t x, const cx_bn_mont_ctx_t *ctx)
{
    cx_bn_t t;
    cx_err_t err;
    if (z != x) {
        return cx_mont_from_montgomery(z, x, ctx);
    }
    err = na_fresh(&t, z);
    if (err != CX_OK) {
        return err;
    }
    return na_commit(z, &t, cx_mont_from_montgomery(t, x, ctx));
}

cx_err_t zkn_cx_mont_mul(cx_bn_t r, const cx_bn_t a, const cx_bn_t b, const cx_bn_mont_ctx_t *ctx)
{
    cx_bn_t t;
    cx_err_t err;
    if (r != a && r != b) {
        return cx_mont_mul(r, a, b, ctx);
    }
    err = na_fresh(&t, r);
    if (err != CX_OK) {
        return err;
    }
    return na_commit(r, &t, cx_mont_mul(t, a, b, ctx));
}

cx_err_t zkn_cx_mont_pow(cx_bn_t r, const cx_bn_t a, const uint8_t *e, uint32_t e_len,
                         const cx_bn_mont_ctx_t *ctx)
{
    cx_bn_t t;
    cx_err_t err;
    if (r != a) {
        return cx_mont_pow(r, a, e, e_len, ctx);
    }
    err = na_fresh(&t, r);
    if (err != CX_OK) {
        return err;
    }
    return na_commit(r, &t, cx_mont_pow(t, a, e, e_len, ctx));
}
#endif /* ZKN_CX_NO_ALIAS */

#if defined(ZKN_CX_UNREDUCED)
/* ──────────────────────────────────────────────────────────────────────
 * Comparisons of residues. See zkn_bn.h: on this device a value modulo n
 * may be held as that value plus n.
 * ────────────────────────────────────────────────────────────────────── */

/* t = x mod n, in a fresh bignum. The reduction never runs in place: that
 * is one of the calls the device gets wrong. */
static cx_err_t ur_reduced(cx_bn_t *t, cx_bn_t x, cx_bn_t n)
{
    cx_err_t err = na_fresh(t, n);
    if (err != CX_OK) {
        return err;
    }
    err = cx_bn_reduce(*t, x, n);
    if (err != CX_OK) {
        cx_bn_destroy(t);
    }
    return err;
}

cx_err_t zkn_cx_bn_cmp_mod(const cx_bn_t a, const cx_bn_t b, const cx_bn_t n, int *diff)
{
    cx_bn_t ta, tb;
    cx_err_t err, err2;
    err = ur_reduced(&ta, a, n);
    if (err != CX_OK) {
        return err;
    }
    err = ur_reduced(&tb, b, n);
    if (err == CX_OK) {
        err = cx_bn_cmp(ta, tb, diff);
        err2 = cx_bn_destroy(&tb);
        if (err == CX_OK) {
            err = err2;
        }
    }
    err2 = cx_bn_destroy(&ta);
    return (err != CX_OK) ? err : err2;
}

cx_err_t zkn_cx_bn_cmp_u32_mod(const cx_bn_t a, uint32_t v, const cx_bn_t n, int *diff)
{
    cx_bn_t ta;
    cx_err_t err, err2;
    err = ur_reduced(&ta, a, n);
    if (err != CX_OK) {
        return err;
    }
    err = cx_bn_cmp_u32(ta, v, diff);
    err2 = cx_bn_destroy(&ta);
    return (err != CX_OK) ? err : err2;
}
#endif /* ZKN_CX_UNREDUCED */

#endif /* ZKN_BN_BACKEND_LEDGER */
