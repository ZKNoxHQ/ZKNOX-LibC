/*
 * zkn_bn_ledger.h — helpers of the Ledger (cx) backend
 *
 * Included by zkn_bn.h, after os.h and cx.h, when ZKN_BN_BACKEND_LEDGER is
 * defined.
 */
#ifndef ZKN_BN_LEDGER_H
#define ZKN_BN_LEDGER_H

#include <stddef.h>
#include <stdint.h>

int zkn_montgomery_init(cx_bn_mont_ctx_t *mont, uint8_t *in, size_t len, cx_bn_t out);
int zkn_montgomery_export(cx_bn_mont_ctx_t *mont, cx_bn_t in, uint8_t *out, size_t len);

#if defined(ZKN_CX_NO_ALIAS)
/* The cx primitives that are wrong on Nano S when the result bignum is also
 * an operand, safe for that case. Same arguments and error codes as the
 * syscalls, plus those of cx_bn_alloc when the result is an operand: one
 * more bignum lives for that call. */
cx_err_t zkn_cx_bn_reduce(cx_bn_t r, const cx_bn_t d, const cx_bn_t n);
cx_err_t zkn_cx_bn_mod_mul(cx_bn_t r, const cx_bn_t a, const cx_bn_t b, const cx_bn_t n);
cx_err_t zkn_cx_mont_to_montgomery(cx_bn_t x, const cx_bn_t z, const cx_bn_mont_ctx_t *ctx);
cx_err_t zkn_cx_mont_from_montgomery(cx_bn_t z, const cx_bn_t x, const cx_bn_mont_ctx_t *ctx);
cx_err_t zkn_cx_mont_mul(cx_bn_t r, const cx_bn_t a, const cx_bn_t b, const cx_bn_mont_ctx_t *ctx);
cx_err_t zkn_cx_mont_pow(cx_bn_t r, const cx_bn_t a, const uint8_t *e, uint32_t e_len,
                         const cx_bn_mont_ctx_t *ctx);
#endif

#if defined(ZKN_CX_UNREDUCED)
/* Comparisons of residues modulo n for a backend whose values are not all
 * below n: both operands are reduced into fresh bignums first. diff is 0 for
 * equal residues; its sign is that of the comparison of the reduced values. */
cx_err_t zkn_cx_bn_cmp_mod(const cx_bn_t a, const cx_bn_t b, const cx_bn_t n, int *diff);
cx_err_t zkn_cx_bn_cmp_u32_mod(const cx_bn_t a, uint32_t v, const cx_bn_t n, int *diff);
#endif

#endif /* ZKN_BN_LEDGER_H */
