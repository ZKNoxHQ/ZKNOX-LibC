/*
 * zkn_bn.h — Big number backend router
 *
 * Selects the big-number backend at build time via one of:
 *   -DZKN_BN_BACKEND_LEDGER   → Ledger SDK cx_bn_* / cx_mont_*
 *   -DZKN_BN_BACKEND_SW       → software implementation (zkn_sw_bn / zkn_mont256)
 *
 * The public API is the same in both backends (alias-by-macro for Ledger,
 * pure C for software). Code that uses zkn_bn_*, zkn_mont_*, zkn_bn_t,
 * zkn_mont_ctx_t works identically in either backend.
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#ifndef ZKN_BN_H
#define ZKN_BN_H

#if defined(ZKN_BN_BACKEND_LEDGER) && defined(ZKN_BN_BACKEND_SW)
#  error "Cannot define both ZKN_BN_BACKEND_LEDGER and ZKN_BN_BACKEND_SW"
#endif

#if defined(ZKN_BN_BACKEND_LEDGER)
/* ───────────────────────────────────────────────────────────────────
 * Ledger SDK backend: alias cx_bn_ and cx_mont_ identifiers to zkn_
 * The actual symbols are provided by the SDK at link time. We just
 * pretend they are zkn_* in the calling code.
 * ─────────────────────────────────────────────────────────────────── */
#  include "os.h"
#  include "cx.h"

   typedef cx_bn_t              zkn_bn_t;
   typedef cx_bn_mont_ctx_t     zkn_mont_ctx_t;
   typedef cx_bn_mont_ctx_t     zkn_bn_mont_ctx_t;
   typedef cx_err_t             zkn_err_t;

#  define zkn_bn_lock              cx_bn_lock
#  define zkn_bn_unlock            cx_bn_unlock
#  define zkn_bn_alloc             cx_bn_alloc
#  define zkn_bn_alloc_init        cx_bn_alloc_init
#  define zkn_bn_destroy           cx_bn_destroy
#  define zkn_bn_init              cx_bn_init
#  define zkn_bn_copy              cx_bn_copy
#  define zkn_bn_export            cx_bn_export
#  define zkn_bn_nbytes            cx_bn_nbytes
#  define zkn_bn_cmp               cx_bn_cmp
#  define zkn_bn_cmp_u32           cx_bn_cmp_u32
#  define zkn_bn_set_u32           cx_bn_set_u32
#  define zkn_bn_tst_bit           cx_bn_tst_bit
#  define zkn_bn_mod_add           cx_bn_mod_add
#  define zkn_bn_mod_sub           cx_bn_mod_sub
#  define zkn_bn_mod_invert_nprime cx_bn_mod_invert_nprime

#  define zkn_mont_alloc           cx_mont_alloc
#  define zkn_mont_destroy         cx_mont_destroy
#  define zkn_mont_init            cx_mont_init
#  define zkn_mont_invert_nprime   cx_mont_invert_nprime

   /* Nano S (ST31), firmware 2.1.0: the multiplications of the coprocessor
    * return a wrong value when the result bignum is also an operand. Measured
    * on the device, primitive by primitive:
    *
    *   wrong   cx_mont_to_montgomery(x, x)      cx_mont_from_montgomery(x, x)
    *           cx_mont_mul, r == a or r == b    cx_mont_pow, r == a
    *           cx_bn_mod_mul, r == a or r == b  cx_bn_reduce(r, r)
    *   right   cx_bn_mod_add, cx_bn_mod_sub, cx_mont_invert_nprime,
    *           cx_bn_mod_invert_nprime with an aliased result
    *
    * A bignum is made of 128-bit words there, and the operand is read word
    * by word from the bignum the result is written to: the Montgomery form
    * of 1 computed in place comes out as that of 1 + J * 2^128, J the top 128
    * bits of 2^384 mod p. The library converts in place in many places (curve
    * constants, Poseidon constants and states), which is fine on the other
    * targets.
    *
    * ZKN_CX_NO_ALIAS routes the six primitives of the first list through
    * zkn_bn_ledger.c, where a call whose result bignum is also an operand
    * computes into a fresh bignum and copies. Calls with a distinct result
    * go straight to the syscall. Set by default on Nano S; other targets keep
    * the direct mapping, so their images do not change. */
#  if defined(TARGET_NANOS) && !defined(ZKN_CX_NO_ALIAS)
#    define ZKN_CX_NO_ALIAS 1
#  endif

#  if defined(ZKN_CX_NO_ALIAS)
#    define zkn_bn_reduce            zkn_cx_bn_reduce
#    define zkn_bn_mod_mul           zkn_cx_bn_mod_mul
#    define zkn_mont_mul             zkn_cx_mont_mul
#    define zkn_mont_to_montgomery   zkn_cx_mont_to_montgomery
#    define zkn_mont_from_montgomery zkn_cx_mont_from_montgomery
#    define zkn_mont_pow             zkn_cx_mont_pow
#  else
#    define zkn_bn_reduce            cx_bn_reduce
#    define zkn_bn_mod_mul           cx_bn_mod_mul
#    define zkn_mont_mul             cx_mont_mul
#    define zkn_mont_to_montgomery   cx_mont_to_montgomery
#    define zkn_mont_from_montgomery cx_mont_from_montgomery
#    define zkn_mont_pow             cx_mont_pow
#  endif

   /* Same device, second fault: a Montgomery product comes back in [0, 2p),
    * without the last conditional subtraction. Measured: four squares chosen
    * to be at least p before that subtraction came back as the expected
    * value plus p, on both fields. A value modulo p then exists as two
    * bignums, and comparing two of them as bignums says "different" for
    * equal residues.
    *
    * ZKN_CX_UNREDUCED makes zkn_bn_cmp_mod and zkn_bn_cmp_u32_mod, below,
    * reduce their operands into fresh bignums before they compare. Set by
    * default on Nano S. */
#  if defined(TARGET_NANOS) && !defined(ZKN_CX_UNREDUCED)
#    define ZKN_CX_UNREDUCED 1
#  endif

   /* Helpers specific to the Ledger backend, declared in zkn_bn_ledger.h */
#  include "zkn_bn_ledger.h"

#elif defined(ZKN_BN_BACKEND_SW)
/* ───────────────────────────────────────────────────────────────────
 * Software backend: zkn_* functions are defined in zkn_bn_sw.{c,h}
 * They are drop-in API-compatible with the Ledger SDK equivalents.
 * ─────────────────────────────────────────────────────────────────── */
#  include "zkn_bn_sw.h"

#else
#  error "Define ZKN_BN_BACKEND_LEDGER or ZKN_BN_BACKEND_SW"
#endif

/* ───────────────────────────────────────────────────────────────────
 * Comparing residues modulo n.
 *
 * zkn_bn_cmp compares bignums. It compares residues only where the backend
 * keeps every value below the modulus, which the cx backend does not on
 * Nano S (ZKN_CX_UNREDUCED above). Code that compares two field elements,
 * or a field element with a small constant, uses these two:
 *
 *   zkn_bn_cmp_mod(a, b, n, &diff)       diff == 0 iff a = b modulo n
 *   zkn_bn_cmp_u32_mod(a, v, n, &diff)   diff == 0 iff a = v modulo n
 *
 * Everywhere else they are zkn_bn_cmp and zkn_bn_cmp_u32, and n is not
 * evaluated.
 * ─────────────────────────────────────────────────────────────────── */
#if defined(ZKN_BN_BACKEND_LEDGER) && defined(ZKN_CX_UNREDUCED)
#  define zkn_bn_cmp_mod(a, b, n, diff)     zkn_cx_bn_cmp_mod((a), (b), (n), (diff))
#  define zkn_bn_cmp_u32_mod(a, v, n, diff) zkn_cx_bn_cmp_u32_mod((a), (v), (n), (diff))
#else
#  define zkn_bn_cmp_mod(a, b, n, diff)     zkn_bn_cmp((a), (b), (diff))
#  define zkn_bn_cmp_u32_mod(a, v, n, diff) zkn_bn_cmp_u32((a), (v), (diff))
#endif

#endif /* ZKN_BN_H */
