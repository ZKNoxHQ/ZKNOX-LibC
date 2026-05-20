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
 * Ledger SDK backend: alias cx_bn_*/cx_mont_* identifiers as zkn_*
 * The actual symbols are provided by the SDK at link time. We just
 * pretend they are zkn_* in the calling code.
 * ─────────────────────────────────────────────────────────────────── */
#  include "os.h"
#  include "cx.h"

   typedef cx_bn_t              zkn_bn_t;
   typedef cx_bn_mont_ctx_t     zkn_mont_ctx_t;
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
#  define zkn_bn_reduce            cx_bn_reduce
#  define zkn_bn_tst_bit           cx_bn_tst_bit
#  define zkn_bn_mod_add           cx_bn_mod_add
#  define zkn_bn_mod_sub           cx_bn_mod_sub
#  define zkn_bn_mod_mul           cx_bn_mod_mul
#  define zkn_bn_mod_invert_nprime cx_bn_mod_invert_nprime

#  define zkn_mont_alloc           cx_mont_alloc
#  define zkn_mont_destroy         cx_mont_destroy
#  define zkn_mont_init            cx_mont_init
#  define zkn_mont_mul             cx_mont_mul
#  define zkn_mont_invert_nprime   cx_mont_invert_nprime
#  define zkn_mont_to_montgomery   cx_mont_to_montgomery
#  define zkn_mont_from_montgomery cx_mont_from_montgomery

   /* Helper specific to Ledger backend — declared in zkn_bn_ledger.h */
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

#endif /* ZKN_BN_H */
