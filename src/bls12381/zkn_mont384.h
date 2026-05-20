/*
 * zkn_mont384.h — 384-bit Montgomery arithmetic (backend dispatcher)
 *
 * Public API used by all consumers (fp2, fp6, fp12, g1, g2, miller, groth16).
 * Maps zkn_* symbols to the active backend:
 *
 *   ZKN_BACKEND_LEDGER  →  cx_bn_* (Ledger SDK)     [not yet implemented]
 *   default             →  zkn_sw_* (portable C / ARM ASM)
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_MONT384_H
#define ZKN_MONT384_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ZKN_BACKEND_LEDGER

  #error "ZKN_BACKEND_LEDGER not yet implemented for mont384"

#else

  #include "zkn_sw_mont384.h"

  #define ZKN_MONT384_NLIMBS      ZKN_SW_MONT384_NLIMBS
  #define ZKN_MONT384_BYTES       ZKN_SW_MONT384_BYTES

  typedef zkn_sw_limb_t           zkn_limb_t;
  typedef zkn_sw_dlimb_t          zkn_dlimb_t;
  typedef zkn_sw_fe384_t          zkn_fe384_t;
  typedef zkn_sw_wide384_t        zkn_wide384_t;
  typedef zkn_sw_mont_ctx384_t    zkn_mont_ctx384_t;

  #define zkn_mul_mont_384        zkn_sw_mul_mont_384
  #define zkn_sqr_mont_384        zkn_sw_sqr_mont_384
  #define zkn_add_mod_384         zkn_sw_add_mod_384
  #define zkn_sub_mod_384         zkn_sw_sub_mod_384
  #define zkn_from_mont_384       zkn_sw_from_mont_384
  #define zkn_redc_mont_384       zkn_sw_redc_mont_384

  #define zkn_mont384_compute_n0  zkn_sw_mont384_compute_n0
  #define zkn_mont_ctx384_init    zkn_sw_mont_ctx384_init
  #define zkn_to_mont_384         zkn_sw_to_mont_384

  #define zkn_fe384_from_be       zkn_sw_fe384_from_be
  #define zkn_fe384_to_be         zkn_sw_fe384_to_be

  #define zkn_fe384_eq            zkn_sw_fe384_eq
  #define zkn_fe384_zero          zkn_sw_fe384_zero
  #define zkn_fe384_cmov          zkn_sw_fe384_cmov
  #define zkn_neg_mod_384         zkn_sw_neg_mod_384

  #define zkn_exp_mont_384        zkn_sw_exp_mont_384
  #define zkn_inv_mont_384        zkn_sw_inv_mont_384

  #define zkn_bls12381_ctx        zkn_sw_bls12381_ctx

#endif

#ifdef __cplusplus
}
#endif

#endif /* ZKN_MONT384_H */
