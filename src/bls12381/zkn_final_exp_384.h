/*
 * zkn_final_exp_384.h — Final exponentiation for BLS12-381 ate pairing
 *
 * f^{(p^12 - 1) / r}  decomposed as:
 *   easy part:  f^{(p^6 - 1)(p^2 + 1)}
 *   hard part:  raise-to-z chain (blst/zkcrypto decomposition)
 *
 * z = -0xd201000000010000
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_FINAL_EXP_384_H
#define ZKN_FINAL_EXP_384_H

#include "zkn_miller.h"   /* zkn_fp12_384_t, zkn_g1/g2_384_t, zkn_miller_loop */

#ifdef __cplusplus
extern "C" {
#endif

/* r = f^{(p^12 - 1) / r}   (r and f may alias) */
void zkn_final_exp(zkn_fp12_384_t          *r,
                   const zkn_fp12_384_t    *f,
                   const zkn_mont_ctx384_t *ctx);

/* e(P, Q) = final_exp(miller_loop(P, Q)) */
void zkn_pairing(zkn_fp12_384_t          *r,
                 const zkn_g1_384_t      *P,
                 const zkn_g2_384_t      *Q,
                 const zkn_mont_ctx384_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_FINAL_EXP_384_H */
