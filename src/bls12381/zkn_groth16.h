/*
 * zkn_groth16.h — BLS12-381 Groth16 proof verification
 *
 * Two APIs:
 *   1. zkn_groth16_verify()         — hardcoded VK (zkAave on-device)
 *   2. zkn_groth16_verify_generic() — parameterized VK (cross-check)
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */
#ifndef ZKN_GROTH16_H
#define ZKN_GROTH16_H

#include "zkn_mont384.h"
#include "zkn_g1_384.h"
#include "zkn_g2_384.h"
#include "zkn_fp12_384.h"

/* ── Hardcoded VK (zkAave, nPublic=2) ─────────────────────────────── */
#define ZKN_GROTH16_N_PUBLIC   2
#define ZKN_GROTH16_SCALAR_LEN 32
#define ZKN_GROTH16_PROOF_LEN  (96 + 192 + 96 + ZKN_GROTH16_N_PUBLIC * ZKN_GROTH16_SCALAR_LEN)

int zkn_groth16_verify(const uint8_t proof_buf[ZKN_GROTH16_PROOF_LEN],
                       const zkn_mont_ctx384_t *ctx);

/* ── Generic verifier (parameterized VK) ──────────────────────────── */
#define ZKN_GROTH16_MAX_PUB  8

typedef struct {
    uint8_t alpha[96];                          /* α ∈ G1  */
    uint8_t beta[192];                          /* β ∈ G2  */
    uint8_t gamma[192];                         /* γ ∈ G2  */
    uint8_t delta[192];                         /* δ ∈ G2  */
    uint8_t IC[ZKN_GROTH16_MAX_PUB + 1][96];   /* IC[0..n] ∈ G1 */
    int     n_public;
} zkn_groth16_vk_generic_t;

typedef struct {
    uint8_t A[96];                              /* π.A ∈ G1 */
    uint8_t B[192];                             /* π.B ∈ G2 */
    uint8_t C[96];                              /* π.C ∈ G1 */
} zkn_groth16_proof_generic_t;

int zkn_groth16_verify_generic(
    const zkn_groth16_vk_generic_t    *vk,
    const zkn_groth16_proof_generic_t *proof,
    const uint8_t                     (*pub)[32],
    int                                n_pub,
    const zkn_mont_ctx384_t           *ctx);

#endif /* ZKN_GROTH16_H */
