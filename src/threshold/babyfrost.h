/*
 * babyfrost.h — BabyFROST threshold signing (babyfrost.ts protocol)
 *
 * Implements the exact protocol from babyfrost.ts, including:
 *   - Binding factors with H4(msg) + H5(encComms) + groupPK (section 4.4)
 *   - Lagrange with modular inverse (section 4.2, FIXED)
 *   - EdDSA-Poseidon compatible verification (cofactor ×8)
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef BABYFROST_H
#define BABYFROST_H

#ifdef ZKN_WITH_BABYFROST

#include <stdint.h>
#include <stddef.h>

#include "zkn_frost.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════════════════════════════
 *  Context: holds hasher + curve, initialized once
 * ══════════════════════════════════════════════════════════════════ */

typedef struct {
    zkn_frost_hasher_t hasher;
    zkn_edcurve_t      curve;
    uint8_t            order[32];       /* BE */
    uint8_t            gen_x[32];       /* Base8 x, BE */
    uint8_t            gen_y[32];       /* Base8 y, BE */
} babyfrost_ctx_t;

int babyfrost_init(babyfrost_ctx_t *ctx);
void babyfrost_destroy(babyfrost_ctx_t *ctx);

/* Re-init curve (needed between scalar mults due to temp allocs) */
void babyfrost_reinit_curve(babyfrost_ctx_t *ctx);

/* ══════════════════════════════════════════════════════════════════
 *  Section 4.3: Encode group commitment list
 *
 *  For each signer:
 *    SerializeScalar(id)                  = 32 bytes LE
 *    SerializeElement(hidingNonceCommit)   = 64 bytes LE (x||y)
 *    SerializeElement(bindingNonceCommit)  = 64 bytes LE (x||y)
 *  Total: 160 bytes per signer
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_encode_commitment_list(uint8_t *out, size_t *out_len,
                                      const zkn_frost_commitment_t *comms,
                                      size_t n);

/* ══════════════════════════════════════════════════════════════════
 *  Section 4.4: Compute binding factors
 *
 *  rhoInput = SerializeElement(groupPK)      [64 bytes LE]
 *           || toBytes(H4(message))           [32 bytes LE]
 *           || toBytes(H5(encCommitmentList)) [32 bytes LE]
 *           || SerializeScalar(identifier)    [32 bytes LE]
 *  bindingFactor_i = H1(rhoInput)
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_compute_binding_factors(babyfrost_ctx_t *ctx,
                                       const uint8_t pk_x_be[32],
                                       const uint8_t pk_y_be[32],
                                       const zkn_frost_commitment_t *comms,
                                       size_t n_signers,
                                       const uint8_t msg_hash_be[32],
                                       uint8_t rho_out[][32]);

/* ══════════════════════════════════════════════════════════════════
 *  Section 5.1: Round 1 — Commit
 *
 *  Generates nonce pair (d, e) and commitments (D = B8*d, E = B8*e).
 *  Deterministic nonce from H3(random || sk_i).
 *
 *  For testing with deterministic nonces, use babyfrost_commit_deterministic
 *  which takes pre-computed nonces instead of generating random ones.
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_commit_deterministic(babyfrost_ctx_t *ctx,
                                    uint32_t identifier,
                                    const uint8_t d_be[32],
                                    const uint8_t e_be[32],
                                    zkn_frost_commitment_t *comm_out);

/* ══════════════════════════════════════════════════════════════════
 *  Section 5.2: Round 2 — Sign
 *
 *  z_i = d_i + e_i * rho_i + lambda_i * sk_i * c   mod order
 *
 *  sk_i should be skShare (= 8 * skShareDiv8) for EdDSA compat.
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_sign(babyfrost_ctx_t *ctx,
                   uint32_t identifier,
                   const uint8_t sk_i_be[32],          /* skShare = 8*s */
                   const uint8_t pk_x_be[32],
                   const uint8_t pk_y_be[32],
                   const uint8_t d_be[32],
                   const uint8_t e_be[32],
                   const uint8_t msg_hash_be[32],
                   const zkn_frost_commitment_t *comms,
                   size_t n_signers,
                   const uint32_t *signer_ids,
                   uint8_t z_i_be[32]);

/* ══════════════════════════════════════════════════════════════════
 *  Section 5.3: Aggregate & Verify
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_aggregate(babyfrost_ctx_t *ctx,
                        const zkn_frost_commitment_t *comms,
                        size_t n_signers,
                        const uint8_t msg_hash_be[32],
                        const uint8_t pk_x_be[32],
                        const uint8_t pk_y_be[32],
                        const uint8_t z_shares[][32],
                        zkn_frost_sig_t *sig_out);

int babyfrost_verify(babyfrost_ctx_t *ctx,
                     const zkn_frost_sig_t *sig,
                     const uint8_t pk_x_be[32],
                     const uint8_t pk_y_be[32],
                     const uint8_t msg_hash_be[32],
                     int *valid);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_WITH_BABYFROST */

#endif /* BABYFROST_H */
