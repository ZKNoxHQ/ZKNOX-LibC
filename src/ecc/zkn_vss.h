// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX @+

#ifndef _ZKN_VSS_H
#define _ZKN_VSS_H

#include "zkn_bn.h"
#include "zkn_hash_compat.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "zkn_tEdwards.h"

// Maximum threshold value (limited by RAM on Nano S Plus ~4KB)
// Each coefficient is 32 bytes, plus stack usage for computation
// Conservative limit: 16 coefficients = 512 bytes for coefflist alone
#define VSS_MAX_THRESHOLD 16

// Maximum number of participants in VSS scheme
#define VSS_MAX_PARTICIPANTS 16

/**
 * Participant input for VSS dealer operations
 * Translates: types.ts::ParticipantInput
 */
typedef struct participant {
    size_t id;              // 1..N (must be positive)
    uint8_t seed[32];       // 32 bytes (private to dealer)
    uint8_t password[32];   // 32 bytes (private to dealer)
} participant_t;

/**
 * VSS share for a single participant
 * Translates: types.ts::Share
 */
typedef struct vss_share {
    size_t id;              // Participant ID (1..N)
    uint8_t sk_share[32];   // skShare = 8 * skShareDiv8 mod L
    uint8_t sk_share_div8[32]; // Raw aggregated evaluation
} vss_share_t;

/**
 * makeDealerCoeffsDeterministic - Derive VSS polynomial coefficients deterministically
 * 
 * Translates: vss-dkg.ts::makeDealerCoeffsDeterministic
 * 
 * For threshold t, produces coefficients [a0, a1, ..., a_{t-1}] where:
 *   - Each a_j = H6(id || j || seed || password) mod subOrder
 *   - id and j are encoded as 32-byte little-endian integers
 *   - a0 MUST be non-zero
 * 
 * @param curve       Initialized BabyJubjub curve context
 * @param p           Participant input (id, seed, password)
 * @param threshold   Number of coefficients (t in t-of-n scheme)
 * @param initial_len Number of pre-computed coefficients (0 to start fresh)
 * @param coefflist   Output: threshold * 32 bytes
 * 
 * @return ZKN_OK on success
 */
int makeDealerCoeffsDeterministic(
    zkn_edcurve_t *curve,
    participant_t *p,
    size_t threshold,
    size_t initial_len,
    uint8_t *coefflist
);

/**
 * evalPolySubgroup - Evaluate polynomial at point x (mod subgroup order)
 * 
 * Translates: vss-dkg.ts::evalPolySubgroup
 * 
 * Computes y = sum(coeffs[j] * x^j) mod L for j in [0, degree)
 * 
 * @param curve     Initialized curve context
 * @param coeffs    Polynomial coefficients [a0, a1, ...], each 32 bytes
 * @param degree    Number of coefficients
 * @param x         Evaluation point (32 bytes, LE)
 * @param y         Output: result (32 bytes)
 * 
 * @return ZKN_OK on success
 */
int evalPolySubgroup(
    zkn_edcurve_t *curve,
    const uint8_t *coeffs,
    size_t degree,
    const uint8_t *x,
    uint8_t *y
);

/**
 * makeDealerCommitments - Compute commitments C_j = G * a_j for each coefficient
 * 
 * Translates: vss-dkg.ts::makeDealerCommitments
 * 
 * @param curve         Initialized curve context
 * @param coeffs        Polynomial coefficients, threshold * 32 bytes
 * @param threshold     Number of coefficients
 * @param commitments   Output: threshold points, each 64 bytes (x,y uncompressed)
 *                      Or threshold * 32 bytes if compressed
 * 
 * @return ZKN_OK on success
 */
int makeDealerCommitments(
    zkn_edcurve_t *curve,
    const uint8_t *coeffs,
    size_t threshold,
    uint8_t *commitments
);

/**
 * computeDealerShareForId - Compute s_k(i) = f_k(i) for recipient i
 * 
 * Translates: vss-dkg.ts::computeDealerSharesForIds (single recipient version)
 * 
 * @param curve     Initialized curve context  
 * @param coeffs    Polynomial coefficients, threshold * 32 bytes
 * @param threshold Number of coefficients
 * @param id        Recipient ID (1..N)
 * @param share     Output: evaluation result (32 bytes)
 * 
 * @return ZKN_OK on success
 */
int computeDealerShareForId(
    zkn_edcurve_t *curve,
    const uint8_t *coeffs,
    size_t threshold,
    size_t id,
    uint8_t *share
);

/**
 * verifyFeldmanShare - Verify share against Feldman commitments
 * 
 * Translates: vss-dkg.ts::verifyFeldmanShare
 * 
 * Checks: G * s_i == sum(C_j * i^j) for j in [0, threshold)
 * 
 * @param curve         Initialized curve context
 * @param id            Participant ID
 * @param share         Share value s_i (32 bytes)
 * @param commitments   Dealer commitments, threshold points
 * @param threshold     Number of commitments
 * @param valid         Output: true if verification passes
 * 
 * @return ZKN_OK on success (check 'valid' for verification result)
 */
int verifyFeldmanShare(
    zkn_edcurve_t *curve,
    size_t id,
    const uint8_t *share,
    const uint8_t *commitments,
    size_t threshold,
    bool *valid
);

/**
 * deriveInterpolatingValue - Compute Lagrange coefficient lambda_i
 * 
 * Translates: vss-dkg.ts::deriveInterpolatingValue
 * 
 * lambda_i = product((x_j) / (x_j - x_i)) for j != i
 * 
 * @param curve     Initialized curve context
 * @param ids       Array of participant IDs in the subset
 * @param num_ids   Number of IDs in subset
 * @param x_i       Target ID for which to compute lambda
 * @param lambda    Output: interpolating value (32 bytes)
 * 
 * @return ZKN_OK on success
 */
int deriveInterpolatingValue(
    zkn_edcurve_t *curve,
    const size_t *ids,
    size_t num_ids,
    size_t x_i,
    uint8_t *lambda
);

/**
 * reconstructConstantFromShares - Recover a0 from threshold shares via Lagrange
 * 
 * Translates: vss-dkg.ts::reconstructConstantFromShares
 * 
 * a0 = sum(s_i * lambda_i) mod L
 * 
 * @param curve     Initialized curve context
 * @param shares    Array of (id, share) pairs
 * @param num_shares Number of shares (must be >= threshold)
 * @param a0        Output: reconstructed constant term (32 bytes)
 * 
 * @return ZKN_OK on success
 */
int reconstructConstantFromShares(
    zkn_edcurve_t *curve,
    const vss_share_t *shares,
    size_t num_shares,
    uint8_t *a0
);

#endif // _ZKN_VSS_H