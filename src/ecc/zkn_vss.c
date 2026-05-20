// SPDX-License-Identifier: MIT
// Copyright (c) 2025 ZKNOX @+

#include <stdint.h>  // uint*_t
#include <stdbool.h> // bool
#include <stddef.h>  // size_t
#include <string.h>  // memset, explicit_bzero

#include "zkn_bn.h"
#include "zkn_hash_compat.h"
#include "zkn_rng_compat.h"

#include "zkn_common.h"
#include "zkn_errors.h"
#include "zkn_rfc9591frost.h"
#include "zkn_tEdwards.h"
#include "zkn_vss.h"

/**
 * makeDealerCoeffsDeterministic - Derive VSS polynomial coefficients deterministically
 * 
 * Translates: vss-dkg.ts::makeDealerCoeffsDeterministic
 * 
 * For threshold t, produces coefficients [a0, a1, ..., a_{t-1}] where:
 *   - Each coefficient is derived as H6(id || j || seed || password) mod order
 *   - id and j are encoded as 32-byte little-endian integers
 *   - a0 MUST be non-zero (error if hash happens to produce 0)
 * 
 * @param curve       Initialized BabyJubjub curve context (provides subgroup order)
 * @param p           Participant input (id, seed, password)
 * @param threshold   Number of coefficients to generate (t in t-of-n scheme)
 * @param initial_len Number of pre-computed coefficients already in coefflist (0 to start fresh)
 * @param coefflist   Output buffer for coefficients, size must be >= threshold * 32 bytes
 *                    If initial_len > 0, first initial_len * 32 bytes contain existing coeffs
 * 
 * @return ZKN_OK on success, error code otherwise
 */
int makeDealerCoeffsDeterministic(
    zkn_edcurve_t *curve, 
    participant_t *p, 
    size_t threshold, 
    size_t initial_len,
    uint8_t *coefflist
) {
    ZKN_ERROR_INIT();

    // Validate parameters
    if (threshold == 0) {
        return ZKN_ERR_INVALID_PARAM;
    }
    if (threshold > VSS_MAX_THRESHOLD) {
        return ZKN_WRONG_LENGTH;
    }
    if (initial_len > threshold) {
        return ZKN_ERR_INVALID_PARAM;
    }
    if (p->id == 0) {
        return ZKN_ERR_INVALID_PARAM;  // IDs must be 1..N
    }

    zkn_bn_t coeff_bn;
    ZKN_CHECK(zkn_bn_alloc(&coeff_bn, 32));

    // Input buffer: id(32) | j(32) | seed(32) | password(32) = 128 bytes
    // All values in little-endian representation
    uint8_t input[128];
    explicit_bzero(input, sizeof(input));

    // Encode participant ID as 32-byte LE integer (id is small, so just first bytes)
    // p->id fits in size_t, write as LE
    input[0] = (uint8_t)(p->id & 0xFF);
    input[1] = (uint8_t)((p->id >> 8) & 0xFF);
    // Remaining bytes of id field are already zero

    // Copy seed and password (they stay constant for all coefficients)
    memcpy(input + 64, p->seed, 32);
    memcpy(input + 96, p->password, 32);

    // Determine starting index for coefficient generation
    size_t start_j = initial_len;

    // If no initial state, we need to derive a0 first
    if (initial_len == 0) {
        // Encode j=0 as 32-byte LE integer (bytes 32-63)
        explicit_bzero(input + 32, 32);  // j = 0

        // Compute H6(id || 0 || seed || password) mod order
        ZKN_CHECK(Babyfrost_H6(input, sizeof(input), curve->order, coeff_bn));

        // Check that a0 is non-zero (extremely unlikely to fail, but required)
        // zkn_bn_cmp_u32 sets diff to: 0 if equal, >0 if bn>n, <0 if bn<n
        int cmp_result = 1;  // Initialize to non-zero
        ZKN_CHECK(zkn_bn_cmp_u32(coeff_bn, 0, &cmp_result));
        if (cmp_result == 0) {
            (void)zkn_bn_destroy(&coeff_bn);
            return ZKN_ERR_INVALID_PARAM;  // a0 must be non-zero
        }

        // Export a0 to coefflist[0..31]
        ZKN_CHECK(zkn_bn_export(coeff_bn, coefflist, 32));

        start_j = 1;
    }

    // Generate remaining coefficients a_{start_j} through a_{threshold-1}
    for (size_t j = start_j; j < threshold; j++) {
        // Encode j as 32-byte LE integer (bytes 32-63)
        explicit_bzero(input + 32, 32);
        input[32] = (uint8_t)(j & 0xFF);
        input[33] = (uint8_t)((j >> 8) & 0xFF);
        // Remaining bytes are already zero

        // Compute H6(id || j || seed || password) mod order
        ZKN_CHECK(Babyfrost_H6(input, sizeof(input), curve->order, coeff_bn));

        // Export coefficient to coefflist[j*32..(j+1)*32-1]
        ZKN_CHECK(zkn_bn_export(coeff_bn, coefflist + (j * 32), 32));
    }

    // Cleanup
    ZKN_CHECK(zkn_bn_destroy(&coeff_bn));

    // Clear sensitive input buffer
    explicit_bzero(input, sizeof(input));

    ZKN_ERROR_CLOSE();
}

