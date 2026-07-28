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
 *   - Each coefficient is derived as H6(VERSION | id | j | n | t | seed | epoch |
 *     name_len | name) mod order — a domain-separated context, so distinct
 *     ceremonies (fresh epoch) and groups (name) get independent polynomials
 *   - id and j are encoded as 32-byte little-endian integers
 *   - a0 MUST be non-zero (error if hash happens to produce 0)
 * 
 * @param curve       Initialized BabyJubjub curve context (provides subgroup order)
 * @param p           Participant input (id, seed, epoch, n, name)
 * @param threshold   Number of coefficients to generate (t in t-of-n scheme)
 * @param initial_len Number of pre-computed coefficients already in coefflist (0 to start fresh)
 * @param coefflist   Output buffer for coefficients, size must be >= threshold * 32 bytes
 *                    If initial_len > 0, first initial_len * 32 bytes contain existing coeffs
 * 
 * @return ZKN_OK on success, error code otherwise
 */
/* Write `v` as a 32-byte little-endian integer. Mirrors vss-dkg.ts::toBytes,
 * which is what the JS side feeds to H6 — the two encodings must agree byte
 * for byte or the derived coefficients silently diverge. */
static void vss_le32(uint8_t *out, uint64_t v)
{
    explicit_bzero(out, 32);
    for (size_t k = 0; k < 8; k++) out[k] = (uint8_t)((v >> (8 * k)) & 0xFF);
}

int makeDealerCoeffsDeterministic(
    zkn_edcurve_t *curve,
    participant_t *p,
    size_t threshold,
    size_t initial_len,
    uint8_t *coefflist
) {
    ZKN_ERROR_INIT();

    if (threshold == 0)                    return ZKN_ERR_INVALID_PARAM;
    if (threshold > VSS_MAX_THRESHOLD)     return ZKN_WRONG_LENGTH;
    if (initial_len > threshold)           return ZKN_ERR_INVALID_PARAM;
    if (p->id == 0)                        return ZKN_ERR_INVALID_PARAM;  // IDs are 1..N
    if (p->n == 0 || threshold > p->n)     return ZKN_ERR_INVALID_PARAM;
    if (p->name_len > VSS_MAX_NAME_LEN)    return ZKN_ERR_INVALID_PARAM;

    zkn_bn_t coeff_bn;
    ZKN_CHECK(zkn_bn_alloc(&coeff_bn, 32));

    /* VERSION(32) | id(32) | j(32) | n(32) | t(32) | seed(32) | epoch(16)
     *                                       | name_len(1) | name(name_len)
     * Fixed-width throughout except `name`, which is length-prefixed and last,
     * so no two distinct contexts share a byte string. */
    uint8_t input[32 * 6 + VSS_EPOCH_LEN + 1 + VSS_MAX_NAME_LEN];
    explicit_bzero(input, sizeof(input));

    const size_t OFF_J    = 64;                       /* the only field that varies */
    const size_t OFF_TAIL = 32 * 6;
    const size_t inlen    = OFF_TAIL + VSS_EPOCH_LEN + 1 + p->name_len;

    vss_le32(input + 0,   (uint64_t)VSS_CTX_VERSION);
    vss_le32(input + 32,  (uint64_t)p->id);
    /* input + 64 = j, set per iteration */
    vss_le32(input + 96,  (uint64_t)p->n);
    vss_le32(input + 128, (uint64_t)threshold);
    memcpy(input + 160, p->seed, 32);
    memcpy(input + OFF_TAIL, p->epoch, VSS_EPOCH_LEN);
    input[OFF_TAIL + VSS_EPOCH_LEN] = (uint8_t)p->name_len;
    if (p->name_len) memcpy(input + OFF_TAIL + VSS_EPOCH_LEN + 1, p->name, p->name_len);

    size_t start_j = initial_len;

    if (initial_len == 0) {
        vss_le32(input + OFF_J, 0);
        ZKN_CHECK(Babyfrost_H6(input, inlen, curve->order, coeff_bn));

        int cmp_result = 1;
        ZKN_CHECK(zkn_bn_cmp_u32(coeff_bn, 0, &cmp_result));
        if (cmp_result == 0) {
            (void)zkn_bn_destroy(&coeff_bn);
            explicit_bzero(input, sizeof(input));
            return ZKN_ERR_INVALID_PARAM;  // a0 must be non-zero
        }
        ZKN_CHECK(zkn_bn_export(coeff_bn, coefflist, 32));
        start_j = 1;
    }

    for (size_t j = start_j; j < threshold; j++) {
        vss_le32(input + OFF_J, (uint64_t)j);
        ZKN_CHECK(Babyfrost_H6(input, inlen, curve->order, coeff_bn));
        ZKN_CHECK(zkn_bn_export(coeff_bn, coefflist + (j * 32), 32));
    }

    ZKN_CHECK(zkn_bn_destroy(&coeff_bn));
    explicit_bzero(input, sizeof(input));

    ZKN_ERROR_CLOSE();
}


/* ─────────────────────────── VSS/DKG API ───────────────────────────
 * Implementations of the functions declared in zkn_vss.h.
 * Translates: src/frost/vss-dkg.ts. Scalars are 32-byte big-endian; points
 * are 64-byte x||y. All arithmetic is modulo curve->order.                 */

/* evalPolySubgroup - Horner evaluation of p(x) = Σ coeffs[j]*x^j mod order. */
int evalPolySubgroup(zkn_edcurve_t *curve, const uint8_t *coeffs, size_t degree,
                     const uint8_t *x, uint8_t *y)
{
    ZKN_ERROR_INIT();
    zkn_bn_t acc, xbn, cbn, tmp;
    ZKN_CHECK(zkn_bn_alloc_init(&acc, 32, coeffs + degree * 32, 32)); // highest coeff
    ZKN_CHECK(zkn_bn_alloc_init(&xbn, 32, x, 32));
    ZKN_CHECK(zkn_bn_alloc(&cbn, 32));
    ZKN_CHECK(zkn_bn_alloc(&tmp, 32));
    for (size_t j = degree; j-- > 0;) // j = degree-1 .. 0
    {
        ZKN_CHECK(zkn_bn_mod_mul(tmp, acc, xbn, curve->order)); // tmp = acc*x
        ZKN_CHECK(zkn_bn_init(cbn, coeffs + j * 32, 32));
        ZKN_CHECK(zkn_bn_mod_add(acc, tmp, cbn, curve->order)); // acc = acc*x + a_j
    }
    ZKN_CHECK(zkn_bn_export(acc, y, 32));
    ZKN_CHECK(zkn_bn_destroy(&acc));
    ZKN_CHECK(zkn_bn_destroy(&xbn));
    ZKN_CHECK(zkn_bn_destroy(&cbn));
    ZKN_CHECK(zkn_bn_destroy(&tmp));
    ZKN_ERROR_CLOSE();
}

/* makeDealerCommitments - C_j = a_j * G for each coefficient.
 * Uses scalar multiplication, gated behind ZKNOX_DEBUG (production needs a
 * constant-time fixed-base table, like the EdDSA prv2pub path). */
#ifdef ZKNOX_DEBUG
int makeDealerCommitments(zkn_edcurve_t *curve, const uint8_t *coeffs,
                          size_t threshold, uint8_t *commitments)
{
    ZKN_ERROR_INIT();
    zkn_edpoint_t P;
    ZKN_CHECK(tEdwards_alloc(curve, &P));
    for (size_t j = 0; j < threshold; j++)
    {
        /* The coefficients are the dealer's secret polynomial — a0 is its
         * contribution to the group key. Fixed base, constant time. */
        ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, (const uint8_t *)(coeffs + j * 32), &P));
        ZKN_CHECK(tEdwards_normalize(curve, &P));
        ZKN_CHECK(tEdwards_export(curve, &P, commitments + j * 64, commitments + j * 64 + 32));
    }
    ZKN_CHECK(tEdwards_destroy(curve, &P));
    ZKN_ERROR_CLOSE();
}
#endif /* ZKNOX_DEBUG */

/* computeDealerShareForId - s(i) = p(i). */
int computeDealerShareForId(zkn_edcurve_t *curve, const uint8_t *coeffs,
                            size_t threshold, size_t id, uint8_t *share)
{
    ZKN_ERROR_INIT();
    zkn_bn_t x;
    uint8_t xb[32];
    ZKN_CHECK(zkn_bn_alloc(&x, 32));
    ZKN_CHECK(zkn_bn_set_u32(x, (uint32_t)id));
    ZKN_CHECK(zkn_bn_export(x, xb, 32));
    ZKN_CHECK(zkn_bn_destroy(&x));
    ZKN_CHECK(evalPolySubgroup(curve, coeffs, threshold - 1, xb, share));
    ZKN_ERROR_CLOSE();
}

/* verifyFeldmanShare - check s(i)*G == Σ_j i^j * C_j.
 * Uses scalar multiplication, gated behind ZKNOX_DEBUG (see above). */
#ifdef ZKNOX_DEBUG
int verifyFeldmanShare(zkn_edcurve_t *curve, size_t id, const uint8_t *share,
                       const uint8_t *commitments, size_t threshold, bool *valid)
{
    ZKN_ERROR_INIT();
    zkn_edpoint_t lhs, rhs, tmp, Cj;
    zkn_bn_t x;
    uint8_t idb[32], lx[32], ly[32], rx[32], ry[32];
    ZKN_CHECK(zkn_bn_alloc(&x, 32));
    ZKN_CHECK(zkn_bn_set_u32(x, (uint32_t)id));
    ZKN_CHECK(zkn_bn_export(x, idb, 32));
    ZKN_CHECK(zkn_bn_destroy(&x));
    ZKN_CHECK(tEdwards_alloc(curve, &lhs));
    ZKN_CHECK(tEdwards_alloc(curve, &rhs));
    ZKN_CHECK(tEdwards_alloc(curve, &tmp));
    ZKN_CHECK(tEdwards_alloc(curve, &Cj));
    // lhs = s(i) * G
    /* lhs = s(i) * G — s(i) is the secret share just received. Fixed base,
     * constant time. */
    ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, (const uint8_t *)share, &lhs));
    ZKN_CHECK(tEdwards_normalize(curve, &lhs));
    // rhs = Σ i^j * C_j via Horner: rhs = C_{t-1}; for j=t-2..0: rhs = rhs*i + C_j
    ZKN_CHECK(tEdwards_init(curve, (uint8_t *)(commitments + (threshold - 1) * 64),
                            (uint8_t *)(commitments + (threshold - 1) * 64 + 32), &rhs));
    for (size_t j = threshold - 1; j-- > 0;)
    {
        ZKN_CHECK(tEdwards_scalarMul(curve, &rhs, idb, 32, &tmp)); // tmp = rhs*i
        ZKN_CHECK(tEdwards_init(curve, (uint8_t *)(commitments + j * 64),
                                (uint8_t *)(commitments + j * 64 + 32), &Cj));
        ZKN_CHECK(tEdwards_add(curve, &tmp, &Cj, &rhs)); // rhs = tmp + C_j
    }
    ZKN_CHECK(tEdwards_normalize(curve, &rhs));
    ZKN_CHECK(tEdwards_export(curve, &lhs, lx, ly));
    ZKN_CHECK(tEdwards_export(curve, &rhs, rx, ry));
    *valid = (memcmp(lx, rx, 32) == 0 && memcmp(ly, ry, 32) == 0);
    ZKN_CHECK(tEdwards_destroy(curve, &lhs));
    ZKN_CHECK(tEdwards_destroy(curve, &rhs));
    ZKN_CHECK(tEdwards_destroy(curve, &tmp));
    ZKN_CHECK(tEdwards_destroy(curve, &Cj));
    ZKN_ERROR_CLOSE();
}
#endif /* ZKNOX_DEBUG */

/* deriveInterpolatingValue - Lagrange coefficient at 0 for x_i over {ids}. */
int deriveInterpolatingValue(zkn_edcurve_t *curve, const size_t *ids, size_t num_ids,
                             size_t x_i, uint8_t *lambda)
{
    ZKN_ERROR_INIT();
    zkn_bn_t num, den, xi, xj, tmp, res;
    ZKN_CHECK(zkn_bn_alloc(&num, 32));
    ZKN_CHECK(zkn_bn_set_u32(num, 1));
    ZKN_CHECK(zkn_bn_alloc(&den, 32));
    ZKN_CHECK(zkn_bn_set_u32(den, 1));
    ZKN_CHECK(zkn_bn_alloc(&xi, 32));
    ZKN_CHECK(zkn_bn_set_u32(xi, (uint32_t)x_i));
    ZKN_CHECK(zkn_bn_alloc(&xj, 32));
    ZKN_CHECK(zkn_bn_alloc(&tmp, 32));
    ZKN_CHECK(zkn_bn_alloc(&res, 32));
    for (size_t k = 0; k < num_ids; k++)
    {
        if (ids[k] == x_i)
            continue;
        ZKN_CHECK(zkn_bn_set_u32(xj, (uint32_t)ids[k]));
        ZKN_CHECK(zkn_bn_mod_mul(num, num, xj, curve->order));  // num *= x_j
        ZKN_CHECK(zkn_bn_mod_sub(tmp, xj, xi, curve->order));   // x_j - x_i
        ZKN_CHECK(zkn_bn_mod_mul(den, den, tmp, curve->order)); // den *= (x_j - x_i)
    }
    ZKN_CHECK(zkn_bn_mod_invert_nprime(res, den, curve->order)); // 1/den
    ZKN_CHECK(zkn_bn_mod_mul(res, res, num, curve->order));      // num/den
    ZKN_CHECK(zkn_bn_export(res, lambda, 32));
    ZKN_CHECK(zkn_bn_destroy(&num));
    ZKN_CHECK(zkn_bn_destroy(&den));
    ZKN_CHECK(zkn_bn_destroy(&xi));
    ZKN_CHECK(zkn_bn_destroy(&xj));
    ZKN_CHECK(zkn_bn_destroy(&tmp));
    ZKN_CHECK(zkn_bn_destroy(&res));
    ZKN_ERROR_CLOSE();
}

/* reconstructConstantFromShares - a0 = Σ λ_i * s_i (Lagrange at 0). */
int reconstructConstantFromShares(zkn_edcurve_t *curve, const vss_share_t *shares,
                                  size_t num_shares, uint8_t *a0)
{
    ZKN_ERROR_INIT();
    size_t ids[VSS_MAX_PARTICIPANTS];
    zkn_bn_t acc, lam, si, tmp;
    uint8_t lamb[32];
    for (size_t k = 0; k < num_shares; k++)
        ids[k] = shares[k].id;
    ZKN_CHECK(zkn_bn_alloc(&acc, 32));
    ZKN_CHECK(zkn_bn_set_u32(acc, 0));
    ZKN_CHECK(zkn_bn_alloc(&lam, 32));
    ZKN_CHECK(zkn_bn_alloc(&si, 32));
    ZKN_CHECK(zkn_bn_alloc(&tmp, 32));
    for (size_t k = 0; k < num_shares; k++)
    {
        ZKN_CHECK(deriveInterpolatingValue(curve, ids, num_shares, shares[k].id, lamb));
        ZKN_CHECK(zkn_bn_init(lam, lamb, 32));
        ZKN_CHECK(zkn_bn_init(si, shares[k].sk_share_div8, 32)); // reconstruct over div8 shares
        ZKN_CHECK(zkn_bn_mod_mul(tmp, lam, si, curve->order));   // λ * s_i
        ZKN_CHECK(zkn_bn_mod_add(acc, acc, tmp, curve->order));  // acc += λ * s_i
    }
    ZKN_CHECK(zkn_bn_export(acc, a0, 32));
    ZKN_CHECK(zkn_bn_destroy(&acc));
    ZKN_CHECK(zkn_bn_destroy(&lam));
    ZKN_CHECK(zkn_bn_destroy(&si));
    ZKN_CHECK(zkn_bn_destroy(&tmp));
    ZKN_ERROR_CLOSE();
}
