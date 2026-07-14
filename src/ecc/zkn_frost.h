

#ifndef _ZKN_FROST_H
#define _ZKN_FROST_H

#include "zkn_bn.h"
#include "zkn_hash_compat.h"

// Lagrangian interpolation in 0= prod(x_i)/prod(xj-xi)
int zkn_frost_interpolate(zkn_bn_t *L, size_t len, zkn_bn_t x_i, zkn_bn_t modulus, zkn_bn_t result);

// Lagrangian interpolation in 0= prod(x_i)/prod(xj-xi).Q
int zkn_frost_interpolate_points(zkn_edcurve_t *curve, zkn_edpoint_t *Pubs, zkn_bn_t *Ids, size_t len, zkn_edpoint_t *out);

int zkn_evalshare(zkn_edcurve_t *curve, zkn_bn_t *Polynomial, size_t degree, zkn_bn_t Id, zkn_bn_t secret);

int zkn_frost_commit(zkn_edcurve_t *curve, uint8_t *secret, uint8_t *secret_nonces, zkn_edpoint_t *comms);

int zkn_frost_interpolate_secrets(zkn_edcurve_t *curve, zkn_bn_t *Ids, zkn_bn_t *secrets, size_t len, zkn_bn_t master_secret);

int zkn_encode_group_commitmentHash(zkn_edcurve_t *curve, uint8_t *commitment_list, size_t len, zkn_bn_t H);

int zkn_compute_group_commitment(zkn_edcurve_t *curve, uint8_t *commitment_list, uint8_t *bindingFactorList, size_t len, zkn_edpoint_t *R);

int compute_challenge(zkn_edcurve_t *curve, zkn_edpoint_t *group_commitment, uint8_t *group_public_key_be, uint8_t *msg, size_t msglen, zkn_bn_t hm);

int zkn_compute_binding_factors(zkn_edcurve_t *curve,
                                uint8_t *group_public_key, // Packed point (1 field element)
                                uint8_t *commitment_list,
                                size_t len,
                                uint8_t *msg,
                                size_t msglen,
                                uint8_t *binding_factors);

int zkn_partial_sig(
    zkn_edcurve_t *curve,

    // static elements in RAM
    size_t identifier,
    uint8_t *secret_key_be,
    uint8_t *groupkey_be, // public key compressed, 64 bits
    uint8_t *hiding_nonce,
    uint8_t *binding_nonce,

    // provided by the APDU
    uint8_t *commitment_list,
    size_t len, // size of commitment list
    uint8_t *msg_le,
    size_t msglen, // msgsize

    // lambda_i, to be computed instead
    uint8_t *lambda_i,
    uint8_t *sig);

#ifndef ZKN_FROST_MAX_SIGNERS
#define ZKN_FROST_MAX_SIGNERS 16
#endif

// High-level FROST API (mirrors curves-lite/babyfrost.ts).
// groupkey_be and R8_be are 64-byte x||y (big-endian); scalars are 32-byte BE.

// aggregate partial signature shares -> (R8, S)
int zkn_frost_aggregate(zkn_edcurve_t *curve, uint8_t *groupkey_be,
                        uint8_t *commitment_list, size_t len,
                        uint8_t *msg_le, size_t msglen,
                        uint8_t *sig_shares, uint8_t *R8_be, uint8_t *S);

// verify a single partial signature share; sets *valid to 0/1
int zkn_frost_verify_share(zkn_edcurve_t *curve, size_t identifier, uint8_t *sk_be,
                           uint8_t *commitment_i, uint8_t *sig_share,
                           uint8_t *commitment_list, size_t len,
                           uint8_t *groupkey_be, uint8_t *msg_le, size_t msglen, int *valid);

// verify the aggregate signature (verifyPoseidon: S·G == R8 + 8·hm·A); sets *valid
int zkn_frost_verify(zkn_edcurve_t *curve, uint8_t *R8_be, uint8_t *S,
                     uint8_t *groupkey_be, uint8_t *msg_le, size_t msglen, int *valid);

#endif