/* AUDIT_2026-06-22 (variable-time scalar mul gating): FROST primitives
 * call tEdwards_scalarMul_bn (variable-time) — now gated behind
 * ZKNOX_DEBUG. Gate the whole translation unit to match. */
#ifdef ZKNOX_DEBUG

#include <stdint.h>  // uint*_t
#include <stdbool.h> // bool
#include <stddef.h>  // size_t

#include "zkn_bn.h"
#include "zkn_hash_compat.h"
#include "zkn_rng_compat.h"
#include "zkn_errors.h"
#include "zkn_common.h"
#include "zkn_tEdwards.h"
#include "zkn_poseidon.h"
#include "zkn_rfc9591frost.h"
#include "zkn_frost.h"

// Lagrangian interpolation in 0= prod(x_i)/prod(xj-xi)
int zkn_frost_interpolate(zkn_bn_t *L, size_t len, zkn_bn_t x_i, zkn_bn_t modulus, zkn_bn_t result)
{

  int different;
  zkn_bn_t deno;
  zkn_bn_t num;
  zkn_bn_t tmp;

  ZKN_ERROR_INIT();
  ZKN_CHECK(zkn_bn_alloc(&deno, 32));
  ZKN_CHECK(zkn_bn_alloc(&num, 32));
  ZKN_CHECK(zkn_bn_alloc(&tmp, 32));
  ZKN_CHECK(zkn_bn_set_u32(deno, 1));
  ZKN_CHECK(zkn_bn_set_u32(num, 1));

  for (size_t j = 0; j < len; j++)
  {
    ZKN_CHECK(zkn_bn_cmp(L[j], x_i, &different));
    if (different != 0)
    {
      ZKN_CHECK(zkn_bn_mod_mul(num, num, L[j], modulus));
      ZKN_CHECK(zkn_bn_mod_sub(tmp, L[j], x_i, modulus)); // xj-xi
      ZKN_CHECK(zkn_bn_mod_mul(deno, deno, tmp, modulus));
    }
  }

  ZKN_CHECK(zkn_bn_mod_invert_nprime(result, deno, modulus));
  ZKN_CHECK(zkn_bn_mod_mul(result, result, num, modulus));

  ZKN_CHECK(zkn_bn_destroy(&deno));
  ZKN_CHECK(zkn_bn_destroy(&num));

  ZKN_ERROR_CLOSE();
}

int zkn_frost_interpolate_secrets(zkn_edcurve_t *curve, zkn_bn_t *Ids, zkn_bn_t *secrets, size_t len, zkn_bn_t master_secret)
{

  ZKN_ERROR_INIT();
  zkn_bn_t a0; // degree 0 coefficients, the master secret
  zkn_bn_t delta;
  ZKN_CHECK(zkn_bn_alloc(&a0, 32));
  ZKN_CHECK(zkn_bn_alloc(&delta, 32));
  ZKN_CHECK(zkn_bn_set_u32(a0, 0));

  for (size_t i = 0; i < len; i++)
  {
    ZKN_CHECK(zkn_frost_interpolate(Ids, len, Ids[i], curve->order, delta));
    ZKN_CHECK(zkn_bn_mod_mul(delta, delta, secrets[i], curve->order)); // yi * interpolate(L,xi)
    ZKN_CHECK(zkn_bn_mod_add(a0, a0, delta, curve->order));
  }

  ZKN_CHECK(zkn_bn_reduce(master_secret, a0, curve->order));

  ZKN_ERROR_CLOSE();
}

// Lagrangian interpolation in 0= prod(x_i)/prod(xj-xi).Q
// pubkeys is a list of point
// ids is a list of bigInt
int zkn_frost_interpolate_points(zkn_edcurve_t *curve, zkn_edpoint_t *Pubs, zkn_bn_t *Ids, size_t len, zkn_edpoint_t *out)
{
  zkn_bn_t lam_i;

  zkn_edpoint_t Q;
  zkn_edpoint_t tmp;

  ZKN_ERROR_INIT();
  ZKN_CHECK(zkn_bn_alloc(&lam_i, 32));
  ZKN_CHECK(tEdwards_alloc(curve, &Q));
  ZKN_CHECK(tEdwards_alloc(curve, &tmp));

  for (size_t i = 0; i < len; i++)
  {
    ZKN_CHECK(zkn_frost_interpolate(Ids, len, Ids[i], curve->order, lam_i));
    ZKN_CHECK(tEdwards_scalarMul_bn(curve, &Pubs[i], &lam_i, &tmp));
    ZKN_CHECK(tEdwards_add(curve, &Q, &tmp, &Q));
  }
  ZKN_CHECK(tEdwards_copy(&Q, out));
  ZKN_CHECK(zkn_bn_destroy(&lam_i));
  ZKN_CHECK(tEdwards_destroy(curve, &Q));
  ZKN_CHECK(tEdwards_destroy(curve, &tmp));

  ZKN_ERROR_CLOSE();
}

// returns a secret polynomial
// int zkn_frost_trusted_keygen_init(zkn_edcurve_t *curve, size_t degree, zkn_bn_t *Polynomial){

//}

// given secret polynomial, compute the secret share of participant of given Id, horner method
int zkn_evalshare(zkn_edcurve_t *curve, zkn_bn_t *Polynomial, size_t degree, zkn_bn_t Id, zkn_bn_t secret)
{

  ZKN_ERROR_INIT();
  zkn_bn_t acc;
  ZKN_CHECK(zkn_bn_alloc(&acc, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_copy(secret, Polynomial[degree])); // a_d

  for (size_t i = 0; i < degree; i++)
  {
    ZKN_CHECK(zkn_bn_mod_mul(acc, secret, Id, curve->order));
    ZKN_CHECK(zkn_bn_mod_add(secret, acc, Polynomial[degree - i - 1], curve->order));
  }
  ZKN_CHECK(zkn_bn_reduce(acc, secret, curve->order));
  ZKN_CHECK(zkn_bn_copy(secret, acc));

  ZKN_CHECK(zkn_bn_destroy(&acc));

  ZKN_ERROR_CLOSE();
}

int zkn_frost_nonce_generate(zkn_edcurve_t *curve, uint8_t *secret, uint8_t *out)
{
  ZKN_ERROR_INIT();
  uint8_t buffer[64];
  zkn_rng(buffer, 32);
  memcpy(buffer + 32, secret, 32);
  zkn_bn_t h_output;
  ZKN_CHECK(zkn_bn_alloc(&h_output, curve->fieldsize8));
  ZKN_CHECK(Babyfrost_H3(buffer, 64, curve->order, h_output));
  ZKN_CHECK(zkn_bn_export(h_output, out, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_destroy(&h_output));
  ZKN_ERROR_CLOSE();
}

/*
def commit(sk_i):
  hiding_nonce = nonce_generate(sk_i)
  binding_nonce = nonce_generate(sk_i)
  hiding_nonce_commitment = G.ScalarBaseMult(hiding_nonce)
  binding_nonce_commitment = G.ScalarBaseMult(binding_nonce)
  nonces = (hiding_nonce, binding_nonce)
  comms = (hiding_nonce_commitment, binding_nonce_commitment)
  return (nonces, comms)
*/
int zkn_frost_commit(zkn_edcurve_t *curve, uint8_t *secret, uint8_t *secret_nonces, zkn_edpoint_t *comms)
{

  ZKN_ERROR_INIT();
  ZKN_CHECK(zkn_frost_nonce_generate(curve, secret, secret_nonces));
  ZKN_CHECK(zkn_frost_nonce_generate(curve, secret, secret_nonces + 32));

  ZKN_CHECK(tEdwards_scalarMul(curve, &curve->G, secret_nonces, curve->fieldsize8, comms));
  ZKN_CHECK(tEdwards_normalize(curve, comms));

  ZKN_CHECK(tEdwards_scalarMul(curve, &curve->G, secret_nonces + 32, curve->fieldsize8, comms + 1));
  ZKN_CHECK(tEdwards_normalize(curve, comms + 1));

  ZKN_ERROR_CLOSE();
}

// hypothesis: a commitment list is a list of 5-uples of curve->fieldsize8 elements, i.e Id, hidingnonce_x, hidingnonce_y, binding_nonce_x, binding_nonce_y

int zkn_encode_group_commitmentHash(zkn_edcurve_t *curve, uint8_t *commitment_list, size_t len, zkn_bn_t H)
{

  zkn_blake2b_t state;
  uint8_t tmp[ECC_MAXSIZE8];

  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_frost_H5_init((zkn_hash_t *)&state));

  for (size_t i = 0; i < len; i++)
  { // for each commitment

    size_t hiding_y_offset = curve->fieldsize8 * (5 * i + 2); // hiding_nonce_y

    // Copy identifier, swapped to little endian
    for (size_t j = 0; j < curve->fieldsize8; j++)
    {

      tmp[curve->fieldsize8 - j - 1] = commitment_list[(curve->fieldsize8 * 5 * i) + j]; // if encoding points LE
      // tmp[j] = commitment_list[hiding_y_offset + j];//if encoding points BE
    }
    ZKN_CHECK(zkn_frost_hash_update((zkn_hash_t *)&state, tmp, curve->fieldsize8));

    // Read lsb bit of hiding nonce x (last byte of the big-endian field)
    size_t hiding_x_offset = curve->fieldsize8 * (5 * i + 1); // hiding_nonce_x
    uint8_t lsb_x = commitment_list[hiding_x_offset + curve->fieldsize8 - 1] & 1;

    // Copy hiding nonce_y, swapped to little endian
    for (size_t j = 0; j < curve->fieldsize8; j++)
    {
      tmp[curve->fieldsize8 - j - 1] = commitment_list[hiding_y_offset + j]; // if encoding points LE
      // tmp[j] = commitment_list[hiding_y_offset + j];//if encoding points BE
    }
    // Point packing: set MSB of last byte (byte 31 in little-endian after swap)
    tmp[curve->fieldsize8 - 1] |= (lsb_x) << 7;

    ZKN_CHECK(zkn_frost_hash_update((zkn_hash_t *)&state, tmp, curve->fieldsize8));

    // Read lsb bit of binding nonce x (last byte of the big-endian field)
    size_t binding_x_offset = curve->fieldsize8 * (5 * i + 3); // binding_nonce_x
    lsb_x = commitment_list[binding_x_offset + curve->fieldsize8 - 1] & 1;

    // Copy binding nonce_y, swapped to little endian
    size_t binding_y_offset = curve->fieldsize8 * (5 * i + 4); // binding_nonce_y
    for (size_t j = 0; j < curve->fieldsize8; j++)
    {
      tmp[curve->fieldsize8 - j - 1] = commitment_list[binding_y_offset + j]; // LE encoding
      // tmp[j] = commitment_list[binding_y_offset + j];//BE encoding
    }
    // Point packing: set MSB of last byte
    tmp[curve->fieldsize8 - 1] |= (lsb_x) << 7;

    ZKN_CHECK(zkn_frost_hash_update((zkn_hash_t *)&state, tmp, curve->fieldsize8));
  }

  ZKN_CHECK(zkn_frost_hash_final((zkn_hash_t *)&state, curve->order, H));

  ZKN_ERROR_CLOSE();
  return 0;
}

// def compute_group_commitment(commitment_list, binding_factor_list): of RFC9591
// hypothesis: a commitment list is a list of 5-uples of curve->fieldsize8 elements, i.e Id, hidingnonce_x, hidingnonce_y, binding_nonce_x, binding_nonce_y
// big endian encodings
int zkn_compute_group_commitment(zkn_edcurve_t *curve, uint8_t *commitment_list, uint8_t *bindingFactorList, size_t len, zkn_edpoint_t *R)
{
  zkn_edpoint_t T1;
  zkn_edpoint_t T2;

  ZKN_ERROR_INIT();

  ZKN_CHECK(tEdwards_alloc(curve, &T1));
  ZKN_CHECK(tEdwards_alloc(curve, &T2));

  ZKN_CHECK(tEdwards_SetNeutral(curve, R));

  for (size_t i = 0; i < len; i++)
  {
    // Extract and accumulate hiding nonce commitment
    size_t hiding_x_offset = curve->fieldsize8 * (5 * i + 1);
    size_t hiding_y_offset = curve->fieldsize8 * (5 * i + 2);
    ZKN_CHECK(tEdwards_init(curve, commitment_list + hiding_x_offset, commitment_list + hiding_y_offset, &T1));
    ZKN_CHECK(tEdwards_add(curve, R, &T1, R));

    // Extract binding nonce commitment and scale by binding factor
    size_t binding_x_offset = curve->fieldsize8 * (5 * i + 3);
    size_t binding_y_offset = curve->fieldsize8 * (5 * i + 4);
    ZKN_CHECK(tEdwards_init(curve, commitment_list + binding_x_offset, commitment_list + binding_y_offset, &T1));

    uint8_t *bindingfactor = bindingFactorList + (curve->fieldsize8 * i);
    ZKN_CHECK(tEdwards_scalarMul(curve, &T1, bindingfactor, curve->fieldsize8, &T2));

    // Accumulate scaled binding nonce
    ZKN_CHECK(tEdwards_add(curve, R, &T2, R));
  }

  ZKN_CHECK(tEdwards_normalize(curve, R));

  ZKN_CHECK(tEdwards_destroy(curve, &T1));
  ZKN_CHECK(tEdwards_destroy(curve, &T2));

  ZKN_ERROR_CLOSE();
}

#define MAX_SHARES 3

/*
def compute_binding_factors(group_public_key, commitment_list, msg):
  group_public_key_enc = G.SerializeElement(group_public_key)
  // Hashed to a fixed length.
  msg_hash = H4(msg)
  // Hashed to a fixed length.
  encoded_commitment_hash =
      H5(encode_group_commitment_list(commitment_list))
  // The encoding of the group public key is a fixed length
  // within a ciphersuite.
  rho_input_prefix = group_public_key_enc || msg_hash ||
   encoded_commitment_hash
   binding_factor_list = []
  for (identifier, hiding_nonce_commitment,
       binding_nonce_commitment) in commitment_list:
    rho_input = rho_input_prefix || G.SerializeScalar(identifier)
    binding_factor = H1(rho_input)
    binding_factor_list.append((identifier, binding_factor))
  return binding_factor_list
*/
// the function returns only the binding factors

// Helper function to serialize a scalar from BE to LE for hashing
// Similar to SerializeScalar in the TypeScript implementation
static inline void zkn_serialize_scalar_for_hash(const uint8_t *scalar_be, size_t size, uint8_t *scalar_le)
{
  for (size_t j = 0; j < size; j++)
  {
    scalar_le[size - j - 1] = scalar_be[j];
  }
}

// Compute binding factors for FROST (section 4.4 of RFC 9591)
// Inputs and outputs are BE
int zkn_compute_binding_factors(zkn_edcurve_t *curve,
                                uint8_t *group_public_key, // Packed point (1 field element)
                                uint8_t *commitment_list,
                                size_t len,
                                uint8_t *msg,
                                size_t msglen,
                                uint8_t *binding_factors)
{

  zkn_bn_t msgHash;
  zkn_bn_t encodedCommitmentHash;
  zkn_blake2b_t state;
  uint8_t tmp[ECC_MAXSIZE8];

  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_bn_alloc(&msgHash, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&encodedCommitmentHash, curve->fieldsize8));

  // Compute H4(message) - msg is already in correct format, no swap needed
  ZKN_CHECK(Babyfrost_H4(msg, msglen, curve->order, msgHash));

  // Compute H5(encodeGroupCommitmentList)
  ZKN_CHECK(zkn_encode_group_commitmentHash(curve, commitment_list, len, encodedCommitmentHash));

  // Export msgHash and encodedCommitmentHash for reuse (already in BE from hash_final)
  uint8_t msgHash_bytes[ECC_MAXSIZE8];
  uint8_t commitHash_bytes[ECC_MAXSIZE8];
  ZKN_CHECK(zkn_bn_export(msgHash, msgHash_bytes, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_export(encodedCommitmentHash, commitHash_bytes, curve->fieldsize8));

  // For each participant, compute binding factor using streaming hash
  for (size_t i = 0; i < len; i++)
  {
    zkn_bn_t bindingFactor;

    ZKN_CHECK(zkn_bn_alloc(&bindingFactor, curve->fieldsize8));

    // Initialize H1 hash state
    ZKN_CHECK(zkn_frost_H1_init((zkn_hash_t *)&state));

    // Update with groupPublicKey (packed, serialize BE to LE)
    zkn_serialize_scalar_for_hash(group_public_key, curve->fieldsize8, tmp);
    ZKN_CHECK(zkn_frost_hash_update((zkn_hash_t *)&state, tmp, curve->fieldsize8));

    // Update with msgHash (serialize BE to LE)
    zkn_serialize_scalar_for_hash(msgHash_bytes, curve->fieldsize8, tmp);
    ZKN_CHECK(zkn_frost_hash_update((zkn_hash_t *)&state, tmp, curve->fieldsize8));

    // Update with encodedCommitmentHash (serialize BE to LE)
    zkn_serialize_scalar_for_hash(commitHash_bytes, curve->fieldsize8, tmp);
    ZKN_CHECK(zkn_frost_hash_update((zkn_hash_t *)&state, tmp, curve->fieldsize8));

    // Update with identifier (first field element for this participant, serialize BE to LE)
    size_t id_offset = curve->fieldsize8 * 5 * i;
    zkn_serialize_scalar_for_hash(commitment_list + id_offset, curve->fieldsize8, tmp);
    ZKN_CHECK(zkn_frost_hash_update((zkn_hash_t *)&state, tmp, curve->fieldsize8));

    // Finalize and reduce modulo order (output is BE)
    ZKN_CHECK(zkn_frost_hash_final((zkn_hash_t *)&state, curve->order, bindingFactor));

    // Export binding factor (already BE)
    ZKN_CHECK(zkn_bn_export(bindingFactor, binding_factors + (i * curve->fieldsize8), curve->fieldsize8));

    ZKN_CHECK(zkn_bn_destroy(&bindingFactor));
  }

  ZKN_CHECK(zkn_bn_destroy(&msgHash));
  ZKN_CHECK(zkn_bn_destroy(&encodedCommitmentHash));

  ZKN_ERROR_CLOSE();
  return 0;
}

int zkn_participants_from_commitment_list(zkn_edcurve_t *curve, uint8_t *commitment_list, size_t len, uint8_t *ids)
{
  ZKN_ERROR_INIT();

  if (len > MAX_SHARES)
  {
    error = ZKN_WRONG_LENGTH;
    goto end;
  }
  for (size_t i = 0; i < len; i++)
  {
    for (size_t j = 0; j < curve->fieldsize8; j++)
      ids[curve->fieldsize8 * i + j] = commitment_list[curve->fieldsize8 * 5 * i + j];
  }

  ZKN_ERROR_CLOSE();
}

#define MAX_MSGLEN 64

// todo: push upper to eddsa
// the function is destructive for the curve structure and groupcommitment for poseidon to function
// once here it is the H(R, A, msg) as in typical schnorr
int compute_challenge(zkn_edcurve_t *curve, zkn_edpoint_t *group_commitment, uint8_t *group_public_key_be, uint8_t *msg, size_t msglen, zkn_bn_t hm)
{

  ZKN_ERROR_INIT();

  zkn_poseidon_ctx_t Ctx;

  if (msglen != 32)
  {
    return ZKN_WRONG_LENGTH;
  }

  ZKN_CHECK(tEdwards_Curve_partial_destroy(curve)); // need to not overflow RAM crypto, no elliptic curve computation from here
  ZKN_CHECK(zkn_poseidon_init(&Ctx, 5, 5, &(curve->ctx)));

  // initialize state with R8x, R8y, A8x, A8y, msg in montgomery representation, state[0] is initialized at 0 at calling
  ZKN_CHECK(zkn_bn_copy(Ctx.state[1], group_commitment->x)); // already in montgomery
  ZKN_CHECK(zkn_bn_copy(Ctx.state[2], group_commitment->y)); // already in montgomery

  ZKN_CHECK(zkn_bn_init(Ctx.state[3], group_public_key_be, curve->fieldsize8));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[3], Ctx.state[3], &curve->ctx)); // montgomerization
  ZKN_CHECK(zkn_bn_init(Ctx.state[4], group_public_key_be + 32, curve->fieldsize8));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[4], Ctx.state[4], &curve->ctx)); // montgomerization
  ZKN_CHECK(zkn_bn_init(Ctx.state[5], msg, msglen));                          // init state5 with message
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[5], Ctx.state[5], &curve->ctx)); // montgomerize message

  ZKN_CHECK(tEdwards_destroy(curve, group_commitment)); // spare memory

  ZKN_CHECK(zkn_poseidon(&Ctx, 0, (zkn_bn_t *)hm, 1)); // state[0] is initialized with 0

  ZKN_CHECK(zkn_mont_from_montgomery(hm, hm, &curve->ctx)); // back to normal domain

  /* Release the Poseidon bignum handles. No-op on SW backend; required on
   * cx_bn backend to keep the BOLOS BN pool from filling up. */
  ZKN_CHECK(zkn_poseidon_destroy(&Ctx));

  ZKN_ERROR_CLOSE();
}

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
    uint8_t *msg_be,
    size_t msglen, // msgsize

    // lambda_i, to be computed instead
    uint8_t *lambda_i,
    uint8_t *sig)
{
  ZKN_ERROR_INIT();

  zkn_edpoint_t group_commitment;
  zkn_bn_t H;

  uint8_t binding_factors[32 * 3];
  uint8_t msg_le[32];
  uint8_t groupkey_compressed[32];

  for (size_t i = 0; i < 32; i++)
  {
    msg_le[i] = msg_be[31 - i];
    groupkey_compressed[i] = groupkey_be[i + 32];
    groupkey_compressed[0] ^= (groupkey_be[31] & 1)<<7; // parity bit of x in highest bit of y
  }

  ZKN_CHECK(zkn_bn_alloc(&H, 32));

  ZKN_CHECK(tEdwards_alloc(curve, &group_commitment));

  ZKN_CHECK(zkn_compute_binding_factors(curve, groupkey_compressed, commitment_list, len, msg_le, msglen, binding_factors));
  ZKN_CHECK(zkn_compute_group_commitment(curve, commitment_list, binding_factors, len, &group_commitment));

  ZKN_CHECK(compute_challenge(curve, &group_commitment, groupkey_be, msg_be, 32, H));

  ZKN_CHECK(zkn_bn_export(H, sig, 32));

  // elliptic structure is released
  zkn_bn_t bn_challenge;
  zkn_bn_t bn_order;

  // 0x60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1
  uint8_t order[32] = {0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05, 0x37, 0x0a, 0x08, 0xb6, 0xd0, 0x30, 0x2b, 0x0b, 0xab, 0x3e, 0xed, 0xb8, 0x39, 0x20, 0xee, 0x0a, 0x67, 0x72, 0x97, 0xdc, 0x39, 0x21, 0x26, 0xf1};

  ZKN_CHECK(zkn_bn_alloc(&bn_challenge, 32));
  ZKN_CHECK(zkn_bn_alloc_init(&bn_order, 32, order, 32));

  ZKN_CHECK(zkn_bn_reduce(bn_challenge, H, bn_order));

  zkn_bn_t bn_hidingNonce;
  zkn_bn_t bn_bindingNonce;
  zkn_bn_t bnlambda_i;
  zkn_bn_t bn_sk;
  zkn_bn_t temp;
  zkn_bn_t bn_bindingfactor1;

  ZKN_CHECK(zkn_bn_alloc_init(&bn_hidingNonce, 32, hiding_nonce, 32));
  ZKN_CHECK(zkn_bn_alloc_init(&bn_bindingNonce, 32, binding_nonce, 32));
  ZKN_CHECK(zkn_bn_alloc_init(&bnlambda_i, 32, lambda_i, 32));
  ZKN_CHECK(zkn_bn_alloc_init(&bn_sk, 32, secret_key_be, 32));
  ZKN_CHECK(zkn_bn_alloc_init(&bn_bindingfactor1, 32, binding_factors + (identifier - 1) * 32, 32));

  ZKN_CHECK(zkn_bn_alloc(&temp, 32));

  // const sigShare = hidingNonce + (bindingNonce * bindingFactor) + (lambda_i * sk_i * challenge)

  ZKN_CHECK(zkn_bn_mod_mul(temp, bn_bindingNonce, bn_bindingfactor1, bn_order)); //(bindingNonce * bindingFactor)

  ZKN_CHECK(zkn_bn_mod_mul(bn_bindingNonce, bnlambda_i, bn_sk, bn_order));        // lambda_i * sk_i
  ZKN_CHECK(zkn_bn_mod_mul(bnlambda_i, bn_bindingNonce, bn_challenge, bn_order)); //(lambda_i * sk_i * challenge)

  ZKN_CHECK(zkn_bn_mod_add(bn_bindingfactor1, temp, bnlambda_i, bn_order));     // prod=(bindingNonce * bindingFactor)+(lambda_i * sk_i * challenge)
  ZKN_CHECK(zkn_bn_mod_add(temp, bn_bindingfactor1, bn_hidingNonce, bn_order)); // hidingNonce + prod
  ZKN_CHECK(zkn_bn_reduce(H, temp, bn_order));

  ZKN_CHECK(zkn_bn_export(H, sig, 32));

  ZKN_ERROR_CLOSE();
}

#endif /* ZKNOX_DEBUG — closes the file-level gate at the top */