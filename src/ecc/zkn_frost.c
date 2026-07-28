/* FROST primitives call tEdwards_scalarMul_bn (variable-time) which
 * is gated behind ZKNOX_DEBUG — gate the whole translation unit to
 * match. */
#if defined(ZKNOX_DEBUG) || defined(ZKN_FROST)

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

/* Pack the group public key the way H1 (binding factors) expects it:
 * y in big-endian, parity bit of x folded into the top bit (applied once).
 * Single source of truth, shared by zkn_partial_sig and the verify helpers. */
static void zkn_frost_pack_groupkey(const uint8_t *groupkey_be, uint8_t *out)
{
  for (size_t i = 0; i < 32; i++) out[i] = groupkey_be[i + 32];
  out[0] ^= (groupkey_be[31] & 1) << 7;
}

/* Extract the `len` participant identifiers (first field element of each
 * commitment-list entry, big-endian) as bn scalars. */
static int zkn_frost_ids_from_list(uint8_t *commitment_list, size_t len, zkn_bn_t *ids_out)
{
  ZKN_ERROR_INIT();
  for (size_t i = 0; i < len; i++)
    ZKN_CHECK(zkn_bn_alloc_init(&ids_out[i], 32, commitment_list + i * 5 * 32, 32));
  ZKN_ERROR_CLOSE();
}

/* Position of `identifier` in the commitment list. The binding factors are
 * indexed by POSITION, not by identifier: assuming idx == identifier-1 only
 * holds when the signers happen to be 1..len, and reads out of bounds
 * otherwise (quorum {2,3} of a 2-of-3 asks for index 2 of a 2-entry list). */
static int zkn_frost_index_of_id(uint8_t *commitment_list, size_t len,
                                 size_t identifier, size_t *idx_out)
{
  for (size_t i = 0; i < len; i++)
  {
    const uint8_t *idb = commitment_list + i * 5 * 32;
    int match = 1;
    for (int b = 0; b < 24; b++) if (idb[b]) { match = 0; break; }
    if (!match) continue;
    size_t v = 0;
    for (int b = 24; b < 32; b++) v = (v << 8) | idb[b];
    if (v == identifier) { *idx_out = i; return ZKN_OK; }
  }
  return ZKN_ERR_INVALID_PARAM; /* not a signer of this quorum */
}

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

  /* fixedBase_4MSM, not scalarMul: (d_i, e_i) are the one-time FROST nonces,
   * and tEdwards_scalarMul is a variable-time double-and-add. Leaking a nonce
   * through timing leaks the share — the whole point of the ZKNOX_DEBUG gate
   * on scalarMul was to keep it out of anything that touches a secret. The
   * two are proven to agree on the same 32-byte big-endian scalar
   * (tests/test_frost_fixedbase.c), so this is a substitution, not a change
   * of behaviour. */
  ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, secret_nonces, comms));
  ZKN_CHECK(tEdwards_normalize(curve, comms));

  ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, secret_nonces + 32, comms + 1));
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

// Load a wire-supplied point and refuse it if it is not on the curve.
//
// tEdwards_init does no validation at all: it converts x and y to Montgomery
// form, sets z = 1, and hands back whatever it was given. Every point in a
// commitment list comes from the coordinator, which is untrusted by design —
// so without this check zkn_compute_group_commitment folds arbitrary bytes
// into R, computes a challenge over the result, and the device signs against
// it. The signature can never verify, but the one-time nonces (d_i, e_i) are
// spent: a hostile coordinator burns the round again and again, and the
// per-signer attribution the host-side RFC 9591 §5.3 check provides names the
// victim, not the culprit.
//
// tEdwards_IsOnCurve already existed and had no callers anywhere in the
// library. This is its first one.
//
// Only the curve equation is checked, not prime-order membership. Clearing the
// cofactor would cost a full scalar multiplication by the order per point —
// 2t of them per signature — and buys little here: the verification equation
// is checked with the cofactor applied (circomlib's S·Base8 == R8 + (hm·8)·A),
// so a torsion component cannot turn an invalid signature into a valid one.
static int zkn_frost_load_oncurve(zkn_edcurve_t *curve, uint8_t *x_be, uint8_t *y_be,
                                  zkn_edpoint_t *out)
{
  bool on_curve = false;

  ZKN_ERROR_INIT();

  ZKN_CHECK(tEdwards_init(curve, x_be, y_be, out));
  ZKN_CHECK(tEdwards_IsOnCurve(curve, out, &on_curve));
  if (!on_curve)
  {
    error = ZKN_ERR_INVALID_PARAM;
    goto end;
  }

  ZKN_ERROR_CLOSE();
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
    ZKN_CHECK(zkn_frost_load_oncurve(curve, commitment_list + hiding_x_offset,
                                     commitment_list + hiding_y_offset, &T1));
    ZKN_CHECK(tEdwards_add(curve, R, &T1, R));

    // Extract binding nonce commitment and scale by binding factor
    size_t binding_x_offset = curve->fieldsize8 * (5 * i + 3);
    size_t binding_y_offset = curve->fieldsize8 * (5 * i + 4);
    ZKN_CHECK(zkn_frost_load_oncurve(curve, commitment_list + binding_x_offset,
                                     commitment_list + binding_y_offset, &T1));

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
  uint8_t msg_be[32]; // circomlib message is little-endian; reverse to recover the field element
  for (size_t i = 0; i < msglen; i++)
    msg_be[i] = msg[msglen - 1 - i];
  ZKN_CHECK(zkn_bn_init(Ctx.state[5], msg_be, msglen));                        // init state5 with message (LE)
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
    uint8_t *msg_le, // message little-endian (circomlib)
    size_t msglen, // msgsize

    // lambda_i, to be computed instead
    uint8_t *lambda_i,
    uint8_t *sig)
{
  ZKN_ERROR_INIT();

  zkn_edpoint_t group_commitment;
  zkn_bn_t H;

  uint8_t binding_factors[32 * ZKN_FROST_MAX_SIGNERS];
  uint8_t groupkey_compressed[32];
  size_t bf_idx;

  /* zkn_compute_binding_factors writes len*32 bytes here. */
  if (len == 0 || len > ZKN_FROST_MAX_SIGNERS) return ZKN_ERR_INVALID_PARAM;

  // msg_le is the little-endian (circomlib) encoding of the message field element,
  // used directly for both binding factors and the challenge.
  zkn_frost_pack_groupkey(groupkey_be, groupkey_compressed); // y_be with x parity in top bit

  ZKN_CHECK(zkn_bn_alloc(&H, 32));

  ZKN_CHECK(tEdwards_alloc(curve, &group_commitment));

  ZKN_CHECK(zkn_compute_binding_factors(curve, groupkey_compressed, commitment_list, len, msg_le, msglen, binding_factors));
  ZKN_CHECK(zkn_compute_group_commitment(curve, commitment_list, binding_factors, len, &group_commitment));

  ZKN_CHECK(compute_challenge(curve, &group_commitment, groupkey_be, msg_le, 32, H));

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
  ZKN_CHECK(zkn_frost_index_of_id(commitment_list, len, identifier, &bf_idx));
  ZKN_CHECK(zkn_bn_alloc_init(&bn_bindingfactor1, 32, binding_factors + bf_idx * 32, 32));

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

/* ───────────────────────── high-level FROST API ─────────────────────────
 * aggregate / verify_share / verify — mirror curves-lite/babyfrost.ts.
 * groupkey_be and R8_be are 64-byte x||y (big-endian); scalars are 32-byte BE.
 * These allocate a fresh curve internally for compute_challenge (which is
 * destructive), leaving the caller's `curve` usable for the elliptic ops.   */

static int zkn_frost_points_equal(zkn_edcurve_t *curve, zkn_edpoint_t *P, zkn_edpoint_t *Q, int *equal)
{
  ZKN_ERROR_INIT();
  uint8_t px[32], py[32], qx[32], qy[32];
  ZKN_CHECK(tEdwards_export(curve, P, px, py));
  ZKN_CHECK(tEdwards_export(curve, Q, qx, qy));
  *equal = (memcmp(px, qx, 32) == 0 && memcmp(py, qy, 32) == 0);
  ZKN_ERROR_CLOSE();
}

/* challenge hm = poseidon5(R8x,R8y,Ax,Ay,msg), computed on a throwaway curve. */
static int zkn_frost_challenge(uint8_t *R8_be, uint8_t *groupkey_be,
                               uint8_t *msg_le, size_t msglen, zkn_bn_t hm)
{
  ZKN_ERROR_INIT();
  zkn_edcurve_t cc;
  zkn_edpoint_t R8;
  ZKN_CHECK(tEdwards_Curve_alloc_init(&cc, _BABYJUJUB_ID));
  ZKN_CHECK(tEdwards_alloc(&cc, &R8));
  ZKN_CHECK(tEdwards_init(&cc, R8_be, R8_be + 32, &R8));
  ZKN_CHECK(compute_challenge(&cc, &R8, groupkey_be, msg_le, msglen, hm));
  /* cc is partial-destroyed by compute_challenge; do not Curve_destroy */
  ZKN_ERROR_CLOSE();
}

/* frost.aggregate: (R8, S) from the partial signature shares. */
int zkn_frost_aggregate(zkn_edcurve_t *curve, uint8_t *groupkey_be,
                        uint8_t *commitment_list, size_t len,
                        uint8_t *msg_le, size_t msglen,
                        uint8_t *sig_shares, uint8_t *R8_be, uint8_t *S)
{
  ZKN_ERROR_INIT();
  uint8_t gk[32];
  uint8_t bfs[ZKN_FROST_MAX_SIGNERS * 32];
  zkn_edpoint_t R8;
  zkn_bn_t acc, zi;

  zkn_frost_pack_groupkey(groupkey_be, gk);

  ZKN_CHECK(zkn_compute_binding_factors(curve, gk, commitment_list, len, msg_le, msglen, bfs));
  ZKN_CHECK(tEdwards_alloc(curve, &R8));
  ZKN_CHECK(zkn_compute_group_commitment(curve, commitment_list, bfs, len, &R8));
  ZKN_CHECK(tEdwards_export(curve, &R8, R8_be, R8_be + 32));

  ZKN_CHECK(zkn_bn_alloc(&acc, 32));
  ZKN_CHECK(zkn_bn_set_u32(acc, 0));
  ZKN_CHECK(zkn_bn_alloc(&zi, 32));
  for (size_t i = 0; i < len; i++)
  {
    ZKN_CHECK(zkn_bn_init(zi, sig_shares + i * 32, 32));
    ZKN_CHECK(zkn_bn_mod_add(acc, acc, zi, curve->order));
  }
  ZKN_CHECK(zkn_bn_export(acc, S, 32));
  ZKN_ERROR_CLOSE();
}

/* frost.verifySignatureShare: check one partial signature.
 *   z_i·G  ==  (hiding_i + bf_i·binding_i) + (lambda_i·sk_i·challenge)·G      */
int zkn_frost_verify_share(zkn_edcurve_t *curve, size_t identifier, uint8_t *sk_be,
                           uint8_t *commitment_i, uint8_t *sig_share,
                           uint8_t *commitment_list, size_t len,
                           uint8_t *groupkey_be, uint8_t *msg_le, size_t msglen, int *valid)
{
  ZKN_ERROR_INIT();
  uint8_t gk[32], R8_be[64], chal_be[32], rs_be[32];
  uint8_t bfs[ZKN_FROST_MAX_SIGNERS * 32];
  zkn_bn_t ids[ZKN_FROST_MAX_SIGNERS];
  zkn_edpoint_t H, B, BM, CS, LEFT, RSG, RIGHT, R8;
  zkn_bn_t hm, chal, lam, bn_sk, t, rs;
  size_t idx = 0;

  zkn_frost_pack_groupkey(groupkey_be, gk);

  /* binding factors, and index of `identifier` in the list */
  ZKN_CHECK(zkn_compute_binding_factors(curve, gk, commitment_list, len, msg_le, msglen, bfs));
  /* Absent identifier used to fall through with idx = 0, verifying against
   * someone else's binding factor. */
  ZKN_CHECK(zkn_frost_index_of_id(commitment_list, len, identifier, &idx));

  /* commitmentShare = hiding_i + bf_i · binding_i */
  ZKN_CHECK(tEdwards_alloc(curve, &H));
  ZKN_CHECK(tEdwards_alloc(curve, &B));
  ZKN_CHECK(tEdwards_alloc(curve, &BM));
  ZKN_CHECK(tEdwards_alloc(curve, &CS));
  ZKN_CHECK(tEdwards_alloc(curve, &LEFT));
  ZKN_CHECK(tEdwards_alloc(curve, &RSG));
  ZKN_CHECK(tEdwards_alloc(curve, &RIGHT));
  ZKN_CHECK(tEdwards_init(curve, commitment_i + 1 * 32, commitment_i + 2 * 32, &H));
  ZKN_CHECK(tEdwards_init(curve, commitment_i + 3 * 32, commitment_i + 4 * 32, &B));
  ZKN_CHECK(tEdwards_scalarMul(curve, &B, bfs + idx * 32, 32, &BM));
  ZKN_CHECK(tEdwards_add(curve, &H, &BM, &CS));

  /* leftSide = z_i · G */
  ZKN_CHECK(tEdwards_scalarMul(curve, &curve->G, sig_share, 32, &LEFT));

  /* challenge mod order (recompute R8 on the caller curve first) */
  ZKN_CHECK(tEdwards_alloc(curve, &R8));
  ZKN_CHECK(zkn_compute_group_commitment(curve, commitment_list, bfs, len, &R8));
  ZKN_CHECK(tEdwards_export(curve, &R8, R8_be, R8_be + 32));
  ZKN_CHECK(zkn_bn_alloc(&hm, 32));
  ZKN_CHECK(zkn_frost_challenge(R8_be, groupkey_be, msg_le, msglen, hm));
  ZKN_CHECK(zkn_bn_alloc(&chal, 32));
  ZKN_CHECK(zkn_bn_reduce(chal, hm, curve->order));
  ZKN_CHECK(zkn_bn_export(chal, chal_be, 32));

  /* rightScalar = lambda_i · sk_i · challenge */
  ZKN_CHECK(zkn_frost_ids_from_list(commitment_list, len, ids));
  ZKN_CHECK(zkn_bn_alloc(&lam, 32));
  {
    zkn_bn_t x_i;
    ZKN_CHECK(zkn_bn_alloc_init(&x_i, 32, commitment_i, 32));
    ZKN_CHECK(zkn_frost_interpolate(ids, len, x_i, curve->order, lam));
    ZKN_CHECK(zkn_bn_destroy(&x_i));
  }
  ZKN_CHECK(zkn_bn_alloc_init(&bn_sk, 32, sk_be, 32));
  ZKN_CHECK(zkn_bn_alloc(&t, 32));
  ZKN_CHECK(zkn_bn_alloc(&rs, 32));
  ZKN_CHECK(zkn_bn_mod_mul(t, lam, bn_sk, curve->order));
  ZKN_CHECK(zkn_bn_mod_mul(rs, t, chal, curve->order));
  ZKN_CHECK(zkn_bn_export(rs, rs_be, 32));

  /* rightSide = commitmentShare + rightScalar · G.
   * rs = lambda * sk_i * challenge, so the scalar is share-derived: fixed base,
   * constant time. */
  ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, rs_be, &RSG));
  ZKN_CHECK(tEdwards_add(curve, &CS, &RSG, &RIGHT));

  ZKN_CHECK(zkn_frost_points_equal(curve, &LEFT, &RIGHT, valid));
  ZKN_ERROR_CLOSE();
}

/* verifyPoseidon: S·G == R8 + (8·hm)·A,  hm = poseidon5(R8x,R8y,Ax,Ay,msg). */
int zkn_frost_verify(zkn_edcurve_t *curve, uint8_t *R8_be, uint8_t *S,
                     uint8_t *groupkey_be, uint8_t *msg_le, size_t msglen, int *valid)
{
  ZKN_ERROR_INIT();
  uint8_t k_be[32];
  zkn_bn_t hm, eight, k;
  zkn_edpoint_t A, R8, kA, LEFT, RIGHT;

  ZKN_CHECK(zkn_bn_alloc(&hm, 32));
  ZKN_CHECK(zkn_frost_challenge(R8_be, groupkey_be, msg_le, msglen, hm));
  ZKN_CHECK(zkn_bn_alloc(&eight, 32));
  ZKN_CHECK(zkn_bn_set_u32(eight, 8));
  ZKN_CHECK(zkn_bn_alloc(&k, 32));
  ZKN_CHECK(zkn_bn_mod_mul(k, hm, eight, curve->order)); // (8·hm) mod order
  ZKN_CHECK(zkn_bn_export(k, k_be, 32));

  ZKN_CHECK(tEdwards_alloc(curve, &A));
  ZKN_CHECK(tEdwards_alloc(curve, &R8));
  ZKN_CHECK(tEdwards_alloc(curve, &kA));
  ZKN_CHECK(tEdwards_alloc(curve, &LEFT));
  ZKN_CHECK(tEdwards_alloc(curve, &RIGHT));
  ZKN_CHECK(tEdwards_init(curve, groupkey_be, groupkey_be + 32, &A));
  ZKN_CHECK(tEdwards_init(curve, R8_be, R8_be + 32, &R8));

  ZKN_CHECK(tEdwards_scalarMul(curve, &curve->G, S, 32, &LEFT)); // S·G
  ZKN_CHECK(tEdwards_scalarMul(curve, &A, k_be, 32, &kA));       // (8hm)·A
  ZKN_CHECK(tEdwards_add(curve, &R8, &kA, &RIGHT));              // R8 + (8hm)·A

  ZKN_CHECK(zkn_frost_points_equal(curve, &LEFT, &RIGHT, valid));
  ZKN_ERROR_CLOSE();
}

#endif /* ZKNOX_DEBUG || ZKN_FROST — closes the file-level gate at the top */