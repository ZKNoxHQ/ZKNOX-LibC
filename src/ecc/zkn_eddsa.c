
#include <stdint.h>  // uint*_t
#include <stdbool.h> // bool
#include <stddef.h>  // size_t

#include "zkn_bn.h"
#include "zkn_hash_compat.h"
#include "zkn_rng_compat.h"
#include "zkn_errors.h"
#include "zkn_common.h"
#include "zkn_blake512.h"
#include "zkn_tEdwards.h"
#include "zkn_poseidon_constants.h"
#include "zkn_poseidon_soft.h"
#include "zkn_eddsa.h"

#define EDDSA_SIZE8 32

// beware that out must have allocated size>64 bytes to hold blake512b result
int zkn_prv_hash(const uint8_t *prv, uint8_t *out, size_t len)
{

  ZKN_ERROR_INIT();
  // 1.  Hash the 32-byte private key using SHA-512, storing the digest in   a 64-octet large buffer, denoted h.  Only the lower 32 bytes are       used for generating the public key.
  // ZKN_CHECK(zkn_blake2b_512_hash(prv, len, out));

  ZKN_CHECK(zkn_blake512(prv, len, out));
  // 2.  Prune the buffer: The lowest three bits of the first octet are cleared, the highest bit of the last octet is cleared, and the second highest bit of the last octet is set.

  out[0] = out[0] & 0xF8;   // The lowest three bits of the first octet are cleared
  out[31] = out[31] & 0x7F; // the highest bit of the last octet is cleared
  out[31] = out[31] | 0x40; // and the second highest bit of the last octet is set.

  // 3.  Interpret the buffer as the little-endian integer
  rev256((uint64_t *)out); // from BE to LE, used to derive kpub
  // rev256((uint64_t*) (out+32 ));//from BE to LE, used to sign

  /*

  uint8_t carry3 = 0;

  for (size_t i = 0; i < 32; i++) {
        uint8_t tmp = out[i];
        out[i] = (out[i] >> 3) | (carry3 << 5);
        carry3 = tmp & 0x07;
  }*/

  ZKN_ERROR_CLOSE();
}

static void shr3(uint8_t *out)
{
  uint8_t carry3 = 0;

  for (size_t i = 0; i < 32; i++)
  {
    uint8_t tmp = out[i];
    out[i] = (out[i] >> 3) | (carry3 << 5);
    carry3 = tmp & 0x07;
  }
}

int zkn_prv2pub(zkn_edcurve_t *curve, uint8_t *prv, zkn_edpoint_t *Pub)
{

  uint8_t out[64]; // secretkey||composebuff_low||

  ZKN_ERROR_INIT();

  zkn_prv_hash(prv, out, curve->fieldsize8);
  // 3.  Interpret the buffer as the little-endian integer, forming asecret scalar s.  Perform a fixed-base scalar multiplication [s]B.
  shr3(out);

  ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, out, Pub));
  // ZKN_CHECK(tEdwards_scalarMul(curve, &curve->G, out, curve->fieldsize8, Pub));
  ZKN_CHECK(tEdwards_normalize(curve, Pub)); // montgomery and normalized

  ZKN_ERROR_CLOSE();
}

// the function is destructive for the curve structure and groupcommitment for poseidon to function
// once here it is the H(R, A, msg) as in typical schnorr
int challenge(zkn_edcurve_t *curve, zkn_edpoint_t *R, zkn_edpoint_t *Pub, uint8_t *msg_be, size_t msglen)
{

  ZKN_ERROR_INIT();

  poseidon_ctx_t Ctx;

  ZKN_CHECK(Poseidon_alloc_init(&Ctx, 5, 5, &(curve->ctx)));

  // initialize state with R8x, R8y, A8x, A8y, msg in montgomery representation, state[0] is initialized at 0 at calling
  ZKN_CHECK(zkn_bn_copy(Ctx.state[1], R->x));           // already in montgomery
  ZKN_CHECK(zkn_bn_copy(Ctx.state[2], R->y));           // already in montgomery
  ZKN_CHECK(zkn_bn_copy(Ctx.state[3], Pub->x));         // already in montgomery and normalized
  ZKN_CHECK(zkn_bn_copy(Ctx.state[4], Pub->y));         // already in montgomery and normalized
  ZKN_CHECK(zkn_bn_init(Ctx.state[5], msg_be, msglen)); // init state5 with message

  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[5], Ctx.state[5], &curve->ctx)); // montgomerize message

  ZKN_ERROR_CLOSE();
}

// derivation of public key, in a RFC8032 way, but using babyjujub
// for now message is limited to 64 bytes
// todo: use init/update/final
// note: for now it is destructive for the input curve structure
int EddsaPoseidon_Sign_final(zkn_edcurve_t *curve, uint8_t *prv, zkn_edpoint_t *Pub, uint8_t *msg, size_t len, uint8_t *out)
{

  ZKN_ERROR_INIT();
#ifndef RAILGUN
  poseidon_ctx_t Ctx;
#endif

  if (len != 32)
  {
    return ZKN_WRONG_LENGTH;
  }

  zkn_bn_t r;       // r allocated on 64 bytes, output of blake prior to reduction, or 32 bytes when working on Fq
  zkn_bn_t bnbig_n; // order encoded over 64 bytes to allow reduction to be called on r
  zkn_bn_t red_r;   // r reduced over 64 bytes

  zkn_bn_t bn_s;
  zkn_bn_t hm; // poseidon hash of the message

  zkn_edpoint_t R;

  ZKN_CHECK(tEdwards_alloc(curve, &R));

  uint8_t sbuff[64];
  uint8_t rbuff[64];
  uint8_t s_u8[32];
  uint8_t r_u8[32];

  ZKN_CHECK(zkn_prv_hash(prv, sbuff, curve->fieldsize8)); // s | rbuff_low
  for (size_t i = 0; i < 32; i++)
    s_u8[i] = sbuff[i];

  // Nonce r = BLAKE-512(rb || msg) — must use original BLAKE-512, not BLAKE2b
  {
    zkn_blake512_ctx_t bctx;
    ZKN_CHECK(zkn_blake512_init(&bctx));
    ZKN_CHECK(zkn_blake512_update(&bctx, sbuff + 32, 32));
    ZKN_CHECK(zkn_blake512_update(&bctx, msg, len));
    ZKN_CHECK(zkn_blake512_final(&bctx, rbuff));
  }

  for (size_t i = 0; i < 64; i++)
    sbuff[i] = rbuff[63 - i]; // endianness

  ZKN_CHECK(zkn_bn_alloc_init(&r, 64, sbuff, 64));
  ZKN_CHECK(zkn_bn_alloc(&red_r, 64));

  uint8_t big_n[64] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05, 0x37, 0x0a, 0x08, 0xb6, 0xd0, 0x30, 0x2b, 0x0b,
      0xab, 0x3e, 0xed, 0xb8, 0x39, 0x20, 0xee, 0x0a, 0x67, 0x72, 0x97, 0xdc, 0x39, 0x21, 0x26, 0xf1};

  ZKN_CHECK(zkn_bn_alloc_init(&bnbig_n, 64, big_n, 64));

  ZKN_CHECK(zkn_bn_reduce(red_r, r, bnbig_n)); // reduce cannot be used in place ?

  uint8_t scalar[32];
  ZKN_CHECK(zkn_bn_export(red_r, scalar, 32));
#ifdef RAILGUN
  ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, scalar, &R));
#else
  ZKN_CHECK(tEdwards_fixedBase_2MSM(curve, scalar, &R));
#endif
  // ZKN_CHECK(tEdwards_scalarMul_bn(curve, &curve->G, &red_r, &R));
  ZKN_CHECK(tEdwards_normalize(curve, &R));
  ZKN_CHECK(tEdwards_export(curve, &R, out, out + 32));

  ZKN_CHECK(zkn_bn_export(red_r, r_u8, 32));

  // large size not required anymore
  ZKN_CHECK(zkn_bn_destroy(&bnbig_n));
  ZKN_CHECK(zkn_bn_destroy(&r));
  ZKN_CHECK(zkn_bn_destroy(&red_r));

  ZKN_CHECK(tEdwards_Curve_partial_destroy(curve)); // liberate work variables only

  for (size_t i = 0; i < 32; i++)
    rbuff[i] = msg[31 - i]; // i will always hate you

#ifdef RAILGUN
  // ── Soft Poseidon (zkn_bn, no zkn_bn pool pressure) ──
  {
    // Export Pub coordinates (de-montgomerize in-place, Pub not used after this)
    uint8_t pub_xy[64];
    ZKN_CHECK(zkn_mont_from_montgomery(Pub->x, Pub->x, &curve->ctx));
    ZKN_CHECK(zkn_mont_from_montgomery(Pub->y, Pub->y, &curve->ctx));
    ZKN_CHECK(zkn_bn_export(Pub->x, pub_xy, 32));
    ZKN_CHECK(zkn_bn_export(Pub->y, pub_xy + 32, 32));

    ZKN_CHECK(tEdwards_destroy(curve, &R));

    // Set up soft Montgomery context
    static const uint8_t bbjj_p[32] = {
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
        0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01};

    zkn_bn_mont_ctx_t soft_montctx;
    zkn_bn_t soft_modulus;
    ZKN_CHECK(zkn_bn_alloc_init(&soft_modulus, 32, bbjj_p, 32));
    ZKN_CHECK(zkn_mont_alloc(&soft_montctx, 32));
    ZKN_CHECK(zkn_mont_init(&soft_montctx, soft_modulus));

    poseidon_soft_ctx_t sctx;
    ZKN_CHECK(zkn_poseidon_init(&sctx, 5, 5, &soft_montctx));

    // R.x, R.y already exported to out[0..63] by tEdwards_export
    ZKN_CHECK(zkn_bn_init(sctx.state[1], out, 32));
    ZKN_CHECK(zkn_mont_to_montgomery(sctx.state[1], sctx.state[1], &soft_montctx));
    ZKN_CHECK(zkn_bn_init(sctx.state[2], out + 32, 32));
    ZKN_CHECK(zkn_mont_to_montgomery(sctx.state[2], sctx.state[2], &soft_montctx));

    // Pub.x, Pub.y
    ZKN_CHECK(zkn_bn_init(sctx.state[3], pub_xy, 32));
    ZKN_CHECK(zkn_mont_to_montgomery(sctx.state[3], sctx.state[3], &soft_montctx));
    ZKN_CHECK(zkn_bn_init(sctx.state[4], pub_xy + 32, 32));
    ZKN_CHECK(zkn_mont_to_montgomery(sctx.state[4], sctx.state[4], &soft_montctx));

    // msg (reversed to BE)
    ZKN_CHECK(zkn_bn_init(sctx.state[5], rbuff, 32));
    ZKN_CHECK(zkn_mont_to_montgomery(sctx.state[5], sctx.state[5], &soft_montctx));

    zkn_bn_t soft_temp;
    ZKN_CHECK(zkn_poseidon(&sctx, 0, &soft_temp, 1));

    ZKN_CHECK(zkn_mont_from_montgomery(sctx.state[0], sctx.state[0], &soft_montctx));

    uint8_t hash_out[32];
    ZKN_CHECK(zkn_bn_export(sctx.state[0], hash_out, 32));

    ZKN_CHECK(zkn_bn_alloc_init(&hm, 32, hash_out, 32));
  }
#else
  // ── Hard Poseidon (zkn_bn pool) ──
  ZKN_CHECK(Poseidon_alloc_init(&Ctx, 5, 5, &(curve->ctx)));

  ZKN_CHECK(zkn_bn_copy(Ctx.state[1], R.x));        // already in montgomery
  ZKN_CHECK(zkn_bn_copy(Ctx.state[2], R.y));        // already in montgomery
  ZKN_CHECK(zkn_bn_copy(Ctx.state[3], Pub->x));     // already in montgomery and normalized
  ZKN_CHECK(zkn_bn_copy(Ctx.state[4], Pub->y));     // already in montgomery and normalized
  ZKN_CHECK(zkn_bn_init(Ctx.state[5], rbuff, len)); // init state5 with message
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[5], Ctx.state[5], &curve->ctx));

  ZKN_CHECK(tEdwards_destroy(curve, &R));

  ZKN_CHECK(zkn_bn_alloc(&hm, 32));
  ZKN_CHECK(Poseidon(&Ctx, 0, &hm, 1));
  ZKN_CHECK(zkn_mont_from_montgomery(hm, hm, &curve->ctx)); // back to normal domain
#endif

  //----------------- COMPUTE S PART
  ZKN_CHECK(zkn_bn_alloc_init(&bn_s, 32, s_u8, 32));

  zkn_bn_t hms;
  ZKN_CHECK(zkn_bn_alloc(&hms, 32));

  ZKN_CHECK(zkn_bn_alloc_init(&bnbig_n, 32, big_n + 32, 32));
  // ZKN_CHECK(zkn_bn_export(bnbig_n, out+64, 32));

  ZKN_CHECK(zkn_bn_mod_mul(hms, hm, bn_s, bnbig_n)); // hms=hm*s mod q, beware modmul is destructive

  // ZKN_CHECK(zkn_bn_export(hms, out+96, 32));//ok, so hm and s are validated

  ZKN_CHECK(zkn_bn_init(hm, r_u8, 32)); // reload r
  // ZKN_CHECK(zkn_bn_export(hm, out+128, 32));

  ZKN_CHECK(zkn_bn_mod_add(bn_s, hm, hms, bnbig_n)); // hm*s+r%q
  // ZKN_CHECK(zkn_bn_export(bn_s, out+160, 32));

  ZKN_CHECK(zkn_bn_reduce(hm, bn_s, bnbig_n)); // hm*s+r %q because above is failing like shit, see https://github.com/LedgerHQ/ledger-secure-sdk/issues/1266

  ZKN_CHECK(zkn_bn_export(hm, out + 64, 32)); // last part S of signature

  ZKN_ERROR_CLOSE();
}
