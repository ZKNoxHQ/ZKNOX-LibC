
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
#include "zkn_poseidon.h"
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
  /* from LE to BE (full 32-byte reversal). Was rev256((uint64_t *)out): an
   * unaligned uint64_t access through a uint8_t buffer (strict-aliasing UB;
   * LDRD on an unaligned address faults on ARMv7-M). Same result. */
  ByteSwap(out, 32);
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

  ZKN_CHECK(zkn_prv_hash(prv, out, curve->fieldsize8));
  // 3.  Interpret the buffer as the little-endian integer, forming asecret scalar s.  Perform a fixed-base scalar multiplication [s]B.
  shr3(out);

#if defined(ZKN_FIXEDBASE_SCALAR_BLINDING)
#if !defined(ZKN_HAVE_FIXEDBASE_BLIND)
#error "ZKN_FIXEDBASE_SCALAR_BLINDING needs ZKN_FIXEDBASE_FLASH_TABLE and the software bignums"
#endif
  /* The private scalar is the same at every call: it is blinded with a
   * multiple of the subgroup order, fresh each time. */
  ZKN_CHECK(tEdwards_fixedBase_4MSM_blind(curve, out, Pub));
#else
  ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, out, Pub));
#endif
  // ZKN_CHECK(tEdwards_scalarMul(curve, &curve->G, out, curve->fieldsize8, Pub));
  ZKN_CHECK(tEdwards_normalize(curve, Pub)); // montgomery and normalized

end: __attribute__((unused))
  /* out[] holds the private scalar and the nonce-derivation key. */
  explicit_bzero(out, sizeof(out));
  return error;
}

/* 1 iff the 32-byte little-endian value is < p_be (32-byte big-endian). */
static int eddsa_msg_is_field_element(const uint8_t *msg_le, const uint8_t *p_be)
{
  for (int i = 0; i < 32; i++)
  {
    uint8_t m = msg_le[31 - i];
    if (m < p_be[i]) return 1;
    if (m > p_be[i]) return 0;
  }
  return 0; /* equal to p */
}

#if defined(ZKN_LOW_RAM) && defined(ZKN_BN_BACKEND_SW)
/* ══════════════════════════════════════════════════════════════════════
 *  Low-RAM EddsaPoseidon_Sign_final (software bignums)
 *
 *  Same operations and same signature, byte for byte, as the standard
 *  implementation further down. Only the layout changes: SW bignums are
 *  32-byte arrays living in the caller's frame, so the standard function
 *  keeps every temporary of every step alive at once (3.4 KB on ARMv6-M).
 *  Here each step runs in its own non-inlined function and returns only
 *  what the next one needs, so the frames never stack up:
 *
 *      check_pub   Pd = [s>>3]B, compared with the caller's Pub
 *      nonce_hash  H = BLAKE-512(prv_hash[32..64] || msg)
 *      nonce_red   r = H mod l
 *      commit      R = [r]B                       -> out[0..64]
 *      challenge   hm = Poseidon(R, Pub, msg)
 *      response    S = r + hm*s mod l             -> out[64..96]
 *
 *  l is the subgroup order of the signing curve, read from the curve as in
 *  the standard implementation. `challenge` releases curve->order with the
 *  work variables, so the bytes of l cross it in the 64 bytes of scratch
 *  that held H, free once r is reduced: no stack is added for them.
 *
 *  s is recomputed in `response` instead of being carried across the
 *  scalar multiplications: one more BLAKE-512 block, 32 secret bytes less
 *  on the stack at the deepest point.
 *
 *  EddsaPoseidon_Sign is the same signer without the caller's Pub: it
 *  derives the public key itself, once, so `check_pub` has nothing to
 *  compare and is replaced by that derivation.
 * ══════════════════════════════════════════════════════════════════════ */

#define ZKN_NOINLINE __attribute__((noinline))

/* Re-derive the public key from prv and refuse a caller-supplied Pub that
 * does not match it ("double public key" signing oracle, see the standard
 * implementation). Leaves Pub normalized, in Montgomery form. */
static ZKN_NOINLINE int lr_check_pub(zkn_edcurve_t *curve, uint8_t *prv, zkn_edpoint_t *Pub)
{
  ZKN_ERROR_INIT();
  zkn_edpoint_t Pd;
  int cx = 1, cy = 1;

  ZKN_CHECK(tEdwards_alloc(curve, &Pd));
  ZKN_CHECK(zkn_prv2pub(curve, prv, &Pd)); /* normalized, Montgomery */
  ZKN_CHECK(tEdwards_normalize(curve, Pub));
  ZKN_CHECK(zkn_bn_cmp_mod(Pd.x, Pub->x, curve->modulus, &cx));
  ZKN_CHECK(zkn_bn_cmp_mod(Pd.y, Pub->y, curve->modulus, &cy));
  ZKN_CHECK(tEdwards_destroy(curve, &Pd));
  if (cx != 0 || cy != 0)
    error = ZKN_ERR_INVALID_PARAM;

  ZKN_ERROR_CLOSE();
}

/* h_be = BLAKE-512(prv_hash(prv)[32..64] || msg), as a 512-bit big-endian
 * integer: h_be[0..32] = high half, h_be[32..64] = low half. */
static ZKN_NOINLINE int lr_nonce_hash(zkn_edcurve_t *curve, const uint8_t *prv,
                                      const uint8_t *msg, size_t len, uint8_t h_be[64])
{
  ZKN_ERROR_INIT();
  uint8_t sbuff[64]; /* s | nonce key, then the raw digest */
  zkn_blake512_ctx_t bctx;

  ZKN_CHECK(zkn_prv_hash(prv, sbuff, curve->fieldsize8));

  // Nonce r = BLAKE-512(rb || msg) — must use original BLAKE-512, not BLAKE2b
  ZKN_CHECK(zkn_blake512_init(&bctx));
  ZKN_CHECK(zkn_blake512_update(&bctx, sbuff + 32, 32));
  ZKN_CHECK(zkn_blake512_update(&bctx, msg, len));
  ZKN_CHECK(zkn_blake512_final(&bctx, sbuff));

  for (size_t i = 0; i < 64; i++)
    h_be[i] = sbuff[63 - i];

end: __attribute__((unused))
  explicit_bzero(sbuff, sizeof(sbuff));
  explicit_bzero(&bctx, sizeof(bctx)); /* buffered the nonce key */
  return error;
}

/* r_be = h mod l, with 256-bit arithmetic only:
 *     r = (lo + hi * (2^256 mod l)) mod l
 * (see the standard implementation for why a single 512-bit reduce is not
 * available on the SW backend). l is curve->order, still allocated here. */
static ZKN_NOINLINE int lr_nonce_reduce(zkn_edcurve_t *curve, const uint8_t h_be[64], uint8_t r_be[32])
{
  ZKN_ERROR_INIT();
  zkn_bn_t bn_c, bn_hi, bn_lo, red_r;

  /* 2^256 mod l, from 2^256 - l: congruent to 2^256, and it fits the 256-bit
   * bignum. r_be is free until r is exported. */
  ZKN_CHECK(zkn_bn_export(curve->order, r_be, 32));
  {
    unsigned carry = 1;
    for (size_t i = 32; i-- > 0;)
    {
      carry += (uint8_t)~r_be[i];
      r_be[i] = (uint8_t)carry;
      carry >>= 8;
    }
  }
  ZKN_CHECK(zkn_bn_alloc_init(&bn_hi, 32, r_be, 32));      /* 2^256 - l */
  ZKN_CHECK(zkn_bn_alloc(&bn_c, 32));
  ZKN_CHECK(zkn_bn_reduce(bn_c, bn_hi, curve->order));     /* 2^256 mod l */
  ZKN_CHECK(zkn_bn_init(bn_hi, h_be, 32));                 /* hi (BE) */
  ZKN_CHECK(zkn_bn_alloc_init(&bn_lo, 32, h_be + 32, 32)); /* lo (BE) */

  ZKN_CHECK(zkn_bn_alloc(&red_r, 32));
  /* red_r = hi * (2^256 mod l) mod l */
  ZKN_CHECK(zkn_bn_mod_mul(red_r, bn_hi, bn_c, curve->order));
  /* red_r = (red_r + lo) mod l */
  ZKN_CHECK(zkn_bn_mod_add(red_r, red_r, bn_lo, curve->order));

  ZKN_CHECK(zkn_bn_export(red_r, r_be, 32));

end: __attribute__((unused))
  explicit_bzero(red_r, sizeof(red_r));
  explicit_bzero(bn_hi, sizeof(bn_hi));
  explicit_bzero(bn_lo, sizeof(bn_lo));
  return error;
}

/* R = [r]B, exported as canonical big-endian affine coordinates. */
static ZKN_NOINLINE int lr_commit(zkn_edcurve_t *curve, const uint8_t r_be[32],
                                  uint8_t rx_be[32], uint8_t ry_be[32])
{
  ZKN_ERROR_INIT();
  zkn_edpoint_t R;

  ZKN_CHECK(tEdwards_alloc(curve, &R));
  ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, r_be, &R));
  /* tEdwards_export normalizes: one inversion, not two. */
  ZKN_CHECK(tEdwards_export(curve, &R, rx_be, ry_be));
  ZKN_CHECK(tEdwards_destroy(curve, &R));

  ZKN_ERROR_CLOSE();
}

/* hm_be = Poseidon(R.x, R.y, Pub.x, Pub.y, msg), canonical big-endian.
 *
 * R comes in as the canonical bytes just exported. Pub is taken out of
 * Montgomery form in place, exactly as the standard implementation does
 * before exporting it: Pub and the curve's work variables are consumed. */
static ZKN_NOINLINE int lr_challenge(zkn_edcurve_t *curve, zkn_edpoint_t *Pub,
                                     const uint8_t rx_be[32], const uint8_t ry_be[32],
                                     const uint8_t *msg, size_t len, uint8_t hm_be[32])
{
  ZKN_ERROR_INIT();
  zkn_poseidon_ctx_t Ctx;
  zkn_bn_t hm;
  uint8_t msg_be[32];
  bool ctx_inited = false;

  ZKN_CHECK(zkn_mont_from_montgomery(Pub->x, Pub->x, &curve->ctx));
  ZKN_CHECK(zkn_mont_from_montgomery(Pub->y, Pub->y, &curve->ctx));

  ZKN_CHECK(tEdwards_Curve_partial_destroy(curve)); // liberate work variables only

  for (size_t i = 0; i < 32; i++)
    msg_be[i] = msg[31 - i];

  ZKN_CHECK(zkn_poseidon_init(&Ctx, 5, 5, &(curve->ctx), curve->modulus));
  ctx_inited = true;

  ZKN_CHECK(zkn_bn_init(Ctx.state[1], rx_be, 32));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[1], Ctx.state[1], &curve->ctx));
  ZKN_CHECK(zkn_bn_init(Ctx.state[2], ry_be, 32));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[2], Ctx.state[2], &curve->ctx));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[3], Pub->x, &curve->ctx));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[4], Pub->y, &curve->ctx));
  ZKN_CHECK(zkn_bn_init(Ctx.state[5], msg_be, len));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[5], Ctx.state[5], &curve->ctx));

  ZKN_CHECK(tEdwards_destroy(curve, Pub));

  ZKN_CHECK(zkn_bn_alloc(&hm, 32));
  ZKN_CHECK(zkn_poseidon(&Ctx, 0, &hm, 1));
  ZKN_CHECK(zkn_mont_from_montgomery(hm, hm, &curve->ctx)); // back to normal domain
  ZKN_CHECK(zkn_bn_export(hm, hm_be, 32));

end: __attribute__((unused))
  if (ctx_inited)
    (void)zkn_poseidon_destroy(&Ctx);
  return error;
}

/* S = (r + hm * s) mod l, canonical big-endian. l_be holds l: curve->order
 * is released by the time this runs. */
static ZKN_NOINLINE int lr_response(zkn_edcurve_t *curve, const uint8_t *prv,
                                    const uint8_t r_be[32], const uint8_t hm_be[32],
                                    const uint8_t l_be[32], uint8_t s_out[32])
{
  ZKN_ERROR_INIT();
  uint8_t sbuff[64];
  zkn_bn_t bn_s, hms, bnbig_n, hm;

  ZKN_CHECK(zkn_bn_alloc(&bn_s, 32));
  ZKN_CHECK(zkn_bn_alloc(&hms, 32));
  ZKN_CHECK(zkn_bn_alloc(&hm, 32));

  ZKN_CHECK(zkn_prv_hash(prv, sbuff, curve->fieldsize8)); // s | nonce key
  ZKN_CHECK(zkn_bn_init(bn_s, sbuff, 32));
  ZKN_CHECK(zkn_bn_init(hm, hm_be, 32));

  ZKN_CHECK(zkn_bn_alloc_init(&bnbig_n, 32, l_be, 32));

  ZKN_CHECK(zkn_bn_mod_mul(hms, hm, bn_s, bnbig_n)); // hms=hm*s mod q, beware modmul is destructive
  ZKN_CHECK(zkn_bn_init(hm, r_be, 32));              // reload r
  ZKN_CHECK(zkn_bn_mod_add(bn_s, hm, hms, bnbig_n)); // hm*s+r%q
  ZKN_CHECK(zkn_bn_reduce(hm, bn_s, bnbig_n));       // same final reduce as the standard path

  ZKN_CHECK(zkn_bn_export(hm, s_out, 32)); // last part S of signature

end: __attribute__((unused))
  explicit_bzero(sbuff, sizeof(sbuff));
  explicit_bzero(bn_s, sizeof(bn_s));
  explicit_bzero(hms, sizeof(hms));
  explicit_bzero(hm, sizeof(hm)); /* held r */
  return error;
}

/* len == 32 and msg < p: same check, same bound (curve->modulus) as the
 * standard implementation. p_be is 32 bytes of scratch. */
static int lr_check_msg(zkn_edcurve_t *curve, const uint8_t *msg, size_t len, uint8_t *p_be)
{
  if (len != 32)
  {
    return ZKN_WRONG_LENGTH;
  }
  if (curve->fieldsize8 != 32 || zkn_bn_export(curve->modulus, p_be, 32) != ZKN_OK)
  {
    return ZKN_ERR_INVALID_PARAM;
  }
  if (!eddsa_msg_is_field_element(msg, p_be))
  {
    return ZKN_ERR_INVALID_PARAM;
  }
  return ZKN_OK;
}

/* The steps that follow the public key: nonce, commitment, challenge,
 * response. Pub is the signer's own public key, normalized and in
 * Montgomery form; it is consumed. wide is 64 bytes of scratch, wiped.
 * Inlined in the two entry points, whose frames stay those of a single
 * function. */
static inline __attribute__((always_inline)) int lr_sign_steps(zkn_edcurve_t *curve, uint8_t *prv,
                                                               zkn_edpoint_t *Pub, uint8_t *msg, size_t len,
                                                               uint8_t *out, uint8_t wide[64])
{
  ZKN_ERROR_INIT();
  uint8_t r_be[32]; /* the nonce r */
  uint8_t hm_be[32];

  ZKN_CHECK(lr_nonce_hash(curve, prv, msg, len, wide));
  ZKN_CHECK(lr_nonce_reduce(curve, wide, r_be));
  explicit_bzero(wide, 64);

  /* l for lr_response, taken before lr_challenge releases curve->order. */
  ZKN_CHECK(zkn_bn_export(curve->order, wide, 32));

  ZKN_CHECK(lr_commit(curve, r_be, out, out + 32));
  ZKN_CHECK(lr_challenge(curve, Pub, out, out + 32, msg, len, hm_be));
  ZKN_CHECK(lr_response(curve, prv, r_be, hm_be, wide, out + 64));

end: __attribute__((unused))
  explicit_bzero(wide, 64);
  explicit_bzero(r_be, sizeof(r_be));
  return error;
}

int EddsaPoseidon_Sign_final(zkn_edcurve_t *curve, uint8_t *prv, zkn_edpoint_t *Pub, uint8_t *msg, size_t len, uint8_t *out)
{
  ZKN_ERROR_INIT();
  uint8_t wide[64]; /* p, then the 512-bit nonce hash */

  error = lr_check_msg(curve, msg, len, wide);
  if (error != ZKN_OK)
  {
    return error;
  }

  ZKN_CHECK(lr_check_pub(curve, prv, Pub));
  ZKN_CHECK(lr_sign_steps(curve, prv, Pub, msg, len, out, wide));

end: __attribute__((unused))
  explicit_bzero(wide, sizeof(wide));
  return error;
}

/* Sign with the public key derived here, from prv, once.
 *
 * zkn_prv2pub() followed by EddsaPoseidon_Sign_final() computes the public
 * key twice: in the caller, and again in the check that guards the signer
 * against a caller-supplied Pub that is not the key's (the "double public
 * key" oracle: r does not depend on Pub, the challenge does). With no Pub
 * coming in there is nothing to forge and nothing to compare: two fixed-base
 * multiplications instead of three, two inversions instead of five. Same
 * signature, byte for byte.
 *
 * What goes with the second derivation: a fault in the single one is not
 * caught here. Neither entry point catches a fault in R or in the hash. */
int EddsaPoseidon_Sign(zkn_edcurve_t *curve, uint8_t *prv, uint8_t *msg, size_t len, uint8_t *out)
{
  ZKN_ERROR_INIT();
  uint8_t wide[64]; /* p, then the 512-bit nonce hash */
  zkn_edpoint_t Pub;
  bool pub_alloc = false;

  error = lr_check_msg(curve, msg, len, wide);
  if (error != ZKN_OK)
  {
    return error;
  }

  ZKN_CHECK(tEdwards_alloc(curve, &Pub));
  pub_alloc = true;
  ZKN_CHECK(zkn_prv2pub(curve, prv, &Pub)); /* normalized, Montgomery */
  ZKN_CHECK(lr_sign_steps(curve, prv, &Pub, msg, len, out, wide));

end: __attribute__((unused))
  explicit_bzero(wide, sizeof(wide));
  if (error != ZKN_OK && pub_alloc)
  {
    (void)tEdwards_destroy(curve, &Pub); /* the challenge step destroys it otherwise */
  }
  return error;
}

#else /* standard implementation */

// derivation of public key, in a RFC8032 way, but using babyjujub
// for now message is limited to 64 bytes
// todo: use init/update/final
// note: for now it is destructive for the input curve structure AND for
//       the input Pub point (both freed before Poseidon to keep the cx_bn
//       pool peak under 64 — see the inline comment near the Poseidon
//       stage for the rationale and historical wipe context).
int EddsaPoseidon_Sign_final(zkn_edcurve_t *curve, uint8_t *prv, zkn_edpoint_t *Pub, uint8_t *msg, size_t len, uint8_t *out)
{

  ZKN_ERROR_INIT();
  zkn_poseidon_ctx_t Ctx;

  if (len != 32)
  {
    return ZKN_WRONG_LENGTH;
  }
  /* The message is an element of the curve's base field, the field Poseidon
   * runs over below (circomlib signPoseidon takes F.e(msg)). Values >= p were
   * silently reduced inside Poseidon, so the same signature was valid for two
   * distinct 32-byte messages (m and m + p). The bound is curve->modulus, not
   * the BabyJubjub prime: Bandersnatch hashes over the larger BLS12-381 Fr. */
  {
    uint8_t p_be[32];
    if (curve->fieldsize8 != 32 || zkn_bn_export(curve->modulus, p_be, 32) != ZKN_OK)
    {
      return ZKN_ERR_INVALID_PARAM;
    }
    if (!eddsa_msg_is_field_element(msg, p_be))
    {
      return ZKN_ERR_INVALID_PARAM;
    }
  }

  zkn_bn_t bnbig_n; // order encoded over 64 bytes to allow reduction to be called on r
  zkn_bn_t red_r;   // r reduced over 64 bytes

  zkn_bn_t bn_s;
  zkn_bn_t hm; // poseidon hash of the message

  zkn_edpoint_t R;
  uint8_t scalar[32];

  /* SECURITY — "double public key" signing oracle (key recovery).
   *
   * The nonce r = H(prv_hi || msg) does not depend on Pub, but the challenge
   * hm = Poseidon(R, Pub, msg) does. The signer used to trust the
   * caller-supplied Pub, so signing the same msg twice with two different
   * Pub values produced S1 = r + h1*s and S2 = r + h2*s with the same r, and
   * s = (S1 - S2) / (h1 - h2) fell out immediately (demonstrated against this
   * library). Re-derive the public key from prv and refuse to sign if the
   * caller's Pub does not match it. */
  {
    zkn_edpoint_t Pd;
    int cx = 1, cy = 1;
    ZKN_CHECK(tEdwards_alloc(curve, &Pd));
    ZKN_CHECK(zkn_prv2pub(curve, prv, &Pd));     /* normalized, Montgomery */
    ZKN_CHECK(tEdwards_normalize(curve, Pub));
    /* As residues: both are affine and in Montgomery form, but a backend
     * may hold a coordinate as its value plus p (zkn_bn.h). */
    ZKN_CHECK(zkn_bn_cmp_mod(Pd.x, Pub->x, curve->modulus, &cx));
    ZKN_CHECK(zkn_bn_cmp_mod(Pd.y, Pub->y, curve->modulus, &cy));
    ZKN_CHECK(tEdwards_destroy(curve, &Pd));
    if (cx != 0 || cy != 0)
    {
      error = ZKN_ERR_INVALID_PARAM;
      goto end;
    }
  }

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

  /* Reduce the 512-bit BLAKE output modulo the subgroup order l.
   *
   * The SW backend's zkn_bn_t is a fixed 256-bit type, so it cannot hold the
   * 512-bit nonce hash. Computing r = H mod l via a single 64-byte zkn_bn was
   * silently truncating H to 256 bits (the low/high half depending on
   * zkn_bn_init's byte-keeping policy), producing a wrong nonce and a
   * signature that did not match circomlib.
   *
   * Instead we split H (big-endian after the reversal below) into two 256-bit
   * halves and combine them with 256-bit modular arithmetic only:
   *     r = (lo + hi * (2^256 mod l)) mod l
   * which equals fromRprLE(rbuff,0,64) mod l — bit-for-bit identical to
   * circomlib's signPoseidon. Works on both the SW and Ledger backends.
   */
  for (size_t i = 0; i < 64; i++)
    sbuff[i] = rbuff[63 - i]; // 512-bit BE: sbuff[0..32]=hi, sbuff[32..64]=lo

  /* l = subgroup order of the signing curve.
   *
   * It used to be the BabyJubjub order, hard-coded, for every curve. On
   * Bandersnatch r and S were then reduced modulo the order of another group,
   * and the signature did not satisfy [S]B = R + [8h]A.
   *
   * curve->order is released with the work variables before S is computed
   * (tEdwards_Curve_partial_destroy), hence the byte copy. */
  uint8_t order_l[32];
  ZKN_CHECK(zkn_bn_export(curve->order, order_l, 32));
  /* 2^256 mod l, from 2^256 - l: congruent to 2^256, and it fits the 256-bit
   * bignum. `scalar` is free until r is exported. */
  {
    unsigned carry = 1;
    for (size_t i = 32; i-- > 0;)
    {
      carry += (uint8_t)~order_l[i];
      scalar[i] = (uint8_t)carry;
      carry >>= 8;
    }
  }

  zkn_bn_t bn_l, bn_c, bn_hi, bn_lo;
  ZKN_CHECK(zkn_bn_alloc_init(&bn_l, 32, order_l, 32));
  ZKN_CHECK(zkn_bn_alloc_init(&bn_hi, 32, scalar, 32));       /* 2^256 - l */
  ZKN_CHECK(zkn_bn_alloc(&bn_c, 32));
  ZKN_CHECK(zkn_bn_reduce(bn_c, bn_hi, bn_l));                /* 2^256 mod l */
  ZKN_CHECK(zkn_bn_init(bn_hi, sbuff, 32));                   /* hi (BE) */
  ZKN_CHECK(zkn_bn_alloc_init(&bn_lo, 32, sbuff + 32, 32));   /* lo (BE) */

  ZKN_CHECK(zkn_bn_alloc(&red_r, 32));
  /* red_r = hi * (2^256 mod l) mod l */
  ZKN_CHECK(zkn_bn_mod_mul(red_r, bn_hi, bn_c, bn_l));
  /* red_r = (red_r + lo) mod l */
  ZKN_CHECK(zkn_bn_mod_add(red_r, red_r, bn_lo, bn_l));

  ZKN_CHECK(zkn_bn_destroy(&bn_l));
  ZKN_CHECK(zkn_bn_destroy(&bn_c));
  ZKN_CHECK(zkn_bn_destroy(&bn_hi));
  ZKN_CHECK(zkn_bn_destroy(&bn_lo));

  ZKN_CHECK(zkn_bn_export(red_r, scalar, 32));
  ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, scalar, &R));
  // ZKN_CHECK(tEdwards_scalarMul_bn(curve, &curve->G, &red_r, &R));
  ZKN_CHECK(tEdwards_normalize(curve, &R));
  ZKN_CHECK(tEdwards_export(curve, &R, out, out + 32));

  ZKN_CHECK(zkn_bn_export(red_r, r_u8, 32));

  // large size not required anymore
  ZKN_CHECK(zkn_bn_destroy(&red_r));

  /* Snapshot R and Pub coordinates as NON-Montgomery (affine) bytes so
   * that both points can be freed BEFORE zkn_poseidon_init allocates its
   * 49 BN, AND so that state[1..4] can be loaded via the same
   * bn_init+to_montgomery pattern as the working arity-5 Poseidon test
   * (handler_poseidon.c).
   *
   * Coordinates must cross the release/reload boundary in their raw affine
   * representation. Reloading Montgomery-form bytes with cx_bn_init bypasses
   * the required domain conversion and caused the former CX signing fault at
   * Poseidon's first multiplication.
   *
   * In-place from_montgomery is safe (SDK allows dst == src). /!\ Pub is
   * destroyed in place; callers must not touch it after this function
   * returns. */
  uint8_t rx_raw[32], ry_raw[32], px_raw[32], py_raw[32];
  ZKN_CHECK(zkn_mont_from_montgomery(R.x,    R.x,    &curve->ctx));
  ZKN_CHECK(zkn_mont_from_montgomery(R.y,    R.y,    &curve->ctx));
  ZKN_CHECK(zkn_mont_from_montgomery(Pub->x, Pub->x, &curve->ctx));
  ZKN_CHECK(zkn_mont_from_montgomery(Pub->y, Pub->y, &curve->ctx));
  ZKN_CHECK(zkn_bn_export(R.x,    rx_raw, 32));
  ZKN_CHECK(zkn_bn_export(R.y,    ry_raw, 32));
  ZKN_CHECK(zkn_bn_export(Pub->x, px_raw, 32));
  ZKN_CHECK(zkn_bn_export(Pub->y, py_raw, 32));

  ZKN_CHECK(tEdwards_destroy(curve, &R));
  ZKN_CHECK(tEdwards_destroy(curve, Pub));

  ZKN_CHECK(tEdwards_Curve_partial_destroy(curve)); // liberate work variables only

  for (size_t i = 0; i < 32; i++)
    rbuff[i] = msg[31 - i]; // i will always hate you

  // ── Poseidon hm = H(R.x, R.y, Pub.x, Pub.y, msg) ──
  // Reuses curve->ctx as the Montgomery context. R + Pub were freed above
  // so their 6 BN are no longer competing with the 49 Ctx allocs.
  ZKN_CHECK(zkn_poseidon_init(&Ctx, 5, 5, &(curve->ctx), curve->modulus));

  // Load raw affine coords + to_montgomery. Mirrors handler_poseidon.c —
  // the working arity-5 Poseidon path always calls to_montgomery on state
  // inputs, so we do the same here rather than the "bn_init verbatim from
  // Montgomery bytes" shortcut that triggered the CX-sign wipe.
  ZKN_CHECK(zkn_bn_init(Ctx.state[1], rx_raw, 32));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[1], Ctx.state[1], &curve->ctx));
  ZKN_CHECK(zkn_bn_init(Ctx.state[2], ry_raw, 32));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[2], Ctx.state[2], &curve->ctx));
  ZKN_CHECK(zkn_bn_init(Ctx.state[3], px_raw, 32));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[3], Ctx.state[3], &curve->ctx));
  ZKN_CHECK(zkn_bn_init(Ctx.state[4], py_raw, 32));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[4], Ctx.state[4], &curve->ctx));
  ZKN_CHECK(zkn_bn_init(Ctx.state[5], rbuff, len));
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[5], Ctx.state[5], &curve->ctx));

  ZKN_CHECK(zkn_bn_alloc(&hm, 32));
  ZKN_CHECK(zkn_poseidon(&Ctx, 0, &hm, 1));
  ZKN_CHECK(zkn_mont_from_montgomery(hm, hm, &curve->ctx)); // back to normal domain

  /* Release the 49 cx_bn allocated by zkn_poseidon_init. No-op on SW
   * backend; required on cx_bn backend to keep the BOLOS BN pool from
   * filling up across consecutive signatures. */
  ZKN_CHECK(zkn_poseidon_destroy(&Ctx));

  //----------------- COMPUTE S PART
  ZKN_CHECK(zkn_bn_alloc_init(&bn_s, 32, s_u8, 32));

  zkn_bn_t hms;
  ZKN_CHECK(zkn_bn_alloc(&hms, 32));

  ZKN_CHECK(zkn_bn_alloc_init(&bnbig_n, 32, order_l, 32));
  // ZKN_CHECK(zkn_bn_export(bnbig_n, out+64, 32));

  ZKN_CHECK(zkn_bn_mod_mul(hms, hm, bn_s, bnbig_n)); // hms=hm*s mod q, beware modmul is destructive

  // ZKN_CHECK(zkn_bn_export(hms, out+96, 32));//ok, so hm and s are validated

  ZKN_CHECK(zkn_bn_init(hm, r_u8, 32)); // reload r
  // ZKN_CHECK(zkn_bn_export(hm, out+128, 32));

  ZKN_CHECK(zkn_bn_mod_add(bn_s, hm, hms, bnbig_n)); // hm*s+r%q
  // ZKN_CHECK(zkn_bn_export(bn_s, out+160, 32));

  ZKN_CHECK(zkn_bn_reduce(hm, bn_s, bnbig_n)); // hm*s+r %q because above is failing like shit, see https://github.com/LedgerHQ/ledger-secure-sdk/issues/1266

  ZKN_CHECK(zkn_bn_export(hm, out + 64, 32)); // last part S of signature

  ZKN_CHECK(zkn_bn_destroy(&hms));
  ZKN_CHECK(zkn_bn_destroy(&bnbig_n));
  ZKN_CHECK(zkn_bn_destroy(&bn_s));
  ZKN_CHECK(zkn_bn_destroy(&hm));

  /* S17: explicit_bzero every secret-bearing stack buffer on EVERY exit
   * path (success + every ZKN_CHECK-triggered goto). sbuff[64] holds
   * the derived spending scalar (hi||lo); rbuff[64] holds intermediate
   * BLAKE-512 nonce material; s_u8[32] is the BE-reversed scalar fed
   * to the Poseidon state; r_u8[32] is the BE-reversed message word.
   * Inlines the ZKN_ERROR_CLOSE() macro body so the cleanup is
   * physically between the `end:` label and the return — both the
   * success path and the goto-end error path run it.
   */
end: __attribute__((unused))
  explicit_bzero(sbuff, sizeof(sbuff));
  explicit_bzero(rbuff, sizeof(rbuff));
  explicit_bzero(s_u8,  sizeof(s_u8));
  explicit_bzero(r_u8,  sizeof(r_u8));
  explicit_bzero(scalar, sizeof(scalar)); /* the nonce r */
#ifdef ZKN_BN_BACKEND_SW
  /* SW bignums are stack arrays holding s, r and s*hm. (On the cx_bn backend
   * these are pool handles; the pool is erased by cx_bn_unlock.) */
  explicit_bzero(red_r, sizeof(red_r));
  explicit_bzero(bn_s, sizeof(bn_s));
  explicit_bzero(hms, sizeof(hms));
  explicit_bzero(bn_hi, sizeof(bn_hi)); /* BLAKE-512 nonce hash halves: */
  explicit_bzero(bn_lo, sizeof(bn_lo)); /* r = hi*2^256 + lo mod l       */
  explicit_bzero(hm, sizeof(hm));       /* holds r between reload and S */
#endif
  return error;
}

#endif /* ZKN_LOW_RAM && ZKN_BN_BACKEND_SW */
