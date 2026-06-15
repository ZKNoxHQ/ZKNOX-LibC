
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

  /* l = BabyJubjub subgroup order */
  static const uint8_t order_l[32] = {
      0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05, 0x37, 0x0a, 0x08, 0xb6, 0xd0, 0x30, 0x2b, 0x0b,
      0xab, 0x3e, 0xed, 0xb8, 0x39, 0x20, 0xee, 0x0a, 0x67, 0x72, 0x97, 0xdc, 0x39, 0x21, 0x26, 0xf1};
  /* 2^256 mod l (precomputed) */
  static const uint8_t two256_mod_l[32] = {
      0x01, 0xf1, 0x64, 0x24, 0xe1, 0xbb, 0x77, 0x24, 0xf8, 0x5a, 0x92, 0x01, 0xd8, 0x18, 0xf0, 0x15,
      0xe7, 0xac, 0xff, 0xc6, 0xa0, 0x98, 0xf2, 0x4b, 0x07, 0x33, 0x15, 0xde, 0xa0, 0x8f, 0x9c, 0x76};

  zkn_bn_t bn_l, bn_c, bn_hi, bn_lo;
  ZKN_CHECK(zkn_bn_alloc_init(&bn_l, 32, order_l, 32));
  ZKN_CHECK(zkn_bn_alloc_init(&bn_c, 32, two256_mod_l, 32));
  ZKN_CHECK(zkn_bn_alloc_init(&bn_hi, 32, sbuff, 32));        /* hi (BE) */
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

  uint8_t scalar[32];
  ZKN_CHECK(zkn_bn_export(red_r, scalar, 32));
  ZKN_CHECK(tEdwards_fixedBase_4MSM(curve, scalar, &R));
  // ZKN_CHECK(tEdwards_scalarMul_bn(curve, &curve->G, &red_r, &R));
  ZKN_CHECK(tEdwards_normalize(curve, &R));
  ZKN_CHECK(tEdwards_export(curve, &R, out, out + 32));

  ZKN_CHECK(zkn_bn_export(red_r, r_u8, 32));

  // large size not required anymore
  ZKN_CHECK(zkn_bn_destroy(&red_r));

  /* Snapshot R and Pub coordinates as Montgomery-form bytes so that both
   * points can be freed BEFORE zkn_poseidon_init allocates its 49 BN.
   *
   * Pre-patch the peak sat at ~58/64 with R(3) + Pub(3) + Ctx(49) + hm(1)
   * + curve residue all alive at once. SDK transients inside cx_bn_reduce
   * / cx_bn_mod_mul (a few slots each) pushed us over 64 and wiped the
   * device. Releasing R + Pub here drops the peak by 6, leaving ~52/64
   * with real headroom for the SDK's internal allocations.
   *
   * Bytes are taken straight from the Montgomery-form handles — no
   * mont_from_montgomery — and reloaded post-init via zkn_bn_init, which
   * preserves the bit-pattern. /!\ Pub is destroyed in place; callers
   * must not touch it after this function returns. */
  uint8_t rx_mont[32], ry_mont[32], px_mont[32], py_mont[32];
  ZKN_CHECK(zkn_bn_export(R.x,    rx_mont, 32));
  ZKN_CHECK(zkn_bn_export(R.y,    ry_mont, 32));
  ZKN_CHECK(zkn_bn_export(Pub->x, px_mont, 32));
  ZKN_CHECK(zkn_bn_export(Pub->y, py_mont, 32));

  ZKN_CHECK(tEdwards_destroy(curve, &R));
  ZKN_CHECK(tEdwards_destroy(curve, Pub));

  ZKN_CHECK(tEdwards_Curve_partial_destroy(curve)); // liberate work variables only

  for (size_t i = 0; i < 32; i++)
    rbuff[i] = msg[31 - i]; // i will always hate you

  // ── Poseidon hm = H(R.x, R.y, Pub.x, Pub.y, msg) ──
  // Reuses curve->ctx as the Montgomery context. R + Pub were freed above
  // so their 6 BN are no longer competing with the 49 Ctx allocs.
  ZKN_CHECK(zkn_poseidon_init(&Ctx, 5, 5, &(curve->ctx)));

  // R.x, R.y, Pub.x, Pub.y bytes are already Montgomery — load verbatim,
  // no to_montgomery (would double-Montgomerize and produce wrong hash).
  ZKN_CHECK(zkn_bn_init(Ctx.state[1], rx_mont, 32));
  ZKN_CHECK(zkn_bn_init(Ctx.state[2], ry_mont, 32));
  ZKN_CHECK(zkn_bn_init(Ctx.state[3], px_mont, 32));
  ZKN_CHECK(zkn_bn_init(Ctx.state[4], py_mont, 32));
  ZKN_CHECK(zkn_bn_init(Ctx.state[5], rbuff, len)); // init state5 with message
  ZKN_CHECK(zkn_mont_to_montgomery(Ctx.state[5], Ctx.state[5], &curve->ctx));

  ZKN_CHECK(zkn_bn_alloc(&hm, 32));
  ZKN_CHECK(zkn_poseidon(&Ctx, 0, (zkn_bn_t *)hm, 1));
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

  ZKN_ERROR_CLOSE();
}
