/* test_security_regressions.c — regression tests for the security review.
 *
 * Every check below failed (or crashed / hung) on the code before the fixes
 * documented in SECURITY_AUDIT.md. Grouped by finding ID.
 *
 * Requires ZKN_HOST_TESTS and ZKNOX_DEBUG (FROST / VSS helpers).
 * The ECDH section additionally needs a WITH_KEYS=1 build.
 */
#if defined(ZKN_HOST_TESTS) && defined(ZKNOX_DEBUG)

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zkn_bn.h"
#include "zkn_common.h"
#include "zkn_rng_compat.h"
#include "zkn_tEdwards.h"
#include "zkn_eddsa.h"
#include "zkn_frost.h"
#include "zkn_vss.h"
#include "zkn_poseidon.h"
#include "zkn_miller.h"
#include "zkn_pairing_384.h"
#include "zkn_final_exp_384.h"
#include "zkn_groth16.h"
#include "zkn_plonk.h"
#include "storage_proof.h"
#ifdef ZKN_WITH_KEYS
#include "zkn_ed25519_ecdh.h"
#endif

static int g_pass = 0, g_fail = 0;
static void check(const char *name, int ok)
{
  printf("  %s %s\n", ok ? "[PASS]" : "[FAIL]", name);
  if (ok) g_pass++; else g_fail++;
}

/* raw 256-bit big-endian addition (no reduction) */
static void add_be(uint8_t *a, const uint8_t *b, size_t n)
{
  unsigned c = 0;
  for (size_t i = n; i-- > 0;) { unsigned s = a[i] + b[i] + c; a[i] = (uint8_t)s; c = s >> 8; }
}

static const uint8_t BJJ_P[32] = {
  0x30,0x64,0x4e,0x72,0xe1,0x31,0xa0,0x29,0xb8,0x50,0x45,0xb6,0x81,0x81,0x58,0x5d,
  0x28,0x33,0xe8,0x48,0x79,0xb9,0x70,0x91,0x43,0xe1,0xf5,0x93,0xf0,0x00,0x00,0x01};
static const uint8_t BJJ_L[32] = {
  0x06,0x0c,0x89,0xce,0x5c,0x26,0x34,0x05,0x37,0x0a,0x08,0xb6,0xd0,0x30,0x2b,0x0b,
  0xab,0x3e,0xed,0xb8,0x39,0x20,0xee,0x0a,0x67,0x72,0x97,0xdc,0x39,0x21,0x26,0xf1};

/* ═════════════════════════ C-3 / L-4  bignum, helpers ═════════════════════════ */

static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;
static uint32_t xr(void) { rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17; return (uint32_t)rng_state; }

/* Independent reference: Montgomery round trip a*1 mod m (odd m only). */
static void ref_reduce(zkn_bn_t r, const zkn_bn_t v, const zkn_bn_t m)
{
  zkn_bn_t one; zkn_bn_set_u32(one, 1);
  zkn_bn_mod_mul(r, v, one, m);
}

static void test_bignum(void)
{
  printf("\n── bignum / helpers ──\n");
  zkn_bn_t mods[4];
  zkn_bn_init(mods[0], BJJ_P, 32);
  zkn_bn_init(mods[1], BJJ_L, 32);
  zkn_bn_set_u32(mods[2], 65537);
  memset(mods[3], 0xff, sizeof(zkn_bn_t)); mods[3][0] = 0xffffffbbu;   /* top bit set */
  int ok = 1;
  for (int m = 0; m < 4; m++)
    for (int t = 0; t < 2000; t++) {
      zkn_bn_t v, a, b;
      for (int i = 0; i < 8; i++) v[i] = xr();
      zkn_bn_reduce(a, v, mods[m]);
      ref_reduce(b, v, mods[m]);
      if (memcmp(a, b, sizeof a)) ok = 0;
    }
  check("constant-time zkn_bn_reduce == reference (8000 random values, 4 moduli)", ok);
  zkn_bn_t z, v, r; zkn_bn_set_u32(z, 0); zkn_bn_set_u32(v, 5);
  check("zkn_bn_reduce rejects a zero modulus (used to loop forever)", zkn_bn_reduce(r, v, z) != 0);

  uint8_t buf[32], exp[32];
  for (int i = 0; i < 32; i++) { buf[i] = (uint8_t)i; exp[i] = (uint8_t)(31 - i); }
  ByteSwap(buf, 32);
  check("ByteSwap reverses all 32 bytes (used to swap only bytes 0 and 16)", memcmp(buf, exp, 32) == 0);

  uint8_t rnd[32] = {0};
  check("zkn_rng_checked succeeds on host", zkn_rng_checked(rnd, 32) == 0);
}

/* ═════════════════════════ C-1  EdDSA double-public-key oracle ═════════════════════════ */

static int eddsa_sign_on(uint32_t curve_id, const uint8_t prv[32], const uint8_t pub_from[32],
                         const uint8_t msg[32], uint8_t sig[96])
{
  zkn_edcurve_t c; zkn_edpoint_t P; uint8_t k[32], m[32];
  tEdwards_Curve_alloc_init(&c, curve_id);
  tEdwards_alloc(&c, &P);
  memcpy(k, pub_from, 32); zkn_prv2pub(&c, k, &P);
  memcpy(k, prv, 32); memcpy(m, msg, 32);
  return EddsaPoseidon_Sign_final(&c, k, &P, m, 32, sig);
}

static int eddsa_sign(const uint8_t prv[32], const uint8_t pub_from[32], const uint8_t msg[32], uint8_t sig[96])
{
  return eddsa_sign_on(_BABYJUJUB_ID, prv, pub_from, msg, sig);
}

static void test_eddsa(void)
{
  printf("\n── EdDSA-Poseidon signer ──\n");
  uint8_t prv[32], other[32], msg[32], sig[96];
  for (int i = 0; i < 32; i++) { prv[i] = (uint8_t)(3 + 17 * i); other[i] = (uint8_t)(0x5a ^ i); msg[i] = (uint8_t)i; }
  msg[31] = 0x01; /* little-endian: top byte small -> < p */
  check("sign with the matching public key succeeds", eddsa_sign(prv, prv, msg, sig) == 0);
  check("sign with a foreign public key is refused (key-recovery oracle)", eddsa_sign(prv, other, msg, sig) != 0);
  uint8_t big[32]; memset(big, 0xff, 32);
  check("sign of a message >= p is refused", eddsa_sign(prv, prv, big, sig) != 0);
  /* The bound is the signing curve's base field: Bandersnatch hashes over
   * BLS12-381 Fr (0x73ed...), larger than the BabyJubjub prime (0x3064...). */
  uint8_t mid[32]; memcpy(mid, msg, 32);
  mid[31] = 0x50; /* little-endian: 0x30644e.. <= value < 0x73eda7.. */
  check("BabyJubjub: message in [p_bjj, p_bls) is refused", eddsa_sign(prv, prv, mid, sig) != 0);
  check("Bandersnatch: message in [p_bjj, p_bls) is signed",
        eddsa_sign_on(_BANDERSNATCH_ID, prv, prv, mid, sig) == 0);
  check("Bandersnatch: message >= p_bls is refused",
        eddsa_sign_on(_BANDERSNATCH_ID, prv, prv, big, sig) != 0);
}

/* ═════════════════════════ FROST ═════════════════════════ */

#define FS 32
#define ENTRY (5 * FS)

static const uint8_t SK[3][32] = {
  {0x02,0x88,0x1c,0x64,0x76,0xea,0xc0,0xfc,0x58,0xc1,0x4b,0x73,0x5c,0x68,0xc7,0x6e,
   0xf3,0xe5,0x9b,0xc1,0xad,0x40,0xb3,0xe4,0x5a,0x4d,0x5b,0xf1,0x36,0x57,0x72,0x3e},
  {0x02,0xa9,0xe8,0xcf,0xb9,0xed,0x08,0x34,0x0e,0xe9,0x90,0x28,0x66,0x95,0x80,0xe8,
   0xf1,0x7b,0x45,0x84,0xc9,0xb9,0x71,0xf9,0xf3,0x1c,0xd0,0x21,0x3f,0x5f,0x99,0x9e},
  {0x03,0xd2,0xd3,0x53,0xf9,0xdf,0x75,0x8a,0x60,0x68,0x7d,0x74,0x09,0xfa,0xe7,0xc3,
   0x5f,0xd0,0x9a,0x28,0x53,0xf5,0xc6,0x54,0xd2,0xa1,0xc8,0x34,0x07,0x18,0x6f,0xe3}};
static const uint8_t GK[64] = {
  0x1e,0x07,0x62,0xd6,0x61,0x0a,0x0b,0x47,0xf3,0xb5,0xe3,0xf2,0x3f,0x5f,0x74,0x8f,
  0xde,0x5a,0xbb,0x88,0x43,0xf3,0x3c,0xf0,0x84,0xc0,0xda,0xbd,0x8d,0xc8,0x13,0xe6,
  0x0b,0x82,0xb7,0x39,0xe7,0x8d,0xda,0x57,0xe7,0x5a,0xc6,0x80,0xef,0x68,0x9d,0xf1,
  0x15,0x8f,0xe3,0xee,0xd8,0x09,0x5c,0x6d,0x4b,0xd1,0xb2,0xc7,0xc1,0x66,0xee,0xfd};
static const uint8_t MSG_BE[32] = {
  0x01,0x65,0xc4,0xd5,0x5f,0x44,0x17,0xb3,0x68,0xe9,0x5a,0x54,0x00,0x1a,0x30,0x32,
  0x3c,0xb0,0x4f,0xe8,0x34,0x3e,0x5a,0xd4,0x84,0x45,0x23,0x63,0xa5,0x98,0xd0,0x59};

static uint8_t MSG_LE[32];

/* round 1 for signers 1..3 */
static void frost_round1(uint8_t nonces[3][64], uint8_t clist[3 * ENTRY])
{
  zkn_edcurve_t c; tEdwards_Curve_alloc_init(&c, _BABYJUJUB_ID);
  for (int i = 0; i < 3; i++) {
    zkn_edpoint_t cm[2]; uint8_t sk[32]; memcpy(sk, SK[i], 32);
    tEdwards_alloc(&c, &cm[0]); tEdwards_alloc(&c, &cm[1]);
    zkn_frost_commit(&c, sk, nonces[i], cm);
    uint8_t *e = clist + i * ENTRY;
    memset(e, 0, ENTRY); e[FS - 1] = (uint8_t)(i + 1);
    tEdwards_export(&c, &cm[0], e + 1 * FS, e + 2 * FS);
    tEdwards_export(&c, &cm[1], e + 3 * FS, e + 4 * FS);
  }
}

/* zkn_partial_sig on a fresh curve; nonces are CONSUMED in place */
static int frost_sign(int id, uint8_t nonce[64], const uint8_t *clist, size_t len,
                      const uint8_t *msg_le, const uint8_t *lambda, uint8_t z[32])
{
  zkn_edcurve_t c; tEdwards_Curve_alloc_init(&c, _BABYJUJUB_ID);
  uint8_t sk[32], gk[64], m[32], lam[32], cl[ENTRY * ZKN_FROST_MAX_SIGNERS];
  memcpy(sk, SK[id - 1], 32); memcpy(gk, GK, 64); memcpy(m, msg_le, 32); memcpy(cl, clist, len * ENTRY);
  if (lambda) memcpy(lam, lambda, 32);
  return zkn_partial_sig(&c, (size_t)id, sk, gk, nonce, nonce + 32, cl, len, m, 32, lambda ? lam : NULL, z);
}

static void test_frost(void)
{
  printf("\n── FROST ──\n");
  for (int i = 0; i < 32; i++) MSG_LE[i] = MSG_BE[31 - i];
  uint8_t nonces[3][64], clist[3 * ENTRY], z[3][32];
  frost_round1(nonces, clist);

  /* happy path, no caller lambda */
  int ok = 1;
  uint8_t keep[3][64]; memcpy(keep, nonces, sizeof keep);
  for (int i = 0; i < 3; i++) ok &= frost_sign(i + 1, nonces[i], clist, 3, MSG_LE, NULL, z[i]) == 0;
  check("3-of-3 signing with lambda derived internally", ok);

  zkn_edcurve_t c; tEdwards_Curve_alloc_init(&c, _BABYJUJUB_ID);
  int v = 0; ok = 1;
  for (int i = 0; i < 3; i++) {
    v = 0;
    ok &= zkn_frost_verify_share(&c, (size_t)(i + 1), (uint8_t *)SK[i], clist + i * ENTRY, z[i],
                                 clist, 3, (uint8_t *)GK, MSG_LE, 32, &v) == 0 && v == 1;
  }
  check("each signature share verifies", ok);
  uint8_t shares[3 * 32], R8[64], S[32];
  for (int i = 0; i < 3; i++) memcpy(shares + 32 * i, z[i], 32);
  check("aggregate succeeds", zkn_frost_aggregate(&c, (uint8_t *)GK, clist, 3, MSG_LE, 32, shares, R8, S) == 0);
  v = 0;
  check("aggregate signature verifies", zkn_frost_verify(&c, R8, S, (uint8_t *)GK, MSG_LE, 32, &v) == 0 && v == 1);

  /* H-1 nonce consumption */
  uint8_t zero64[64] = {0};
  check("nonces are wiped by zkn_partial_sig", memcmp(nonces[0], zero64, 64) == 0);
  uint8_t zz[32];
  int rc = frost_sign(1, nonces[0], clist, 3, MSG_LE, NULL, zz);
  check("re-signing with consumed (zero) nonces is refused", rc != 0);
  check("...and no share is output", memcmp(zz, zero64, 32) == 0);

  /* H-3 malleability / validation in verify */
  uint8_t S2[32]; memcpy(S2, S, 32); add_be(S2, BJJ_L, 32);
  v = 1; zkn_frost_verify(&c, R8, S2, (uint8_t *)GK, MSG_LE, 32, &v);
  check("verify rejects S + order (signature malleability)", v == 0);
  uint8_t S0[32] = {0};
  v = 1; rc = zkn_frost_verify(&c, R8, S0, (uint8_t *)GK, MSG_LE, 32, &v);
  check("verify of S = 0 returns (used to hang) and is invalid", rc == 0 && v == 0);
  uint8_t R8bad[64]; memcpy(R8bad, R8, 64); R8bad[63] ^= 1;
  v = 1; zkn_frost_verify(&c, R8bad, S, (uint8_t *)GK, MSG_LE, 32, &v);
  check("verify rejects an off-curve R8", v == 0);
  uint8_t msgbig[32]; memset(msgbig, 0xff, 32);
  v = 1; zkn_frost_verify(&c, R8, S, (uint8_t *)GK, msgbig, 32, &v);
  check("verify rejects a message >= p", v == 0);

  /* H-2 length bounds */
  size_t big = ZKN_FROST_MAX_SIGNERS + 1;
  uint8_t *bigl = calloc(big, ENTRY), *bigs = calloc(big, 32);
  check("aggregate rejects len > ZKN_FROST_MAX_SIGNERS (was a stack overflow)",
        zkn_frost_aggregate(&c, (uint8_t *)GK, bigl, big, MSG_LE, 32, bigs, R8, S) != 0);
  check("verify_share rejects len > ZKN_FROST_MAX_SIGNERS (was a stack overflow)",
        zkn_frost_verify_share(&c, 1, (uint8_t *)SK[0], bigl, z[0], bigl, big, (uint8_t *)GK, MSG_LE, 32, &v) != 0);
  free(bigl); free(bigs);
  check("verify_share rejects a commitment_i that is not identifier's list entry",
        zkn_frost_verify_share(&c, 1, (uint8_t *)SK[0], clist + 1 * ENTRY, z[0], clist, 3, (uint8_t *)GK, MSG_LE, 32, &v) != 0);
  uint8_t badshare[32]; memcpy(badshare, z[0], 32); add_be(badshare, BJJ_L, 32);
  check("aggregate rejects a non-canonical share (>= order)", ({
        uint8_t sh[96]; memcpy(sh, shares, 96); memcpy(sh, badshare, 32);
        zkn_frost_aggregate(&c, (uint8_t *)GK, clist, 3, MSG_LE, 32, sh, R8, S) != 0; }));

  /* H-1 commitment list validation (fresh round each time) */
  uint8_t n2[3][64], cl2[3 * ENTRY], lam[32];
  {
    frost_round1(n2, cl2);
    zkn_bn_t ids[3], l; for (int i = 0; i < 3; i++) { zkn_bn_alloc(&ids[i], 32); zkn_bn_set_u32(ids[i], (uint32_t)(i + 1)); }
    zkn_bn_alloc(&l, 32); zkn_frost_interpolate(ids, 3, ids[1], c.order, l); zkn_bn_export(l, lam, 32);
    uint8_t n[64]; memcpy(n, n2[1], 64);
    check("a correct caller-supplied lambda is accepted", frost_sign(2, n, cl2, 3, MSG_LE, lam, zz) == 0);
    lam[31] ^= 1; memcpy(n, n2[1], 64);
    check("a caller-supplied lambda inconsistent with the list is refused", frost_sign(2, n, cl2, 3, MSG_LE, lam, zz) != 0);
  }
  {
    uint8_t cl[3 * ENTRY], n[64];
    memcpy(cl, cl2, sizeof cl); memset(cl, 0, FS); memcpy(n, n2[1], 64);
    check("identifier 0 in the commitment list is refused", frost_sign(2, n, cl, 3, MSG_LE, NULL, zz) != 0);
    memcpy(cl, cl2, sizeof cl); memcpy(cl + 2 * ENTRY, cl + 1 * ENTRY, FS); memcpy(n, n2[1], 64);
    check("duplicate identifiers are refused", frost_sign(2, n, cl, 3, MSG_LE, NULL, zz) != 0);
    memcpy(cl, cl2 + ENTRY, ENTRY); memcpy(cl + ENTRY, cl2, ENTRY); memcpy(cl + 2 * ENTRY, cl2 + 2 * ENTRY, ENTRY);
    memcpy(n, n2[1], 64);
    check("an unsorted commitment list is refused", frost_sign(2, n, cl, 3, MSG_LE, NULL, zz) != 0);
    memcpy(cl, cl2, sizeof cl); memcpy(cl + 1 * ENTRY + FS, cl2 + 0 * ENTRY + FS, 2 * FS); memcpy(n, n2[1], 64);
    check("own hiding commitment substituted by the coordinator is refused", frost_sign(2, n, cl, 3, MSG_LE, NULL, zz) != 0);
    memcpy(cl, cl2, sizeof cl); add_be(cl + 0 * ENTRY + FS, BJJ_P, 32); memcpy(n, n2[1], 64);
    check("non-canonical point coordinate (x + p) is refused", frost_sign(2, n, cl, 3, MSG_LE, NULL, zz) != 0);
    memcpy(n, n2[1], 64);
    check("signing a message >= p is refused", frost_sign(2, n, cl2, 3, msgbig, NULL, zz) != 0);
  }
}

/* ═════════════════════════ VSS ═════════════════════════ */

static void test_vss(void)
{
  printf("\n── VSS ──\n");
  zkn_edcurve_t c; tEdwards_Curve_alloc_init(&c, _BABYJUJUB_ID);
  participant_t p; memset(&p, 0, sizeof p);
  p.id = 1; p.n = 3; memset(p.seed, 7, 32);
  uint8_t coeffs[3 * 32], share[32], comm[3 * 64];
  makeDealerCoeffsDeterministic(&c, &p, 3, 0, coeffs);
  makeDealerCommitments(&c, coeffs, 3, comm);

  check("share for id = 0 is refused (returned the dealer secret a0)",
        computeDealerShareForId(&c, coeffs, 3, 0, share) != 0);
  check("share for id = 2^32 is refused (aliases to 0)",
        computeDealerShareForId(&c, coeffs, 3, (size_t)1 << 32, share) != 0);
  check("share with threshold = 0 is refused (out-of-bounds read)",
        computeDealerShareForId(&c, coeffs, 0, 1, share) != 0);

  bool valid = false;
  computeDealerShareForId(&c, coeffs, 3, 2, share);
  check("a genuine share verifies against genuine commitments",
        verifyFeldmanShare(&c, 2, share, comm, 3, &valid) == 0 && valid);
  check("verifyFeldmanShare rejects threshold = 0 (read commitments[-64])",
        verifyFeldmanShare(&c, 2, share, comm, 0, &valid) != 0);
  {
    uint8_t bad[3 * 64]; memcpy(bad, comm, sizeof bad); bad[64 + 63] ^= 1;
    check("an off-curve commitment is refused", verifyFeldmanShare(&c, 2, share, bad, 3, &valid) != 0);
    /* C0 + (0,-1): on the curve, outside the prime-order subgroup */
    zkn_bn_t pp, x, y, zero; zkn_bn_init(pp, BJJ_P, 32); zkn_bn_set_u32(zero, 0);
    zkn_bn_init(x, comm, 32); zkn_bn_init(y, comm + 32, 32);
    zkn_bn_mod_sub(x, zero, x, pp); zkn_bn_mod_sub(y, zero, y, pp);
    memcpy(bad, comm, sizeof bad); zkn_bn_export(x, bad, 32); zkn_bn_export(y, bad + 32, 32);
    check("a commitment with a torsion component is refused", verifyFeldmanShare(&c, 2, share, bad, 3, &valid) != 0);
  }

  vss_share_t sh[VSS_MAX_PARTICIPANTS + 1]; memset(sh, 0, sizeof sh);
  for (size_t k = 0; k <= VSS_MAX_PARTICIPANTS; k++) sh[k].id = k + 1;
  uint8_t a0[32];
  check("reconstruct rejects num_shares > VSS_MAX_PARTICIPANTS (was a stack overflow)",
        reconstructConstantFromShares(&c, sh, VSS_MAX_PARTICIPANTS + 1, a0) != 0);
  size_t dup[3] = {1, 2, 2}; uint8_t lam[32];
  check("deriveInterpolatingValue rejects duplicate ids", deriveInterpolatingValue(&c, dup, 3, 1, lam) != 0);
  size_t alias[2] = {1, ((size_t)1 << 32) + 1};
  check("deriveInterpolatingValue rejects ids aliasing mod 2^32", deriveInterpolatingValue(&c, alias, 2, 1, lam) != 0);
  size_t ok3[3] = {1, 2, 3};
  check("deriveInterpolatingValue rejects x_i not in the quorum", deriveInterpolatingValue(&c, ok3, 3, 4, lam) != 0);
  check("deriveInterpolatingValue accepts a valid quorum", deriveInterpolatingValue(&c, ok3, 3, 2, lam) == 0);
}

/* ═════════════════════════ Pairing: batched Miller loop ═════════════════════════ */

static void pairing_product(zkn_fp12_384_t *out, const zkn_g1_384_t *const P[], const zkn_g2_384_t *const Q[],
                            size_t n, const zkn_mont_ctx384_t *ctx)
{
  memset(out, 0xAB, sizeof *out);
  zkn_miller_loop_n(out, P, Q, n, ctx);
  zkn_final_exp(out, out, ctx);
}

static void test_miller(void)
{
  printf("\n── batched Miller loop ──\n");
  const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();
  zkn_g1_384_t G1, P2, P3, O1; zkn_g2_384_t G2;
  uint8_t two[1] = {2}, three[1] = {3};
  zkn_g1_384_generator(&G1, ctx); zkn_g2_384_generator(&G2, ctx);
  zkn_g1_384_mul(&P2, &G1, two, 1, ctx); zkn_g1_384_mul(&P3, &G1, three, 1, ctx);
  zkn_g1_384_zero(&O1);
  zkn_fp12_384_t a, b, one; zkn_fp12_384_one(&one, ctx);

  { const zkn_g1_384_t *P[2] = {&G1, &O1}; const zkn_g2_384_t *Q[2] = {&G2, &G2};
    const zkn_g1_384_t *P1[1] = {&G1};      const zkn_g2_384_t *Q1[1] = {&G2};
    pairing_product(&a, P, Q, 2, ctx); pairing_product(&b, P1, Q1, 1, ctx);
    check("[(P,Q),(O,Q)] == e(P,Q)  (trailing infinity left f uninitialised)", zkn_fp12_384_eq(&a, &b)); }
  { const zkn_g1_384_t *P[4] = {&O1, &G1, &P2, &P3}; const zkn_g2_384_t *Q[4] = {&G2, &G2, &G2, &G2};
    const zkn_g1_384_t *P1[3] = {&G1, &P2, &P3};    const zkn_g2_384_t *Q1[3] = {&G2, &G2, &G2};
    pairing_product(&a, P, Q, 4, ctx); pairing_product(&b, P1, Q1, 3, ctx);
    check("[(O,Q),(P,Q),(2P,Q),(3P,Q)] == product of the three (leading infinity)", zkn_fp12_384_eq(&a, &b)); }
  { const zkn_g1_384_t *P[2] = {&O1, &O1}; const zkn_g2_384_t *Q[2] = {&G2, &G2};
    memset(&a, 0xAB, sizeof a); zkn_miller_loop_n(&a, P, Q, 2, ctx);
    check("all-infinity batch returns 1 (used to return garbage)", zkn_fp12_384_eq(&a, &one)); }
}

/* ═════════════════════════ Groth16 (toy VK with known trapdoor) ═════════════════════════ */

static void sc32(uint8_t out[32], uint32_t v) { memset(out, 0, 32); out[28] = v >> 24; out[29] = v >> 16; out[30] = v >> 8; out[31] = v; }
static void g1_bytes(uint8_t out[96], const uint8_t k[32], const zkn_mont_ctx384_t *ctx)
{ zkn_g1_384_t G, P; zkn_fe384_t x, y; zkn_g1_384_generator(&G, ctx); zkn_g1_384_mul(&P, &G, k, 32, ctx);
  zkn_g1_384_to_affine(x, y, &P, ctx); zkn_fe384_to_be(out, x); zkn_fe384_to_be(out + 48, y); }
static void g2_bytes(uint8_t out[192], const uint8_t k[32], const zkn_mont_ctx384_t *ctx)
{ zkn_g2_384_t G, P; zkn_fp2_384_t x, y; zkn_g2_384_generator(&G, ctx); zkn_g2_384_mul(&P, &G, k, 32, ctx);
  zkn_g2_384_to_affine(&x, &y, &P, ctx);
  zkn_fe384_to_be(out, x.c0); zkn_fe384_to_be(out + 48, x.c1); zkn_fe384_to_be(out + 96, y.c0); zkn_fe384_to_be(out + 144, y.c1); }

static const uint8_t BLS_P[48] = {
  0x1a,0x01,0x11,0xea,0x39,0x7f,0xe6,0x9a,0x4b,0x1b,0xa7,0xb6,0x43,0x4b,0xac,0xd7,
  0x64,0x77,0x4b,0x84,0xf3,0x85,0x12,0xbf,0x67,0x30,0xd2,0xa0,0xf6,0xb0,0xf6,0x24,
  0x1e,0xab,0xff,0xfe,0xb1,0x53,0xff,0xff,0xb9,0xfe,0xff,0xff,0xff,0xff,0xaa,0xab};
/* (4, Y) lies on y^2 = x^3 + 4 but not in the order-r subgroup */
static const uint8_t NON_SG_Y[48] = {
  0x0a,0x98,0x9b,0xad,0xd4,0x0d,0x62,0x12,0xb3,0x3c,0xff,0xc3,0xf3,0x76,0x3e,0x9b,
  0xc7,0x60,0xf9,0x88,0xc9,0x92,0x6b,0x26,0xda,0x9d,0xd8,0x5e,0x92,0x84,0x83,0x44,
  0x63,0x46,0xb8,0xed,0x00,0xe1,0xde,0x5d,0x5e,0xa9,0x3e,0x35,0x4a,0xbe,0x70,0x6c};

static void test_groth16(void)
{
  printf("\n── Groth16 generic verifier ──\n");
  const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();
  const uint8_t *R = zkn_bls12381_r_be();
  zkn_bn_t r, al, be, ga, de, i0, i1, a, b, x, t, u, cc;
  zkn_bn_init(r, R, 32);
  zkn_bn_set_u32(al, 2); zkn_bn_set_u32(be, 3); zkn_bn_set_u32(ga, 5); zkn_bn_set_u32(de, 7);
  zkn_bn_set_u32(i0, 11); zkn_bn_set_u32(i1, 13); zkn_bn_set_u32(a, 17); zkn_bn_set_u32(b, 19); zkn_bn_set_u32(x, 23);
  zkn_bn_mod_mul(t, a, b, r); zkn_bn_mod_mul(u, al, be, r); zkn_bn_mod_sub(t, t, u, r);
  zkn_bn_mod_mul(u, x, i1, r); zkn_bn_mod_add(u, u, i0, r); zkn_bn_mod_mul(u, u, ga, r); zkn_bn_mod_sub(t, t, u, r);
  zkn_bn_mod_invert_nprime(u, de, r); zkn_bn_mod_mul(cc, t, u, r);

  zkn_groth16_vk_generic_t vk; memset(&vk, 0, sizeof vk);
  zkn_groth16_proof_generic_t pf, bad; uint8_t k[32];
  sc32(k, 2); g1_bytes(vk.alpha, k, ctx); sc32(k, 3); g2_bytes(vk.beta, k, ctx);
  sc32(k, 5); g2_bytes(vk.gamma, k, ctx); sc32(k, 7); g2_bytes(vk.delta, k, ctx);
  sc32(k, 11); g1_bytes(vk.IC[0], k, ctx); sc32(k, 13); g1_bytes(vk.IC[1], k, ctx); vk.n_public = 1;
  sc32(k, 17); g1_bytes(pf.A, k, ctx); sc32(k, 19); g2_bytes(pf.B, k, ctx); zkn_bn_export(cc, k, 32); g1_bytes(pf.C, k, ctx);

  uint8_t pub[1][32]; sc32(pub[0], 23);
  #define V(P, PUB) zkn_groth16_verify_generic(&vk, &(P), (const uint8_t (*)[32])(PUB), 1, ctx)
  check("valid toy proof verifies", V(pf, pub) == 1);
  uint8_t alias[1][32]; memcpy(alias, pub, 32); add_be(alias[0], R, 32);
  check("public input x + r is refused (aliasing)", V(pf, alias) == 0);
  bad = pf; memset(bad.A, 0, 96);
  check("pi.A = point at infinity is refused", V(bad, pub) == 0);
  bad = pf; bad.A[95] ^= 1;
  check("off-curve pi.A is refused", V(bad, pub) == 0);
  bad = pf; add_be(bad.A, BLS_P, 48);
  check("non-canonical pi.A (x + p) is refused", V(bad, pub) == 0);
  bad = pf; memset(bad.A, 0, 48); bad.A[47] = 4; memcpy(bad.A + 48, NON_SG_Y, 48);
  check("pi.A on the curve but outside the r-subgroup is refused", V(bad, pub) == 0);
  bad = pf; bad.B[191] ^= 1;
  check("off-twist pi.B is refused", V(bad, pub) == 0);
  #undef V
}

static void test_plonk(void)
{
  printf("\n── PLONK verifier (argument validation) ──\n");
  const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();
  static zkn_plonk_vk_t vk; static zkn_plonk_proof_t pf;
  memset(&vk, 0, sizeof vk); memset(&pf, 0, sizeof pf);
  uint8_t pub[1][32]; memset(pub, 0, sizeof pub);
  vk.n_public = 1;
  vk.power = 0;
  check("power = 0 is refused", zkn_plonk_verify(&vk, &pf, (const uint8_t (*)[32])pub, 1, ctx) == -1);
  vk.power = 31;
  check("power = 31 is refused (1 << 31 is undefined)", zkn_plonk_verify(&vk, &pf, (const uint8_t (*)[32])pub, 1, ctx) == -1);
  vk.power = 4; memset(pub[0], 0xff, 32);
  check("public input >= r is refused", zkn_plonk_verify(&vk, &pf, (const uint8_t (*)[32])pub, 1, ctx) == 0);
}

/* ═════════════════════════ RLP / storage proof ═════════════════════════ */

static void test_rlp(void)
{
  printf("\n── RLP / storage proof ──\n");
  RlpItem it; uint32_t used;
  uint8_t ovf[8] = {0xbb, 0xff, 0xff, 0xff, 0xff, 0, 0, 0};
  check("long-string length 0xFFFFFFFF in an 8-byte buffer is refused (uint32 wrap)", rlp_decode(ovf, 8, &it, &used) != RLP_OK);
  uint8_t ovf8[12] = {0xbf, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0};
  check("8-byte length-of-length is refused", rlp_decode(ovf8, 12, &it, &used) != RLP_OK);
  uint8_t nc1[2] = {0x81, 0x05};
  check("non-canonical single byte (0x81 0x05) is refused", rlp_decode(nc1, 2, &it, &used) == RLP_ERR_NONCANONICAL);
  uint8_t nc2[7] = {0xb8, 0x05, 1, 2, 3, 4, 5};
  check("long form used for a short string is refused", rlp_decode(nc2, 7, &it, &used) == RLP_ERR_NONCANONICAL);
  uint8_t dog[4] = {0x83, 'd', 'o', 'g'};
  check("valid short string decodes", rlp_decode(dog, 4, &it, &used) == RLP_OK && it.len == 3 && used == 4);

  uint8_t slot[32] = {0}; slot[31] = 7;
  uint8_t kh[32]; spf_keccak256(slot, 32, kh);
  uint8_t node[128], root[32], val[32]; uint32_t n;
  const uint8_t *nodes[1] = {node}; uint32_t lens[1];

  /* leaf with the full 64-nibble path: [HP(0x20 || keccak(slot)), RLP(0x1234)] */
  n = 0; node[n++] = 0xe6; node[n++] = 0xa1; node[n++] = 0x20; memcpy(node + n, kh, 32); n += 32;
  node[n++] = 0x83; node[n++] = 0x82; node[n++] = 0x12; node[n++] = 0x34;
  spf_keccak256(node, n, root); lens[0] = n;
  int e = spf_verify(root, slot, nodes, lens, 1, val);
  check("genuine single-leaf proof verifies with the right value", e == SPF_OK && val[30] == 0x12 && val[31] == 0x34);

  /* leaf whose path stops after 10 nibbles */
  n = 0; node[n++] = 0xc0 + 1 + 6 + 1; node[n++] = 0x86; node[n++] = 0x20; memcpy(node + n, kh, 5); n += 5; node[n++] = 0x01;
  spf_keccak256(node, n, root); lens[0] = n;
  check("leaf that does not consume the whole key is refused (was accepted)", spf_verify(root, slot, nodes, lens, 1, val) == SPF_ERR_PATH_MISMATCH);

  /* 40-byte path: overflowed the 128-nibble stack buffer */
  n = 0; node[n++] = 0xc0 + 41 + 1; node[n++] = 0x80 + 40; node[n++] = 0x20; memset(node + n, 0xaa, 39); n += 39; node[n++] = 0x01;
  spf_keccak256(node, n, root); lens[0] = n;
  check("over-long HP path is refused (stack overflow before)", spf_verify(root, slot, nodes, lens, 1, val) == SPF_ERR_BAD_NODE);
}

/* ═════════════════════════ Poseidon ═════════════════════════ */

static void test_poseidon(void)
{
  printf("\n── Poseidon ──\n");
  zkn_bn_t modulus; zkn_bn_mont_ctx_t mc; zkn_poseidon_ctx_t pc;
  zkn_bn_init(modulus, BJJ_P, 32); zkn_mont_init(&mc, modulus);
  zkn_poseidon_init(&pc, 5, 2, &mc, modulus);
  zkn_bn_t out[16];
  check("zkn_poseidon rejects sizeout > state width", zkn_poseidon(&pc, 0, out, 9) != 0);
  check("zkn_poseidon accepts sizeout = 1", zkn_poseidon(&pc, 0, out, 1) == 0);
}

#ifdef ZKN_WITH_KEYS
static void test_ecdh(void)
{
  printf("\n── Ed25519 ECDH ──\n");
  uint8_t k[32] = {0}, key[32];
  k[31] = 5;
  static const uint8_t BASE[32] = {0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
                                   0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66};
  uint8_t ident[32] = {1};
  uint8_t order2[32]; memset(order2, 0xff, 32); order2[0] = 0xec; order2[31] = 0x7f;   /* y = p - 1 */
  check("ECDH with the base point works", zkn_ed25519_ecdh_kdf(k, BASE, key) == 0);
  check("ECDH with the identity as peer key is refused", zkn_ed25519_ecdh_kdf(k, ident, key) != 0);
  check("ECDH with an order-2 peer key is refused", zkn_ed25519_ecdh_kdf(k, order2, key) != 0);
}
#endif

int main(void)
{
  printf("== security regression tests ==\n");
  test_bignum();
  test_eddsa();
  test_frost();
  test_vss();
  test_miller();
  test_groth16();
  test_plonk();
  test_rlp();
  test_poseidon();
#ifdef ZKN_WITH_KEYS
  test_ecdh();
#endif
  printf("\n== Results: %d/%d passed ==\n", g_pass, g_pass + g_fail);
  return g_fail ? 1 : 0;
}

#endif
