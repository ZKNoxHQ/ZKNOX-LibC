/* test_frost_consistency.c — C-only FROST sign/verify consistency test.
 *
 * Mirrors curves-lite/test/babyfrost.test.ts:
 *     commit -> sign -> verifySignatureShare -> aggregate -> verifyPoseidon
 *
 * The verify/aggregate steps now call the library API
 * (zkn_frost_verify_share / zkn_frost_aggregate / zkn_frost_verify); the test
 * only wires them together. Nonces are random (zkn_frost_commit), like the JS
 * frost.commit(), so this is a randomized consistency test, not a fixed KAT.
 *
 * Requires ZKNOX_DEBUG (FROST) and ZKN_HOST_TESTS.
 */
#if defined(ZKN_HOST_TESTS) && defined(ZKNOX_DEBUG)

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "zkn_bn.h"
#include "zkn_tEdwards.h"
#include "zkn_frost.h"

#define FS 32
#define ENTRY (5 * FS) /* commitment-list entry: id|hx|hy|bx|by (all BE) */

static int g_fail = 0;
static void check(const char *name, int ok)
{
  printf("  %s %s\n", ok ? "[PASS]" : "[FAIL]", name);
  if (!ok) g_fail++;
}

/* frost.commit(sk_i, id) -> random nonces + one commitment-list entry */
static int frost_commit(zkn_edcurve_t *c, const uint8_t sk_be[32], uint32_t id,
                        uint8_t nonces_out[64], uint8_t entry_out[ENTRY])
{
  zkn_edpoint_t comms[2];
  uint8_t sk[32];
  tEdwards_alloc(c, &comms[0]);
  tEdwards_alloc(c, &comms[1]);
  memcpy(sk, sk_be, 32);
  int r = zkn_frost_commit(c, sk, nonces_out, comms);
  memset(entry_out, 0, ENTRY);
  entry_out[FS - 1] = (uint8_t)(id & 0xff);
  entry_out[FS - 2] = (uint8_t)((id >> 8) & 0xff);
  tEdwards_export(c, &comms[0], entry_out + 1 * FS, entry_out + 2 * FS);
  tEdwards_export(c, &comms[1], entry_out + 3 * FS, entry_out + 4 * FS);
  tEdwards_destroy(c, &comms[0]);
  tEdwards_destroy(c, &comms[1]);
  return r;
}

/* frost.sign(...) -> z_i (fresh curve: zkn_partial_sig is destructive) */
static int frost_sign(uint32_t position, const uint8_t sk_be[32], const uint8_t groupkey_be[64],
                      const uint8_t nonces[64], const uint8_t *clist, size_t len,
                      const uint32_t *ids, const uint8_t msg_be[32], uint8_t z_out[32])
{
  zkn_edcurve_t c;
  zkn_bn_t Ids[ZKN_FROST_MAX_SIGNERS], lamb;
  uint8_t lam[32], sk[32], gk[64], msg[32], nz[64], cl[ZKN_FROST_MAX_SIGNERS * ENTRY];
  tEdwards_Curve_alloc_init(&c, _BABYJUJUB_ID);
  for (size_t i = 0; i < len; i++) { zkn_bn_alloc(&Ids[i], FS); zkn_bn_set_u32(Ids[i], ids[i]); }
  zkn_bn_alloc(&lamb, FS);
  zkn_frost_interpolate(Ids, len, Ids[position - 1], c.order, lamb);
  zkn_bn_export(lamb, lam, FS);
  zkn_bn_destroy(&lamb);
  memcpy(sk, sk_be, 32); memcpy(gk, groupkey_be, 64);
  memcpy(msg, msg_be, 32); memcpy(nz, nonces, 64); memcpy(cl, clist, len * ENTRY);
  return zkn_partial_sig(&c, position, sk, gk, nz, nz + 32, cl, len, msg, 32, lam, z_out);
}

int main(void)
{
  printf("== FROST RFC9591 — C-only sign/verify consistency (library API) ==\n\n");

  /* same vector as curves-lite/test/babyfrost.test.ts (skShare = 8·div8 mod L) */
  static const uint8_t SK[3][32] = {
    {0x02,0x88,0x1c,0x64,0x76,0xea,0xc0,0xfc,0x58,0xc1,0x4b,0x73,0x5c,0x68,0xc7,0x6e,
     0xf3,0xe5,0x9b,0xc1,0xad,0x40,0xb3,0xe4,0x5a,0x4d,0x5b,0xf1,0x36,0x57,0x72,0x3e},
    {0x02,0xa9,0xe8,0xcf,0xb9,0xed,0x08,0x34,0x0e,0xe9,0x90,0x28,0x66,0x95,0x80,0xe8,
     0xf1,0x7b,0x45,0x84,0xc9,0xb9,0x71,0xf9,0xf3,0x1c,0xd0,0x21,0x3f,0x5f,0x99,0x9e},
    {0x03,0xd2,0xd3,0x53,0xf9,0xdf,0x75,0x8a,0x60,0x68,0x7d,0x74,0x09,0xfa,0xe7,0xc3,
     0x5f,0xd0,0x9a,0x28,0x53,0xf5,0xc6,0x54,0xd2,0xa1,0xc8,0x34,0x07,0x18,0x6f,0xe3}};
  static const uint8_t AX[32] = {
    0x1e,0x07,0x62,0xd6,0x61,0x0a,0x0b,0x47,0xf3,0xb5,0xe3,0xf2,0x3f,0x5f,0x74,0x8f,
    0xde,0x5a,0xbb,0x88,0x43,0xf3,0x3c,0xf0,0x84,0xc0,0xda,0xbd,0x8d,0xc8,0x13,0xe6};
  static const uint8_t AY[32] = {
    0x0b,0x82,0xb7,0x39,0xe7,0x8d,0xda,0x57,0xe7,0x5a,0xc6,0x80,0xef,0x68,0x9d,0xf1,
    0x15,0x8f,0xe3,0xee,0xd8,0x09,0x5c,0x6d,0x4b,0xd1,0xb2,0xc7,0xc1,0x66,0xee,0xfd};
  static const uint8_t MSG[32] = { /* poseidon([0x3039]) mod L */
    0x01,0x65,0xc4,0xd5,0x5f,0x44,0x17,0xb3,0x68,0xe9,0x5a,0x54,0x00,0x1a,0x30,0x32,
    0x3c,0xb0,0x4f,0xe8,0x34,0x3e,0x5a,0xd4,0x84,0x45,0x23,0x63,0xa5,0x98,0xd0,0x59};

  const uint32_t ids[3] = {1, 2, 3};
  uint8_t groupkey_be[64];
  memcpy(groupkey_be, AX, 32);
  memcpy(groupkey_be + 32, AY, 32);

  /* the library takes the message little-endian (circomlib); dump BE for the JS */
  uint8_t MSG_LE[32];
  for (int i = 0; i < 32; i++) MSG_LE[i] = MSG[31 - i];

  /* round 1: commitment (random nonces) */
  uint8_t nonces[3][64], clist[3 * ENTRY];
  zkn_edcurve_t cc; tEdwards_Curve_alloc_init(&cc, _BABYJUJUB_ID);
  for (int i = 0; i < 3; i++) frost_commit(&cc, SK[i], ids[i], nonces[i], clist + i * ENTRY);
  tEdwards_Curve_destroy(&cc);

  /* round 2: partial signatures */
  uint8_t z[3][32];
  for (int i = 0; i < 3; i++)
    frost_sign(ids[i], SK[i], groupkey_be, nonces[i], clist, 3, ids, MSG_LE, z[i]);

  /* per-share verification — library call */
  zkn_edcurve_t c; tEdwards_Curve_alloc_init(&c, _BABYJUJUB_ID);
  for (int i = 0; i < 3; i++) {
    int ok = 0;
    zkn_frost_verify_share(&c, ids[i], (uint8_t *)SK[i], clist + i * ENTRY, z[i],
                           clist, 3, groupkey_be, (uint8_t *)MSG_LE, 32, &ok);
    char name[48]; snprintf(name, sizeof name, "zkn_frost_verify_share(participant %d)", ids[i]);
    check(name, ok);
  }

  /* aggregation — library call */
  uint8_t sig_shares[3 * 32], R8_be[64], S[32];
  for (int i = 0; i < 3; i++) memcpy(sig_shares + i * 32, z[i], 32);
  zkn_frost_aggregate(&c, groupkey_be, clist, 3, (uint8_t *)MSG_LE, 32, sig_shares, R8_be, S);

  /* final signature verification — library call */
  int ok = 0;
  zkn_frost_verify(&c, R8_be, S, groupkey_be, (uint8_t *)MSG_LE, 32, &ok);
  check("zkn_frost_verify(aggregate signature)", ok);

  /* dump outputs for the JS cross-check */
  {
    FILE *f = fopen("frost_consistency.json", "w");
    #define JH(k,b) do{ fprintf(f,"\"%s\":\"",k); for(int _i=0;_i<32;_i++)fprintf(f,"%02x",(b)[_i]); fprintf(f,"\"");}while(0)
    fprintf(f, "{\n");
    JH("Ax",AX); fprintf(f,",\n"); JH("Ay",AY); fprintf(f,",\n"); JH("msg",MSG); fprintf(f,",\n");
    fprintf(f, "\"signers\":[\n");
    for (int i=0;i<3;i++){
      const uint8_t *e = clist + i*ENTRY;
      fprintf(f,"  {\"id\":%u,", ids[i]);
      JH("sk",SK[i]); fprintf(f,",");
      JH("hidingCommX",e+1*FS); fprintf(f,","); JH("hidingCommY",e+2*FS); fprintf(f,",");
      JH("bindingCommX",e+3*FS); fprintf(f,","); JH("bindingCommY",e+4*FS); fprintf(f,",");
      JH("z",z[i]); fprintf(f,"}%s\n", i==2?"":",");
    }
    fprintf(f,"],\n");
    JH("R8x",R8_be); fprintf(f,",\n"); JH("R8y",R8_be+32); fprintf(f,",\n"); JH("S",S); fprintf(f,"\n}\n");
    #undef JH
    fclose(f);
  }

  printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "ALL PASSED", g_fail, g_fail == 1 ? "" : "s");
  return g_fail ? 1 : 0;
}

#endif
