/* test_frost_host.c — deterministic full FROST execution, dumps frost_vectors.json
 *
 * Drives the REAL C FROST primitives (zkn_frost.c) with FIXED shares and
 * FIXED nonces so the result can be reproduced bit-for-bit by the JS
 * reference (curves-lite/babyfrost.ts) in verify_frost.mjs.
 *
 * Requires ZKNOX_DEBUG (frost + scalarMul_bn) and ZKN_HOST_TESTS.
 *
 * Lifecycle note (same as test_sign_host.c): compute_challenge() — called
 * inside zkn_partial_sig() — partial-destroys the curve. So we use a FRESH
 * curve for every zkn_partial_sig() and for the standalone challenge dump,
 * and do all non-destructive elliptic work (shares, pubkey, commitments,
 * binding factors, group commitment R8) on a separate long-lived curve.
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
#include "zkn_rfc9591frost.h"

#define FS 32          /* fieldsize8 for babyjubjub */
#define NSIG 2         /* signers = participants {1,2}, threshold t=2 */

/* ---- fixed test inputs (all < subgroup order) ---- */
/* master secret a0 and degree-1 coeff a1 */
static const uint8_t A0_BE[32] = {
  0x02,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
  0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0x01};
static const uint8_t A1_BE[32] = {
  0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,
  0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0x02};
/* per-signer fixed nonces (hiding, binding) */
static const uint8_t HID_BE[NSIG][32] = {
 {0x03,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
  0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x11},
 {0x04,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,
  0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x22}};
static const uint8_t BND_BE[NSIG][32] = {
 {0x05,0x11,0x11,0x22,0x22,0x33,0x33,0x44,0x44,0x55,0x55,0x66,0x66,0x77,0x77,0x88,
  0x88,0x99,0x99,0xaa,0xaa,0xbb,0xbb,0xcc,0xcc,0xdd,0xdd,0xee,0xee,0xff,0xff,0x33},
 {0x06,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,
  0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0x44}};
/* 32-byte message (big-endian field element) */
static const uint8_t MSG_BE[32] = {
  0x00,0x8c,0x1f,0x26,0x71,0x82,0x27,0x70,0x7c,0x6e,0x5c,0x61,0x41,0x7b,0x47,0xda,
  0xcc,0xaf,0xab,0xca,0x9f,0x57,0x4c,0x16,0xe1,0x52,0x1d,0xd6,0xa9,0xc7,0x0d,0x05};

static void jhex(FILE *f, const char *k, const uint8_t *b, int n){
  fprintf(f, "\"%s\":\"", k);
  for (int i=0;i<n;i++) fprintf(f,"%02x", b[i]);
  fprintf(f, "\"");
}

/* replicate the exact groupkey_compressed prologue of zkn_partial_sig
 * (INCLUDING the in-loop parity XOR) so our dumped binding factors / R8
 * match what partial_sig actually used internally. */
static void groupkey_compressed_like_partialsig(const uint8_t *groupkey_be, uint8_t *out){
  for (size_t i=0;i<32;i++){
    out[i] = groupkey_be[i+32];
  }
  out[0] ^= (groupkey_be[31] & 1) << 7;   // parity bit applied once (matches fixed partial_sig)
}

int main(void){
  int rc = 0;
  zkn_edcurve_t curve;
  zkn_edpoint_t P;

  /* long-lived curve for non-destructive work */
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  tEdwards_alloc(&curve, &P);

  /* dump curve order (which l does the C actually use?) */
  uint8_t order_be[32];
  zkn_bn_export(curve.order, order_be, FS);

  /* ---- shares via zkn_evalshare on poly [a0,a1] ---- */
  zkn_bn_t poly[2];
  zkn_bn_alloc(&poly[0], FS); zkn_bn_init(poly[0], A0_BE, 32);
  zkn_bn_alloc(&poly[1], FS); zkn_bn_init(poly[1], A1_BE, 32);

  zkn_bn_t Ids[NSIG];
  uint8_t  ids_be[NSIG][32];
  uint8_t  sk_be[NSIG][32];
  for (int s=0;s<NSIG;s++){
    zkn_bn_alloc(&Ids[s], FS);
    zkn_bn_set_u32(Ids[s], (uint32_t)(s+1));   /* participant ids 1,2 */
    zkn_bn_export(Ids[s], ids_be[s], FS);
    zkn_bn_t sk; zkn_bn_alloc(&sk, FS);
    zkn_evalshare(&curve, poly, 1 /*degree*/, Ids[s], sk);
    zkn_bn_export(sk, sk_be[s], FS);
    zkn_bn_destroy(&sk);
  }

  /* ---- group public key A = G^a0 ---- */
  uint8_t A_x[32], A_y[32], groupkey_be[64];
  tEdwards_scalarMul(&curve, &curve.G, A0_BE, FS, &P);
  tEdwards_normalize(&curve, &P);
  tEdwards_export(&curve, &P, A_x, A_y);
  memcpy(groupkey_be, A_x, 32);
  memcpy(groupkey_be+32, A_y, 32);

  /* ---- per-signer nonce commitments + build commitment_list (5*32 BE) ---- */
  uint8_t clist[NSIG * 5 * FS];
  uint8_t hcx[NSIG][32], hcy[NSIG][32], bcx[NSIG][32], bcy[NSIG][32];
  for (int s=0;s<NSIG;s++){
    tEdwards_scalarMul(&curve, &curve.G, HID_BE[s], FS, &P);
    tEdwards_normalize(&curve, &P);
    tEdwards_export(&curve, &P, hcx[s], hcy[s]);
    tEdwards_scalarMul(&curve, &curve.G, BND_BE[s], FS, &P);
    tEdwards_normalize(&curve, &P);
    tEdwards_export(&curve, &P, bcx[s], bcy[s]);

    uint8_t *e = clist + s*5*FS;
    memcpy(e + 0*FS, ids_be[s], FS);
    memcpy(e + 1*FS, hcx[s],   FS);
    memcpy(e + 2*FS, hcy[s],   FS);
    memcpy(e + 3*FS, bcx[s],   FS);
    memcpy(e + 4*FS, bcy[s],   FS);
  }

  /* ---- binding factors (replicate partial_sig's groupkey_compressed) ---- */
  uint8_t msg_le[32];
  for (int i=0;i<32;i++) msg_le[i] = MSG_BE[31-i];
  uint8_t gk_comp[32];
  groupkey_compressed_like_partialsig(groupkey_be, gk_comp);
  uint8_t bfs[NSIG * FS];
  zkn_compute_binding_factors(&curve, gk_comp, clist, NSIG, msg_le, 32, bfs);

  /* ---- dump H4(msg_le) and H5(encode(clist)) for component cross-check ---- */
  uint8_t msgHash_be[32], encHash_be[32], gkEnc_be[32];
  {
    zkn_bn_t h; zkn_bn_alloc(&h, FS);
    Babyfrost_H4(msg_le, 32, curve.order, h); zkn_bn_export(h, msgHash_be, FS);
    zkn_encode_group_commitmentHash(&curve, clist, NSIG, h); zkn_bn_export(h, encHash_be, FS);
    zkn_bn_destroy(&h);
    /* gkEnc = LE(gk_comp) : what actually goes into H1 for the group key */
    for (int i=0;i<32;i++) gkEnc_be[i] = gk_comp[31-i];
  }

  /* ---- group commitment R8 ---- */
  zkn_edpoint_t R8; tEdwards_alloc(&curve, &R8);
  zkn_compute_group_commitment(&curve, clist, bfs, NSIG, &R8);
  uint8_t R8x[32], R8y[32];
  tEdwards_export(&curve, &R8, R8x, R8y);
  tEdwards_destroy(&curve, &R8);

  /* ---- lambda_i (interpolating values over {Ids}) ---- */
  uint8_t lam_be[NSIG][32];
  for (int s=0;s<NSIG;s++){
    zkn_bn_t lam; zkn_bn_alloc(&lam, FS);
    zkn_frost_interpolate(Ids, NSIG, Ids[s], curve.order, lam);
    zkn_bn_export(lam, lam_be[s], FS);
    zkn_bn_destroy(&lam);
  }

  /* ---- challenge H = poseidon5(R8x,R8y,Ax,Ay,msg) — needs a FRESH curve
   *      because compute_challenge partial-destroys it ---- */
  uint8_t chall_be[32];
  {
    zkn_edcurve_t c2; zkn_edpoint_t R8c;
    tEdwards_Curve_alloc_init(&c2, _BABYJUJUB_ID);
    tEdwards_alloc(&c2, &R8c);
    tEdwards_init(&c2, R8x, R8y, &R8c);   /* rebuild R8 on fresh curve */
    zkn_bn_t H; zkn_bn_alloc(&H, FS);
    compute_challenge(&c2, &R8c, groupkey_be, msg_le, 32, H);
    zkn_bn_export(H, chall_be, FS);
    zkn_bn_destroy(&H);
    /* c2 was partial-destroyed by compute_challenge; do not Curve_destroy */
  }

  /* ---- partial signatures z_i (FRESH curve per call) ---- */
  uint8_t z_be[NSIG][32];
  for (int s=0;s<NSIG;s++){
    zkn_edcurve_t cs; zkn_edpoint_t Ps;
    tEdwards_Curve_alloc_init(&cs, _BABYJUJUB_ID);
    tEdwards_alloc(&cs, &Ps);
    uint8_t sig[32];
    int r = zkn_partial_sig(&cs, (size_t)(s+1), sk_be[s], groupkey_be,
                            (uint8_t*)HID_BE[s], (uint8_t*)BND_BE[s],
                            clist, NSIG, msg_le, 32,
                            lam_be[s], sig);
    if (r != 0){ fprintf(stderr, "partial_sig[%d] rc=%d\n", s, r); rc = 1; }
    memcpy(z_be[s], sig, 32);
    tEdwards_destroy(&cs, &Ps);
    /* cs partial-destroyed inside partial_sig; no Curve_destroy */
  }

  /* ---- aggregate S = sum z_i mod order ---- */
  uint8_t S_be[32];
  {
    zkn_bn_t acc, zi, ord;
    zkn_bn_alloc(&acc, FS); zkn_bn_set_u32(acc, 0);
    zkn_bn_alloc(&zi, FS);
    zkn_bn_alloc_init(&ord, FS, order_be, 32);
    for (int s=0;s<NSIG;s++){
      zkn_bn_init(zi, z_be[s], 32);
      zkn_bn_mod_add(acc, acc, zi, ord);
    }
    zkn_bn_export(acc, S_be, FS);
    zkn_bn_destroy(&acc); zkn_bn_destroy(&zi); zkn_bn_destroy(&ord);
  }

  /* ---- emit JSON ---- */
  FILE *f = fopen("frost_vectors.json", "w");
  fprintf(f, "{\n");
  jhex(f,"order",order_be,32); fprintf(f,",\n");
  jhex(f,"a0",A0_BE,32); fprintf(f,",\n");
  jhex(f,"a1",A1_BE,32); fprintf(f,",\n");
  jhex(f,"Ax",A_x,32); fprintf(f,",\n");
  jhex(f,"Ay",A_y,32); fprintf(f,",\n");
  jhex(f,"msg",MSG_BE,32); fprintf(f,",\n");
  fprintf(f,"\"signers\":[\n");
  for (int s=0;s<NSIG;s++){
    fprintf(f,"  {");
    jhex(f,"id",ids_be[s],32); fprintf(f,",");
    jhex(f,"sk",sk_be[s],32); fprintf(f,",");
    jhex(f,"hiding",HID_BE[s],32); fprintf(f,",");
    jhex(f,"binding",BND_BE[s],32); fprintf(f,",");
    jhex(f,"hidingCommX",hcx[s],32); fprintf(f,",");
    jhex(f,"hidingCommY",hcy[s],32); fprintf(f,",");
    jhex(f,"bindingCommX",bcx[s],32); fprintf(f,",");
    jhex(f,"bindingCommY",bcy[s],32); fprintf(f,",");
    jhex(f,"bindingFactor",bfs + s*FS,32); fprintf(f,",");
    jhex(f,"lambda",lam_be[s],32); fprintf(f,",");
    jhex(f,"z",z_be[s],32);
    fprintf(f,"}%s\n", s==NSIG-1?"":",");
  }
  fprintf(f,"],\n");
  jhex(f,"dbg_gkEnc",gkEnc_be,32); fprintf(f,",\n");
  jhex(f,"dbg_msgHash",msgHash_be,32); fprintf(f,",\n");
  jhex(f,"dbg_encHash",encHash_be,32); fprintf(f,",\n");
  jhex(f,"R8x",R8x,32); fprintf(f,",\n");
  jhex(f,"R8y",R8y,32); fprintf(f,",\n");
  jhex(f,"challenge",chall_be,32); fprintf(f,",\n");
  jhex(f,"S",S_be,32); fprintf(f,"\n}\n");
  fclose(f);

  printf("wrote frost_vectors.json (rc=%d)\n", rc);
  printf("order = "); for(int i=0;i<32;i++)printf("%02x",order_be[i]); printf("\n");
  printf("A.x   = "); for(int i=0;i<32;i++)printf("%02x",A_x[i]); printf("  (x parity=%d)\n", A_x[31]&1);
  return rc;
}

#endif
