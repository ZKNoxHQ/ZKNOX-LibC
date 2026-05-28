/* Force the RAILGUN (soft-Poseidon) sign path — matches device BACKEND=sw. */
#ifndef RAILGUN
#define RAILGUN
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "zkn_tEdwards.h"
#include "zkn_eddsa.h"
#include "zkn_bn.h"

/*
 * test_sign_host.c — prv2pub assertion + EdDSA-Poseidon sign (RAILGUN path).
 *
 * IMPORTANT lifecycle note:
 *   EddsaPoseidon_Sign_final() calls tEdwards_Curve_partial_destroy(curve)
 *   internally — after a sign, the curve's working BNs (a..j, G, cA, cD,
 *   mont_One, order) are freed and the curve is NOT usable again. So we must
 *   allocate a FRESH curve before every sign and must NOT call
 *   tEdwards_Curve_destroy() on a curve that has already been signed with
 *   (that would double-free what the sign already released).
 *
 * Writes signatures.json for optional circomlibjs cross-verification.
 */

static const uint8_t PRIV_KEY[32] = {
    0x00,0xa2,0xac,0x13,0xcd,0xba,0x83,0x0a,0x55,0xbf,0x40,0x7e,0xa7,0x0c,0x5f,0xd2,
    0x93,0x12,0xc1,0x70,0x60,0xf0,0x7d,0x35,0xfe,0xa5,0xde,0x47,0xd6,0xc0,0x3e,0xd2};
static const uint8_t MSG_ASIS[32] = {
    0x8c,0x1f,0x26,0x71,0x82,0x27,0x70,0x7c,0x6e,0x5c,0x61,0x41,0x7b,0x47,0xda,0xcc,
    0xaf,0xab,0xca,0x9f,0x57,0x4c,0x16,0xe1,0x52,0x1d,0xd6,0xa9,0xc7,0x0d,0x84,0x05};

/* Expected public key from circomlibjs eddsa.prv2pub(priv) — exact match */
static const uint8_t EXPECT_PUB_X[32] = {
    0x1c,0xa3,0x3c,0x18,0x1e,0x2c,0x6b,0x7b,0x4a,0xba,0x90,0x43,0x62,0xea,0x6b,0xf8,
    0xf2,0xbb,0x1e,0x8c,0x41,0x39,0x46,0xb2,0x90,0xea,0xc6,0x59,0x8a,0x7c,0xfe,0x3a};
static const uint8_t EXPECT_PUB_Y[32] = {
    0x09,0x86,0x33,0xab,0xa6,0xd5,0x09,0x4a,0x98,0xf8,0x5c,0x43,0x69,0x12,0xb5,0x46,
    0x80,0x71,0x44,0x9a,0xcb,0xc2,0x2a,0xdb,0xe2,0x6f,0x88,0xac,0xb1,0xf3,0x34,0xa0};

static int pass = 0, fail = 0;
static void chk(const char *what, int cond) {
    if (cond) { printf("  ✅ %s\n", what); pass++; }
    else      { printf("  ❌ %s\n", what); fail++; }
}

/* Derive the public key into pub_x/pub_y using a throwaway curve.
 * (prv2pub does not partial-destroy, but we keep it isolated for clarity.) */
static void derive_pub(uint8_t pub_x[32], uint8_t pub_y[32]) {
    zkn_edcurve_t curve;
    zkn_edpoint_t Pub;
    tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
    tEdwards_alloc(&curve, &Pub);
    zkn_prv2pub(&curve, (uint8_t *)PRIV_KEY, &Pub);
    tEdwards_export(&curve, &Pub, pub_x, pub_y);
    tEdwards_destroy(&curve, &Pub);
    tEdwards_Curve_destroy(&curve);   /* safe: prv2pub did NOT partial-destroy */
}

/* Sign one message with a FRESH curve. The curve is consumed by the sign
 * (partial_destroy inside), so we neither reuse nor Curve_destroy it after. */
static int sign_once(const uint8_t *msg, uint8_t sig[96]) {
    zkn_edcurve_t curve;
    zkn_edpoint_t Pub;
    tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
    tEdwards_alloc(&curve, &Pub);
    zkn_prv2pub(&curve, (uint8_t *)PRIV_KEY, &Pub);
    int rc = EddsaPoseidon_Sign_final(&curve, (uint8_t *)PRIV_KEY, &Pub,
                                       (uint8_t *)msg, 32, sig);
    /* DO NOT tEdwards_Curve_destroy(&curve): the sign already
     * partial-destroyed it. tEdwards_destroy(&Pub) is still ours to free. */
    tEdwards_destroy(&curve, &Pub);
    return rc;
}

static void emit_hex(FILE *f, const char *key, const uint8_t *b, int n) {
    fprintf(f, "    \"%s\": \"", key);
    for (int i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
    fprintf(f, "\"");
}

int main(void) {
    printf("════════════════════════════════════════════════════════════\n");
    printf("  EdDSA-Poseidon sign (RAILGUN) — prv2pub + 2 signatures     \n");
    printf("════════════════════════════════════════════════════════════\n");

    /* ── prv2pub ── */
    uint8_t pub_x[32], pub_y[32];
    derive_pub(pub_x, pub_y);
    printf("\n[prv2pub]\n");
    chk("Pub.x matches circomlibjs", memcmp(pub_x, EXPECT_PUB_X, 32) == 0);
    chk("Pub.y matches circomlibjs", memcmp(pub_y, EXPECT_PUB_Y, 32) == 0);

    /* ── sign variant A: msg as-is ── */
    uint8_t sigA[96];
    clock_t t0 = clock();
    int rcA = sign_once(MSG_ASIS, sigA);
    clock_t t1 = clock();
    printf("\n[variant A] msg_asIs : rc=%d in %.2f ms\n",
           rcA, (t1 - t0) * 1000.0 / CLOCKS_PER_SEC);
    chk("sign A rc == 0", rcA == 0);

    /* ── sign variant B: msg reversed ── */
    uint8_t msgRev[32];
    for (int i = 0; i < 32; i++) msgRev[i] = MSG_ASIS[31 - i];
    uint8_t sigB[96];
    t0 = clock();
    int rcB = sign_once(msgRev, sigB);
    t1 = clock();
    printf("[variant B] msg_rev  : rc=%d in %.2f ms\n",
           rcB, (t1 - t0) * 1000.0 / CLOCKS_PER_SEC);
    chk("sign B rc == 0", rcB == 0);

    chk("sigA != sigB (different messages)", memcmp(sigA, sigB, 96) != 0);

    /* ── dump signatures.json ── */
    FILE *f = fopen("signatures.json", "w");
    if (f) {
        fprintf(f, "{\n");
        emit_hex(f, "priv",     PRIV_KEY, 32); fprintf(f, ",\n");
        emit_hex(f, "msg_asIs", MSG_ASIS, 32); fprintf(f, ",\n");
        emit_hex(f, "msg_rev",  msgRev,   32); fprintf(f, ",\n");
        emit_hex(f, "pub_x",    pub_x,    32); fprintf(f, ",\n");
        emit_hex(f, "pub_y",    pub_y,    32); fprintf(f, ",\n");
        fprintf(f, "    \"sigA\": {\n");
        emit_hex(f, "r8x", sigA + 0, 32); fprintf(f, ",\n");
        emit_hex(f, "r8y", sigA + 32, 32); fprintf(f, ",\n");
        emit_hex(f, "s",   sigA + 64, 32); fprintf(f, "\n    },\n");
        fprintf(f, "    \"sigB\": {\n");
        emit_hex(f, "r8x", sigB + 0, 32); fprintf(f, ",\n");
        emit_hex(f, "r8y", sigB + 32, 32); fprintf(f, ",\n");
        emit_hex(f, "s",   sigB + 64, 32); fprintf(f, "\n    }\n");
        fprintf(f, "}\n");
        fclose(f);
        printf("\n  (wrote signatures.json)\n");
    }

    printf("\n════════════════════════════════════════════════════════════\n");
    printf("  Results: %d passed, %d failed\n", pass, fail);
    printf("════════════════════════════════════════════════════════════\n");
    return fail ? 1 : 0;
}
