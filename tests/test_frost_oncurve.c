/* test_frost_oncurve.c — wire-supplied commitments must be on the curve.
 *
 * zkn_compute_group_commitment folds points straight off the wire into R.
 * tEdwards_init does no validation, so before this check an off-curve D or E
 * was accepted and R came out meaningless: the device then signs against a
 * challenge derived from garbage, the signature can never verify, and the
 * one-time nonces are spent. A hostile coordinator repeats that at will.
 *
 * The negative cases below are the point of the test; the last one is the
 * guard against fixing it too hard — a legitimate list must still go through.
 */
/* Host-only. The firmware Makefile compiles every .c under src/, and the
 * SDK has no exclusion variable — host-only files under src/zknox/ have to
 * exclude themselves, or their main() collides at link time. */
#ifdef ZKN_HOST_TESTS

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "zkn_errors.h"
#include "zkn_bn.h"
#include "zkn_tEdwards.h"
#include "zkn_frost.h"

static int g_pass = 0, g_fail = 0;
static void chk(const char *n, int c)
{
    printf(c ? "[PASS] %s\n" : "[FAIL] %s\n", n);
    c ? g_pass++ : g_fail++;
}

/* commitment_list entry: id || D.x || D.y || E.x || E.y, 32-byte big-endian */
static void put_id(uint8_t *rec, uint8_t id)
{
    memset(rec, 0, 32);
    rec[31] = id;
}
static void put_pt(uint8_t *dst, const uint8_t x[32], const uint8_t y[32])
{
    memcpy(dst, x, 32);
    memcpy(dst + 32, y, 32);
}
/* (2,3) is not a BabyJubJub point */
static void put_bogus(uint8_t *dst)
{
    memset(dst, 0, 64);
    dst[31] = 2;
    dst[63] = 3;
}

int main(void)
{
    zkn_edcurve_t curve;
    if (tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID) != 0) {
        printf("curve init failed\n");
        return 1;
    }

    /* Two genuine points to build a valid list from: G and 2G. */
    uint8_t gx[32], gy[32], g2x[32], g2y[32];
    zkn_edpoint_t G2;
    if (tEdwards_alloc(&curve, &G2) != 0 ||
        tEdwards_double(&curve, &curve.G, &G2) != 0 ||
        tEdwards_normalize(&curve, &G2) != 0 ||
        tEdwards_export(&curve, &curve.G, gx, gy) != 0 ||
        tEdwards_export(&curve, &G2, g2x, g2y) != 0) {
        printf("setup failed\n");
        return 1;
    }

    uint8_t bf[32];
    memset(bf, 0, 32);
    bf[31] = 1; /* rho = 1 */

    zkn_edpoint_t R;
    if (tEdwards_alloc(&curve, &R) != 0) { printf("alloc failed\n"); return 1; }

    uint8_t rec[5 * 32];
    int rc;

    /* 1. valid D and E — must be accepted, and R must land on the curve */
    put_id(rec, 1);
    put_pt(rec + 32, gx, gy);
    put_pt(rec + 96, g2x, g2y);
    rc = zkn_compute_group_commitment(&curve, rec, bf, 1, &R);
    chk("a genuine commitment list is accepted", rc == 0);

    bool on_curve = false;
    chk("...and the resulting R is on the curve",
        tEdwards_IsOnCurve(&curve, &R, &on_curve) == 0 && on_curve);

    /* 2. off-curve hiding commitment D */
    put_id(rec, 1);
    put_bogus(rec + 32);
    put_pt(rec + 96, g2x, g2y);
    rc = zkn_compute_group_commitment(&curve, rec, bf, 1, &R);
    chk("an off-curve hiding commitment D is rejected", rc == ZKN_ERR_INVALID_PARAM);

    /* 3. off-curve binding commitment E */
    put_id(rec, 1);
    put_pt(rec + 32, gx, gy);
    put_bogus(rec + 96);
    rc = zkn_compute_group_commitment(&curve, rec, bf, 1, &R);
    chk("an off-curve binding commitment E is rejected", rc == ZKN_ERR_INVALID_PARAM);

    /* 4. a bad point in the SECOND signer of a two-signer list: the loop must
     *    not stop checking after the first entry. */
    uint8_t rec2[2 * 5 * 32];
    uint8_t bf2[2 * 32];
    memset(bf2, 0, sizeof bf2);
    bf2[31] = 1;
    bf2[63] = 1;
    put_id(rec2, 1);
    put_pt(rec2 + 32, gx, gy);
    put_pt(rec2 + 96, g2x, g2y);
    put_id(rec2 + 160, 2);
    put_pt(rec2 + 192, gx, gy);
    put_bogus(rec2 + 256);
    rc = zkn_compute_group_commitment(&curve, rec2, bf2, 2, &R);
    chk("a bad point in the second signer is rejected too", rc == ZKN_ERR_INVALID_PARAM);

    /* 5. the same two-signer list, all genuine — still accepted */
    put_pt(rec2 + 256, g2x, g2y);
    rc = zkn_compute_group_commitment(&curve, rec2, bf2, 2, &R);
    chk("a genuine two-signer list is still accepted", rc == 0);

    printf("\n== Results: %d/%d passed ==\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}
#endif /* ZKN_HOST_TESTS */
