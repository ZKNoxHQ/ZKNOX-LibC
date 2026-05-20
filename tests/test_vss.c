/*
 * test_vss.c — Smoke test for the VSS dealer coefficient derivation
 *
 * Currently only makeDealerCoeffsDeterministic is implemented in zkn_vss.c
 * of zknox_1905. The other functions (evalPolySubgroup, verifyFeldmanShare,
 * etc.) are declared in zkn_vss.h but their implementation is pending
 * (likely on Simon's clear-signing branch).
 *
 * This smoke test verifies that the implemented entry point is:
 *   - Deterministic for the same participant input
 *   - Different for different participant IDs / seeds / passwords
 *   - Producing non-zero coefficients
 *
 * Once the other VSS functions land in zkn_vss.c, this test will be
 * extended to cover the full t-of-n share generation + verification.
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#ifdef ZKN_HOST_TESTS

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "zkn_bn.h"
#include "zkn_tEdwards.h"
#include "zkn_vss.h"

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int cond)
{
    if (cond) { printf("[PASS] %s\n", name); g_pass++; }
    else      { printf("[FAIL] %s\n", name); g_fail++; }
}

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static int bytes_zero(const uint8_t *a, size_t n)
{
    for (size_t i = 0; i < n; i++) if (a[i] != 0) return 0;
    return 1;
}

int main(void)
{
    printf("══ VSS (makeDealerCoeffsDeterministic) smoke tests ══\n\n");

    static zkn_edcurve_t curve;
    int rc = tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
    check("tEdwards_Curve_alloc_init(BabyJubjub)", rc == 0);
    if (rc != 0) return 1;

    /* ── Test 1: determinism ─────────────────────────────────────── */
    static participant_t p1 = { .id = 1 };
    memset(p1.seed,     0x11, 32);
    memset(p1.password, 0xAA, 32);

    static uint8_t coeffs_run1[3 * 32];
    static uint8_t coeffs_run2[3 * 32];

    rc = makeDealerCoeffsDeterministic(&curve, &p1, 3, 0, coeffs_run1);
    check("makeDealerCoeffsDeterministic(p1, t=3) run1", rc == 0);

    rc = makeDealerCoeffsDeterministic(&curve, &p1, 3, 0, coeffs_run2);
    check("makeDealerCoeffsDeterministic(p1, t=3) run2", rc == 0);

    check("coeffs deterministic across runs",
          bytes_eq(coeffs_run1, coeffs_run2, 3 * 32));

    /* ── Test 2: coefficients are non-zero (required by VSS) ─────── */
    check("a0 non-zero (constant term)", !bytes_zero(coeffs_run1, 32));
    check("a1 non-zero",                  !bytes_zero(coeffs_run1 + 32, 32));
    check("a2 non-zero",                  !bytes_zero(coeffs_run1 + 64, 32));

    /* ── Test 3: distinct coefficients in the polynomial ─────────── */
    check("a0 != a1", !bytes_eq(coeffs_run1, coeffs_run1 + 32, 32));
    check("a1 != a2", !bytes_eq(coeffs_run1 + 32, coeffs_run1 + 64, 32));
    check("a0 != a2", !bytes_eq(coeffs_run1, coeffs_run1 + 64, 32));

    /* ── Test 4: different participant id → different polynomial ── */
    static participant_t p2 = { .id = 2 };
    memcpy(p2.seed,     p1.seed,     32);  /* same seed & password */
    memcpy(p2.password, p1.password, 32);

    static uint8_t coeffs_p2[3 * 32];
    rc = makeDealerCoeffsDeterministic(&curve, &p2, 3, 0, coeffs_p2);
    check("makeDealerCoeffsDeterministic(p2)", rc == 0);
    check("different id -> different coeffs",
          !bytes_eq(coeffs_run1, coeffs_p2, 3 * 32));

    /* ── Test 5: different seed → different polynomial ──────────── */
    static participant_t p3 = { .id = 1 };
    memset(p3.seed,     0x33, 32);  /* different seed */
    memcpy(p3.password, p1.password, 32);  /* same password */

    static uint8_t coeffs_p3[3 * 32];
    rc = makeDealerCoeffsDeterministic(&curve, &p3, 3, 0, coeffs_p3);
    check("makeDealerCoeffsDeterministic(p3, different seed)", rc == 0);
    check("different seed -> different coeffs",
          !bytes_eq(coeffs_run1, coeffs_p3, 3 * 32));

    /* ── Test 6: different password → different polynomial ──────── */
    static participant_t p4 = { .id = 1 };
    memcpy(p4.seed, p1.seed, 32);
    memset(p4.password, 0xCC, 32);

    static uint8_t coeffs_p4[3 * 32];
    rc = makeDealerCoeffsDeterministic(&curve, &p4, 3, 0, coeffs_p4);
    check("makeDealerCoeffsDeterministic(p4, different password)", rc == 0);
    check("different password -> different coeffs",
          !bytes_eq(coeffs_run1, coeffs_p4, 3 * 32));

    /* ── Test 7: different threshold value ──────────────────────── */
    static uint8_t coeffs_t5[5 * 32];
    rc = makeDealerCoeffsDeterministic(&curve, &p1, 5, 0, coeffs_t5);
    check("makeDealerCoeffsDeterministic(p1, t=5)", rc == 0);
    /* First 3 coefficients should match coeffs_run1 (deterministic from
     * (id, j, seed, password) — j is the only thing that varies). */
    check("first 3 coeffs (t=5) match first 3 coeffs (t=3)",
          bytes_eq(coeffs_run1, coeffs_t5, 3 * 32));
    check("a3 non-zero",                  !bytes_zero(coeffs_t5 + 96, 32));
    check("a4 non-zero",                  !bytes_zero(coeffs_t5 + 128, 32));

    tEdwards_Curve_destroy(&curve);

    printf("\n══ Results: %d/%d passed ══\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}

#endif /* ZKN_HOST_TESTS */
