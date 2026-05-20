/*
 * test_rfc9591frost.c — Smoke tests for the RFC 9591 (FROST) hash functions
 *
 * Verifies that Babyfrost_H1/H3/H4/H5/H6 (zknox_1905 API) are:
 *   - Deterministic
 *   - Non-trivial (output != 0)
 *   - Collision-resistant on distinct inputs (different inputs → different outputs)
 *   - Domain-separated (H1 ≠ H3 ≠ H4 ≠ H5 ≠ H6 on the same input)
 *
 * Cross-validation against the JS reference vectors is deferred to
 * Phase 3 (test_babyfrost / test_groth16).
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "zkn_bn.h"
#include "zkn_rfc9591frost.h"

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int cond)
{
    if (cond) { printf("[PASS] %s\n", name); g_pass++; }
    else      { printf("[FAIL] %s\n", name); g_fail++; }
}

/* BabyJubjub subgroup order (l) - 32 bytes little-endian limbs */
static void load_order(zkn_bn_t order)
{
    /* L = 2736030358979909402780800718157159386076813972158567259200215660948447373041 */
    /* big-endian: 060c89ce5c2634053b0a08b6d0302b0bab3eedb83920ee0a677297dc392126f1 */
    static const uint8_t L_BE[32] = {
        0x06,0x0c,0x89,0xce,0x5c,0x26,0x34,0x05,
        0x3b,0x0a,0x08,0xb6,0xd0,0x30,0x2b,0x0b,
        0xab,0x3e,0xed,0xb8,0x39,0x20,0xee,0x0a,
        0x67,0x72,0x97,0xdc,0x39,0x21,0x26,0xf1
    };
    /* BE bytes → LE limbs */
    for (int i = 0; i < 8; i++) {
        uint32_t limb = 0;
        for (int j = 0; j < 4; j++) limb = (limb << 8) | L_BE[i*4 + j];
        order[7-i] = limb;
    }
}

static void print_hex(const char *label, const zkn_bn_t v)
{
    printf("       %s = 0x", label);
    uint8_t out[32];
    /* zkn_bn_export: LE limbs → BE bytes */
    for (int i = 0; i < 8; i++) {
        uint32_t limb = v[7-i];
        out[i*4 + 0] = (limb >> 24) & 0xFF;
        out[i*4 + 1] = (limb >> 16) & 0xFF;
        out[i*4 + 2] = (limb >>  8) & 0xFF;
        out[i*4 + 3] =  limb        & 0xFF;
    }
    for (int i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
}

static int bn_eq(const zkn_bn_t a, const zkn_bn_t b)
{
    return memcmp(a, b, sizeof(zkn_bn_t)) == 0;
}

static int bn_is_zero(const zkn_bn_t v)
{
    for (int i = 0; i < 8; i++) if (v[i] != 0) return 0;
    return 1;
}

int main(void)
{
    printf("══ RFC 9591 FROST hashes (Babyfrost_H1/H3/H4/H5/H6) — smoke ══\n\n");

    static zkn_bn_t order;
    load_order(order);

    const uint8_t msg1[] = "Hello, FROST world!";
    const uint8_t msg2[] = "Hello, FROST world?";  /* one char diff */
    const uint8_t msg3[] = "Completely different message for collision check";

    static zkn_bn_t h1_msg1, h1_msg1_rerun, h1_msg2, h1_msg3;
    static zkn_bn_t h3_msg1, h4_msg1, h5_msg1, h6_msg1;

    /* ── H1 determinism ── */
    check("H1(msg1) call 1", Babyfrost_H1(msg1, sizeof(msg1) - 1, order, h1_msg1) == 0);
    check("H1(msg1) call 2", Babyfrost_H1(msg1, sizeof(msg1) - 1, order, h1_msg1_rerun) == 0);
    check("H1 is deterministic", bn_eq(h1_msg1, h1_msg1_rerun));
    check("H1 output non-zero", !bn_is_zero(h1_msg1));
    print_hex("H1(msg1)", h1_msg1);

    /* ── H1 collision-resistance ── */
    check("H1(msg2)", Babyfrost_H1(msg2, sizeof(msg2) - 1, order, h1_msg2) == 0);
    check("H1(msg3)", Babyfrost_H1(msg3, sizeof(msg3) - 1, order, h1_msg3) == 0);
    check("H1(msg1) != H1(msg2) (1-char diff)", !bn_eq(h1_msg1, h1_msg2));
    check("H1(msg1) != H1(msg3) (different msgs)", !bn_eq(h1_msg1, h1_msg3));

    /* ── H3 / H4 / H5 / H6 on msg1 ── */
    check("H3(msg1)", Babyfrost_H3(msg1, sizeof(msg1) - 1, order, h3_msg1) == 0);
    check("H4(msg1)", Babyfrost_H4(msg1, sizeof(msg1) - 1, order, h4_msg1) == 0);
    check("H5(msg1)", Babyfrost_H5(msg1, sizeof(msg1) - 1, order, h5_msg1) == 0);
    check("H6(msg1)", Babyfrost_H6(msg1, sizeof(msg1) - 1, order, h6_msg1) == 0);

    check("H3 output non-zero", !bn_is_zero(h3_msg1));
    check("H4 output non-zero", !bn_is_zero(h4_msg1));
    check("H5 output non-zero", !bn_is_zero(h5_msg1));
    check("H6 output non-zero", !bn_is_zero(h6_msg1));

    /* ── Domain separation: H1, H3, H4, H5, H6 differ on identical input ── */
    check("domain separation: H1(msg1) != H3(msg1)", !bn_eq(h1_msg1, h3_msg1));
    check("domain separation: H1(msg1) != H4(msg1)", !bn_eq(h1_msg1, h4_msg1));
    check("domain separation: H1(msg1) != H5(msg1)", !bn_eq(h1_msg1, h5_msg1));
    check("domain separation: H1(msg1) != H6(msg1)", !bn_eq(h1_msg1, h6_msg1));
    check("domain separation: H3(msg1) != H4(msg1)", !bn_eq(h3_msg1, h4_msg1));
    check("domain separation: H4(msg1) != H5(msg1)", !bn_eq(h4_msg1, h5_msg1));
    check("domain separation: H5(msg1) != H6(msg1)", !bn_eq(h5_msg1, h6_msg1));

    printf("\n══ Results: %d/%d passed ══\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}
