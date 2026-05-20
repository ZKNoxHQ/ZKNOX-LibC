/*
 * test_poseidon.c — Smoke test for the zknox_1905 Poseidon API
 *                   (Poseidon_alloc_init / Poseidon_destroy / Poseidon)
 *
 * Replaces the sources.zip test_poseidon.c which used the older
 * zkn_poseidon_init / zkn_poseidon API. The new API requires an
 * initialized Montgomery context for the BN254 scalar field and
 * follows a state-machine pattern.
 *
 * Coverage:
 *   - alloc_init / destroy round-trip
 *   - Determinism: same input → same output across two calls
 *   - Non-collision: H(1,2,3,4,5) != H(5,4,3,2,1)
 *   - Output non-zero
 *
 * NOTE: cross-validation against circomlibjs reference values is
 * deferred to Phase 3 (test_babyfrost / test_groth16). Here we only
 * test internal consistency of the C implementation.
 *
 * Copyright (c) 2025 ZKNOX
 */

#ifdef ZKN_HOST_TESTS

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "zkn_bn.h"
#include "zkn_poseidon_constants.h"

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int cond)
{
    if (cond) { printf("[PASS] %s\n", name); g_pass++; }
    else      { printf("[FAIL] %s\n", name); g_fail++; }
}

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("       %s = 0x", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

/* BN254 scalar field prime (curve order of bn256/altbn128) */
static const uint8_t BN254_R_BE[32] = {
    0x30,0x64,0x4e,0x72,0xe1,0x31,0xa0,0x29,
    0xb8,0x50,0x45,0xb6,0x81,0x81,0x58,0x5d,
    0x97,0x81,0x6a,0x91,0x68,0x71,0xca,0x8d,
    0x3c,0x20,0x8c,0x16,0xd8,0x7c,0xfd,0x47
};

/* Build a 32-byte big-endian representation of a uint32_t */
static void u32_to_be32(uint8_t out[32], uint32_t v)
{
    memset(out, 0, 32);
    out[28] = (v >> 24) & 0xFF;
    out[29] = (v >> 16) & 0xFF;
    out[30] = (v >>  8) & 0xFF;
    out[31] =  v        & 0xFF;
}

/* Run Poseidon on 5 inputs (state cells 1..5, cell 0 = initState=0).
 * Inputs must already be in Montgomery form for the BN254 scalar field.
 * Output is also in Montgomery form. */
static int run_poseidon5(zkn_bn_mont_ctx_t *montctx,
                          const zkn_bn_t in1, const zkn_bn_t in2,
                          const zkn_bn_t in3, const zkn_bn_t in4,
                          const zkn_bn_t in5,
                          uint8_t out[32])
{
    static poseidon_ctx_t ctx;  /* static: 1600 B, avoid stack frame */
    int rc;

    rc = Poseidon_alloc_init(&ctx, 5, 5, montctx);
    if (rc != 0) return rc;

    /* Fill state[1..5] = inputs (state[0] is initState, set inside Poseidon()) */
    memcpy(ctx.state[1], in1, sizeof(zkn_bn_t));
    memcpy(ctx.state[2], in2, sizeof(zkn_bn_t));
    memcpy(ctx.state[3], in3, sizeof(zkn_bn_t));
    memcpy(ctx.state[4], in4, sizeof(zkn_bn_t));
    memcpy(ctx.state[5], in5, sizeof(zkn_bn_t));

    /* Run Poseidon permutation, initState = 0 */
    static zkn_bn_t output;
    rc = Poseidon(&ctx, 0, &output, 1);
    if (rc != 0) { Poseidon_destroy(&ctx); return rc; }

    /* Convert output out of Montgomery form, then to big-endian bytes */
    static zkn_bn_t normal;
    zkn_mont_from_montgomery(normal, output, montctx);
    /* Serialize: zkn_bn_t is uint32_t[8] little-endian internally;
     * export to BE bytes via zkn_bn_export. */
    zkn_bn_export(normal, out, 32);

    Poseidon_destroy(&ctx);
    return 0;
}

int main(void)
{
    printf("══ Poseidon (zknox_1905 API) smoke test ══\n\n");

    /* ── Init Montgomery context for BN254 scalar field ── */
    static zkn_bn_mont_ctx_t montctx;
    static zkn_bn_t order;

    /* Load BN254_R_BE into a zkn_bn_t */
    /* zkn_bn_t is uint32_t[8] in little-endian limb order */
    /* Use zkn_bn_alloc_init or manual conversion */
    {
        /* manual: BE bytes → LE limbs */
        for (int i = 0; i < 8; i++) {
            uint32_t limb = 0;
            for (int j = 0; j < 4; j++) {
                limb = (limb << 8) | BN254_R_BE[i*4 + j];
            }
            order[7-i] = limb;
        }
    }
    int rc = zkn_mont_init(&montctx, order);
    check("mont_init(BN254 scalar field)", rc == 0);
    if (rc != 0) return 1;

    /* ── Build 5 inputs in Montgomery form ── */
    static zkn_bn_t in[5];
    for (uint32_t i = 0; i < 5; i++) {
        static zkn_bn_t natural;
        uint8_t be[32];
        u32_to_be32(be, i + 1);  /* 1, 2, 3, 4, 5 */
        for (int k = 0; k < 8; k++) {
            uint32_t limb = 0;
            for (int j = 0; j < 4; j++) limb = (limb << 8) | be[k*4 + j];
            natural[7-k] = limb;
        }
        zkn_mont_to_montgomery(in[i], natural, &montctx);
    }

    /* ── Test 1: run twice, expect determinism ── */
    static uint8_t out1[32], out2[32];
    rc = run_poseidon5(&montctx, in[0], in[1], in[2], in[3], in[4], out1);
    check("Poseidon(1,2,3,4,5) run1", rc == 0);
    rc = run_poseidon5(&montctx, in[0], in[1], in[2], in[3], in[4], out2);
    check("Poseidon(1,2,3,4,5) run2", rc == 0);
    check("determinism: run1 == run2", memcmp(out1, out2, 32) == 0);
    print_hex("output", out1, 32);

    /* ── Test 2: output is non-zero ── */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) if (out1[i] != 0) { all_zero = 0; break; }
    check("output is non-zero", !all_zero);

    /* ── Test 3: different input order → different output ── */
    static uint8_t out_rev[32];
    rc = run_poseidon5(&montctx, in[4], in[3], in[2], in[1], in[0], out_rev);
    check("Poseidon(5,4,3,2,1)", rc == 0);
    check("non-collision: H(1,2,3,4,5) != H(5,4,3,2,1)",
          memcmp(out1, out_rev, 32) != 0);
    print_hex("reversed", out_rev, 32);

    /* ── Test 4: single-bit change → different output ── */
    static zkn_bn_t in_almost_zero;
    {
        uint8_t be[32];
        u32_to_be32(be, 1);
        for (int k = 0; k < 8; k++) {
            uint32_t limb = 0;
            for (int j = 0; j < 4; j++) limb = (limb << 8) | be[k*4 + j];
            in_almost_zero[7-k] = limb;
        }
        static zkn_bn_t tmp;
        zkn_mont_to_montgomery(tmp, in_almost_zero, &montctx);
        memcpy(in_almost_zero, tmp, sizeof(zkn_bn_t));
    }
    /* Replace in[0]=1_mont with itself — actually test changing in[0] to something else */
    static uint8_t out_changed[32];
    rc = run_poseidon5(&montctx, in_almost_zero, in[1], in[2], in[3], in[4], out_changed);
    check("Poseidon(1',2,3,4,5)", rc == 0);
    /* in_almost_zero is already 1 in Mont (built from u32_to_be32(buf, 1)).
     * in[0] is also 1 in Mont. So out_changed should equal out1. */
    check("identical inputs give identical output (Mont-form sanity)",
          memcmp(out1, out_changed, 32) == 0);

    /* ── Test 5: change one input — should change output ── */
    static zkn_bn_t in_42;
    {
        uint8_t be[32];
        u32_to_be32(be, 42);
        for (int k = 0; k < 8; k++) {
            uint32_t limb = 0;
            for (int j = 0; j < 4; j++) limb = (limb << 8) | be[k*4 + j];
            in_42[7-k] = limb;
        }
        static zkn_bn_t tmp;
        zkn_mont_to_montgomery(tmp, in_42, &montctx);
        memcpy(in_42, tmp, sizeof(zkn_bn_t));
    }
    static uint8_t out_42[32];
    rc = run_poseidon5(&montctx, in_42, in[1], in[2], in[3], in[4], out_42);
    check("Poseidon(42,2,3,4,5)", rc == 0);
    check("avalanche: H(42,2,3,4,5) != H(1,2,3,4,5)",
          memcmp(out_42, out1, 32) != 0);

    printf("\n══ Results: %d/%d passed ══\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}

#endif /* ZKN_HOST_TESTS */
