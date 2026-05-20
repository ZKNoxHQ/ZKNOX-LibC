/*
 * test_poseidon.c — Test suite for zkn_poseidon (circomlib-compatible)
 *
 * Tests:
 *   - Grain LFSR determinism
 *   - Poseidon(0,0,0,0,0) basic smoke
 *   - Poseidon(1,2,3,4,5) determinism + known answer
 *   - Different inputs → different outputs
 *   - zkn_poseidon_hash convenience API
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include <stdio.h>
#include <string.h>
#include "zkn_poseidon_soft.h"

static int test_count = 0;
static int fail_count = 0;

/* ── Helpers ───────────────────────────────────────────────────────── */

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("    %s = 0x", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

static void check_bytes(const char *name,
                        const uint8_t *got,
                        const uint8_t *expected,
                        size_t len)
{
    test_count++;
    if (memcmp(got, expected, len) == 0) {
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n", name);
        print_hex("expected", expected, len);
        print_hex("got     ", got, len);
        fail_count++;
    }
}

static void check_ok(const char *name, int rc)
{
    test_count++;
    if (rc == 0)
        printf("[PASS] %s\n", name);
    else {
        printf("[FAIL] %s (rc=%d)\n", name, rc);
        fail_count++;
    }
}

static void check_bool(const char *name, int cond)
{
    test_count++;
    if (cond)
        printf("[PASS] %s\n", name);
    else {
        printf("[FAIL] %s\n", name);
        fail_count++;
    }
}

/* ── Build 32-byte big-endian from uint32 ──────────────────────────── */

static void u32_to_be32(uint8_t out[32], uint32_t v)
{
    memset(out, 0, 32);
    out[28] = (v >> 24) & 0xFF;
    out[29] = (v >> 16) & 0xFF;
    out[30] = (v >>  8) & 0xFF;
    out[31] =  v        & 0xFF;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test: determinism — same inputs always give same output
 * ══════════════════════════════════════════════════════════════════════ */

static void test_determinism(void)
{
    printf("\n--- determinism ---\n");

    uint8_t inputs[5 * 32];
    for (int i = 0; i < 5; i++)
        u32_to_be32(inputs + 32 * i, i + 1);  /* [1, 2, 3, 4, 5] */

    uint8_t out1[32], out2[32];
    check_ok("hash run 1", zkn_poseidon_hash(inputs, 5, out1));
    check_ok("hash run 2", zkn_poseidon_hash(inputs, 5, out2));
    check_bytes("deterministic", out1, out2, 32);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test: different inputs → different outputs
 * ══════════════════════════════════════════════════════════════════════ */

static void test_different_inputs(void)
{
    printf("\n--- collision resistance ---\n");

    uint8_t in_a[5 * 32], in_b[5 * 32];
    for (int i = 0; i < 5; i++) {
        u32_to_be32(in_a + 32 * i, i + 1);  /* [1, 2, 3, 4, 5] */
        u32_to_be32(in_b + 32 * i, i + 2);  /* [2, 3, 4, 5, 6] */
    }

    uint8_t out_a[32], out_b[32];
    zkn_poseidon_hash(in_a, 5, out_a);
    zkn_poseidon_hash(in_b, 5, out_b);
    check_bool("H(1..5) != H(2..6)", memcmp(out_a, out_b, 32) != 0);

    /* Flip one input bit */
    uint8_t in_c[5 * 32];
    memcpy(in_c, in_a, sizeof(in_c));
    in_c[31] ^= 0x01;  /* input[0] goes from 1 to 0 */
    uint8_t out_c[32];
    zkn_poseidon_hash(in_c, 5, out_c);
    check_bool("1-bit flip → different", memcmp(out_a, out_c, 32) != 0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test: Poseidon(0,0,0,0,0) — all-zero input
 * ══════════════════════════════════════════════════════════════════════ */

static void test_zero_inputs(void)
{
    printf("\n--- zero inputs ---\n");

    uint8_t inputs[5 * 32];
    memset(inputs, 0, sizeof(inputs));

    uint8_t out[32];
    check_ok("hash(0,0,0,0,0)", zkn_poseidon_hash(inputs, 5, out));

    /* Output should be nonzero */
    uint8_t zero[32] = {0};
    check_bool("output nonzero", memcmp(out, zero, 32) != 0);

    /* Output must be < p (top byte 0x30 for BJJ prime) */
    check_bool("output < p", out[0] <= 0x30);

    printf("    hash(0,0,0,0,0) = 0x");
    for (int i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test: Poseidon(1,2,3,4,5)
 *  Print output for cross-validation with Ledger device / JS.
 * ══════════════════════════════════════════════════════════════════════ */

static void test_known_vector(void)
{
    printf("\n--- Poseidon(1,2,3,4,5) ---\n");

    uint8_t inputs[5 * 32];
    for (int i = 0; i < 5; i++)
        u32_to_be32(inputs + 32 * i, i + 1);

    uint8_t out[32];
    check_ok("hash(1,2,3,4,5)", zkn_poseidon_hash(inputs, 5, out));

    printf("    hash(1,2,3,4,5) = 0x");
    for (int i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");

    /* Output must be < p */
    check_bool("output < p", out[0] <= 0x30);

    /*
     * Validated against circomlib (old/original, createHash(6,8,57)):
     *   poseidon([1,2,3,4,5]) = 0x0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0
     * Ref: https://github.com/iden3/circomlibjs/issues/14
     */
    static const uint8_t EXPECTED[32] = {
        0x0d, 0xab, 0x94, 0x49, 0xe4, 0xa1, 0x39, 0x8a,
        0x15, 0x22, 0x4c, 0x0b, 0x15, 0xa4, 0x9d, 0x59,
        0x8b, 0x21, 0x74, 0xd3, 0x05, 0xa3, 0x16, 0xc9,
        0x18, 0x12, 0x5f, 0x8f, 0xee, 0xb1, 0x23, 0xc0
    };
    check_bytes("known answer (circomlib)", out, EXPECTED, 32);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test: full Poseidon API (mimics handler_cmd_Poseidon flow)
 * ══════════════════════════════════════════════════════════════════════ */

static void test_handler_flow(void)
{
    printf("\n--- handler flow ---\n");

    static const uint8_t BJJ_PRIME_BE[32] = {
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
        0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01
    };

    /* Exact sequence from handler_cmd_Poseidon */
    zkn_bn_lock(32, 0);

    zkn_bn_mont_ctx_t montctx;
    zkn_bn_t modulus, temp;

    zkn_bn_alloc_init(&modulus, 32, BJJ_PRIME_BE, 32);
    zkn_bn_alloc_init(&temp, 32, BJJ_PRIME_BE, 32);
    zkn_mont_alloc(&montctx, 32);
    zkn_mont_init(&montctx, modulus);

    poseidon_soft_ctx_t Ctx;
    check_ok("poseidon_init", zkn_poseidon_init(&Ctx, 5, 5, &montctx));

    /* Load 5 inputs: [1, 2, 3, 4, 5] */
    uint8_t input_be[32];
    for (int i = 0; i < 5; i++) {
        u32_to_be32(input_be, i + 1);
        zkn_bn_init(Ctx.state[i + 1], input_be, 32);
        zkn_mont_to_montgomery(Ctx.state[i + 1], Ctx.state[i + 1], &montctx);
    }

    zkn_bn_t result;
    check_ok("poseidon", zkn_poseidon(&Ctx, 0, &result, 1));

    /* De-montgomerize and export */
    zkn_mont_from_montgomery(result, result, &montctx);
    uint8_t out[32];
    zkn_bn_export(result, out, 32);

    /* Should match convenience API */
    uint8_t inputs_flat[5 * 32];
    for (int i = 0; i < 5; i++)
        u32_to_be32(inputs_flat + 32 * i, i + 1);
    uint8_t out2[32];
    zkn_poseidon_hash(inputs_flat, 5, out2);

    check_bytes("handler==convenience", out, out2, 32);

    zkn_bn_destroy(&temp);
    zkn_bn_unlock();
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test: all 6 state outputs are different
 * ══════════════════════════════════════════════════════════════════════ */

static void test_all_outputs(void)
{
    printf("\n--- all state outputs ---\n");

    static const uint8_t BJJ_PRIME_BE[32] = {
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
        0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01
    };

    zkn_bn_mont_ctx_t montctx;
    zkn_bn_t modulus;
    zkn_bn_alloc_init(&modulus, 32, BJJ_PRIME_BE, 32);
    zkn_mont_alloc(&montctx, 32);
    zkn_mont_init(&montctx, modulus);

    poseidon_soft_ctx_t Ctx;
    zkn_poseidon_init(&Ctx, 5, 5, &montctx);

    uint8_t input_be[32];
    for (int i = 0; i < 5; i++) {
        u32_to_be32(input_be, i + 1);
        zkn_bn_init(Ctx.state[i + 1], input_be, 32);
        zkn_mont_to_montgomery(Ctx.state[i + 1], Ctx.state[i + 1], &montctx);
    }

    /* Get all 6 outputs */
    zkn_bn_t results[6];
    zkn_poseidon(&Ctx, 0, results, 6);

    uint8_t outputs[6][32];
    for (int i = 0; i < 6; i++) {
        zkn_mont_from_montgomery(results[i], results[i], &montctx);
        zkn_bn_export(results[i], outputs[i], 32);
    }

    /* All outputs should be pairwise different */
    int all_different = 1;
    for (int i = 0; i < 6; i++) {
        for (int j = i + 1; j < 6; j++) {
            if (memcmp(outputs[i], outputs[j], 32) == 0) {
                printf("    state[%d] == state[%d]!\n", i, j);
                all_different = 0;
            }
        }
    }
    check_bool("6 outputs pairwise different", all_different);

    /* Print state[0] for reference */
    printf("    state[0] = 0x");
    for (int i = 0; i < 32; i++) printf("%02x", outputs[0][i]);
    printf("\n");
}

/* ══════════════════════════════════════════════════════════════════════
 *  NEW: Large field element inputs (near BJJ prime)
 *
 *  The BabyJubjub prime is:
 *    p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
 *
 *  We feed values p-1, p-2, p-3, p-4, p-5 as inputs to Poseidon-5
 *  and verify:
 *    - Output is non-zero and < p
 *    - Output is deterministic
 *    - Different large inputs → different outputs
 *    - Matches the convenience API
 * ══════════════════════════════════════════════════════════════════════ */

static const uint8_t BJJ_PRIME_LARGE[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01
};

/* Compute p - k (big-endian 32 bytes) */
static void bjj_pm_k(uint8_t out[32], uint32_t k)
{
    memcpy(out, BJJ_PRIME_LARGE, 32);
    /* subtract k from the last 4 bytes (big-endian) */
    uint32_t borrow = k;
    for (int i = 31; i >= 0 && borrow; i--) {
        uint32_t x = (uint32_t)out[i];
        if (x >= borrow) { out[i] = (uint8_t)(x - borrow); borrow = 0; }
        else              { out[i] = (uint8_t)(x + 256 - borrow); borrow = 1; }
    }
}

static void test_large_inputs(void)
{
    printf("\n--- Poseidon with large inputs (near p) ---\n");

    /*
     * Build 5 inputs: p-1, p-2, p-3, p-4, p-5
     */
    uint8_t inputs[5 * 32];
    for (int i = 0; i < 5; i++)
        bjj_pm_k(inputs + 32 * i, (uint32_t)(i + 1));

    /* Run twice — must be deterministic */
    uint8_t out1[32], out2[32];
    check_ok("large: hash(p-1..p-5) run1", zkn_poseidon_hash(inputs, 5, out1));
    check_ok("large: hash(p-1..p-5) run2", zkn_poseidon_hash(inputs, 5, out2));
    check_bytes("large: deterministic", out1, out2, 32);

    /* Output must be non-zero */
    uint8_t zero[32] = {0};
    check_bool("large: output non-zero", memcmp(out1, zero, 32) != 0);

    /* Output < p (top byte <= 0x30) */
    check_bool("large: output < p", out1[0] <= 0x30);

    printf("    hash(p-1,p-2,p-3,p-4,p-5) = 0x");
    for (int i = 0; i < 32; i++) printf("%02x", out1[i]);
    printf("\n");

    /*
     * Different large inputs → different outputs:
     * compare (p-1..p-5) vs (p-6..p-10)
     */
    uint8_t inputs_b[5 * 32];
    for (int i = 0; i < 5; i++)
        bjj_pm_k(inputs_b + 32 * i, (uint32_t)(i + 6));

    uint8_t out_b[32];
    zkn_poseidon_hash(inputs_b, 5, out_b);
    check_bool("large: H(p-1..p-5) != H(p-6..p-10)",
               memcmp(out1, out_b, 32) != 0);

    /*
     * Mixed: one small (1) and four large (p-1..p-4) inputs
     */
    uint8_t inputs_mixed[5 * 32];
    u32_to_be32(inputs_mixed, 1);
    for (int i = 1; i < 5; i++)
        bjj_pm_k(inputs_mixed + 32 * i, (uint32_t)i);

    uint8_t out_mixed[32];
    check_ok("large: hash(1,p-1,p-2,p-3,p-4)", zkn_poseidon_hash(inputs_mixed, 5, out_mixed));
    check_bool("large: mixed output < p", out_mixed[0] <= 0x30);
    check_bool("large: mixed != large-only",
               memcmp(out_mixed, out1, 32) != 0);

    printf("    hash(1,p-1..p-4)         = 0x");
    for (int i = 0; i < 32; i++) printf("%02x", out_mixed[i]);
    printf("\n");

    /*
     * Full handler-flow with large inputs (same as test_handler_flow but
     * using p-1..p-5 as state inputs, verify matches convenience API)
     */
    zkn_bn_lock(32, 0);
    zkn_bn_mont_ctx_t montctx;
    zkn_bn_t modulus;
    zkn_bn_alloc_init(&modulus, 32, BJJ_PRIME_LARGE, 32);
    zkn_mont_alloc(&montctx, 32);
    zkn_mont_init(&montctx, modulus);

    poseidon_soft_ctx_t Ctx;
    check_ok("large: poseidon_init", zkn_poseidon_init(&Ctx, 5, 5, &montctx));

    for (int i = 0; i < 5; i++) {
        uint8_t inp[32];
        bjj_pm_k(inp, (uint32_t)(i + 1));
        zkn_bn_init(Ctx.state[i + 1], inp, 32);
        zkn_mont_to_montgomery(Ctx.state[i + 1], Ctx.state[i + 1], &montctx);
    }

    zkn_bn_t result;
    check_ok("large: poseidon", zkn_poseidon(&Ctx, 0, &result, 1));
    zkn_mont_from_montgomery(result, result, &montctx);
    uint8_t out_handler[32];
    zkn_bn_export(result, out_handler, 32);

    check_bytes("large: handler==convenience", out_handler, out1, 32);
    zkn_bn_unlock();
}

/* ══════════════════════════════════════════════════════════════════════
 *  Main
 * ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("=== zkn_poseidon_soft test suite ===\n");
#ifdef ZKN_MONT256_ASM
    printf("    backend: ARM Thumb-2 ASM (Fp layer)\n");
#else
    printf("    backend: portable C\n");
#endif

    test_determinism();
    test_different_inputs();
    test_zero_inputs();
    test_known_vector();
    test_handler_flow();
    test_all_outputs();

    /* ── NEW: large inputs near BJJ prime ── */
    test_large_inputs();

    printf("\n=== Results: %d/%d passed ===\n",
           test_count - fail_count, test_count);

    return fail_count ? 1 : 0;
}
