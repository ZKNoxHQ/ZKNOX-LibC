/*
 * test_g1_384.c — Test suite for zkn_g1_384 (BLS12-381 G1 curve)
 *
 * Tests:
 *   - Generator on curve
 *   - Affine round-trip
 *   - Infinity / zero handling
 *   - Doubling, addition, mixed addition
 *   - Negation:  P + (-P) = O
 *   - Scalar mul: known multiples of generator
 *   - Order test: [r]·G = O  (subgroup order)
 *   - Associativity / commutativity of add
 *   - Aliasing
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifdef ZKN_HOST_TESTS

#include <stdio.h>
#include <string.h>
#include "zkn_g1_384.h"

static int test_count = 0;
static int fail_count = 0;

static void check(const char *name, int cond)
{
    test_count++;
    if (cond) printf("[PASS] %s\n", name);
    else      { printf("[FAIL] %s\n", name); fail_count++; }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Known test vectors
 * ══════════════════════════════════════════════════════════════════════ */

/*
 * BLS12-381 subgroup order r (big-endian, 32 bytes):
 * r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
 */
static const uint8_t BLS12_381_R_BE[32] = {
    0x73,0xed,0xa7,0x53,0x29,0x9d,0x7d,0x48,
    0x33,0x39,0xd8,0x08,0x09,0xa1,0xd8,0x05,
    0x53,0xbd,0xa4,0x02,0xff,0xfe,0x5b,0xfe,
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01
};

/*
 * [2]G1 affine coordinates (from sage/py_ecc):
 * x = 0x0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e
 * y = 0x166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28
 */
static const uint8_t G1_2X_BE[48] = {
    0x05,0x72,0xcb,0xea,0x90,0x4d,0x67,0x46,
    0x88,0x08,0xc8,0xeb,0x50,0xa9,0x45,0x0c,
    0x97,0x21,0xdb,0x30,0x91,0x28,0x01,0x25,
    0x43,0x90,0x2d,0x0a,0xc3,0x58,0xa6,0x2a,
    0xe2,0x8f,0x75,0xbb,0x8f,0x1c,0x7c,0x42,
    0xc3,0x9a,0x8c,0x55,0x29,0xbf,0x0f,0x4e
};
static const uint8_t G1_2Y_BE[48] = {
    0x16,0x6a,0x9d,0x8c,0xab,0xc6,0x73,0xa3,
    0x22,0xfd,0xa6,0x73,0x77,0x9d,0x8e,0x38,
    0x22,0xba,0x3e,0xcb,0x86,0x70,0xe4,0x61,
    0xf7,0x3b,0xb9,0x02,0x1d,0x5f,0xd7,0x6a,
    0x4c,0x56,0xd9,0xd4,0xcd,0x16,0xbd,0x1b,
    0xba,0x86,0x88,0x19,0x79,0x74,0x9d,0x28
};

/*
 * [3]G1:
 * x = 0x0b776e1fe1f737b99bba5181f9aeccc0f97715ea4db4e10e86e tried a known vector approach
 * Actually let's compute [3]G = [2]G + G and verify on-curve + affine round-trip instead.
 */

/* ══════════════════════════════════════════════════════════════════════
 *  Tests
 * ══════════════════════════════════════════════════════════════════════ */

static void test_generator(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 generator ---\n");

    zkn_g1_384_t G;
    zkn_g1_384_generator(&G, ctx);

    check("G on curve", zkn_g1_384_on_curve(&G, ctx));
    check("G not zero", !zkn_g1_384_is_zero(&G));
}

static void test_affine_roundtrip(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 affine round-trip ---\n");

    zkn_g1_384_t G;
    zkn_g1_384_generator(&G, ctx);

    /* to_affine then from_affine should give same point */
    zkn_fe384_t ax, ay;
    zkn_g1_384_to_affine(ax, ay, &G, ctx);

    zkn_g1_384_t G2;
    zkn_g1_384_from_affine(&G2, ax, ay, ctx);

    check("round-trip eq", zkn_g1_384_eq(&G, &G2, ctx));

    /* Verify the actual generator x coordinate */
    static const uint8_t GEN_X_BE[48] = {
        0x17,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,
        0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
        0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,
        0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
        0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,
        0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb
    };
    zkn_fe384_t expected_x;
    zkn_fe384_from_be(expected_x, GEN_X_BE);
    check("gen x matches", zkn_fe384_eq(ax, expected_x));
}

static void test_infinity(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 infinity ---\n");

    zkn_g1_384_t O;
    zkn_g1_384_zero(&O);
    check("O is zero", zkn_g1_384_is_zero(&O));
    check("O on curve", zkn_g1_384_on_curve(&O, ctx));

    zkn_g1_384_t G;
    zkn_g1_384_generator(&G, ctx);

    /* G + O = G */
    zkn_g1_384_t r;
    zkn_g1_384_add(&r, &G, &O, ctx);
    check("G+O=G", zkn_g1_384_eq(&r, &G, ctx));

    /* O + G = G */
    zkn_g1_384_add(&r, &O, &G, ctx);
    check("O+G=G", zkn_g1_384_eq(&r, &G, ctx));

    /* O + O = O */
    zkn_g1_384_add(&r, &O, &O, ctx);
    check("O+O=O", zkn_g1_384_is_zero(&r));

    /* dbl(O) = O */
    zkn_g1_384_dbl(&r, &O, ctx);
    check("dbl(O)=O", zkn_g1_384_is_zero(&r));
}

static void test_negation(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 negation ---\n");

    zkn_g1_384_t G, negG, r;
    zkn_g1_384_generator(&G, ctx);
    zkn_g1_384_neg(&negG, &G, ctx);

    check("-G on curve", zkn_g1_384_on_curve(&negG, ctx));
    check("-G != G", !zkn_g1_384_eq(&negG, &G, ctx));

    /* G + (-G) = O */
    zkn_g1_384_add(&r, &G, &negG, ctx);
    check("G+(-G)=O", zkn_g1_384_is_zero(&r));

    /* -(-G) = G */
    zkn_g1_384_t negNegG;
    zkn_g1_384_neg(&negNegG, &negG, ctx);
    check("-(-G)=G", zkn_g1_384_eq(&negNegG, &G, ctx));
}

static void test_doubling(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 doubling ---\n");

    zkn_g1_384_t G;
    zkn_g1_384_generator(&G, ctx);

    /* [2]G via dbl */
    zkn_g1_384_t dblG;
    zkn_g1_384_dbl(&dblG, &G, ctx);
    check("[2]G on curve", zkn_g1_384_on_curve(&dblG, ctx));

    /* Verify [2]G affine coordinates against known vector */
    zkn_fe384_t ax, ay;
    zkn_g1_384_to_affine(ax, ay, &dblG, ctx);

    zkn_fe384_t exp_x, exp_y;
    zkn_fe384_from_be(exp_x, G1_2X_BE);
    zkn_fe384_from_be(exp_y, G1_2Y_BE);

    check("[2]G.x matches", zkn_fe384_eq(ax, exp_x));
    check("[2]G.y matches", zkn_fe384_eq(ay, exp_y));

    /* dbl(G) == G + G */
    zkn_g1_384_t addGG;
    zkn_g1_384_add(&addGG, &G, &G, ctx);
    check("dbl(G)==G+G", zkn_g1_384_eq(&dblG, &addGG, ctx));
}

static void test_addition(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 addition ---\n");

    zkn_g1_384_t G;
    zkn_g1_384_generator(&G, ctx);

    zkn_g1_384_t G2, G3;
    zkn_g1_384_dbl(&G2, &G, ctx);

    /* [3]G = [2]G + G */
    zkn_g1_384_add(&G3, &G2, &G, ctx);
    check("[3]G on curve", zkn_g1_384_on_curve(&G3, ctx));

    /* [3]G = G + [2]G (commutativity) */
    zkn_g1_384_t G3b;
    zkn_g1_384_add(&G3b, &G, &G2, ctx);
    check("[3]G commutative", zkn_g1_384_eq(&G3, &G3b, ctx));

    /* [4]G = [3]G + G == dbl([2]G) */
    zkn_g1_384_t G4a, G4b;
    zkn_g1_384_add(&G4a, &G3, &G, ctx);
    zkn_g1_384_dbl(&G4b, &G2, ctx);
    check("[4]G: [3]G+G == dbl([2]G)", zkn_g1_384_eq(&G4a, &G4b, ctx));

    /* Associativity: (G + [2]G) + [3]G == G + ([2]G + [3]G) */
    zkn_g1_384_t lhs, rhs, t;
    zkn_g1_384_add(&t, &G, &G2, ctx);
    zkn_g1_384_add(&lhs, &t, &G3, ctx);
    zkn_g1_384_add(&t, &G2, &G3, ctx);
    zkn_g1_384_add(&rhs, &G, &t, ctx);
    check("associativity", zkn_g1_384_eq(&lhs, &rhs, ctx));
}

static void test_mixed_add(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 mixed addition ---\n");

    zkn_g1_384_t G;
    zkn_g1_384_generator(&G, ctx);   /* G has Z = mont(1) = affine */

    zkn_g1_384_t G2;
    zkn_g1_384_dbl(&G2, &G, ctx);    /* G2 has Z ≠ 1 */

    /* mixed_add(G2, G) should equal add(G2, G) */
    zkn_g1_384_t r_mixed, r_full;
    zkn_g1_384_add_mixed(&r_mixed, &G2, &G, ctx);
    zkn_g1_384_add(&r_full, &G2, &G, ctx);
    check("mixed==full [3]G", zkn_g1_384_eq(&r_mixed, &r_full, ctx));

    /* mixed_add(O, G) = G */
    zkn_g1_384_t O;
    zkn_g1_384_zero(&O);
    zkn_g1_384_add_mixed(&r_mixed, &O, &G, ctx);
    check("mixed: O+G=G", zkn_g1_384_eq(&r_mixed, &G, ctx));
}

static void test_scalar_mul(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 scalar mul ---\n");

    zkn_g1_384_t G;
    zkn_g1_384_generator(&G, ctx);

    /* [1]·G = G */
    uint8_t one_be[1] = {0x01};
    zkn_g1_384_t r;
    zkn_g1_384_mul(&r, &G, one_be, 1, ctx);
    check("[1]G=G", zkn_g1_384_eq(&r, &G, ctx));

    /* [2]·G == dbl(G) */
    uint8_t two_be[1] = {0x02};
    zkn_g1_384_t dblG;
    zkn_g1_384_dbl(&dblG, &G, ctx);
    zkn_g1_384_mul(&r, &G, two_be, 1, ctx);
    check("[2]G==dbl(G)", zkn_g1_384_eq(&r, &dblG, ctx));

    /* [3]·G == dbl(G)+G */
    uint8_t three_be[1] = {0x03};
    zkn_g1_384_t G3;
    zkn_g1_384_add(&G3, &dblG, &G, ctx);
    zkn_g1_384_mul(&r, &G, three_be, 1, ctx);
    check("[3]G==G2+G", zkn_g1_384_eq(&r, &G3, ctx));

    /* [7]·G */
    uint8_t seven_be[1] = {0x07};
    zkn_g1_384_t G7;
    zkn_g1_384_mul(&G7, &G, seven_be, 1, ctx);
    check("[7]G on curve", zkn_g1_384_on_curve(&G7, ctx));

    /* [7]G == [4]G + [3]G */
    zkn_g1_384_t G4;
    zkn_g1_384_dbl(&G4, &dblG, ctx);
    zkn_g1_384_t G7b;
    zkn_g1_384_add(&G7b, &G4, &G3, ctx);
    check("[7]G==[4]G+[3]G", zkn_g1_384_eq(&G7, &G7b, ctx));

    /* [0]·G = O */
    uint8_t zero_be[1] = {0x00};
    zkn_g1_384_mul(&r, &G, zero_be, 1, ctx);
    check("[0]G=O", zkn_g1_384_is_zero(&r));
}

static void test_order(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 order ---\n");

    zkn_g1_384_t G;
    zkn_g1_384_generator(&G, ctx);

    /* [r]·G = O  where r is the BLS12-381 subgroup order */
    zkn_g1_384_t r;
    zkn_g1_384_mul(&r, &G, BLS12_381_R_BE, 32, ctx);
    check("[r]G=O", zkn_g1_384_is_zero(&r));

    /* [r-1]·G = -G */
    /* r-1 in big-endian */
    uint8_t rm1[32];
    memcpy(rm1, BLS12_381_R_BE, 32);
    /* subtract 1 from LE byte (last byte) */
    rm1[31] -= 1;  /* r ends in 0x01, so r-1 ends in 0x00 */

    zkn_g1_384_t rm1G;
    zkn_g1_384_mul(&rm1G, &G, rm1, 32, ctx);

    zkn_g1_384_t negG;
    zkn_g1_384_neg(&negG, &G, ctx);
    check("[r-1]G=-G", zkn_g1_384_eq(&rm1G, &negG, ctx));
}

static void test_aliasing(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 aliasing ---\n");

    zkn_g1_384_t G;
    zkn_g1_384_generator(&G, ctx);

    /* dbl in-place */
    zkn_g1_384_t expected, alias;
    zkn_g1_384_dbl(&expected, &G, ctx);
    zkn_g1_384_copy(&alias, &G);
    zkn_g1_384_dbl(&alias, &alias, ctx);
    check("dbl(r,r)", zkn_g1_384_eq(&alias, &expected, ctx));

    /* add in-place (r = r + b) */
    zkn_g1_384_t G2;
    zkn_g1_384_dbl(&G2, &G, ctx);
    zkn_g1_384_add(&expected, &G2, &G, ctx);
    zkn_g1_384_copy(&alias, &G2);
    zkn_g1_384_add(&alias, &alias, &G, ctx);
    check("add(r,r,b)", zkn_g1_384_eq(&alias, &expected, ctx));

    /* neg in-place */
    zkn_g1_384_neg(&expected, &G, ctx);
    zkn_g1_384_copy(&alias, &G);
    zkn_g1_384_neg(&alias, &alias, ctx);
    check("neg(r,r)", zkn_g1_384_eq(&alias, &expected, ctx));
}

static void test_scalar_mul_large(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G1 scalar mul (large 32-byte scalars) ---\n");

    zkn_g1_384_t G;
    zkn_g1_384_generator(&G, ctx);

    /*
     * k1 = 0x1234567890abcdef1122334455667788aabbccddeeff00112233445566778899
     * k2 = 0x0fedcba9876543211f2e3d4c5b6a7988796a5b4c3d2e1f0feeddccbbaa998877
     * k_sum = k1 + k2  (verified by hand to not exceed r for this test)
     *
     * We simply test:
     *   [k1]G on curve, [k2]G on curve
     *   [k1]G + [k2]G == [(k1+k2)]G
     *   [k1]([k2]G) != O  (non-trivial)
     */

    static const uint8_t K1[32] = {
        0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,
        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99
    };
    static const uint8_t K2[32] = {
        0x0f,0xed,0xcb,0xa9,0x87,0x65,0x43,0x21,
        0x1f,0x2e,0x3d,0x4c,0x5b,0x6a,0x79,0x88,
        0x79,0x6a,0x5b,0x4c,0x3d,0x2e,0x1f,0x0f,
        0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77
    };
    /* K1 + K2 (big-endian 256-bit addition, no carry expected here) */
    static const uint8_t K_SUM[32] = {
                0x22,0x22,0x22,0x22,0x18,0x11,0x11,0x10,
        0x30,0x50,0x70,0x90,0xb0,0xd0,0xf1,0x11,
        0x24,0x26,0x28,0x2a,0x2c,0x2d,0x1f,0x21,
        0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x10
    };

    zkn_g1_384_t P1, P2, P_sum_mul, P_sum_add;

    zkn_g1_384_mul(&P1, &G, K1, 32, ctx);
    zkn_g1_384_mul(&P2, &G, K2, 32, ctx);

    check("large: [k1]G on curve", zkn_g1_384_on_curve(&P1, ctx));
    check("large: [k2]G on curve", zkn_g1_384_on_curve(&P2, ctx));
    check("large: [k1]G != O",    !zkn_g1_384_is_zero(&P1));
    check("large: [k2]G != O",    !zkn_g1_384_is_zero(&P2));

    /* [k1]G + [k2]G == [(k1+k2)]G */
    zkn_g1_384_add(&P_sum_add, &P1, &P2, ctx);
    zkn_g1_384_mul(&P_sum_mul, &G, K_SUM, 32, ctx);
    check("large: [k1]G+[k2]G==[k1+k2]G",
          zkn_g1_384_eq(&P_sum_add, &P_sum_mul, ctx));

    /* 2·[k1]G == dbl([k1]G) */
    zkn_g1_384_t dbl_P1, two_k1_G;
    zkn_g1_384_dbl(&dbl_P1, &P1, ctx);

    /* Compute 2*k1 in 33 bytes (big-endian, one extra byte for carry) */
    uint8_t TWO_K1[33] = {0};
    uint32_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint32_t s = (uint32_t)K1[i] * 2 + carry;
        TWO_K1[i + 1] = (uint8_t)(s & 0xFF);
        carry = s >> 8;
    }
    TWO_K1[0] = (uint8_t)carry;
    /* trim leading zero byte for scalar_mul */
    int offset = (TWO_K1[0] == 0) ? 1 : 0;
    zkn_g1_384_mul(&two_k1_G, &G, TWO_K1 + offset, 33 - offset, ctx);
    check("large: 2*[k1]G==dbl([k1]G)",
          zkn_g1_384_eq(&two_k1_G, &dbl_P1, ctx));

    /* mixed_add [k1]G + G  (compare with full add) */
    /* [k1+1]G: scalar = k1 + 1 */
    uint8_t K1_PLUS_1[32];
    memcpy(K1_PLUS_1, K1, 32);
    int inc_carry = 1;
    for (int i = 31; i >= 0 && inc_carry; i--) {
        uint32_t s = K1_PLUS_1[i] + inc_carry;
        K1_PLUS_1[i] = (uint8_t)(s & 0xFF);
        inc_carry = s >> 8;
    }
    zkn_g1_384_t P1_plus_G_full, P1_plus_G_mixed, K1p1_G;
    zkn_g1_384_add(&P1_plus_G_full, &P1, &G, ctx);
    zkn_g1_384_add_mixed(&P1_plus_G_mixed, &P1, &G, ctx);
    zkn_g1_384_mul(&K1p1_G, &G, K1_PLUS_1, 32, ctx);
    check("large: [k1]G+G (full) on curve",
          zkn_g1_384_on_curve(&P1_plus_G_full, ctx));
    check("large: mixed_add([k1]G,G)==full_add([k1]G,G)",
          zkn_g1_384_eq(&P1_plus_G_full, &P1_plus_G_mixed, ctx));
    check("large: [k1]G+G==[k1+1]G",
          zkn_g1_384_eq(&P1_plus_G_full, &K1p1_G, ctx));

    /* neg([k1]G) + [k1]G == O */
    zkn_g1_384_t neg_P1, sum;
    zkn_g1_384_neg(&neg_P1, &P1, ctx);
    zkn_g1_384_add(&sum, &P1, &neg_P1, ctx);
    check("large: [k1]G+(-[k1]G)==O", zkn_g1_384_is_zero(&sum));
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("=== zkn_g1_384 test suite (BLS12-381 G1) ===\n");
#ifdef ZKN_MONT384_ASM
    printf("    backend: ARM Thumb-2 ASM (Fp layer)\n");
#else
    printf("    backend: portable C\n");
#endif

    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();

    test_generator(ctx);
    test_affine_roundtrip(ctx);
    test_infinity(ctx);
    test_negation(ctx);
    test_doubling(ctx);
    test_addition(ctx);
    test_mixed_add(ctx);
    test_scalar_mul(ctx);
    test_order(ctx);
    test_aliasing(ctx);

    /* ── NEW: large 32-byte scalar tests ── */
    test_scalar_mul_large(ctx);

    printf("\n=== Results: %d/%d passed ===\n",
           test_count - fail_count, test_count);

    return fail_count ? 1 : 0;
}

#endif /* ZKN_HOST_TESTS */
