/*
 * test_g2_384.c — Test suite for zkn_g2_384 (BLS12-381 G2 twist curve)
 *
 * Tests:
 *   - Generator on curve
 *   - Affine round-trip
 *   - Infinity / zero handling
 *   - Doubling, addition, mixed addition
 *   - Negation
 *   - Scalar mul: known small multiples
 *   - Order test: [r]·G2 = O
 *   - Associativity / commutativity
 *   - Aliasing
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifdef ZKN_HOST_TESTS

#include <stdio.h>
#include <string.h>
#include "zkn_g2_384.h"

static int test_count = 0;
static int fail_count = 0;

static void check(const char *name, int cond)
{
    test_count++;
    if (cond) printf("[PASS] %s\n", name);
    else      { printf("[FAIL] %s\n", name); fail_count++; }
}

/* BLS12-381 subgroup order r */
static const uint8_t BLS12_381_R_BE[32] = {
    0x73,0xed,0xa7,0x53,0x29,0x9d,0x7d,0x48,
    0x33,0x39,0xd8,0x08,0x09,0xa1,0xd8,0x05,
    0x53,0xbd,0xa4,0x02,0xff,0xfe,0x5b,0xfe,
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01
};

/* Helper: make Fp2 from two big-endian byte arrays (normal form) */
static void fp2_from_be(zkn_fp2_384_t *r,
                        const uint8_t c0_be[48],
                        const uint8_t c1_be[48])
{
    zkn_fe384_from_be(r->c0, c0_be);
    zkn_fe384_from_be(r->c1, c1_be);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Known vectors — G2 generator (verify round-trip)
 * ══════════════════════════════════════════════════════════════════════ */

static const uint8_t G2_GEN_X0[48] = {
    0x02,0x4a,0xa2,0xb2,0xf0,0x8f,0x0a,0x91,
    0x26,0x08,0x05,0x27,0x2d,0xc5,0x10,0x51,
    0xc6,0xe4,0x7a,0xd4,0xfa,0x40,0x3b,0x02,
    0xb4,0x51,0x0b,0x64,0x7a,0xe3,0xd1,0x77,
    0x0b,0xac,0x03,0x26,0xa8,0x05,0xbb,0xef,
    0xd4,0x80,0x56,0xc8,0xc1,0x21,0xbd,0xb8
};
static const uint8_t G2_GEN_X1[48] = {
    0x13,0xe0,0x2b,0x60,0x52,0x71,0x9f,0x60,
    0x7d,0xac,0xd3,0xa0,0x88,0x27,0x4f,0x65,
    0x59,0x6b,0xd0,0xd0,0x99,0x20,0xb6,0x1a,
    0xb5,0xda,0x61,0xbb,0xdc,0x7f,0x50,0x49,
    0x33,0x4c,0xf1,0x12,0x13,0x94,0x5d,0x57,
    0xe5,0xac,0x7d,0x05,0x5d,0x04,0x2b,0x7e
};
static const uint8_t G2_GEN_Y0[48] = {
    0x0c,0xe5,0xd5,0x27,0x72,0x7d,0x6e,0x11,
    0x8c,0xc9,0xcd,0xc6,0xda,0x2e,0x35,0x1a,
    0xad,0xfd,0x9b,0xaa,0x8c,0xbd,0xd3,0xa7,
    0x6d,0x42,0x9a,0x69,0x51,0x60,0xd1,0x2c,
    0x92,0x3a,0xc9,0xcc,0x3b,0xac,0xa2,0x89,
    0xe1,0x93,0x54,0x86,0x08,0xb8,0x28,0x01
};
static const uint8_t G2_GEN_Y1[48] = {
    0x06,0x06,0xc4,0xa0,0x2e,0xa7,0x34,0xcc,
    0x32,0xac,0xd2,0xb0,0x2b,0xc2,0x8b,0x99,
    0xcb,0x3e,0x28,0x7e,0x85,0xa7,0x63,0xaf,
    0x26,0x74,0x92,0xab,0x57,0x2e,0x99,0xab,
    0x3f,0x37,0x0d,0x27,0x5c,0xec,0x1d,0xa1,
    0xaa,0xa9,0x07,0x5f,0xf0,0x5f,0x79,0xbe
};

/*
 * [2]G2 affine (computed and verified: dbl(G)==G+G, [r]G=O, on_curve all pass)
 * x0 = 0x1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053
 * x1 = 0x0a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577
 * y0 = 0x0468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899
 * y1 = 0x0f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf3
 */
static const uint8_t G2_2X0[48] = {
    0x16,0x38,0x53,0x39,0x57,0xd5,0x40,0xa9,
    0xd2,0x37,0x0f,0x17,0xcc,0x7e,0xd5,0x86,
    0x3b,0xc0,0xb9,0x95,0xb8,0x82,0x5e,0x0e,
    0xe1,0xea,0x1e,0x1e,0x4d,0x00,0xdb,0xae,
    0x81,0xf1,0x4b,0x0b,0xf3,0x61,0x1b,0x78,
    0xc9,0x52,0xaa,0xca,0xb8,0x27,0xa0,0x53
};
static const uint8_t G2_2X1[48] = {
    0x0a,0x4e,0xde,0xf9,0xc1,0xed,0x7f,0x72,
    0x9f,0x52,0x0e,0x47,0x73,0x0a,0x12,0x4f,
    0xd7,0x06,0x62,0xa9,0x04,0xba,0x10,0x74,
    0x72,0x81,0x14,0xd1,0x03,0x1e,0x15,0x72,
    0xc6,0xc8,0x86,0xf6,0xb5,0x7e,0xc7,0x2a,
    0x61,0x78,0x28,0x8c,0x47,0xc3,0x35,0x77
};
static const uint8_t G2_2Y0[48] = {
    0x04,0x68,0xfb,0x44,0x0d,0x82,0xb0,0x63,
    0x0a,0xeb,0x8d,0xca,0x2b,0x52,0x56,0x78,
    0x9a,0x66,0xda,0x69,0xbf,0x91,0x00,0x9c,
    0xbf,0xe6,0xbd,0x22,0x1e,0x47,0xaa,0x8a,
    0xe8,0x8d,0xec,0xe9,0x76,0x4b,0xf3,0xbd,
    0x99,0x9d,0x95,0xd7,0x1e,0x4c,0x98,0x99
};
static const uint8_t G2_2Y1[48] = {
    0x0f,0x6d,0x45,0x52,0xfa,0x65,0xdd,0x26,
    0x38,0xb3,0x61,0x54,0x3f,0x88,0x71,0x36,
    0xa4,0x32,0x53,0xd9,0xc6,0x6c,0x41,0x16,
    0x97,0x00,0x3f,0x7a,0x13,0xc3,0x08,0xf5,
    0x42,0x2e,0x1a,0xa0,0xa5,0x9c,0x89,0x67,
    0xac,0xde,0xfd,0x8b,0x6e,0x36,0xcc,0xf3
};

/* ══════════════════════════════════════════════════════════════════════
 *  Tests
 * ══════════════════════════════════════════════════════════════════════ */

static void test_generator(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 generator ---\n");

    zkn_g2_384_t G;
    zkn_g2_384_generator(&G, ctx);

    check("G2 on curve", zkn_g2_384_on_curve(&G, ctx));
    check("G2 not zero", !zkn_g2_384_is_zero(&G));
}

static void test_affine_roundtrip(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 affine round-trip ---\n");

    zkn_g2_384_t G;
    zkn_g2_384_generator(&G, ctx);

    /* to_affine now returns normal (non-Montgomery) Fp2 values */
    zkn_fp2_384_t ax, ay;
    zkn_g2_384_to_affine(&ax, &ay, &G, ctx);

    /* Compare directly with known bytes (both are normal form) */
    zkn_fp2_384_t exp_x, exp_y;
    fp2_from_be(&exp_x, G2_GEN_X0, G2_GEN_X1);
    fp2_from_be(&exp_y, G2_GEN_Y0, G2_GEN_Y1);

    check("gen x0 matches", zkn_fe384_eq(ax.c0, exp_x.c0));
    check("gen x1 matches", zkn_fe384_eq(ax.c1, exp_x.c1));
    check("gen y0 matches", zkn_fe384_eq(ay.c0, exp_y.c0));
    check("gen y1 matches", zkn_fe384_eq(ay.c1, exp_y.c1));

    /* Round-trip: from_affine(to_affine(G)) == G
     * Both functions now handle Montgomery conversion internally:
     *   to_affine  → normal form
     *   from_affine → converts to Montgomery */
    zkn_g2_384_t G2;
    zkn_g2_384_from_affine(&G2, &ax, &ay, ctx);
    check("round-trip eq", zkn_g2_384_eq(&G, &G2, ctx));
}

static void test_infinity(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 infinity ---\n");

    zkn_g2_384_t O;
    zkn_g2_384_zero(&O);
    check("O is zero", zkn_g2_384_is_zero(&O));
    check("O on curve", zkn_g2_384_on_curve(&O, ctx));

    zkn_g2_384_t G;
    zkn_g2_384_generator(&G, ctx);

    zkn_g2_384_t r;
    zkn_g2_384_add(&r, &G, &O, ctx);
    check("G+O=G", zkn_g2_384_eq(&r, &G, ctx));

    zkn_g2_384_add(&r, &O, &G, ctx);
    check("O+G=G", zkn_g2_384_eq(&r, &G, ctx));

    zkn_g2_384_add(&r, &O, &O, ctx);
    check("O+O=O", zkn_g2_384_is_zero(&r));

    zkn_g2_384_dbl(&r, &O, ctx);
    check("dbl(O)=O", zkn_g2_384_is_zero(&r));
}

static void test_negation(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 negation ---\n");

    zkn_g2_384_t G, negG, r;
    zkn_g2_384_generator(&G, ctx);
    zkn_g2_384_neg(&negG, &G, ctx);

    check("-G on curve", zkn_g2_384_on_curve(&negG, ctx));
    check("-G != G", !zkn_g2_384_eq(&negG, &G, ctx));

    zkn_g2_384_add(&r, &G, &negG, ctx);
    check("G+(-G)=O", zkn_g2_384_is_zero(&r));

    zkn_g2_384_t negNegG;
    zkn_g2_384_neg(&negNegG, &negG, ctx);
    check("-(-G)=G", zkn_g2_384_eq(&negNegG, &G, ctx));
}

static void test_doubling(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 doubling ---\n");

    zkn_g2_384_t G;
    zkn_g2_384_generator(&G, ctx);

    zkn_g2_384_t dblG;
    zkn_g2_384_dbl(&dblG, &G, ctx);
    check("[2]G2 on curve", zkn_g2_384_on_curve(&dblG, ctx));

    /* Verify [2]G2 affine against known vector */
    zkn_fp2_384_t ax, ay;
    zkn_g2_384_to_affine(&ax, &ay, &dblG, ctx);

    zkn_fp2_384_t exp_x, exp_y;
    fp2_from_be(&exp_x, G2_2X0, G2_2X1);
    fp2_from_be(&exp_y, G2_2Y0, G2_2Y1);

    check("[2]G2.x0 matches", zkn_fe384_eq(ax.c0, exp_x.c0));
    check("[2]G2.x1 matches", zkn_fe384_eq(ax.c1, exp_x.c1));
    check("[2]G2.y0 matches", zkn_fe384_eq(ay.c0, exp_y.c0));
    check("[2]G2.y1 matches", zkn_fe384_eq(ay.c1, exp_y.c1));

    /* dbl(G) == G + G */
    zkn_g2_384_t addGG;
    zkn_g2_384_add(&addGG, &G, &G, ctx);
    check("dbl(G)==G+G", zkn_g2_384_eq(&dblG, &addGG, ctx));
}

static void test_addition(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 addition ---\n");

    zkn_g2_384_t G;
    zkn_g2_384_generator(&G, ctx);

    zkn_g2_384_t G2, G3;
    zkn_g2_384_dbl(&G2, &G, ctx);
    zkn_g2_384_add(&G3, &G2, &G, ctx);
    check("[3]G2 on curve", zkn_g2_384_on_curve(&G3, ctx));

    /* Commutativity */
    zkn_g2_384_t G3b;
    zkn_g2_384_add(&G3b, &G, &G2, ctx);
    check("[3]G2 commutative", zkn_g2_384_eq(&G3, &G3b, ctx));

    /* [4]G = [3]G + G == dbl([2]G) */
    zkn_g2_384_t G4a, G4b;
    zkn_g2_384_add(&G4a, &G3, &G, ctx);
    zkn_g2_384_dbl(&G4b, &G2, ctx);
    check("[4]G2: two ways", zkn_g2_384_eq(&G4a, &G4b, ctx));

    /* Associativity */
    zkn_g2_384_t lhs, rhs, t;
    zkn_g2_384_add(&t, &G, &G2, ctx);
    zkn_g2_384_add(&lhs, &t, &G3, ctx);
    zkn_g2_384_add(&t, &G2, &G3, ctx);
    zkn_g2_384_add(&rhs, &G, &t, ctx);
    check("associativity", zkn_g2_384_eq(&lhs, &rhs, ctx));
}

static void test_mixed_add(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 mixed addition ---\n");

    zkn_g2_384_t G;
    zkn_g2_384_generator(&G, ctx);

    zkn_g2_384_t G2;
    zkn_g2_384_dbl(&G2, &G, ctx);

    zkn_g2_384_t r_mixed, r_full;
    zkn_g2_384_add_mixed(&r_mixed, &G2, &G, ctx);
    zkn_g2_384_add(&r_full, &G2, &G, ctx);
    check("mixed==full [3]G2", zkn_g2_384_eq(&r_mixed, &r_full, ctx));

    zkn_g2_384_t O;
    zkn_g2_384_zero(&O);
    zkn_g2_384_add_mixed(&r_mixed, &O, &G, ctx);
    check("mixed: O+G=G", zkn_g2_384_eq(&r_mixed, &G, ctx));
}

static void test_scalar_mul(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 scalar mul ---\n");

    zkn_g2_384_t G;
    zkn_g2_384_generator(&G, ctx);

    /* [1]·G = G */
    uint8_t one_be[1] = {0x01};
    zkn_g2_384_t r;
    zkn_g2_384_mul(&r, &G, one_be, 1, ctx);
    check("[1]G2=G", zkn_g2_384_eq(&r, &G, ctx));

    /* [2]·G == dbl(G) */
    uint8_t two_be[1] = {0x02};
    zkn_g2_384_t dblG;
    zkn_g2_384_dbl(&dblG, &G, ctx);
    zkn_g2_384_mul(&r, &G, two_be, 1, ctx);
    check("[2]G2==dbl(G)", zkn_g2_384_eq(&r, &dblG, ctx));

    /* [3]·G */
    uint8_t three_be[1] = {0x03};
    zkn_g2_384_t G3;
    zkn_g2_384_add(&G3, &dblG, &G, ctx);
    zkn_g2_384_mul(&r, &G, three_be, 1, ctx);
    check("[3]G2==G2+G", zkn_g2_384_eq(&r, &G3, ctx));

    /* [0]·G = O */
    uint8_t zero_be[1] = {0x00};
    zkn_g2_384_mul(&r, &G, zero_be, 1, ctx);
    check("[0]G2=O", zkn_g2_384_is_zero(&r));

    /* [7]G on curve */
    uint8_t seven_be[1] = {0x07};
    zkn_g2_384_t G7;
    zkn_g2_384_mul(&G7, &G, seven_be, 1, ctx);
    check("[7]G2 on curve", zkn_g2_384_on_curve(&G7, ctx));
}

static void test_order(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 order ---\n");

    zkn_g2_384_t G;
    zkn_g2_384_generator(&G, ctx);

    /* [r]·G = O */
    zkn_g2_384_t r;
    zkn_g2_384_mul(&r, &G, BLS12_381_R_BE, 32, ctx);
    check("[r]G2=O", zkn_g2_384_is_zero(&r));

    /* [r-1]·G = -G */
    uint8_t rm1[32];
    memcpy(rm1, BLS12_381_R_BE, 32);
    rm1[31] -= 1;

    zkn_g2_384_t rm1G;
    zkn_g2_384_mul(&rm1G, &G, rm1, 32, ctx);

    zkn_g2_384_t negG;
    zkn_g2_384_neg(&negG, &G, ctx);
    check("[r-1]G2=-G", zkn_g2_384_eq(&rm1G, &negG, ctx));
}

static void test_aliasing(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 aliasing ---\n");

    zkn_g2_384_t G;
    zkn_g2_384_generator(&G, ctx);

    zkn_g2_384_t expected, alias;

    /* dbl in-place */
    zkn_g2_384_dbl(&expected, &G, ctx);
    zkn_g2_384_copy(&alias, &G);
    zkn_g2_384_dbl(&alias, &alias, ctx);
    check("dbl(r,r)", zkn_g2_384_eq(&alias, &expected, ctx));

    /* add in-place */
    zkn_g2_384_t G2;
    zkn_g2_384_dbl(&G2, &G, ctx);
    zkn_g2_384_add(&expected, &G2, &G, ctx);
    zkn_g2_384_copy(&alias, &G2);
    zkn_g2_384_add(&alias, &alias, &G, ctx);
    check("add(r,r,b)", zkn_g2_384_eq(&alias, &expected, ctx));

    /* neg in-place */
    zkn_g2_384_neg(&expected, &G, ctx);
    zkn_g2_384_copy(&alias, &G);
    zkn_g2_384_neg(&alias, &alias, ctx);
    check("neg(r,r)", zkn_g2_384_eq(&alias, &expected, ctx));
}

static void test_scalar_mul_large(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- G2 scalar mul (large 32-byte scalars) ---\n");

    zkn_g2_384_t G;
    zkn_g2_384_generator(&G, ctx);

    /*
     * Same scalars K1, K2, K_SUM as in test_g1_384.c
     * K1 + K2 must equal K_SUM exactly (no overflow).
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
    static const uint8_t K_SUM[32] = {
        0x22,0x22,0x22,0x22,0x18,0x11,0x11,0x10,
        0x30,0x50,0x70,0x90,0xb0,0xd0,0xf1,0x11,
        0x24,0x26,0x28,0x2a,0x2c,0x2d,0x1f,0x21,
        0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x10
    };

    zkn_g2_384_t P1, P2, P_sum_mul, P_sum_add;

    zkn_g2_384_mul(&P1, &G, K1, 32, ctx);
    zkn_g2_384_mul(&P2, &G, K2, 32, ctx);

    check("large: [k1]G2 on curve", zkn_g2_384_on_curve(&P1, ctx));
    check("large: [k2]G2 on curve", zkn_g2_384_on_curve(&P2, ctx));
    check("large: [k1]G2 != O",    !zkn_g2_384_is_zero(&P1));
    check("large: [k2]G2 != O",    !zkn_g2_384_is_zero(&P2));

    /* [k1]G + [k2]G == [(k1+k2)]G */
    zkn_g2_384_add(&P_sum_add, &P1, &P2, ctx);
    zkn_g2_384_mul(&P_sum_mul, &G, K_SUM, 32, ctx);
    check("large: [k1]G2+[k2]G2==[k1+k2]G2",
          zkn_g2_384_eq(&P_sum_add, &P_sum_mul, ctx));

    /* 2·[k1]G == dbl([k1]G) */
    zkn_g2_384_t dbl_P1;
    zkn_g2_384_dbl(&dbl_P1, &P1, ctx);

    uint8_t TWO_K1[33] = {0};
    uint32_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint32_t s = (uint32_t)K1[i] * 2 + carry;
        TWO_K1[i + 1] = (uint8_t)(s & 0xFF);
        carry = s >> 8;
    }
    TWO_K1[0] = (uint8_t)carry;
    int offset = (TWO_K1[0] == 0) ? 1 : 0;
    zkn_g2_384_t two_k1_G;
    zkn_g2_384_mul(&two_k1_G, &G, TWO_K1 + offset, 33 - offset, ctx);
    check("large: 2*[k1]G2==dbl([k1]G2)",
          zkn_g2_384_eq(&two_k1_G, &dbl_P1, ctx));

    /* mixed_add([k1]G, G) == full_add([k1]G, G) */
    zkn_g2_384_t P1_plus_G_full, P1_plus_G_mixed;
    zkn_g2_384_add(&P1_plus_G_full, &P1, &G, ctx);
    zkn_g2_384_add_mixed(&P1_plus_G_mixed, &P1, &G, ctx);
    check("large: mixed_add([k1]G2,G2)==full",
          zkn_g2_384_eq(&P1_plus_G_full, &P1_plus_G_mixed, ctx));

    /* neg([k1]G) + [k1]G == O */
    zkn_g2_384_t neg_P1, sum;
    zkn_g2_384_neg(&neg_P1, &P1, ctx);
    zkn_g2_384_add(&sum, &P1, &neg_P1, ctx);
    check("large: [k1]G2+(-[k1]G2)==O", zkn_g2_384_is_zero(&sum));
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("=== zkn_g2_384 test suite (BLS12-381 G2) ===\n");
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
