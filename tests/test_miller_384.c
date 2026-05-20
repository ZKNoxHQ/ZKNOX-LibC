/*
 * test_miller_384.c — Algebraic property tests for the BLS12-381 Miller loop
 *
 * All tests work on the RAW Miller loop output (no final exponentiation).
 * Properties tested:
 *
 *   1. Identity:       ML(O, Q) = 1,  ML(P, O) = 1
 *   2. Negation G1:    ML(-P, Q) = ML(P, Q)^{-1}
 *   3. Negation G2:    ML(P, -Q) = conj(ML(P, Q))
 *   4. Linearity in P: ML(P1+P2, Q) = ML(P1, Q) · ML(P2, Q)  [EXACT]
 *   5. Scalar in P:    ML(kP, Q) = ML(P, Q)^k
 *   6. Consistency:    ML(P, Q)^2  via sqr vs mul
 *   7. Non-degeneracy: ML(G1, G2) ≠ 1
 *
 * Compile with your zkn_mont384, zkn_fp2_384, zkn_fp6_384, zkn_fp12_384,
 * zkn_g1_384, zkn_g2_384, and zkn_pairing_384 object files.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include <stdio.h>
#include <string.h>

#include "zkn_pairing_384.h"
#include "zkn_miller.h"

/* ── Helpers ───────────────────────────────────────────────────────── */

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int cond)
{
    if (cond) {
        printf("  [PASS] %s\n", name);
        g_pass++;
    } else {
        printf("  [FAIL] %s\n", name);
        g_fail++;
    }
}

static int fp12_is_one(const zkn_fp12_384_t *f, const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t one;
    zkn_fp12_384_one(&one, ctx);
    return zkn_fp12_384_eq(f, &one);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test 1 — Identity: ML(O, Q) = 1 and ML(P, O) = 1
 * ══════════════════════════════════════════════════════════════════════ */

static void test_identity(const zkn_mont_ctx384_t *ctx)
{
    printf("Test 1: Identity (point at infinity)\n");

    zkn_g1_384_t G1, O1;
    zkn_g2_384_t G2, O2;
    zkn_fp12_384_t f;

    zkn_g1_384_generator(&G1, ctx);
    zkn_g2_384_generator(&G2, ctx);
    zkn_g1_384_zero(&O1);
    zkn_g2_384_zero(&O2);

    zkn_miller_loop(&f, &O1, &G2, ctx);
    check("ML(O, G2) = 1", fp12_is_one(&f, ctx));

    zkn_miller_loop(&f, &G1, &O2, ctx);
    check("ML(G1, O) = 1", fp12_is_one(&f, ctx));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test 2 — Negation G1: ML(-P, Q) = ML(P, Q)^{-1}
 * ══════════════════════════════════════════════════════════════════════ */

static void test_negation_g1(const zkn_mont_ctx384_t *ctx)
{
    printf("Test 2: Negation in G1\n");

    zkn_g1_384_t G1, negG1;
    zkn_g2_384_t G2;
    zkn_fp12_384_t f, f_neg, f_inv, product;

    zkn_g1_384_generator(&G1, ctx);
    zkn_g2_384_generator(&G2, ctx);

    zkn_g1_384_neg(&negG1, &G1, ctx);

    zkn_miller_loop(&f, &G1, &G2, ctx);
    zkn_miller_loop(&f_neg, &negG1, &G2, ctx);

    /* f_inv = f^{-1} */
    zkn_fp12_384_inv(&f_inv, &f, ctx);

    check("ML(-P, Q) = ML(P, Q)^{-1}", zkn_fp12_384_eq(&f_neg, &f_inv));

    /* Alternative: product = f · f_neg should be 1 */
    zkn_fp12_384_mul(&product, &f, &f_neg, ctx);
    check("ML(P, Q) · ML(-P, Q) = 1", fp12_is_one(&product, ctx));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test 3 — Negation G2: ML(P, -Q) = conj(ML(P, Q))
 *
 *  For BLS12-381 with M-twist, negating Q (flipping Y in Fp2)
 *  propagates as Fp12 conjugation (w ↦ -w).
 * ══════════════════════════════════════════════════════════════════════ */

static void test_negation_g2(const zkn_mont_ctx384_t *ctx)
{
    printf("Test 3: Negation in G2\n");

    zkn_g1_384_t G1;
    zkn_g2_384_t G2, negG2;
    zkn_fp12_384_t f, f_neg, f_conj;

    zkn_g1_384_generator(&G1, ctx);
    zkn_g2_384_generator(&G2, ctx);

    zkn_g2_384_neg(&negG2, &G2, ctx);

    zkn_miller_loop(&f, &G1, &G2, ctx);
    zkn_miller_loop(&f_neg, &G1, &negG2, ctx);

    zkn_fp12_384_conjugate(&f_conj, &f, ctx);

    check("ML(P, -Q) = conj(ML(P, Q))", zkn_fp12_384_eq(&f_neg, &f_conj));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test 4 — Linearity in P (EXACT, no residue)
 *
 *  ML(P1 + P2, Q) = ML(P1, Q) · ML(P2, Q)
 *
 *  This is the most powerful test. Linearity in P is exact at the
 *  Miller loop level because P only appears in line evaluations
 *  (as an affine Fp scalar), not in the G2 loop variable T.
 * ══════════════════════════════════════════════════════════════════════ */

static void test_linearity_p(const zkn_mont_ctx384_t *ctx)
{
    printf("Test 4: Linearity in P (exact)\n");

    /*
     * Use non-trivial, unrelated scalars so P1 and P2 have
     * structurally independent coordinates (no common factors,
     * no doubling relationship). This exercises the full generality
     * of the addition formula and the line evaluation.
     *
     *   k1 = 0xDEAD = 57005
     *   k2 = 0xBEEF = 48879
     *   P1 = k1·G,  P2 = k2·G,  P_sum = (k1+k2)·G
     */
    static const uint8_t k1_be[] = { 0x00, 0x00, 0xDE, 0xAD };
    static const uint8_t k2_be[] = { 0x00, 0x00, 0xBE, 0xEF };
    static const uint8_t k_sum_be[] = { 0x00, 0x01, 0x9D, 0x9C };  /* 0xDEAD + 0xBEEF = 0x19D9C */

    zkn_g1_384_t G1, P1, P2, P_sum_add, P_sum_mul;
    zkn_g2_384_t G2;
    zkn_fp12_384_t f_sum, f1, f2, f_product;

    zkn_g1_384_generator(&G1, ctx);
    zkn_g2_384_generator(&G2, ctx);

    /* P1 = k1·G,  P2 = k2·G */
    zkn_g1_384_mul(&P1, &G1, k1_be, sizeof(k1_be), ctx);
    zkn_g1_384_mul(&P2, &G1, k2_be, sizeof(k2_be), ctx);

    /* P_sum via EC addition (what the test actually checks) */
    zkn_g1_384_add(&P_sum_add, &P1, &P2, ctx);

    /* Sanity: P_sum via scalar mul should match */
    zkn_g1_384_mul(&P_sum_mul, &G1, k_sum_be, sizeof(k_sum_be), ctx);
    check("G1 sanity: k1·G + k2·G = (k1+k2)·G",
          zkn_g1_384_eq(&P_sum_add, &P_sum_mul, ctx));

    /* LHS: ML(P1 + P2, Q) */
    zkn_miller_loop(&f_sum, &P_sum_add, &G2, ctx);

    /* RHS: ML(P1, Q) · ML(P2, Q) */
    zkn_miller_loop(&f1, &P1, &G2, ctx);
    zkn_miller_loop(&f2, &P2, &G2, ctx);
    zkn_fp12_384_mul(&f_product, &f1, &f2, ctx);

    check("ML(P1+P2, Q) = ML(P1, Q) · ML(P2, Q)  [k1=0xDEAD, k2=0xBEEF]",
          zkn_fp12_384_eq(&f_sum, &f_product));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test 5 — Scalar multiplication in P
 *
 *  ML(kP, Q) = ML(P, Q)^k
 *
 *  Corollary of linearity in P. We test k=2 and k=3.
 * ══════════════════════════════════════════════════════════════════════ */

static void test_scalar_p(const zkn_mont_ctx384_t *ctx)
{
    printf("Test 5: Scalar in P\n");

    /*
     * ML(k·P, Q) = ML(P, Q)^k
     *
     * Use k=0x1337 (4919) — large enough to exercise many bits,
     * not a power of two (so it's not just repeated doubling).
     *
     * Compute ML(P,Q)^k by repeated squaring on the Fp12 side,
     * independently of how k·P was computed on the EC side.
     */
    static const uint8_t k_be[] = { 0x13, 0x37 };

    zkn_g1_384_t G1, kG1;
    zkn_g2_384_t G2;
    zkn_fp12_384_t f1, fk, f1_pow;

    zkn_g1_384_generator(&G1, ctx);
    zkn_g2_384_generator(&G2, ctx);

    /* kG1 = k · G1 */
    zkn_g1_384_mul(&kG1, &G1, k_be, sizeof(k_be), ctx);

    /* LHS: ML(k·G1, Q) */
    zkn_miller_loop(&fk, &kG1, &G2, ctx);

    /* RHS: ML(G1, Q)^k via Fp12 exponentiation (square-and-multiply) */
    zkn_miller_loop(&f1, &G1, &G2, ctx);

    {
        /* f1_pow = f1^k, k = 0x1337 = 0b0001001100110111 (13 bits used) */
        uint16_t kval = 0x1337;
        int started = 0;
        int bit;

        zkn_fp12_384_one(&f1_pow, ctx);

        for (bit = 15; bit >= 0; bit--) {
            if (started) {
                zkn_fp12_384_sqr(&f1_pow, &f1_pow, ctx);
            }
            if ((kval >> bit) & 1) {
                if (!started) {
                    zkn_fp12_384_copy(&f1_pow, &f1);
                    started = 1;
                } else {
                    zkn_fp12_384_mul(&f1_pow, &f1_pow, &f1, ctx);
                }
            }
        }
    }

    check("ML(0x1337·P, Q) = ML(P, Q)^0x1337", zkn_fp12_384_eq(&fk, &f1_pow));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test 6 — Fp12 sqr consistency
 *
 *  Verify that sqr(f) == mul(f, f) for a non-trivial f.
 *  If this fails but linearity passes, the bug is in Fp12 sqr.
 * ══════════════════════════════════════════════════════════════════════ */

static void test_fp12_sqr_consistency(const zkn_mont_ctx384_t *ctx)
{
    printf("Test 6: Fp12 sqr vs mul consistency\n");

    zkn_g1_384_t G1;
    zkn_g2_384_t G2;
    zkn_fp12_384_t f, f_sqr, f_mul;

    zkn_g1_384_generator(&G1, ctx);
    zkn_g2_384_generator(&G2, ctx);

    zkn_miller_loop(&f, &G1, &G2, ctx);

    zkn_fp12_384_sqr(&f_sqr, &f, ctx);
    zkn_fp12_384_mul(&f_mul, &f, &f, ctx);

    check("sqr(ML(P,Q)) = mul(ML(P,Q), ML(P,Q))", zkn_fp12_384_eq(&f_sqr, &f_mul));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Test 7 — Non-degeneracy: ML(G1, G2) ≠ 1
 *
 *  The pairing of generators must be non-trivial.
 * ══════════════════════════════════════════════════════════════════════ */

static void test_non_degeneracy(const zkn_mont_ctx384_t *ctx)
{
    printf("Test 7: Non-degeneracy\n");

    zkn_g1_384_t G1;
    zkn_g2_384_t G2;
    zkn_fp12_384_t f;

    zkn_g1_384_generator(&G1, ctx);
    zkn_g2_384_generator(&G2, ctx);

    zkn_miller_loop(&f, &G1, &G2, ctx);

    check("ML(G1, G2) != 1", !fp12_is_one(&f, ctx));
}

/* ══════════════════════════════════════════════════════════════════════
 *  NEW Test 8 — Linearity and scalar tests with large (256-bit) scalars
 *
 *  ML(P1+P2, Q) = ML(P1, Q) · ML(P2, Q)
 *  ML(k·P, Q) = ML(P, Q)^k
 *
 *  Using scalars with full 32-byte entropy (≈ 256-bit) to stress the
 *  complete scalar-mul path rather than only low-bit patterns.
 * ══════════════════════════════════════════════════════════════════════ */

static void test_large_scalars(const zkn_mont_ctx384_t *ctx)
{
    printf("Test 8: Large (256-bit) scalars\n");

    /*
     * k1 = 0x12ab34cd56ef7890aabbccddeeff001122334455667788990011aabbccdd1234
     * k2 = 0x0fedcba987654321f0e1d2c3b4a59687564738291a0b1c2d3e4f5a6b7c8d9eff
     *
     * Both are well below r = 0x73eda753...00000001 (BLS12-381 subgroup order)
     * so the points are non-trivial.
     *
     * k_sum = k1 + k2 (computed below to avoid 256-bit overflow arithmetic here;
     * we instead verify the property via EC addition on the curve side).
     */
    static const uint8_t K1[32] = {
        0x12,0xab,0x34,0xcd,0x56,0xef,0x78,0x90,
        0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,
        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
        0x00,0x11,0xaa,0xbb,0xcc,0xdd,0x12,0x34
    };
    static const uint8_t K2[32] = {
        0x0f,0xed,0xcb,0xa9,0x87,0x65,0x43,0x21,
        0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,
        0x56,0x47,0x38,0x29,0x1a,0x0b,0x1c,0x2d,
        0x3e,0x4f,0x5a,0x6b,0x7c,0x8d,0x9e,0xff
    };

    zkn_g1_384_t G1, P1, P2, P_sum;
    zkn_g2_384_t G2;
    zkn_fp12_384_t f_sum, f1, f2, f_product;

    zkn_g1_384_generator(&G1, ctx);
    zkn_g2_384_generator(&G2, ctx);

    /* P1 = K1·G,  P2 = K2·G */
    zkn_g1_384_mul(&P1, &G1, K1, 32, ctx);
    zkn_g1_384_mul(&P2, &G1, K2, 32, ctx);

    check("large: [k1]G on curve", zkn_g1_384_on_curve(&P1, ctx));
    check("large: [k2]G on curve", zkn_g1_384_on_curve(&P2, ctx));

    /* P_sum = P1 + P2 (EC addition) */
    zkn_g1_384_add(&P_sum, &P1, &P2, ctx);

    /* LHS: ML(P1+P2, G2) */
    zkn_miller_loop(&f_sum, &P_sum, &G2, ctx);

    /* RHS: ML(P1, G2) · ML(P2, G2) */
    zkn_miller_loop(&f1, &P1, &G2, ctx);
    zkn_miller_loop(&f2, &P2, &G2, ctx);
    zkn_fp12_384_mul(&f_product, &f1, &f2, ctx);

    check("large: ML(P1+P2,Q)=ML(P1,Q)*ML(P2,Q)  [256-bit k1,k2]",
          zkn_fp12_384_eq(&f_sum, &f_product));

    /*
     * Scalar test: ML(k1·P1, G2) = ML(P1, G2)^k1
     * where P1 = k1·G is a "random" point.
     *
     * We pick a small scalar (3) applied to P1 (which itself came from
     * a 256-bit derivation), so the input to the Miller loop is
     * 3·(k1·G) — a genuinely large multiple of G.
     */
    uint8_t three_be[1] = {0x03};
    zkn_g1_384_t P1_x3;
    zkn_g1_384_mul(&P1_x3, &P1, three_be, 1, ctx);

    zkn_fp12_384_t f_P1, f_P1_x3, f_P1_cubed;
    zkn_miller_loop(&f_P1, &P1, &G2, ctx);
    zkn_miller_loop(&f_P1_x3, &P1_x3, &G2, ctx);

    /* ML(P1,Q)^3 via mul chain */
    zkn_fp12_384_mul(&f_P1_cubed, &f_P1, &f_P1, ctx);   /* ^2 */
    zkn_fp12_384_mul(&f_P1_cubed, &f_P1_cubed, &f_P1, ctx); /* ^3 */

    check("large: ML(3*(k1·G),Q)=ML(k1·G,Q)^3",
          zkn_fp12_384_eq(&f_P1_x3, &f_P1_cubed));

    /*
     * Non-degeneracy: ML(P1, G2) != ML(P2, G2)
     * (different G1 inputs → different Fp12 outputs with overwhelming probability)
     */
    check("large: ML(P1,Q) != ML(P2,Q)",
          !zkn_fp12_384_eq(&f1, &f2));

    /*
     * Bilinearity consistency: ML(-P1, G2) · ML(P1, G2) = 1
     */
    zkn_g1_384_t neg_P1;
    zkn_g1_384_neg(&neg_P1, &P1, ctx);
    zkn_fp12_384_t f_neg_P1, product;
    zkn_miller_loop(&f_neg_P1, &neg_P1, &G2, ctx);
    zkn_fp12_384_mul(&product, &f_P1, &f_neg_P1, ctx);
    zkn_fp12_384_t one;
    zkn_fp12_384_one(&one, ctx);
    check("large: ML(P1,Q)*ML(-P1,Q)=1", zkn_fp12_384_eq(&product, &one));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Main
 * ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();

    printf("═══════════════════════════════════════════════════\n");
    printf("  Miller loop algebraic property tests (BLS12-381)\n");
    printf("  Raw ML output — no final exponentiation\n");
    printf("═══════════════════════════════════════════════════\n\n");

    test_identity(ctx);
    printf("\n");

    test_negation_g1(ctx);
    printf("\n");

    test_negation_g2(ctx);
    printf("\n");

    test_linearity_p(ctx);
    printf("\n");

    test_scalar_p(ctx);
    printf("\n");

    test_fp12_sqr_consistency(ctx);
    printf("\n");

    test_non_degeneracy(ctx);
    printf("\n");

    /* ── NEW ── */
    test_large_scalars(ctx);
    printf("\n");

    printf("═══════════════════════════════════════════════════\n");
    printf("  Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("═══════════════════════════════════════════════════\n");

    return g_fail ? 1 : 0;
}
