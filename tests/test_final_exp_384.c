/*
 * test_final_exp_384.c — Algebraic property tests for zkn_final_exp
 *
 * Tests:
 *   T1. fe(1)   = 1              (identity)
 *   T2. fe(a·b) = fe(a)·fe(b)   (multiplicativity)
 *   T3. fe(a)·conj(fe(a)) = 1   (output in cyclotomic subgroup GT)
 *   T4. fe(a⁻¹) = fe(a)⁻¹      (inverse)
 *   T5. fe(a²)  = fe(a)²        (squaring consistency)
 *   T6. fe(conj(a)) = conj(fe(a)) (conjugation commutes)
 *   T7. fe(a³)   = fe(a)³       (power consistency, n=3)
 *   T8. r == f aliasing         (in-place safety)
 *
 * Test vectors: all 12 Fp384 components chosen as p-k (k=1..24),
 * where p is the BLS12-381 base prime. These are the largest valid
 * field elements and stress all modular reduction paths:
 *   - every add triggers a subtraction (a+b > p)
 *   - every mul produces a near-2p product before Montgomery reduction
 *
 * p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624
 *       1eabfffeb153ffffb9feffffffffaaab
 *
 * NOTE: fe(fe(a)) = fe(a) is NOT a valid property.
 *   fe(x) = x^e with e = (p^12-1)/r. For fe(fe(a)) = fe(a) we would need
 *   e ≡ 1 mod r, i.e. (p^12-1)/r ≡ 1 mod r — not true for BLS12-381.
 *   fe(a) ∈ GT has order dividing r, so fe(a)^r = 1, but a second
 *   application of fe computes fe(a)^e mod r ≠ fe(a) in general.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include <stdio.h>
#include <string.h>

#include "zkn_final_exp_384.h"
#include "zkn_mont384.h"
#include "zkn_fp12_384.h"

/* ── Test infrastructure ─────────────────────────────────────────── */

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(label, cond)                          \
    do {                                            \
        if (cond) {                                 \
            printf("  [PASS] %s\n", label);         \
            g_pass++;                               \
        } else {                                    \
            printf("  [FAIL] %s\n", label);         \
            g_fail++;                               \
        }                                           \
    } while (0)

/* ── BLS12-381 prime p (big-endian) ──────────────────────────────
 *
 * p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624
 *       1eabfffeb153ffffb9feffffffffaaab
 *
 * Common prefix for all 48-byte vectors (bytes 0..46).
 * Byte [47] = 0xab - k  for p-k  (k=1..24, no borrow since 0xab=171>24).
 */
#define P48_PREFIX \
    0x1a,0x01,0x11,0xea,0x39,0x7f,0xe6,0x9a, \
    0x4b,0x1b,0xa7,0xb6,0x43,0x4b,0xac,0xd7, \
    0x64,0x77,0x4b,0x84,0xf3,0x85,0x12,0xbf, \
    0x67,0x30,0xd2,0xa0,0xf6,0xb0,0xf6,0x24, \
    0x1e,0xab,0xff,0xfe,0xb1,0x53,0xff,0xff, \
    0xb9,0xfe,0xff,0xff,0xff,0xff,0xaa

#define Pmk(k) { P48_PREFIX, (uint8_t)(0xab - (k)) }

/*
 * A: 12 components = p-1 .. p-12
 * B: 12 components = p-13 .. p-24
 * All are maximum-sized valid BLS12-381 field elements.
 */
static const uint8_t RA[12][48] = {
    Pmk(1),  Pmk(2),  Pmk(3),  Pmk(4),
    Pmk(5),  Pmk(6),  Pmk(7),  Pmk(8),
    Pmk(9),  Pmk(10), Pmk(11), Pmk(12)
};

static const uint8_t RB[12][48] = {
    Pmk(13), Pmk(14), Pmk(15), Pmk(16),
    Pmk(17), Pmk(18), Pmk(19), Pmk(20),
    Pmk(21), Pmk(22), Pmk(23), Pmk(24)
};

/* ── Fp12 construction helper ────────────────────────────────────── */

/*
 * Build Fp12 from 12 big-endian Fp384 byte arrays, converting to Montgomery.
 * Layout: [c0.c0.c0, c0.c0.c1, c0.c1.c0, c0.c1.c1,
 *          c0.c2.c0, c0.c2.c1, c1.c0.c0, c1.c0.c1,
 *          c1.c1.c0, c1.c1.c1, c1.c2.c0, c1.c2.c1]
 */
static void fp12_from_be(zkn_fp12_384_t *r,
                         const uint8_t coeff[12][48],
                         const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t tmp;

#define LOAD(dst, idx) \
    do { zkn_fe384_from_be(tmp, coeff[idx]); zkn_to_mont_384((dst), tmp, ctx); } while(0)

    LOAD(r->c0.c0.c0,  0);  LOAD(r->c0.c0.c1,  1);
    LOAD(r->c0.c1.c0,  2);  LOAD(r->c0.c1.c1,  3);
    LOAD(r->c0.c2.c0,  4);  LOAD(r->c0.c2.c1,  5);
    LOAD(r->c1.c0.c0,  6);  LOAD(r->c1.c0.c1,  7);
    LOAD(r->c1.c1.c0,  8);  LOAD(r->c1.c1.c1,  9);
    LOAD(r->c1.c2.c0, 10);  LOAD(r->c1.c2.c1, 11);

#undef LOAD
}

/* ── Individual tests ────────────────────────────────────────────── */

/* T1 — fe(1) = 1 */
static void test_fe_identity(const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t one, result, expected;
    zkn_fp12_384_one(&one,      ctx);
    zkn_fp12_384_one(&expected, ctx);
    zkn_final_exp(&result, &one, ctx);
    CHECK("T1  fe(1) = 1", zkn_fp12_384_eq(&result, &expected));
}

/* T2 — fe(a·b) = fe(a)·fe(b) */
static void test_fe_multiplicative(const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t A, B, AB, feA, feB, feAB_direct, feAB_product;

    fp12_from_be(&A, RA, ctx);
    fp12_from_be(&B, RB, ctx);
    zkn_fp12_384_mul(&AB, &A, &B, ctx);

    zkn_final_exp(&feA,         &A,  ctx);
    zkn_final_exp(&feB,         &B,  ctx);
    zkn_final_exp(&feAB_direct, &AB, ctx);
    zkn_fp12_384_mul(&feAB_product, &feA, &feB, ctx);

    CHECK("T2  fe(a·b) = fe(a)·fe(b)", zkn_fp12_384_eq(&feAB_direct, &feAB_product));
}

/* T3a/b — fe(x) in cyclotomic subgroup: fe(x)·conj(fe(x)) = 1 */
static void test_fe_cyclotomic(const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t X, feX, conjX, product, one;
    zkn_fp12_384_one(&one, ctx);

    fp12_from_be(&X, RA, ctx);
    zkn_final_exp(&feX, &X, ctx);
    zkn_fp12_384_conjugate(&conjX, &feX, ctx);
    zkn_fp12_384_mul(&product, &feX, &conjX, ctx);
    CHECK("T3a fe(A) in GΦ₆: fe(A)·conj(fe(A)) = 1", zkn_fp12_384_eq(&product, &one));

    fp12_from_be(&X, RB, ctx);
    zkn_final_exp(&feX, &X, ctx);
    zkn_fp12_384_conjugate(&conjX, &feX, ctx);
    zkn_fp12_384_mul(&product, &feX, &conjX, ctx);
    CHECK("T3b fe(B) in GΦ₆: fe(B)·conj(fe(B)) = 1", zkn_fp12_384_eq(&product, &one));
}

/* T4 — fe(a⁻¹) = fe(a)⁻¹ */
static void test_fe_inverse(const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t A, Ainv, feA, feAinv, feA_inv, product, one;

    fp12_from_be(&A, RA, ctx);
    zkn_fp12_384_inv(&Ainv, &A, ctx);

    zkn_final_exp(&feA,    &A,    ctx);
    zkn_final_exp(&feAinv, &Ainv, ctx);
    zkn_fp12_384_inv(&feA_inv, &feA, ctx);

    CHECK("T4a fe(a⁻¹) = fe(a)⁻¹",  zkn_fp12_384_eq(&feAinv, &feA_inv));

    zkn_fp12_384_mul(&product, &feA, &feAinv, ctx);
    zkn_fp12_384_one(&one, ctx);
    CHECK("T4b fe(a)·fe(a⁻¹) = 1",   zkn_fp12_384_eq(&product, &one));
}

/* T5 — fe(a²) = fe(a)² */
static void test_fe_squaring(const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t A, A2, feA, feA2_direct, feA_sqr;

    fp12_from_be(&A, RA, ctx);
    zkn_fp12_384_mul(&A2, &A, &A, ctx);

    zkn_final_exp(&feA,          &A,  ctx);
    zkn_final_exp(&feA2_direct,  &A2, ctx);
    zkn_fp12_384_mul(&feA_sqr, &feA, &feA, ctx);

    CHECK("T5  fe(a²) = fe(a)²", zkn_fp12_384_eq(&feA2_direct, &feA_sqr));
}

/* T6 — fe(conj(a)) = conj(fe(a)) */
static void test_fe_conjugate_commutes(const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t A, conjA, feA, feconjA, conjfeA;

    fp12_from_be(&A, RA, ctx);
    zkn_fp12_384_conjugate(&conjA, &A, ctx);

    zkn_final_exp(&feA,    &A,     ctx);
    zkn_final_exp(&feconjA, &conjA, ctx);
    zkn_fp12_384_conjugate(&conjfeA, &feA, ctx);

    CHECK("T6  fe(conj(a)) = conj(fe(a))", zkn_fp12_384_eq(&feconjA, &conjfeA));
}

/* T7 — fe(a³) = fe(a)³  (power consistency, n=3)
 *
 * Follows from multiplicativity but tests a different code path:
 * a³ = a·a·a involves two full Fp12 multiplications before final_exp,
 * exercising deeper Montgomery reduction chains than T2 (which uses a·b).
 * Also cross-validates that fe is a group homomorphism on Fp12*.
 *
 * NOTE: fe(fe(a)) = fe(a) is NOT a valid property for BLS12-381.
 *   fe(x) = x^e with e = (p^12-1)/r. A second application gives fe(a)^e,
 *   and e ≡ 1 mod r does not hold — fe is not idempotent in general.
 */
static void test_fe_power_consistency(const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t A, A3, feA, feA3_direct, feA3_product;

    fp12_from_be(&A, RA, ctx);

    /* A³ = A·A·A */
    zkn_fp12_384_mul(&A3, &A, &A, ctx);
    zkn_fp12_384_mul(&A3, &A3, &A, ctx);

    zkn_final_exp(&feA,          &A,  ctx);
    zkn_final_exp(&feA3_direct,  &A3, ctx);

    /* fe(A)³ = fe(A)·fe(A)·fe(A) */
    zkn_fp12_384_mul(&feA3_product, &feA, &feA,         ctx);
    zkn_fp12_384_mul(&feA3_product, &feA3_product, &feA, ctx);

    CHECK("T7  fe(a³) = fe(a)³  (power n=3)", zkn_fp12_384_eq(&feA3_direct, &feA3_product));
}

/* T8 — in-place aliasing: fe(&f, &f) == fe(&out, &f) */
static void test_fe_aliasing(const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t A, feA_normal, feA_inplace;

    fp12_from_be(&A, RA, ctx);
    zkn_final_exp(&feA_normal, &A, ctx);

    fp12_from_be(&feA_inplace, RA, ctx);
    zkn_final_exp(&feA_inplace, &feA_inplace, ctx);  /* r == f */

    CHECK("T8  fe(f) in-place == fe(f) normal", zkn_fp12_384_eq(&feA_normal, &feA_inplace));
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void)
{
    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();

    printf("── zkn_final_exp_384 algebraic property tests ──\n");
    printf("   vectors: A = (p-1..p-12),  B = (p-13..p-24)\n\n");

    test_fe_identity(ctx);           printf("\n");
    test_fe_multiplicative(ctx);     printf("\n");
    test_fe_cyclotomic(ctx);         printf("\n");
    test_fe_inverse(ctx);            printf("\n");
    test_fe_squaring(ctx);           printf("\n");
    test_fe_conjugate_commutes(ctx); printf("\n");
    test_fe_power_consistency(ctx);  printf("\n");
    test_fe_aliasing(ctx);

    printf("\n──────────────────────────────────────────────\n");
    printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("──────────────────────────────────────────────\n");

    return (g_fail == 0) ? 0 : 1;
}
