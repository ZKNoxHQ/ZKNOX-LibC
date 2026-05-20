/*
 * test_fp12_384.c — Test suite for zkn_fp12_384 (Fp12 = Fp6[w]/(w²−v))
 *
 * Tests include:
 *   - Constructors / equality
 *   - Add / sub / neg / conjugate
 *   - Mul (identity, zero, hardcoded, distributivity)
 *   - Sqr (vs mul(a,a))
 *   - Mul_by_014 (sparse, vs full mul)
 *   - Inv (a · inv(a) = 1, inv(inv(a)) = a)
 *   - Unitary inv (conj(a) · a = norm for cyclotomic elements)
 *   - Frobenius map (φ^k identities, composition)
 *   - Cyclotomic squaring (vs generic sqr for cyclotomic elements)
 *   - w² = v relation
 *   - Random: commutativity, distributivity, associativity,
 *     sqr==mul, inv, mul_by_014, conjugate, frobenius, cyc_sqr (100 iter)
 *   - Aliasing tests
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifdef ZKN_HOST_TESTS

#include <stdio.h>
#include <string.h>
#include "zkn_fp12_384.h"

static int test_count = 0;
static int fail_count = 0;

/* ── Helpers ───────────────────────────────────────────────────────── */

static void check_fp12(const char *name,
                       const zkn_fp12_384_t *got,
                       const zkn_fp12_384_t *expected)
{
    test_count++;
    if (zkn_fp12_384_eq(got, expected)) {
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n", name);
        fail_count++;
    }
}

static void check_bool(const char *name, int condition)
{
    test_count++;
    if (condition)
        printf("[PASS] %s\n", name);
    else {
        printf("[FAIL] %s\n", name);
        fail_count++;
    }
}

/* ── PRNG ──────────────────────────────────────────────────────────── */

static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void random_fp(zkn_fe384_t r, uint32_t *seed, const zkn_fe384_t p)
{
    for (int i = 0; i < ZKN_MONT384_NLIMBS; i++)
        r[i] = xorshift32(seed);
    for (int k = 0; k < 10; k++) {
        zkn_limb_t borrow = 0;
        zkn_fe384_t tmp;
        for (int i = 0; i < ZKN_MONT384_NLIMBS; i++) {
            uint64_t d = (uint64_t)r[i] - p[i] - borrow;
            tmp[i] = (uint32_t)d;
            borrow = (uint32_t)(d >> 63);
        }
        if (!borrow) memcpy(r, tmp, sizeof(zkn_fe384_t));
    }
}

static void random_fp2(zkn_fp2_384_t *r, uint32_t *seed,
                       const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t n0, n1;
    random_fp(n0, seed, ctx->p);
    random_fp(n1, seed, ctx->p);
    zkn_to_mont_384(r->c0, n0, ctx);
    zkn_to_mont_384(r->c1, n1, ctx);
}

static void random_fp6(zkn_fp6_384_t *r, uint32_t *seed,
                       const zkn_mont_ctx384_t *ctx)
{
    random_fp2(&r->c0, seed, ctx);
    random_fp2(&r->c1, seed, ctx);
    random_fp2(&r->c2, seed, ctx);
}

static void random_fp12(zkn_fp12_384_t *r, uint32_t *seed,
                        const zkn_mont_ctx384_t *ctx)
{
    random_fp6(&r->c0, seed, ctx);
    random_fp6(&r->c1, seed, ctx);
}

/* Helper: Fp2 from two small integers */
static void fp2_small(zkn_fp2_384_t *r, uint32_t a, uint32_t b,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t na = {a}, nb = {b};
    zkn_to_mont_384(r->c0, na, ctx);
    zkn_to_mont_384(r->c1, nb, ctx);
}

/* Helper: Fp6 from six small integers */
static void fp6_small(zkn_fp6_384_t *r,
                      uint32_t a0, uint32_t a0i,
                      uint32_t a1, uint32_t a1i,
                      uint32_t a2, uint32_t a2i,
                      const zkn_mont_ctx384_t *ctx)
{
    fp2_small(&r->c0, a0, a0i, ctx);
    fp2_small(&r->c1, a1, a1i, ctx);
    fp2_small(&r->c2, a2, a2i, ctx);
}

/**
 * Construct a cyclotomic element in GΦ₁₂(Fp).
 *
 * Step 1: t = a · conj(a)^{-1} = a^{1−p⁶}   (unitary: t·conj(t) = 1)
 * Step 2: b = frob²(t) · t    = t^{p²+1}     (cyclotomic: b^{p⁴−p²+1} = 1)
 *
 * This is the "easy part" of the final exponentiation: f^{(p⁶−1)(p²+1)}.
 */
static void make_cyclotomic(zkn_fp12_384_t *b, const zkn_fp12_384_t *a,
                            const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t conj_a, inv_conj, t, frob2_t;

    /* Step 1: t = a · conj(a)^{-1}  (unitary) */
    zkn_fp12_384_conjugate(&conj_a, a, ctx);
    zkn_fp12_384_inv(&inv_conj, &conj_a, ctx);
    zkn_fp12_384_mul(&t, a, &inv_conj, ctx);

    /* Step 2: b = frob²(t) · t  (cyclotomic) */
    zkn_fp12_384_frobenius_map(&frob2_t, &t, 2, ctx);
    zkn_fp12_384_mul(b, &frob2_t, &t, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Tests
 * ══════════════════════════════════════════════════════════════════════ */

static void test_constructors(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 constructors ---\n");

    zkn_fp12_384_t z, o;
    zkn_fp12_384_zero(&z);
    zkn_fp12_384_one(&o, ctx);

    zkn_fp6_384_t zero6, one6;
    zkn_fp6_384_zero(&zero6);
    zkn_fp6_384_one(&one6, ctx);

    check_bool("zero: c0=0", zkn_fp6_384_eq(&z.c0, &zero6));
    check_bool("zero: c1=0", zkn_fp6_384_eq(&z.c1, &zero6));
    check_bool("one: c0=1",  zkn_fp6_384_eq(&o.c0, &one6));
    check_bool("one: c1=0",  zkn_fp6_384_eq(&o.c1, &zero6));
    check_bool("zero != one", !zkn_fp12_384_eq(&z, &o));

    zkn_fp12_384_t copy;
    zkn_fp12_384_copy(&copy, &o);
    check_bool("copy == original", zkn_fp12_384_eq(&copy, &o));
}

static void test_add_sub(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 add/sub ---\n");

    zkn_fp12_384_t a, b, r;
    fp6_small(&a.c0, 1,0, 2,0, 3,0, ctx);
    fp6_small(&a.c1, 4,0, 5,0, 6,0, ctx);
    fp6_small(&b.c0, 7,0, 8,0, 9,0, ctx);
    fp6_small(&b.c1, 10,0, 11,0, 12,0, ctx);

    /* (a+b)-b = a */
    zkn_fp12_384_add(&r, &a, &b, ctx);
    zkn_fp12_384_sub(&r, &r, &b, ctx);
    check_fp12("(a+b)-b=a", &r, &a);

    /* a-a = 0 */
    zkn_fp12_384_t zero;
    zkn_fp12_384_zero(&zero);
    zkn_fp12_384_sub(&r, &a, &a, ctx);
    check_fp12("a-a=0", &r, &zero);

    /* a + neg(a) = 0 */
    zkn_fp12_384_t neg_a;
    zkn_fp12_384_neg(&neg_a, &a, ctx);
    zkn_fp12_384_add(&r, &a, &neg_a, ctx);
    check_fp12("a+neg(a)=0", &r, &zero);
}

static void test_conjugate(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 conjugate ---\n");

    zkn_fp12_384_t a;
    fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
    fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);

    /* conj(a).c0 == a.c0 */
    zkn_fp12_384_t conj_a;
    zkn_fp12_384_conjugate(&conj_a, &a, ctx);
    check_bool("conj.c0=a.c0", zkn_fp6_384_eq(&conj_a.c0, &a.c0));

    /* conj(a).c1 == -a.c1 */
    zkn_fp6_384_t neg_c1;
    zkn_fp6_384_neg(&neg_c1, &a.c1, ctx);
    check_bool("conj.c1=-a.c1", zkn_fp6_384_eq(&conj_a.c1, &neg_c1));

    /* conj(conj(a)) = a */
    zkn_fp12_384_t conj2;
    zkn_fp12_384_conjugate(&conj2, &conj_a, ctx);
    check_fp12("conj(conj(a))=a", &conj2, &a);

    /* a + conj(a) has c1 = 0 (real part doubled) */
    zkn_fp12_384_t sum;
    zkn_fp12_384_add(&sum, &a, &conj_a, ctx);
    zkn_fp6_384_t zero6;
    zkn_fp6_384_zero(&zero6);
    check_bool("(a+conj(a)).c1=0", zkn_fp6_384_eq(&sum.c1, &zero6));
}

static void test_mul(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 mul ---\n");

    zkn_fp12_384_t one, zero, r;
    zkn_fp12_384_one(&one, ctx);
    zkn_fp12_384_zero(&zero);

    /* a * 1 = a */
    zkn_fp12_384_t a;
    fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
    fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);
    zkn_fp12_384_mul(&r, &a, &one, ctx);
    check_fp12("a*1=a", &r, &a);

    /* 1 * a = a */
    zkn_fp12_384_mul(&r, &one, &a, ctx);
    check_fp12("1*a=a", &r, &a);

    /* a * 0 = 0 */
    zkn_fp12_384_mul(&r, &a, &zero, ctx);
    check_fp12("a*0=0", &r, &zero);

    /*
     * w · w = w² = v
     * w = (0, 1)  in Fp12, where 1 is the Fp6 one
     * expected: (v, 0) in Fp12, where v = (0, 1, 0) in Fp6
     */
    zkn_fp12_384_t w_elem;
    zkn_fp6_384_zero(&w_elem.c0);
    zkn_fp6_384_one(&w_elem.c1, ctx);

    zkn_fp12_384_t expected;
    zkn_fp6_384_zero(&expected.c1);
    zkn_fp6_384_zero(&expected.c0);
    fp2_small(&expected.c0.c1, 1, 0, ctx);  /* v = (0, 1, 0) */

    zkn_fp12_384_mul(&r, &w_elem, &w_elem, ctx);
    check_fp12("w*w=v", &r, &expected);

    /*
     * (1 + w)² = 1 + 2w + w² = (1+v) + 2w
     * in Fp12: c0 = (1,1,0) in Fp6, c1 = (2,0,0) in Fp6
     */
    zkn_fp12_384_t one_plus_w;
    zkn_fp6_384_one(&one_plus_w.c0, ctx);
    zkn_fp6_384_one(&one_plus_w.c1, ctx);

    zkn_fp12_384_t sq_exp;
    fp6_small(&sq_exp.c0, 1,0, 1,0, 0,0, ctx);   /* 1 + v */
    fp6_small(&sq_exp.c1, 2,0, 0,0, 0,0, ctx);   /* 2w */

    zkn_fp12_384_mul(&r, &one_plus_w, &one_plus_w, ctx);
    check_fp12("(1+w)²=(1+v,2)", &r, &sq_exp);
}

static void test_sqr(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 sqr ---\n");

    /* sqr(1+w) = (1+v, 2) — same as mul test */
    zkn_fp12_384_t a;
    zkn_fp6_384_one(&a.c0, ctx);
    zkn_fp6_384_one(&a.c1, ctx);
    zkn_fp12_384_t expected;
    fp6_small(&expected.c0, 1,0, 1,0, 0,0, ctx);
    fp6_small(&expected.c1, 2,0, 0,0, 0,0, ctx);

    zkn_fp12_384_t r;
    zkn_fp12_384_sqr(&r, &a, ctx);
    check_fp12("sqr(1+w)=(1+v,2)", &r, &expected);

    /* sqr(w) = v */
    zkn_fp12_384_t w_elem;
    zkn_fp6_384_zero(&w_elem.c0);
    zkn_fp6_384_one(&w_elem.c1, ctx);
    zkn_fp12_384_t v_expected;
    zkn_fp6_384_zero(&v_expected.c0);
    fp2_small(&v_expected.c0.c1, 1, 0, ctx);
    zkn_fp6_384_zero(&v_expected.c1);
    zkn_fp12_384_sqr(&r, &w_elem, ctx);
    check_fp12("sqr(w)=v", &r, &v_expected);

    /* sqr(a) == mul(a,a) with arbitrary a */
    fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
    fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);
    zkn_fp12_384_t sq, mm;
    zkn_fp12_384_sqr(&sq, &a, ctx);
    zkn_fp12_384_mul(&mm, &a, &a, ctx);
    check_fp12("sqr(a)==mul(a,a)", &sq, &mm);
}

static void test_mul_by_014(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 mul_by_014 ---\n");

    /* Build sparse Fp12: b = ((b0, b1, 0), (0, b4, 0)) */
    zkn_fp2_384_t b0, b1, b4;
    fp2_small(&b0, 4, 1, ctx);
    fp2_small(&b1, 6, 3, ctx);
    fp2_small(&b4, 8, 5, ctx);

    zkn_fp12_384_t a;
    fp6_small(&a.c0, 2,1, 3,5, 7,2, ctx);
    fp6_small(&a.c1, 11,3, 13,7, 17,11, ctx);

    zkn_fp12_384_t r;
    zkn_fp12_384_mul_by_014(&r, &a, &b0, &b1, &b4, ctx);

    /* Cross-check: build full Fp12 from sparse components and do full mul */
    zkn_fp12_384_t b_full;
    zkn_fp2_384_copy(&b_full.c0.c0, &b0);
    zkn_fp2_384_copy(&b_full.c0.c1, &b1);
    zkn_fp2_384_zero(&b_full.c0.c2);
    zkn_fp2_384_zero(&b_full.c1.c0);
    zkn_fp2_384_copy(&b_full.c1.c1, &b4);
    zkn_fp2_384_zero(&b_full.c1.c2);

    zkn_fp12_384_t r2;
    zkn_fp12_384_mul(&r2, &a, &b_full, ctx);
    check_fp12("mul_by_014==mul(a,sparse)", &r, &r2);

    /* Another vector with different a */
    fp6_small(&a.c0, 31,37, 41,43, 47,53, ctx);
    fp6_small(&a.c1, 59,61, 67,71, 73,79, ctx);
    fp2_small(&b0, 2, 0, ctx);
    fp2_small(&b1, 3, 0, ctx);
    fp2_small(&b4, 5, 0, ctx);

    zkn_fp12_384_mul_by_014(&r, &a, &b0, &b1, &b4, ctx);

    zkn_fp2_384_copy(&b_full.c0.c0, &b0);
    zkn_fp2_384_copy(&b_full.c0.c1, &b1);
    zkn_fp2_384_zero(&b_full.c0.c2);
    zkn_fp2_384_zero(&b_full.c1.c0);
    zkn_fp2_384_copy(&b_full.c1.c1, &b4);
    zkn_fp2_384_zero(&b_full.c1.c2);
    zkn_fp12_384_mul(&r2, &a, &b_full, ctx);
    check_fp12("mul_by_014==mul [primes]", &r, &r2);
}

static void test_inv(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 inv ---\n");

    zkn_fp12_384_t one;
    zkn_fp12_384_one(&one, ctx);

    /* inv(1) = 1 */
    zkn_fp12_384_t r;
    zkn_fp12_384_inv(&r, &one, ctx);
    check_fp12("inv(1)=1", &r, &one);

    /* a * inv(a) = 1 */
    zkn_fp12_384_t a;
    fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
    fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);
    zkn_fp12_384_t inv_a, prod;
    zkn_fp12_384_inv(&inv_a, &a, ctx);
    zkn_fp12_384_mul(&prod, &a, &inv_a, ctx);
    check_fp12("a*inv(a)=1 [small]", &prod, &one);

    /* Another value */
    fp6_small(&a.c0, 31,37, 41,43, 47,53, ctx);
    fp6_small(&a.c1, 59,61, 67,71, 73,79, ctx);
    zkn_fp12_384_inv(&inv_a, &a, ctx);
    zkn_fp12_384_mul(&prod, &a, &inv_a, ctx);
    check_fp12("a*inv(a)=1 [primes]", &prod, &one);

    /* inv(inv(a)) = a */
    zkn_fp12_384_t inv_inv;
    zkn_fp12_384_inv(&inv_inv, &inv_a, ctx);
    check_fp12("inv(inv(a))=a", &inv_inv, &a);
}

static void test_unitary_inv(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 unitary inv ---\n");

    zkn_fp12_384_t a;
    fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
    fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);

    /* Construct cyclotomic element: b = a · conj(a)^{-1} */
    zkn_fp12_384_t b;
    make_cyclotomic(&b, &a, ctx);

    /* Verify: b · conj(b) = 1 */
    zkn_fp12_384_t conj_b, prod;
    zkn_fp12_384_conjugate(&conj_b, &b, ctx);
    zkn_fp12_384_mul(&prod, &b, &conj_b, ctx);

    zkn_fp12_384_t one;
    zkn_fp12_384_one(&one, ctx);
    check_fp12("cyclotomic: b*conj(b)=1", &prod, &one);

    /* For cyclotomic b: unitary_inv(b) == inv(b) */
    zkn_fp12_384_t ui, full_inv;
    zkn_fp12_384_unitary_inv(&ui, &b, ctx);
    zkn_fp12_384_inv(&full_inv, &b, ctx);
    check_fp12("cyclotomic: unitary_inv==inv", &ui, &full_inv);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Frobenius map tests
 * ══════════════════════════════════════════════════════════════════════ */

static void test_frobenius(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 Frobenius map ---\n");

    zkn_fp12_384_t one;
    zkn_fp12_384_one(&one, ctx);

    /* φ^k(1) = 1 for all k */
    {
        zkn_fp12_384_t r;
        zkn_fp12_384_frobenius_map(&r, &one, 1, ctx);
        check_fp12("frob^1(1)=1", &r, &one);

        zkn_fp12_384_frobenius_map(&r, &one, 2, ctx);
        check_fp12("frob^2(1)=1", &r, &one);

        zkn_fp12_384_frobenius_map(&r, &one, 3, ctx);
        check_fp12("frob^3(1)=1", &r, &one);
    }

    /*
     * φ_p is a ring homomorphism: φ(a·b) = φ(a)·φ(b)
     */
    {
        zkn_fp12_384_t a, b;
        fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
        fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);
        fp6_small(&b.c0, 31,37, 41,43, 47,53, ctx);
        fp6_small(&b.c1, 59,61, 67,71, 73,79, ctx);

        zkn_fp12_384_t ab, frob_ab, frob_a, frob_b, prod;
        zkn_fp12_384_mul(&ab, &a, &b, ctx);
        zkn_fp12_384_frobenius_map(&frob_ab, &ab, 1, ctx);
        zkn_fp12_384_frobenius_map(&frob_a, &a, 1, ctx);
        zkn_fp12_384_frobenius_map(&frob_b, &b, 1, ctx);
        zkn_fp12_384_mul(&prod, &frob_a, &frob_b, ctx);
        check_fp12("frob^1(a*b)=frob(a)*frob(b)", &frob_ab, &prod);
    }

    /*
     * φ^1(φ^1(a)) = φ^2(a)
     */
    {
        zkn_fp12_384_t a;
        fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
        fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);

        zkn_fp12_384_t f1, f1f1, f2;
        zkn_fp12_384_frobenius_map(&f1, &a, 1, ctx);
        zkn_fp12_384_frobenius_map(&f1f1, &f1, 1, ctx);
        zkn_fp12_384_frobenius_map(&f2, &a, 2, ctx);
        check_fp12("frob^1(frob^1(a))=frob^2(a)", &f1f1, &f2);
    }

    /*
     * φ^1(φ^2(a)) = φ^3(a)
     */
    {
        zkn_fp12_384_t a;
        fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
        fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);

        zkn_fp12_384_t f2, f1f2, f3;
        zkn_fp12_384_frobenius_map(&f2, &a, 2, ctx);
        zkn_fp12_384_frobenius_map(&f1f2, &f2, 1, ctx);
        zkn_fp12_384_frobenius_map(&f3, &a, 3, ctx);
        check_fp12("frob^1(frob^2(a))=frob^3(a)", &f1f2, &f3);
    }

    /*
     * Additive homomorphism: φ(a+b) = φ(a) + φ(b)
     */
    {
        zkn_fp12_384_t a, b;
        fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
        fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);
        fp6_small(&b.c0, 31,37, 41,43, 47,53, ctx);
        fp6_small(&b.c1, 59,61, 67,71, 73,79, ctx);

        zkn_fp12_384_t ab, frob_ab, frob_a, frob_b, sum;
        zkn_fp12_384_add(&ab, &a, &b, ctx);
        zkn_fp12_384_frobenius_map(&frob_ab, &ab, 1, ctx);
        zkn_fp12_384_frobenius_map(&frob_a, &a, 1, ctx);
        zkn_fp12_384_frobenius_map(&frob_b, &b, 1, ctx);
        zkn_fp12_384_add(&sum, &frob_a, &frob_b, ctx);
        check_fp12("frob^1(a+b)=frob(a)+frob(b)", &frob_ab, &sum);
    }

    /*
     * For BLS12-381 (embedding degree 12): φ^{12}(a) = a
     * We can test: φ^3(φ^3(φ^3(φ^3(a)))) = a
     * But we only have φ^1, φ^2, φ^3.
     * Instead test: φ^2(φ^1(a)) · φ^3(φ^2(φ^1(a)))... complex.
     *
     * Simpler: φ^2(φ^2(φ^2(φ^2(φ^2(φ^2(a)))))) = φ^{12}(a) = a
     */
    {
        zkn_fp12_384_t a, r;
        fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
        fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);

        zkn_fp12_384_copy(&r, &a);
        for (int i = 0; i < 6; i++)
            zkn_fp12_384_frobenius_map(&r, &r, 2, ctx);
        check_fp12("(frob^2)^6(a)=a [φ^12=id]", &r, &a);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Cyclotomic squaring tests
 * ══════════════════════════════════════════════════════════════════════ */

static void test_cyclotomic_sqr(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 cyclotomic sqr ---\n");

    zkn_fp12_384_t one;
    zkn_fp12_384_one(&one, ctx);

    /* cyc_sqr(1) = 1 (1 is trivially cyclotomic) */
    {
        zkn_fp12_384_t r;
        zkn_fp12_384_cyclotomic_sqr(&r, &one, ctx);
        check_fp12("cyc_sqr(1)=1", &r, &one);
    }

    /*
     * For a cyclotomic element b: cyc_sqr(b) == generic sqr(b)
     */
    {
        zkn_fp12_384_t a;
        fp6_small(&a.c0, 3,1, 5,2, 7,4, ctx);
        fp6_small(&a.c1, 11,13, 17,19, 23,29, ctx);

        zkn_fp12_384_t b;
        make_cyclotomic(&b, &a, ctx);

        /* Verify b is cyclotomic */
        zkn_fp12_384_t conj_b, prod;
        zkn_fp12_384_conjugate(&conj_b, &b, ctx);
        zkn_fp12_384_mul(&prod, &b, &conj_b, ctx);
        check_fp12("b is cyclotomic", &prod, &one);

        /* cyc_sqr(b) == sqr(b) */
        zkn_fp12_384_t cyc, gen;
        zkn_fp12_384_cyclotomic_sqr(&cyc, &b, ctx);
        zkn_fp12_384_sqr(&gen, &b, ctx);
        check_fp12("cyc_sqr(b)==sqr(b)", &cyc, &gen);

        /* cyc_sqr(b) == mul(b, b) */
        zkn_fp12_384_t mm;
        zkn_fp12_384_mul(&mm, &b, &b, ctx);
        check_fp12("cyc_sqr(b)==mul(b,b)", &cyc, &mm);
    }

    /*
     * Iterated squaring: cyc_sqr^4(b) == b^16
     * b^16 via mul chain: b² → b⁴ → b⁸ → b¹⁶
     */
    {
        zkn_fp12_384_t a;
        fp6_small(&a.c0, 31,37, 41,43, 47,53, ctx);
        fp6_small(&a.c1, 59,61, 67,71, 73,79, ctx);

        zkn_fp12_384_t b;
        make_cyclotomic(&b, &a, ctx);

        /* 4 iterated cyc_sqr */
        zkn_fp12_384_t cyc;
        zkn_fp12_384_copy(&cyc, &b);
        for (int i = 0; i < 4; i++)
            zkn_fp12_384_cyclotomic_sqr(&cyc, &cyc, ctx);

        /* b^16 via generic: b² → b⁴ → b⁸ → b¹⁶ */
        zkn_fp12_384_t gen;
        zkn_fp12_384_sqr(&gen, &b, ctx);
        zkn_fp12_384_sqr(&gen, &gen, ctx);
        zkn_fp12_384_sqr(&gen, &gen, ctx);
        zkn_fp12_384_sqr(&gen, &gen, ctx);

        check_fp12("cyc_sqr^4==sqr^4", &cyc, &gen);
    }

    /*
     * Result of cyc_sqr should remain cyclotomic
     */
    {
        zkn_fp12_384_t a;
        fp6_small(&a.c0, 2,3, 5,7, 11,13, ctx);
        fp6_small(&a.c1, 17,19, 23,29, 31,37, ctx);

        zkn_fp12_384_t b;
        make_cyclotomic(&b, &a, ctx);

        zkn_fp12_384_t sq;
        zkn_fp12_384_cyclotomic_sqr(&sq, &b, ctx);

        /* Verify sq is cyclotomic: sq · conj(sq) = 1 */
        zkn_fp12_384_t conj_sq, prod;
        zkn_fp12_384_conjugate(&conj_sq, &sq, ctx);
        zkn_fp12_384_mul(&prod, &sq, &conj_sq, ctx);
        check_fp12("cyc_sqr preserves cyclotomic", &prod, &one);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 *  Random property tests (100 iterations)
 * ══════════════════════════════════════════════════════════════════════ */

static void test_random(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 random (100 iterations) ---\n");

    uint32_t seed = 0xFACEFEED;
    const int N = 100;
    int pass_comm = 0, pass_dist = 0, pass_assoc = 0;
    int pass_sqr = 0, pass_inv = 0, pass_014 = 0, pass_conj = 0;
    int pass_frob_hom = 0, pass_frob_comp = 0, pass_cyc_sqr = 0;

    zkn_fp12_384_t one;
    zkn_fp12_384_one(&one, ctx);

    for (int i = 0; i < N; i++) {
        zkn_fp12_384_t a, b, c;
        random_fp12(&a, &seed, ctx);
        random_fp12(&b, &seed, ctx);
        random_fp12(&c, &seed, ctx);

        /* Commutativity: a*b = b*a */
        {
            zkn_fp12_384_t ab, ba;
            zkn_fp12_384_mul(&ab, &a, &b, ctx);
            zkn_fp12_384_mul(&ba, &b, &a, ctx);
            if (zkn_fp12_384_eq(&ab, &ba)) pass_comm++;
        }

        /* Distributivity: a*(b+c) = a*b + a*c */
        {
            zkn_fp12_384_t bc, lhs, ab, ac, rhs;
            zkn_fp12_384_add(&bc, &b, &c, ctx);
            zkn_fp12_384_mul(&lhs, &a, &bc, ctx);
            zkn_fp12_384_mul(&ab, &a, &b, ctx);
            zkn_fp12_384_mul(&ac, &a, &c, ctx);
            zkn_fp12_384_add(&rhs, &ab, &ac, ctx);
            if (zkn_fp12_384_eq(&lhs, &rhs)) pass_dist++;
        }

        /* Associativity: (a*b)*c = a*(b*c) */
        {
            zkn_fp12_384_t ab, ab_c, bc, a_bc;
            zkn_fp12_384_mul(&ab, &a, &b, ctx);
            zkn_fp12_384_mul(&ab_c, &ab, &c, ctx);
            zkn_fp12_384_mul(&bc, &b, &c, ctx);
            zkn_fp12_384_mul(&a_bc, &a, &bc, ctx);
            if (zkn_fp12_384_eq(&ab_c, &a_bc)) pass_assoc++;
        }

        /* sqr(a) == mul(a,a) */
        {
            zkn_fp12_384_t sq, mm;
            zkn_fp12_384_sqr(&sq, &a, ctx);
            zkn_fp12_384_mul(&mm, &a, &a, ctx);
            if (zkn_fp12_384_eq(&sq, &mm)) pass_sqr++;
        }

        /* a * inv(a) = 1 */
        {
            zkn_fp12_384_t inv_a, prod;
            zkn_fp12_384_inv(&inv_a, &a, ctx);
            zkn_fp12_384_mul(&prod, &a, &inv_a, ctx);
            if (zkn_fp12_384_eq(&prod, &one)) pass_inv++;
        }

        /* mul_by_014 == full mul with sparse */
        {
            zkn_fp2_384_t b0, b1, b4;
            random_fp2(&b0, &seed, ctx);
            random_fp2(&b1, &seed, ctx);
            random_fp2(&b4, &seed, ctx);

            zkn_fp12_384_t fast;
            zkn_fp12_384_mul_by_014(&fast, &a, &b0, &b1, &b4, ctx);

            zkn_fp12_384_t b_full, slow;
            zkn_fp2_384_copy(&b_full.c0.c0, &b0);
            zkn_fp2_384_copy(&b_full.c0.c1, &b1);
            zkn_fp2_384_zero(&b_full.c0.c2);
            zkn_fp2_384_zero(&b_full.c1.c0);
            zkn_fp2_384_copy(&b_full.c1.c1, &b4);
            zkn_fp2_384_zero(&b_full.c1.c2);
            zkn_fp12_384_mul(&slow, &a, &b_full, ctx);
            if (zkn_fp12_384_eq(&fast, &slow)) pass_014++;
        }

        /* conj(conj(a)) = a */
        {
            zkn_fp12_384_t ca, cca;
            zkn_fp12_384_conjugate(&ca, &a, ctx);
            zkn_fp12_384_conjugate(&cca, &ca, ctx);
            if (zkn_fp12_384_eq(&cca, &a)) pass_conj++;
        }

        /* Frobenius: φ(a*b) = φ(a)*φ(b) */
        {
            zkn_fp12_384_t ab, f_ab, fa, fb, prod;
            zkn_fp12_384_mul(&ab, &a, &b, ctx);
            zkn_fp12_384_frobenius_map(&f_ab, &ab, 1, ctx);
            zkn_fp12_384_frobenius_map(&fa, &a, 1, ctx);
            zkn_fp12_384_frobenius_map(&fb, &b, 1, ctx);
            zkn_fp12_384_mul(&prod, &fa, &fb, ctx);
            if (zkn_fp12_384_eq(&f_ab, &prod)) pass_frob_hom++;
        }

        /* Frobenius: φ^1(φ^1(a)) = φ^2(a) */
        {
            zkn_fp12_384_t f1, f11, f2;
            zkn_fp12_384_frobenius_map(&f1, &a, 1, ctx);
            zkn_fp12_384_frobenius_map(&f11, &f1, 1, ctx);
            zkn_fp12_384_frobenius_map(&f2, &a, 2, ctx);
            if (zkn_fp12_384_eq(&f11, &f2)) pass_frob_comp++;
        }

        /* Cyclotomic sqr == generic sqr for cyclotomic elements */
        {
            zkn_fp12_384_t cyc_elem;
            make_cyclotomic(&cyc_elem, &a, ctx);
            zkn_fp12_384_t cs, gs;
            zkn_fp12_384_cyclotomic_sqr(&cs, &cyc_elem, ctx);
            zkn_fp12_384_sqr(&gs, &cyc_elem, ctx);
            if (zkn_fp12_384_eq(&cs, &gs)) pass_cyc_sqr++;
        }
    }

    char buf[80];

    snprintf(buf, sizeof(buf), "random: commutativity %d/%d", pass_comm, N);
    check_bool(buf, pass_comm == N);

    snprintf(buf, sizeof(buf), "random: distributivity %d/%d", pass_dist, N);
    check_bool(buf, pass_dist == N);

    snprintf(buf, sizeof(buf), "random: associativity %d/%d", pass_assoc, N);
    check_bool(buf, pass_assoc == N);

    snprintf(buf, sizeof(buf), "random: sqr==mul(a,a) %d/%d", pass_sqr, N);
    check_bool(buf, pass_sqr == N);

    snprintf(buf, sizeof(buf), "random: a*inv(a)=1 %d/%d", pass_inv, N);
    check_bool(buf, pass_inv == N);

    snprintf(buf, sizeof(buf), "random: mul_by_014 %d/%d", pass_014, N);
    check_bool(buf, pass_014 == N);

    snprintf(buf, sizeof(buf), "random: conj(conj(a))=a %d/%d", pass_conj, N);
    check_bool(buf, pass_conj == N);

    snprintf(buf, sizeof(buf), "random: frob hom %d/%d", pass_frob_hom, N);
    check_bool(buf, pass_frob_hom == N);

    snprintf(buf, sizeof(buf), "random: frob comp %d/%d", pass_frob_comp, N);
    check_bool(buf, pass_frob_comp == N);

    snprintf(buf, sizeof(buf), "random: cyc_sqr==sqr %d/%d", pass_cyc_sqr, N);
    check_bool(buf, pass_cyc_sqr == N);
}

/* ── Aliasing tests ────────────────────────────────────────────────── */

static void test_aliasing(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp12 aliasing ---\n");

    uint32_t seed = 0xBADC0FFE;
    zkn_fp12_384_t a, b;
    random_fp12(&a, &seed, ctx);
    random_fp12(&b, &seed, ctx);

    /* mul in-place */
    zkn_fp12_384_t expected, alias;
    zkn_fp12_384_mul(&expected, &a, &b, ctx);
    zkn_fp12_384_copy(&alias, &a);
    zkn_fp12_384_mul(&alias, &alias, &b, ctx);
    check_fp12("alias: mul(r,r,b)", &alias, &expected);

    /* sqr in-place */
    zkn_fp12_384_sqr(&expected, &a, ctx);
    zkn_fp12_384_copy(&alias, &a);
    zkn_fp12_384_sqr(&alias, &alias, ctx);
    check_fp12("alias: sqr(r,r)", &alias, &expected);

    /* inv in-place */
    zkn_fp12_384_inv(&expected, &a, ctx);
    zkn_fp12_384_copy(&alias, &a);
    zkn_fp12_384_inv(&alias, &alias, ctx);
    check_fp12("alias: inv(r,r)", &alias, &expected);

    /* conjugate in-place */
    zkn_fp12_384_conjugate(&expected, &a, ctx);
    zkn_fp12_384_copy(&alias, &a);
    zkn_fp12_384_conjugate(&alias, &alias, ctx);
    check_fp12("alias: conj(r,r)", &alias, &expected);

    /* mul_by_014 in-place */
    zkn_fp2_384_t b0, b1, b4;
    random_fp2(&b0, &seed, ctx);
    random_fp2(&b1, &seed, ctx);
    random_fp2(&b4, &seed, ctx);
    zkn_fp12_384_mul_by_014(&expected, &a, &b0, &b1, &b4, ctx);
    zkn_fp12_384_copy(&alias, &a);
    zkn_fp12_384_mul_by_014(&alias, &alias, &b0, &b1, &b4, ctx);
    check_fp12("alias: mul_by_014(r,r,...)", &alias, &expected);

    /* frobenius in-place */
    zkn_fp12_384_frobenius_map(&expected, &a, 1, ctx);
    zkn_fp12_384_copy(&alias, &a);
    zkn_fp12_384_frobenius_map(&alias, &alias, 1, ctx);
    check_fp12("alias: frob^1(r,r)", &alias, &expected);

    zkn_fp12_384_frobenius_map(&expected, &a, 2, ctx);
    zkn_fp12_384_copy(&alias, &a);
    zkn_fp12_384_frobenius_map(&alias, &alias, 2, ctx);
    check_fp12("alias: frob^2(r,r)", &alias, &expected);

    /* cyclotomic sqr in-place */
    zkn_fp12_384_t cyc;
    make_cyclotomic(&cyc, &a, ctx);
    zkn_fp12_384_cyclotomic_sqr(&expected, &cyc, ctx);
    zkn_fp12_384_copy(&alias, &cyc);
    zkn_fp12_384_cyclotomic_sqr(&alias, &alias, ctx);
    check_fp12("alias: cyc_sqr(r,r)", &alias, &expected);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Main
 * ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("=== zkn_fp12_384 test suite (BLS12-381 Fp12) ===\n");
#ifdef ZKN_MONT384_ASM
    printf("    backend: ARM Thumb-2 ASM (Fp layer)\n");
#else
    printf("    backend: portable C\n");
#endif

    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();

    test_constructors(ctx);
    test_add_sub(ctx);
    test_conjugate(ctx);
    test_mul(ctx);
    test_sqr(ctx);
    test_mul_by_014(ctx);
    test_inv(ctx);
    test_unitary_inv(ctx);
    test_frobenius(ctx);
    test_cyclotomic_sqr(ctx);
    test_random(ctx);
    test_aliasing(ctx);

    printf("\n=== Results: %d/%d passed ===\n",
           test_count - fail_count, test_count);

    return fail_count ? 1 : 0;
}

#endif /* ZKN_HOST_TESTS */
