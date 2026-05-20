/*
 * test_fp6_384.c — Test suite for zkn_fp6_384 (Fp6 = Fp2[v]/(v³−ξ)) over BLS12-381
 *
 * Tests include:
 *   - Constructors / equality
 *   - Add / sub / neg (hardcoded + algebraic)
 *   - Mul (hardcoded vectors, identity, zero, distributivity)
 *   - Sqr (vs mul(a,a))
 *   - Mul_by_01, mul_by_1 (vs full mul with sparse operand)
 *   - Mul_by_v (shift, v³ = ξ cycle)
 *   - Mul_by_fp2 (vs manual component-wise)
 *   - Inv (a · inv(a) = 1)
 *   - Random property tests: commutativity, distributivity, associativity,
 *     sqr==mul, inv, mul_by_01, mul_by_1 (100 iterations each)
 *   - Aliasing tests
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include <stdio.h>
#include <string.h>
#include "zkn_fp6_384.h"

static int test_count = 0;
static int fail_count = 0;

/* ── Helpers ───────────────────────────────────────────────────────── */

static void print_fp2(const char *label, const zkn_fp2_384_t *a)
{
    printf("      %s = (0x", label);
    for (int i = ZKN_MONT384_NLIMBS - 1; i >= 0; i--) printf("%08x", a->c0[i]);
    printf(", 0x");
    for (int i = ZKN_MONT384_NLIMBS - 1; i >= 0; i--) printf("%08x", a->c1[i]);
    printf(")\n");
}

static void print_fp6(const char *label, const zkn_fp6_384_t *a)
{
    printf("    %s:\n", label);
    print_fp2("c0", &a->c0);
    print_fp2("c1", &a->c1);
    print_fp2("c2", &a->c2);
}

static void check_fp6(const char *name,
                      const zkn_fp6_384_t *got,
                      const zkn_fp6_384_t *expected)
{
    test_count++;
    if (zkn_fp6_384_eq(got, expected)) {
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n", name);
        print_fp6("expected", expected);
        print_fp6("got     ", got);
        fail_count++;
    }
}

__attribute__((unused))
static void check_fp2(const char *name,
                      const zkn_fp2_384_t *got,
                      const zkn_fp2_384_t *expected)
{
    test_count++;
    if (zkn_fp2_384_eq(got, expected)) {
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n", name);
        print_fp2("expected", expected);
        print_fp2("got     ", got);
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

/* Helper: make an Fp2 from two small integers */
static void fp2_from_ints(zkn_fp2_384_t *r, uint32_t a, uint32_t b,
                          const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t na = {a}, nb = {b};
    zkn_to_mont_384(r->c0, na, ctx);
    zkn_to_mont_384(r->c1, nb, ctx);
}

/* Helper: make an Fp6 from six small integers */
static void fp6_from_ints(zkn_fp6_384_t *r,
                          uint32_t a0, uint32_t a0i,
                          uint32_t a1, uint32_t a1i,
                          uint32_t a2, uint32_t a2i,
                          const zkn_mont_ctx384_t *ctx)
{
    fp2_from_ints(&r->c0, a0, a0i, ctx);
    fp2_from_ints(&r->c1, a1, a1i, ctx);
    fp2_from_ints(&r->c2, a2, a2i, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Tests
 * ══════════════════════════════════════════════════════════════════════ */

static void test_constructors(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 constructors ---\n");

    zkn_fp6_384_t z, o;
    zkn_fp6_384_zero(&z);
    zkn_fp6_384_one(&o, ctx);

    zkn_fp2_384_t zero2, one2;
    zkn_fp2_384_zero(&zero2);
    zkn_fp2_384_one(&one2, ctx);

    check_bool("zero: c0=0", zkn_fp2_384_eq(&z.c0, &zero2));
    check_bool("zero: c1=0", zkn_fp2_384_eq(&z.c1, &zero2));
    check_bool("zero: c2=0", zkn_fp2_384_eq(&z.c2, &zero2));
    check_bool("one: c0=1",  zkn_fp2_384_eq(&o.c0, &one2));
    check_bool("one: c1=0",  zkn_fp2_384_eq(&o.c1, &zero2));
    check_bool("one: c2=0",  zkn_fp2_384_eq(&o.c2, &zero2));
    check_bool("zero != one", !zkn_fp6_384_eq(&z, &o));

    zkn_fp6_384_t copy;
    zkn_fp6_384_copy(&copy, &o);
    check_bool("copy == original", zkn_fp6_384_eq(&copy, &o));
}

static void test_add_sub(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 add/sub ---\n");

    zkn_fp6_384_t a, b, r;
    fp6_from_ints(&a, 1,0, 2,0, 3,0, ctx);
    fp6_from_ints(&b, 4,0, 5,0, 6,0, ctx);

    zkn_fp6_384_t expected;
    fp6_from_ints(&expected, 5,0, 7,0, 9,0, ctx);

    zkn_fp6_384_add(&r, &a, &b, ctx);
    check_fp6("(1,2,3)+(4,5,6)=(5,7,9)", &r, &expected);

    /* (a+b)-b = a */
    zkn_fp6_384_sub(&r, &r, &b, ctx);
    check_fp6("(a+b)-b=a", &r, &a);

    /* a-a = 0 */
    zkn_fp6_384_t zero;
    zkn_fp6_384_zero(&zero);
    zkn_fp6_384_sub(&r, &a, &a, ctx);
    check_fp6("a-a=0", &r, &zero);

    /* a + neg(a) = 0 */
    zkn_fp6_384_t neg_a;
    zkn_fp6_384_neg(&neg_a, &a, ctx);
    zkn_fp6_384_add(&r, &a, &neg_a, ctx);
    check_fp6("a+neg(a)=0", &r, &zero);
}

static void test_mul(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 mul ---\n");

    zkn_fp6_384_t one, zero, r;
    zkn_fp6_384_one(&one, ctx);
    zkn_fp6_384_zero(&zero);

    /* a * 1 = a */
    zkn_fp6_384_t a;
    fp6_from_ints(&a, 3,1, 5,2, 7,4, ctx);
    zkn_fp6_384_mul(&r, &a, &one, ctx);
    check_fp6("a*1=a", &r, &a);

    /* 1 * a = a */
    zkn_fp6_384_mul(&r, &one, &a, ctx);
    check_fp6("1*a=a", &r, &a);

    /* a * 0 = 0 */
    zkn_fp6_384_mul(&r, &a, &zero, ctx);
    check_fp6("a*0=0", &r, &zero);

    /*
     * Hardcoded: v · v = v²
     * v = (0, 1, 0), expected v² = (0, 0, 1)
     */
    zkn_fp6_384_t vv, v2;
    fp6_from_ints(&vv, 0,0, 1,0, 0,0, ctx);
    fp6_from_ints(&v2, 0,0, 0,0, 1,0, ctx);
    zkn_fp6_384_mul(&r, &vv, &vv, ctx);
    check_fp6("v*v=v²", &r, &v2);

    /*
     * v² · v = v³ = ξ = (1+u, 0, 0)
     * v² = (0, 0, 1), v = (0, 1, 0)
     */
    zkn_fp6_384_t xi_fp6;
    fp2_from_ints(&xi_fp6.c0, 1, 1, ctx);  /* ξ = 1+u */
    zkn_fp2_384_zero(&xi_fp6.c1);
    zkn_fp2_384_zero(&xi_fp6.c2);
    zkn_fp6_384_mul(&r, &v2, &vv, ctx);
    check_fp6("v²·v=ξ", &r, &xi_fp6);

    /*
     * (1 + v)² = 1 + 2v + v²
     * = (1, 2, 1) in Fp6 coordinates
     */
    zkn_fp6_384_t one_plus_v, sq_expected;
    fp6_from_ints(&one_plus_v, 1,0, 1,0, 0,0, ctx);
    fp6_from_ints(&sq_expected, 1,0, 2,0, 1,0, ctx);
    zkn_fp6_384_mul(&r, &one_plus_v, &one_plus_v, ctx);
    check_fp6("(1+v)²=(1,2,1)", &r, &sq_expected);
}

static void test_sqr(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 sqr ---\n");

    /* sqr(1+v) = (1,2,1) — same as mul test */
    zkn_fp6_384_t a, r, expected;
    fp6_from_ints(&a, 1,0, 1,0, 0,0, ctx);
    fp6_from_ints(&expected, 1,0, 2,0, 1,0, ctx);
    zkn_fp6_384_sqr(&r, &a, ctx);
    check_fp6("sqr(1+v)=(1,2,1)", &r, &expected);

    /* sqr(v) = v² = (0,0,1) */
    zkn_fp6_384_t vv;
    fp6_from_ints(&vv, 0,0, 1,0, 0,0, ctx);
    fp6_from_ints(&expected, 0,0, 0,0, 1,0, ctx);
    zkn_fp6_384_sqr(&r, &vv, ctx);
    check_fp6("sqr(v)=(0,0,1)", &r, &expected);

    /* sqr(a) == mul(a,a) with arbitrary a */
    fp6_from_ints(&a, 3,1, 5,2, 7,4, ctx);
    zkn_fp6_384_t sq, mm;
    zkn_fp6_384_sqr(&sq, &a, ctx);
    zkn_fp6_384_mul(&mm, &a, &a, ctx);
    check_fp6("sqr(a)==mul(a,a)", &sq, &mm);
}

static void test_mul_by_v(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 mul_by_v ---\n");

    /* (a0, a1, a2) · v = (ξ·a2, a0, a1) */
    zkn_fp6_384_t a, r;
    fp6_from_ints(&a, 2,0, 3,0, 5,0, ctx);

    zkn_fp6_384_mul_by_v(&r, &a, ctx);

    /* Expected: c0 = ξ·5, c1 = 2, c2 = 3 */
    /* ξ·5 = (1+u)·5 = 5+5u */
    zkn_fp6_384_t expected;
    fp2_from_ints(&expected.c0, 5, 5, ctx);
    fp2_from_ints(&expected.c1, 2, 0, ctx);
    fp2_from_ints(&expected.c2, 3, 0, ctx);
    check_fp6("mul_by_v: (2,3,5)·v=(ξ·5,2,3)", &r, &expected);

    /* Cross-check: mul_by_v(a) == mul(a, v) */
    zkn_fp6_384_t v_elem, r2;
    fp6_from_ints(&v_elem, 0,0, 1,0, 0,0, ctx);
    zkn_fp6_384_mul(&r2, &a, &v_elem, ctx);
    check_fp6("mul_by_v==mul(a,v)", &r, &r2);

    /* v·v·v = v³ = ξ → three mul_by_v from 1 should give ξ */
    zkn_fp6_384_t one;
    zkn_fp6_384_one(&one, ctx);
    zkn_fp6_384_mul_by_v(&r, &one, ctx);     /* v */
    zkn_fp6_384_mul_by_v(&r, &r, ctx);       /* v² */
    zkn_fp6_384_mul_by_v(&r, &r, ctx);       /* v³ = ξ */
    zkn_fp6_384_t xi;
    fp2_from_ints(&xi.c0, 1, 1, ctx);
    zkn_fp2_384_zero(&xi.c1);
    zkn_fp2_384_zero(&xi.c2);
    check_fp6("v³=ξ (via 3× mul_by_v)", &r, &xi);
}

static void test_mul_by_fp2(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 mul_by_fp2 ---\n");

    zkn_fp6_384_t a, r;
    fp6_from_ints(&a, 2,1, 3,2, 5,4, ctx);
    zkn_fp2_384_t s;
    fp2_from_ints(&s, 7, 0, ctx);

    zkn_fp6_384_mul_by_fp2(&r, &a, &s, ctx);

    /* Expected: each Fp2 component × 7 */
    zkn_fp6_384_t expected;
    fp2_from_ints(&expected.c0, 14, 7, ctx);
    fp2_from_ints(&expected.c1, 21, 14, ctx);
    fp2_from_ints(&expected.c2, 35, 28, ctx);
    check_fp6("mul_by_fp2: a*7", &r, &expected);

    /* Cross-check: mul_by_fp2(a,s) = mul(a, (s,0,0)) */
    zkn_fp6_384_t s_fp6;
    zkn_fp2_384_copy(&s_fp6.c0, &s);
    zkn_fp2_384_zero(&s_fp6.c1);
    zkn_fp2_384_zero(&s_fp6.c2);
    zkn_fp6_384_t r2;
    zkn_fp6_384_mul(&r2, &a, &s_fp6, ctx);
    check_fp6("mul_by_fp2==mul(a,(s,0,0))", &r, &r2);
}

static void test_mul_by_01(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 mul_by_01 ---\n");

    zkn_fp6_384_t a;
    fp6_from_ints(&a, 2,1, 3,5, 7,2, ctx);

    zkn_fp2_384_t b0, b1;
    fp2_from_ints(&b0, 4, 1, ctx);
    fp2_from_ints(&b1, 6, 3, ctx);

    zkn_fp6_384_t r;
    zkn_fp6_384_mul_by_01(&r, &a, &b0, &b1, ctx);

    /* Cross-check: should equal mul(a, (b0, b1, 0)) */
    zkn_fp6_384_t b_sparse;
    zkn_fp2_384_copy(&b_sparse.c0, &b0);
    zkn_fp2_384_copy(&b_sparse.c1, &b1);
    zkn_fp2_384_zero(&b_sparse.c2);

    zkn_fp6_384_t r2;
    zkn_fp6_384_mul(&r2, &a, &b_sparse, ctx);
    check_fp6("mul_by_01==mul(a,(b0,b1,0))", &r, &r2);
}

static void test_mul_by_1(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 mul_by_1 ---\n");

    zkn_fp6_384_t a;
    fp6_from_ints(&a, 2,1, 3,5, 7,2, ctx);

    zkn_fp2_384_t b1;
    fp2_from_ints(&b1, 6, 3, ctx);

    zkn_fp6_384_t r;
    zkn_fp6_384_mul_by_1(&r, &a, &b1, ctx);

    /* Cross-check: should equal mul(a, (0, b1, 0)) */
    zkn_fp6_384_t b_sparse;
    zkn_fp2_384_zero(&b_sparse.c0);
    zkn_fp2_384_copy(&b_sparse.c1, &b1);
    zkn_fp2_384_zero(&b_sparse.c2);

    zkn_fp6_384_t r2;
    zkn_fp6_384_mul(&r2, &a, &b_sparse, ctx);
    check_fp6("mul_by_1==mul(a,(0,b1,0))", &r, &r2);
}

static void test_inv(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 inv ---\n");

    zkn_fp6_384_t one;
    zkn_fp6_384_one(&one, ctx);

    /* inv(1) = 1 */
    zkn_fp6_384_t r;
    zkn_fp6_384_inv(&r, &one, ctx);
    check_fp6("inv(1)=1", &r, &one);

    /* a * inv(a) = 1 */
    zkn_fp6_384_t a;
    fp6_from_ints(&a, 3,1, 5,2, 7,4, ctx);
    zkn_fp6_384_t inv_a, prod;
    zkn_fp6_384_inv(&inv_a, &a, ctx);
    zkn_fp6_384_mul(&prod, &a, &inv_a, ctx);
    check_fp6("a*inv(a)=1 [small]", &prod, &one);

    /* Another value */
    fp6_from_ints(&a, 11,13, 17,19, 23,29, ctx);
    zkn_fp6_384_inv(&inv_a, &a, ctx);
    zkn_fp6_384_mul(&prod, &a, &inv_a, ctx);
    check_fp6("a*inv(a)=1 [primes]", &prod, &one);

    /* inv(inv(a)) = a */
    zkn_fp6_384_t inv_inv_a;
    zkn_fp6_384_inv(&inv_inv_a, &inv_a, ctx);
    check_fp6("inv(inv(a))=a", &inv_inv_a, &a);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Random property tests (100 iterations)
 * ══════════════════════════════════════════════════════════════════════ */

static void test_random(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 random (100 iterations) ---\n");

    uint32_t seed = 0xCAFEBABE;
    const int N = 100;
    int pass_comm = 0, pass_dist = 0, pass_assoc = 0;
    int pass_sqr = 0, pass_inv = 0;
    int pass_mul01 = 0, pass_mul1 = 0;

    zkn_fp6_384_t one;
    zkn_fp6_384_one(&one, ctx);

    for (int i = 0; i < N; i++) {
        zkn_fp6_384_t a, b, c;
        random_fp6(&a, &seed, ctx);
        random_fp6(&b, &seed, ctx);
        random_fp6(&c, &seed, ctx);

        /* Commutativity: a*b = b*a */
        {
            zkn_fp6_384_t ab, ba;
            zkn_fp6_384_mul(&ab, &a, &b, ctx);
            zkn_fp6_384_mul(&ba, &b, &a, ctx);
            if (zkn_fp6_384_eq(&ab, &ba)) pass_comm++;
        }

        /* Distributivity: a*(b+c) = a*b + a*c */
        {
            zkn_fp6_384_t bc, lhs, ab, ac, rhs;
            zkn_fp6_384_add(&bc, &b, &c, ctx);
            zkn_fp6_384_mul(&lhs, &a, &bc, ctx);
            zkn_fp6_384_mul(&ab, &a, &b, ctx);
            zkn_fp6_384_mul(&ac, &a, &c, ctx);
            zkn_fp6_384_add(&rhs, &ab, &ac, ctx);
            if (zkn_fp6_384_eq(&lhs, &rhs)) pass_dist++;
        }

        /* Associativity: (a*b)*c = a*(b*c) */
        {
            zkn_fp6_384_t ab, ab_c, bc, a_bc;
            zkn_fp6_384_mul(&ab, &a, &b, ctx);
            zkn_fp6_384_mul(&ab_c, &ab, &c, ctx);
            zkn_fp6_384_mul(&bc, &b, &c, ctx);
            zkn_fp6_384_mul(&a_bc, &a, &bc, ctx);
            if (zkn_fp6_384_eq(&ab_c, &a_bc)) pass_assoc++;
        }

        /* sqr(a) == mul(a,a) */
        {
            zkn_fp6_384_t sq, mm;
            zkn_fp6_384_sqr(&sq, &a, ctx);
            zkn_fp6_384_mul(&mm, &a, &a, ctx);
            if (zkn_fp6_384_eq(&sq, &mm)) pass_sqr++;
        }

        /* a * inv(a) = 1 */
        {
            zkn_fp6_384_t inv_a, prod;
            zkn_fp6_384_inv(&inv_a, &a, ctx);
            zkn_fp6_384_mul(&prod, &a, &inv_a, ctx);
            if (zkn_fp6_384_eq(&prod, &one)) pass_inv++;
        }

        /* mul_by_01(a, b.c0, b.c1) == mul(a, (b.c0, b.c1, 0)) */
        {
            zkn_fp6_384_t fast, b_sparse, slow;
            zkn_fp2_384_t b0, b1;
            random_fp2(&b0, &seed, ctx);
            random_fp2(&b1, &seed, ctx);

            zkn_fp6_384_mul_by_01(&fast, &a, &b0, &b1, ctx);

            zkn_fp2_384_copy(&b_sparse.c0, &b0);
            zkn_fp2_384_copy(&b_sparse.c1, &b1);
            zkn_fp2_384_zero(&b_sparse.c2);
            zkn_fp6_384_mul(&slow, &a, &b_sparse, ctx);
            if (zkn_fp6_384_eq(&fast, &slow)) pass_mul01++;
        }

        /* mul_by_1(a, b1) == mul(a, (0, b1, 0)) */
        {
            zkn_fp6_384_t fast, b_sparse, slow;
            zkn_fp2_384_t b1;
            random_fp2(&b1, &seed, ctx);

            zkn_fp6_384_mul_by_1(&fast, &a, &b1, ctx);

            zkn_fp2_384_zero(&b_sparse.c0);
            zkn_fp2_384_copy(&b_sparse.c1, &b1);
            zkn_fp2_384_zero(&b_sparse.c2);
            zkn_fp6_384_mul(&slow, &a, &b_sparse, ctx);
            if (zkn_fp6_384_eq(&fast, &slow)) pass_mul1++;
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

    snprintf(buf, sizeof(buf), "random: mul_by_01 %d/%d", pass_mul01, N);
    check_bool(buf, pass_mul01 == N);

    snprintf(buf, sizeof(buf), "random: mul_by_1 %d/%d", pass_mul1, N);
    check_bool(buf, pass_mul1 == N);
}

/* ── Aliasing tests ────────────────────────────────────────────────── */

static void test_aliasing(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp6 aliasing ---\n");

    uint32_t seed = 0xDEADFACE;
    zkn_fp6_384_t a, b;
    random_fp6(&a, &seed, ctx);
    random_fp6(&b, &seed, ctx);

    /* mul in-place: r = a*b with r aliased to a */
    zkn_fp6_384_t expected, alias;
    zkn_fp6_384_mul(&expected, &a, &b, ctx);
    zkn_fp6_384_copy(&alias, &a);
    zkn_fp6_384_mul(&alias, &alias, &b, ctx);
    check_fp6("alias: mul(r,r,b)", &alias, &expected);

    /* sqr in-place */
    zkn_fp6_384_sqr(&expected, &a, ctx);
    zkn_fp6_384_copy(&alias, &a);
    zkn_fp6_384_sqr(&alias, &alias, ctx);
    check_fp6("alias: sqr(r,r)", &alias, &expected);

    /* inv in-place */
    zkn_fp6_384_inv(&expected, &a, ctx);
    zkn_fp6_384_copy(&alias, &a);
    zkn_fp6_384_inv(&alias, &alias, ctx);
    check_fp6("alias: inv(r,r)", &alias, &expected);

    /* mul_by_v in-place */
    zkn_fp6_384_mul_by_v(&expected, &a, ctx);
    zkn_fp6_384_copy(&alias, &a);
    zkn_fp6_384_mul_by_v(&alias, &alias, ctx);
    check_fp6("alias: mul_by_v(r,r)", &alias, &expected);

    /* add in-place: r = a+b with r=a */
    zkn_fp6_384_add(&expected, &a, &b, ctx);
    zkn_fp6_384_copy(&alias, &a);
    zkn_fp6_384_add(&alias, &alias, &b, ctx);
    check_fp6("alias: add(r,r,b)", &alias, &expected);

    /* sub in-place */
    zkn_fp6_384_sub(&expected, &a, &b, ctx);
    zkn_fp6_384_copy(&alias, &a);
    zkn_fp6_384_sub(&alias, &alias, &b, ctx);
    check_fp6("alias: sub(r,r,b)", &alias, &expected);

    /* mul_by_01 in-place */
    zkn_fp2_384_t b0, b1;
    random_fp2(&b0, &seed, ctx);
    random_fp2(&b1, &seed, ctx);
    zkn_fp6_384_mul_by_01(&expected, &a, &b0, &b1, ctx);
    zkn_fp6_384_copy(&alias, &a);
    zkn_fp6_384_mul_by_01(&alias, &alias, &b0, &b1, ctx);
    check_fp6("alias: mul_by_01(r,r,...)", &alias, &expected);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Main
 * ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("=== zkn_fp6_384 test suite (BLS12-381 Fp6) ===\n");
#ifdef ZKN_MONT384_ASM
    printf("    backend: ARM Thumb-2 ASM (Fp layer)\n");
#else
    printf("    backend: portable C\n");
#endif

    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();

    test_constructors(ctx);
    test_add_sub(ctx);
    test_mul(ctx);
    test_sqr(ctx);
    test_mul_by_v(ctx);
    test_mul_by_fp2(ctx);
    test_mul_by_01(ctx);
    test_mul_by_1(ctx);
    test_inv(ctx);
    test_random(ctx);
    test_aliasing(ctx);

    printf("\n=== Results: %d/%d passed ===\n",
           test_count - fail_count, test_count);

    return fail_count ? 1 : 0;
}
