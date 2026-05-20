/*
 * test_fp2_384.c — Test suite for zkn_fp2_384 (Fp2 = Fp[u]/(u²+1)) over BLS12-381
 *
 * Same structure as test_fp2.c (BN254 version), adapted for 384-bit field.
 *
 * Tests include:
 *   - Fp neg, exp, inv (prerequisites)
 *   - Fp2 add/sub/neg/conjugate
 *   - Fp2 mul (Karatsuba, hardcoded + random)
 *   - Fp2 sqr (consistency with mul)
 *   - Fp2 inv (a · a⁻¹ = 1)
 *   - Fp2 mul_by_xi (BLS12-381 non-residue ξ = 1+u)
 *   - Fp2 norm (a · conj(a) = norm)
 *   - PRNG random property tests (100 iterations each)
 *   - Aliasing tests
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include <stdio.h>
#include <string.h>
#include "zkn_fp2_384.h"

static int test_count = 0;
static int fail_count = 0;

/* ── Helpers ───────────────────────────────────────────────────────── */

static void print_fe(const char *label, const zkn_fe384_t a)
{
    printf("    %s = 0x", label);
    for (int i = ZKN_MONT384_NLIMBS - 1; i >= 0; i--)
        printf("%08x", a[i]);
    printf("\n");
}

static void print_fp2(const char *label, const zkn_fp2_384_t *a)
{
    printf("    %s.c0 = 0x", label);
    for (int i = ZKN_MONT384_NLIMBS - 1; i >= 0; i--) printf("%08x", a->c0[i]);
    printf("\n    %s.c1 = 0x", label);
    for (int i = ZKN_MONT384_NLIMBS - 1; i >= 0; i--) printf("%08x", a->c1[i]);
    printf("\n");
}

static void check_fe(const char *name,
                     const zkn_fe384_t got,
                     const zkn_fe384_t expected)
{
    test_count++;
    if (zkn_fe384_eq(got, expected)) {
        printf("[PASS] %s\n", name);
    } else {
        printf("[FAIL] %s\n", name);
        print_fe("expected", expected);
        print_fe("got     ", got);
        fail_count++;
    }
}

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

/* ── PRNG (xorshift32, deterministic) ──────────────────────────────── */

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

    /* Reduce mod p (at most 10 subtractions for 384-bit / 381-bit prime) */
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

/* ══════════════════════════════════════════════════════════════════════
 *  Part 1 — Fp base layer (neg, exp, inv)
 * ══════════════════════════════════════════════════════════════════════ */

static void test_fp_neg(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp neg/exp/inv ---\n");

    zkn_fe384_t r;

    /* neg(0) = 0 */
    zkn_fe384_t zero = {0};
    zkn_neg_mod_384(r, zero, ctx->p);
    check_fe("neg(0)=0", r, zero);

    /* neg(1) = p-1 */
    zkn_fe384_t one = {1};
    zkn_fe384_t pm1;
    memcpy(pm1, ctx->p, sizeof(zkn_fe384_t));
    pm1[0] -= 1;
    zkn_neg_mod_384(r, one, ctx->p);
    check_fe("neg(1)=p-1", r, pm1);

    /* a + neg(a) = 0 */
    zkn_fe384_t a = {0xdeadbeef, 0x12345678, 0xabcdef01, 0x00000042};
    zkn_fe384_t neg_a;
    zkn_neg_mod_384(neg_a, a, ctx->p);
    zkn_add_mod_384(r, a, neg_a, ctx->p);
    check_fe("a+neg(a)=0", r, zero);
}

static void test_fp_inv(const zkn_mont_ctx384_t *ctx)
{
    /* inv(1) = 1 */
    zkn_fe384_t r;
    zkn_inv_mont_384(r, ctx->one, ctx);
    check_fe("inv(1)=1", r, ctx->one);

    /* a * inv(a) = 1 for a = 7 */
    zkn_fe384_t a_n = {7};
    zkn_fe384_t a_m;
    zkn_to_mont_384(a_m, a_n, ctx);
    zkn_fe384_t inv_a;
    zkn_inv_mont_384(inv_a, a_m, ctx);
    zkn_mul_mont_384(r, a_m, inv_a, ctx->p, ctx->n0);
    check_fe("7*inv(7)=1", r, ctx->one);

    /* a * inv(a) = 1 for large value */
    zkn_fe384_t big = {
        0xfedcba98, 0x76543210, 0xdeadbeef, 0x13371337,
        0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0x11111111,
        0x99999999, 0x88888888, 0x77777777, 0x06060606
    };
    zkn_fe384_t big_m;
    zkn_to_mont_384(big_m, big, ctx);
    zkn_inv_mont_384(inv_a, big_m, ctx);
    zkn_mul_mont_384(r, big_m, inv_a, ctx->p, ctx->n0);
    check_fe("big*inv(big)=1", r, ctx->one);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Part 2 — Fp2 deterministic tests
 * ══════════════════════════════════════════════════════════════════════ */

static void test_fp2_constructors(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp2 constructors ---\n");

    zkn_fp2_384_t z, o;
    zkn_fp2_384_zero(&z);
    zkn_fp2_384_one(&o, ctx);

    check_bool("zero.c0=0", zkn_fe384_eq(z.c0, (zkn_fe384_t){0}));
    check_bool("zero.c1=0", zkn_fe384_eq(z.c1, (zkn_fe384_t){0}));
    check_bool("one.c0=mont(1)", zkn_fe384_eq(o.c0, ctx->one));
    check_bool("one.c1=0", zkn_fe384_eq(o.c1, (zkn_fe384_t){0}));
    check_bool("zero!=one", !zkn_fp2_384_eq(&z, &o));
}

static void test_fp2_add_sub(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp2 add/sub ---\n");

    /* (1+2u) + (3+4u) = (4+6u) */
    zkn_fp2_384_t a, b, r, expected;

    zkn_fe384_t n1 = {1}, n2 = {2}, n3 = {3}, n4 = {4};
    zkn_fe384_t n6 = {6};
    zkn_to_mont_384(a.c0, n1, ctx);
    zkn_to_mont_384(a.c1, n2, ctx);
    zkn_to_mont_384(b.c0, n3, ctx);
    zkn_to_mont_384(b.c1, n4, ctx);
    zkn_to_mont_384(expected.c0, n4, ctx);
    zkn_to_mont_384(expected.c1, n6, ctx);

    zkn_fp2_384_add(&r, &a, &b, ctx);
    check_fp2("(1+2u)+(3+4u)=(4+6u)", &r, &expected);

    /* (a+b)-b = a */
    zkn_fp2_384_sub(&r, &r, &b, ctx);
    check_fp2("(a+b)-b=a", &r, &a);

    /* a-a = 0 */
    zkn_fp2_384_t zero;
    zkn_fp2_384_zero(&zero);
    zkn_fp2_384_sub(&r, &a, &a, ctx);
    check_fp2("a-a=0", &r, &zero);
}

static void test_fp2_neg_conj(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp2 neg/conj ---\n");

    zkn_fp2_384_t a, r;
    zkn_fe384_t n5 = {5}, n7 = {7};
    zkn_to_mont_384(a.c0, n5, ctx);
    zkn_to_mont_384(a.c1, n7, ctx);

    /* a + neg(a) = 0 */
    zkn_fp2_384_t neg_a;
    zkn_fp2_384_neg(&neg_a, &a, ctx);
    zkn_fp2_384_add(&r, &a, &neg_a, ctx);
    zkn_fp2_384_t zero;
    zkn_fp2_384_zero(&zero);
    check_fp2("a+neg(a)=0", &r, &zero);

    /* conj(a) has same c0, negated c1 */
    zkn_fp2_384_t conj_a;
    zkn_fp2_384_conjugate(&conj_a, &a, ctx);
    check_bool("conj.c0=a.c0", zkn_fe384_eq(conj_a.c0, a.c0));

    zkn_fe384_t neg_c1;
    zkn_neg_mod_384(neg_c1, a.c1, ctx->p);
    check_bool("conj.c1=-a.c1", zkn_fe384_eq(conj_a.c1, neg_c1));
}

static void test_fp2_mul(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp2 mul ---\n");

    /*
     * (1 + 2u)(3 + 4u) = 3 + 4u + 6u + 8u²
     *                   = (3-8) + (4+6)u = -5 + 10u
     * In Fp: c0 = p-5, c1 = 10
     */
    zkn_fp2_384_t a, b, r, expected;
    zkn_fe384_t n1={1}, n2={2}, n3={3}, n4={4}, n10={10};
    zkn_fe384_t pm5;
    memcpy(pm5, ctx->p, sizeof(zkn_fe384_t));
    pm5[0] -= 5;

    zkn_to_mont_384(a.c0, n1, ctx);
    zkn_to_mont_384(a.c1, n2, ctx);
    zkn_to_mont_384(b.c0, n3, ctx);
    zkn_to_mont_384(b.c1, n4, ctx);
    zkn_to_mont_384(expected.c0, pm5, ctx);
    zkn_to_mont_384(expected.c1, n10, ctx);

    zkn_fp2_384_mul(&r, &a, &b, ctx);
    check_fp2("(1+2u)(3+4u)=(-5+10u)", &r, &expected);

    /* 1 * a = a */
    zkn_fp2_384_t one;
    zkn_fp2_384_one(&one, ctx);
    zkn_fp2_384_mul(&r, &a, &one, ctx);
    check_fp2("a*1=a", &r, &a);

    /* a * 0 = 0 */
    zkn_fp2_384_t zero;
    zkn_fp2_384_zero(&zero);
    zkn_fp2_384_mul(&r, &a, &zero, ctx);
    check_fp2("a*0=0", &r, &zero);
}

static void test_fp2_sqr(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp2 sqr ---\n");

    /*
     * (1 + 2u)² = 1 + 4u + 4u² = (1-4) + 4u = -3 + 4u
     */
    zkn_fp2_384_t a, r, expected;
    zkn_fe384_t n1={1}, n2={2}, n4={4};
    zkn_fe384_t pm3;
    memcpy(pm3, ctx->p, sizeof(zkn_fe384_t));
    pm3[0] -= 3;

    zkn_to_mont_384(a.c0, n1, ctx);
    zkn_to_mont_384(a.c1, n2, ctx);
    zkn_to_mont_384(expected.c0, pm3, ctx);
    zkn_to_mont_384(expected.c1, n4, ctx);

    zkn_fp2_384_sqr(&r, &a, ctx);
    check_fp2("(1+2u)²=(-3+4u)", &r, &expected);

    /* sqr(a) == mul(a,a) */
    zkn_fp2_384_t r2;
    zkn_fp2_384_mul(&r2, &a, &a, ctx);
    check_fp2("sqr(a)==mul(a,a)", &r, &r2);
}

static void test_fp2_inv(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp2 inv ---\n");

    /* inv(1+0u) = 1+0u */
    zkn_fp2_384_t one, r;
    zkn_fp2_384_one(&one, ctx);
    zkn_fp2_384_inv(&r, &one, ctx);
    check_fp2("inv(1)=1", &r, &one);

    /* (1+2u) · inv(1+2u) = 1 */
    zkn_fp2_384_t a, inv_a;
    zkn_fe384_t n1={1}, n2={2};
    zkn_to_mont_384(a.c0, n1, ctx);
    zkn_to_mont_384(a.c1, n2, ctx);

    zkn_fp2_384_inv(&inv_a, &a, ctx);
    zkn_fp2_384_mul(&r, &a, &inv_a, ctx);
    check_fp2("(1+2u)*inv(1+2u)=1", &r, &one);

    /* (3+7u) · inv(3+7u) = 1 */
    zkn_fe384_t n3={3}, n7={7};
    zkn_to_mont_384(a.c0, n3, ctx);
    zkn_to_mont_384(a.c1, n7, ctx);
    zkn_fp2_384_inv(&inv_a, &a, ctx);
    zkn_fp2_384_mul(&r, &a, &inv_a, ctx);
    check_fp2("(3+7u)*inv(3+7u)=1", &r, &one);
}

static void test_fp2_norm(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp2 norm ---\n");

    /* norm(3+4u) = 9+16 = 25 */
    zkn_fp2_384_t a;
    zkn_fe384_t n3={3}, n4={4}, n25={25};
    zkn_to_mont_384(a.c0, n3, ctx);
    zkn_to_mont_384(a.c1, n4, ctx);

    zkn_fe384_t norm, expected;
    zkn_fp2_384_norm(norm, &a, ctx);
    zkn_to_mont_384(expected, n25, ctx);
    check_fe("norm(3+4u)=25", norm, expected);

    /* a · conj(a) = norm(a)  (as Fp2: (norm, 0)) */
    zkn_fp2_384_t conj_a, prod;
    zkn_fp2_384_conjugate(&conj_a, &a, ctx);
    zkn_fp2_384_mul(&prod, &a, &conj_a, ctx);
    check_fe("a*conj(a).c0=norm", prod.c0, norm);
    check_fe("a*conj(a).c1=0", prod.c1, (zkn_fe384_t){0});
}

static void test_fp2_mul_by_xi(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp2 mul_by_xi (ξ=1+u) ---\n");

    /*
     * BLS12-381: ξ = 1 + u
     * (2 + 3u) · (1 + u) = 2 + 2u + 3u + 3u²
     *                     = (2-3) + (2+3)u = -1 + 5u
     */
    zkn_fp2_384_t a, r, expected;
    zkn_fe384_t n2={2}, n3={3}, n5={5};
    zkn_fe384_t pm1;
    memcpy(pm1, ctx->p, sizeof(zkn_fe384_t));
    pm1[0] -= 1;

    zkn_to_mont_384(a.c0, n2, ctx);
    zkn_to_mont_384(a.c1, n3, ctx);
    zkn_to_mont_384(expected.c0, pm1, ctx);
    zkn_to_mont_384(expected.c1, n5, ctx);

    zkn_fp2_384_mul_by_xi(&r, &a, ctx);
    check_fp2("(2+3u)·ξ=(-1+5u)", &r, &expected);

    /* Cross-check: mul_by_xi(a) == mul(a, xi) where xi = (1,1) */
    zkn_fp2_384_t xi;
    zkn_fe384_t n1={1};
    zkn_to_mont_384(xi.c0, n1, ctx);
    zkn_to_mont_384(xi.c1, n1, ctx);
    zkn_fp2_384_t r2;
    zkn_fp2_384_mul(&r2, &a, &xi, ctx);
    check_fp2("mul_by_xi==mul(a,xi)", &r, &r2);

    /* Another: (5+0u)·ξ = (5+5u) */
    zkn_fp2_384_t b;
    zkn_to_mont_384(b.c0, n5, ctx);
    zkn_fe384_zero(b.c1);
    zkn_fp2_384_mul_by_xi(&r, &b, ctx);
    zkn_fp2_384_t exp2;
    zkn_to_mont_384(exp2.c0, n5, ctx);
    zkn_to_mont_384(exp2.c1, n5, ctx);
    check_fp2("(5+0u)·ξ=(5+5u)", &r, &exp2);

    /* (0+1u)·ξ = (-1+1u) */
    zkn_fp2_384_t c;
    zkn_fe384_zero(c.c0);
    zkn_to_mont_384(c.c1, n1, ctx);
    zkn_fp2_384_mul_by_xi(&r, &c, ctx);
    zkn_fp2_384_t exp3;
    zkn_to_mont_384(exp3.c0, pm1, ctx);
    zkn_to_mont_384(exp3.c1, n1, ctx);
    check_fp2("(0+1u)·ξ=(-1+1u)", &r, &exp3);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Part 3 — Random property tests (100 iterations)
 * ══════════════════════════════════════════════════════════════════════ */

static void test_fp2_random(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp2 random (100 iterations) ---\n");

    uint32_t seed = 0xDEADBEEF;
    const int N = 100;
    int pass_comm = 0, pass_dist = 0, pass_sqr = 0;
    int pass_inv = 0, pass_assoc = 0, pass_xi = 0;

    zkn_fp2_384_t one;
    zkn_fp2_384_one(&one, ctx);

    /* ξ = (1, 1) for cross-check */
    zkn_fp2_384_t xi;
    zkn_fe384_t n1 = {1};
    zkn_to_mont_384(xi.c0, n1, ctx);
    zkn_to_mont_384(xi.c1, n1, ctx);

    for (int i = 0; i < N; i++) {
        zkn_fp2_384_t a, b, c;
        random_fp2(&a, &seed, ctx);
        random_fp2(&b, &seed, ctx);
        random_fp2(&c, &seed, ctx);

        /* Commutativity: a*b = b*a */
        {
            zkn_fp2_384_t ab, ba;
            zkn_fp2_384_mul(&ab, &a, &b, ctx);
            zkn_fp2_384_mul(&ba, &b, &a, ctx);
            if (zkn_fp2_384_eq(&ab, &ba)) pass_comm++;
        }

        /* Distributivity: a*(b+c) = a*b + a*c */
        {
            zkn_fp2_384_t bc, lhs, ab, ac, rhs;
            zkn_fp2_384_add(&bc, &b, &c, ctx);
            zkn_fp2_384_mul(&lhs, &a, &bc, ctx);
            zkn_fp2_384_mul(&ab, &a, &b, ctx);
            zkn_fp2_384_mul(&ac, &a, &c, ctx);
            zkn_fp2_384_add(&rhs, &ab, &ac, ctx);
            if (zkn_fp2_384_eq(&lhs, &rhs)) pass_dist++;
        }

        /* sqr(a) == mul(a,a) */
        {
            zkn_fp2_384_t sq, mm;
            zkn_fp2_384_sqr(&sq, &a, ctx);
            zkn_fp2_384_mul(&mm, &a, &a, ctx);
            if (zkn_fp2_384_eq(&sq, &mm)) pass_sqr++;
        }

        /* a * inv(a) = 1 */
        {
            zkn_fp2_384_t inv_a, prod;
            zkn_fp2_384_inv(&inv_a, &a, ctx);
            zkn_fp2_384_mul(&prod, &a, &inv_a, ctx);
            if (zkn_fp2_384_eq(&prod, &one)) pass_inv++;
        }

        /* Associativity: (a*b)*c = a*(b*c) */
        {
            zkn_fp2_384_t ab, ab_c, bc, a_bc;
            zkn_fp2_384_mul(&ab, &a, &b, ctx);
            zkn_fp2_384_mul(&ab_c, &ab, &c, ctx);
            zkn_fp2_384_mul(&bc, &b, &c, ctx);
            zkn_fp2_384_mul(&a_bc, &a, &bc, ctx);
            if (zkn_fp2_384_eq(&ab_c, &a_bc)) pass_assoc++;
        }

        /* mul_by_xi(a) == mul(a, xi) */
        {
            zkn_fp2_384_t fast, slow;
            zkn_fp2_384_mul_by_xi(&fast, &a, ctx);
            zkn_fp2_384_mul(&slow, &a, &xi, ctx);
            if (zkn_fp2_384_eq(&fast, &slow)) pass_xi++;
        }
    }

    char buf[80];

    snprintf(buf, sizeof(buf), "random: commutativity %d/%d", pass_comm, N);
    check_bool(buf, pass_comm == N);

    snprintf(buf, sizeof(buf), "random: distributivity %d/%d", pass_dist, N);
    check_bool(buf, pass_dist == N);

    snprintf(buf, sizeof(buf), "random: sqr==mul(a,a) %d/%d", pass_sqr, N);
    check_bool(buf, pass_sqr == N);

    snprintf(buf, sizeof(buf), "random: a*inv(a)=1 %d/%d", pass_inv, N);
    check_bool(buf, pass_inv == N);

    snprintf(buf, sizeof(buf), "random: associativity %d/%d", pass_assoc, N);
    check_bool(buf, pass_assoc == N);

    snprintf(buf, sizeof(buf), "random: mul_by_xi %d/%d", pass_xi, N);
    check_bool(buf, pass_xi == N);
}

/* ── Aliasing tests ────────────────────────────────────────────────── */

static void test_fp2_aliasing(const zkn_mont_ctx384_t *ctx)
{
    printf("\n--- Fp2 aliasing ---\n");

    uint32_t seed = 0x12345678;
    zkn_fp2_384_t a, b;
    random_fp2(&a, &seed, ctx);
    random_fp2(&b, &seed, ctx);

    /* mul in-place: a = a*b */
    zkn_fp2_384_t expected, alias;
    zkn_fp2_384_mul(&expected, &a, &b, ctx);
    zkn_fp2_384_copy(&alias, &a);
    zkn_fp2_384_mul(&alias, &alias, &b, ctx);
    check_fp2("alias: r=a, mul(r,r,b)", &alias, &expected);

    /* sqr in-place: a = a² */
    zkn_fp2_384_sqr(&expected, &a, ctx);
    zkn_fp2_384_copy(&alias, &a);
    zkn_fp2_384_sqr(&alias, &alias, ctx);
    check_fp2("alias: r=a, sqr(r,r)", &alias, &expected);

    /* inv in-place */
    zkn_fp2_384_inv(&expected, &a, ctx);
    zkn_fp2_384_copy(&alias, &a);
    zkn_fp2_384_inv(&alias, &alias, ctx);
    check_fp2("alias: r=a, inv(r,r)", &alias, &expected);

    /* mul_by_xi in-place */
    zkn_fp2_384_mul_by_xi(&expected, &a, ctx);
    zkn_fp2_384_copy(&alias, &a);
    zkn_fp2_384_mul_by_xi(&alias, &alias, ctx);
    check_fp2("alias: r=a, mul_by_xi(r,r)", &alias, &expected);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Main
 * ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("=== zkn_fp2_384 test suite (BLS12-381 Fp2) ===\n");
#ifdef ZKN_MONT384_ASM
    printf("    backend: ARM Thumb-2 ASM (Fp layer)\n");
#else
    printf("    backend: portable C\n");
#endif

    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();

    /* Fp prerequisites */
    test_fp_neg(ctx);
    test_fp_inv(ctx);

    /* Fp2 */
    test_fp2_constructors(ctx);
    test_fp2_add_sub(ctx);
    test_fp2_neg_conj(ctx);
    test_fp2_mul(ctx);
    test_fp2_sqr(ctx);
    test_fp2_inv(ctx);
    test_fp2_norm(ctx);
    test_fp2_mul_by_xi(ctx);
    test_fp2_random(ctx);
    test_fp2_aliasing(ctx);

    printf("\n=== Results: %d/%d passed ===\n",
           test_count - fail_count, test_count);

    return fail_count ? 1 : 0;
}
