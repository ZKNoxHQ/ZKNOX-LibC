/*
 * test_mont384.c — Test suite for zkn_mont384 Montgomery arithmetic
 *
 * Same test structure as test_mont256.c, adapted for the
 * BLS12-381 base field Fp (384 bits, 12 limbs).
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "zkn_mont384.h"

static int test_count = 0;
static int fail_count = 0;

static void print_fe(const char *label, const zkn_fe384_t a)
{
    printf("  %s = 0x", label);
    for (int i = ZKN_MONT384_NLIMBS - 1; i >= 0; i--)
        printf("%08x", a[i]);
    printf("\n");
}

static void check_eq(const char *name,
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

/* ── BLS12-381 base field prime Fp ─────────────────────────────────── */
/*
 * p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf
 *       6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
 */
static const zkn_fe384_t BLS_P = {
    0xffffaaabu, 0xb9feffffu, 0xb153ffffu, 0x1eabfffeu,
    0xf6b0f624u, 0x6730d2a0u, 0xf38512bfu, 0x64774b84u,
    0x434bacd7u, 0x4b1ba7b6u, 0x397fe69au, 0x1a0111eau
};

/* ── Tests ──────────────────────────────────────────────────────────── */

static void test_n0(void)
{
    zkn_limb_t n0 = zkn_mont384_compute_n0(BLS_P[0]);
    zkn_limb_t check = n0 * BLS_P[0] + 1;
    test_count++;
    if (check == 0) {
        printf("[PASS] n0 computation (n0 = 0x%08x)\n", n0);
    } else {
        printf("[FAIL] n0: n0*p0+1 = 0x%08x\n", check);
        fail_count++;
    }
}

static void test_serialization(void)
{
    const uint8_t be_bytes[48] = {
        0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a,
        0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
        0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf,
        0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
        0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff,
        0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab
    };

    zkn_fe384_t loaded;
    zkn_fe384_from_be(loaded, be_bytes);
    check_eq("from_be: loads BLS12-381 p correctly", loaded, BLS_P);

    uint8_t exported[48];
    zkn_fe384_to_be(exported, BLS_P);
    test_count++;
    if (memcmp(exported, be_bytes, 48) == 0)
        printf("[PASS] to_be: exports correctly\n");
    else {
        printf("[FAIL] to_be: mismatch\n");
        fail_count++;
    }
}

static void test_ctx_init(void)
{
    zkn_mont_ctx384_t ctx;
    zkn_mont_ctx384_init(&ctx, BLS_P);

    /* mul(one, one) = one  ⟺  R·R·R⁻¹ = R */
    zkn_fe384_t r;
    zkn_mul_mont_384(r, ctx.one, ctx.one, ctx.p, ctx.n0);
    check_eq("ctx: mul(one,one) == one", r, ctx.one);

    /* from_mont(one) = 1 */
    zkn_from_mont_384(r, ctx.one, ctx.p, ctx.n0);
    zkn_fe384_t literal_one = {1};
    check_eq("ctx: from_mont(one) == 1", r, literal_one);

    /* Round-trip small value */
    zkn_fe384_t val = {42};
    zkn_fe384_t mont_val, back;
    zkn_to_mont_384(mont_val, val, &ctx);
    zkn_from_mont_384(back, mont_val, ctx.p, ctx.n0);
    check_eq("ctx: round-trip(42)", back, val);

    /* Round-trip large value */
    zkn_fe384_t val2 = {
        0xdeadbeef, 0x12345678, 0xabcdef01, 0x98765432,
        0x11111111, 0x22222222, 0x33333333, 0x01234567,
        0xfedcba98, 0x55555555, 0x77777777, 0x09abcdef
    };
    zkn_to_mont_384(mont_val, val2, &ctx);
    zkn_from_mont_384(back, mont_val, ctx.p, ctx.n0);
    check_eq("ctx: round-trip(large)", back, val2);
}

static void test_add(void)
{
    zkn_fe384_t r;

    zkn_fe384_t a = {3};
    zkn_fe384_t b = {5};
    zkn_fe384_t exp = {8};
    zkn_add_mod_384(r, a, b, BLS_P);
    check_eq("add: 3+5=8", r, exp);

    /* Wrap: (p-1) + 2 = 1 */
    zkn_fe384_t pm1; memcpy(pm1, BLS_P, 48); pm1[0] -= 1;
    zkn_fe384_t two = {2};
    zkn_fe384_t one = {1};
    zkn_add_mod_384(r, pm1, two, BLS_P);
    check_eq("add: (p-1)+2=1", r, one);

    /* p + 0 = 0 */
    zkn_fe384_t zero = {0};
    zkn_add_mod_384(r, BLS_P, zero, BLS_P);
    check_eq("add: p+0=0", r, zero);

    /* (p-1)+(p-1) = p-2 */
    zkn_fe384_t pm2; memcpy(pm2, BLS_P, 48); pm2[0] -= 2;
    zkn_add_mod_384(r, pm1, pm1, BLS_P);
    check_eq("add: (p-1)+(p-1)=p-2", r, pm2);
}

static void test_sub(void)
{
    zkn_fe384_t r;

    zkn_fe384_t a = {10};
    zkn_fe384_t b = {3};
    zkn_fe384_t exp = {7};
    zkn_sub_mod_384(r, a, b, BLS_P);
    check_eq("sub: 10-3=7", r, exp);

    /* 0 - 1 = p-1 */
    zkn_fe384_t zero = {0};
    zkn_fe384_t one = {1};
    zkn_fe384_t pm1; memcpy(pm1, BLS_P, 48); pm1[0] -= 1;
    zkn_sub_mod_384(r, zero, one, BLS_P);
    check_eq("sub: 0-1=p-1", r, pm1);

    /* a - a = 0 */
    zkn_sub_mod_384(r, a, a, BLS_P);
    check_eq("sub: a-a=0", r, zero);

    /* (a+b)-b = a */
    zkn_fe384_t t;
    zkn_add_mod_384(t, a, b, BLS_P);
    zkn_sub_mod_384(r, t, b, BLS_P);
    check_eq("sub: (a+b)-b=a", r, a);
}

static void test_mul_mont(void)
{
    zkn_mont_ctx384_t ctx;
    zkn_mont_ctx384_init(&ctx, BLS_P);
    zkn_fe384_t r;

    /* 1 * 1 = 1 */
    zkn_mul_mont_384(r, ctx.one, ctx.one, ctx.p, ctx.n0);
    check_eq("mul: 1*1=1", r, ctx.one);

    /* a * 1 = a */
    zkn_fe384_t a_n = {7};
    zkn_fe384_t a_m; zkn_to_mont_384(a_m, a_n, &ctx);
    zkn_mul_mont_384(r, a_m, ctx.one, ctx.p, ctx.n0);
    check_eq("mul: a*1=a", r, a_m);

    /* 7 * 3 = 21 */
    zkn_fe384_t b_n = {3};
    zkn_fe384_t b_m; zkn_to_mont_384(b_m, b_n, &ctx);
    zkn_fe384_t prod;
    zkn_mul_mont_384(prod, a_m, b_m, ctx.p, ctx.n0);
    zkn_from_mont_384(r, prod, ctx.p, ctx.n0);
    zkn_fe384_t exp21 = {21};
    check_eq("mul: 7*3=21", r, exp21);

    /* a * 0 = 0 */
    zkn_fe384_t zero = {0}, zero_m;
    zkn_to_mont_384(zero_m, zero, &ctx);
    zkn_mul_mont_384(r, a_m, zero_m, ctx.p, ctx.n0);
    zkn_from_mont_384(r, r, ctx.p, ctx.n0);
    check_eq("mul: a*0=0", r, zero);

    /* (-1)*(-1) = 1 */
    zkn_fe384_t pm1; memcpy(pm1, BLS_P, 48); pm1[0] -= 1;
    zkn_fe384_t pm1_m; zkn_to_mont_384(pm1_m, pm1, &ctx);
    zkn_mul_mont_384(r, pm1_m, pm1_m, ctx.p, ctx.n0);
    zkn_from_mont_384(r, r, ctx.p, ctx.n0);
    zkn_fe384_t one = {1};
    check_eq("mul: (p-1)^2=1", r, one);

    /* Distributivity: a*(b+c) = a*b + a*c */
    zkn_fe384_t c_n = {0xdeadbeef, 0x12345678};
    zkn_fe384_t c_m; zkn_to_mont_384(c_m, c_n, &ctx);
    zkn_fe384_t bc_sum; zkn_add_mod_384(bc_sum, b_m, c_m, ctx.p);
    zkn_fe384_t lhs; zkn_mul_mont_384(lhs, a_m, bc_sum, ctx.p, ctx.n0);
    zkn_fe384_t ab, ac, rhs;
    zkn_mul_mont_384(ab, a_m, b_m, ctx.p, ctx.n0);
    zkn_mul_mont_384(ac, a_m, c_m, ctx.p, ctx.n0);
    zkn_add_mod_384(rhs, ab, ac, ctx.p);
    check_eq("mul: a*(b+c)=a*b+a*c", lhs, rhs);
}

static void test_sqr(void)
{
    zkn_mont_ctx384_t ctx;
    zkn_mont_ctx384_init(&ctx, BLS_P);

    zkn_fe384_t a_n = {
        0xfedcba98, 0x76543210, 0xdeadbeef, 0x13371337,
        0xaaaaaaaa, 0xbbbbbbbb, 0xcccccccc, 0x11111111,
        0x99999999, 0x88888888, 0x77777777, 0x06060606
    };
    zkn_fe384_t a_m; zkn_to_mont_384(a_m, a_n, &ctx);

    zkn_fe384_t sq, mul;
    zkn_sqr_mont_384(sq, a_m, ctx.p, ctx.n0);
    zkn_mul_mont_384(mul, a_m, a_m, ctx.p, ctx.n0);
    check_eq("sqr: sqr(a)==mul(a,a)", sq, mul);
}

static void test_redc(void)
{
    zkn_mont_ctx384_t ctx;
    zkn_mont_ctx384_init(&ctx, BLS_P);

    zkn_fe384_t a_m;
    zkn_fe384_t val42 = {42};
    zkn_to_mont_384(a_m, val42, &ctx);

    zkn_wide384_t wide = {0};
    memcpy(wide, a_m, sizeof(zkn_fe384_t));

    zkn_fe384_t r1, r2;
    zkn_redc_mont_384(r1, wide, ctx.p, ctx.n0);
    zkn_from_mont_384(r2, a_m, ctx.p, ctx.n0);
    check_eq("redc: redc(a||0)==from_mont(a)", r1, r2);
}

static void test_edge_cases(void)
{
    zkn_mont_ctx384_t ctx;
    zkn_mont_ctx384_init(&ctx, BLS_P);

    zkn_fe384_t zero = {0}, zero_m, back;
    zkn_to_mont_384(zero_m, zero, &ctx);
    check_eq("edge: to_mont(0)=0", zero_m, zero);
    zkn_from_mont_384(back, zero_m, ctx.p, ctx.n0);
    check_eq("edge: from_mont(0)=0", back, zero);

    /* cmov */
    zkn_fe384_t a = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    zkn_fe384_t b = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120};
    zkn_fe384_t c; memcpy(c, a, 48);
    zkn_fe384_cmov(c, b, 0);
    check_eq("cmov: flag=0 no-op", c, a);
    zkn_fe384_cmov(c, b, 1);
    check_eq("cmov: flag=1 moved", c, b);

    /* eq */
    test_count++;
    if (zkn_fe384_eq(a, a) && !zkn_fe384_eq(a, b))
        printf("[PASS] eq: a==a, a!=b\n");
    else {
        printf("[FAIL] eq\n");
        fail_count++;
    }
}

static void test_fermat(void)
{
    zkn_mont_ctx384_t ctx;
    zkn_mont_ctx384_init(&ctx, BLS_P);

    zkn_fe384_t a_n = {7};
    zkn_fe384_t base; zkn_to_mont_384(base, a_n, &ctx);

    /* p-1 in big-endian */
    zkn_fe384_t pm1; memcpy(pm1, BLS_P, 48); pm1[0] -= 1;
    uint8_t pm1_be[48];
    zkn_fe384_to_be(pm1_be, pm1);

    zkn_fe384_t result;
    zkn_exp_mont_384(result, base, pm1_be, 48, &ctx);

    zkn_fe384_t r;
    zkn_from_mont_384(r, result, ctx.p, ctx.n0);
    zkn_fe384_t one = {1};
    check_eq("Fermat: 7^(p-1)=1", r, one);
}

static void test_bls12381_field(void)
{
    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();

    /* BLS12-381 G1 generator x-coordinate */
    const uint8_t gx_be[48] = {
        0x17, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94,
        0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
        0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05,
        0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
        0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef,
        0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb
    };

    zkn_fe384_t gx; zkn_fe384_from_be(gx, gx_be);
    zkn_fe384_t gx_m, gx2_m, gx2;
    zkn_to_mont_384(gx_m, gx, ctx);
    zkn_sqr_mont_384(gx2_m, gx_m, ctx->p, ctx->n0);
    zkn_from_mont_384(gx2, gx2_m, ctx->p, ctx->n0);

    /* sqr == mul */
    zkn_fe384_t gx2_via_mul;
    zkn_mul_mont_384(gx2_via_mul, gx_m, gx_m, ctx->p, ctx->n0);
    check_eq("bls: sqr(Gx)==mul(Gx,Gx)", gx2_m, gx2_via_mul);

    /* Gx*(Gx+1) = Gx^2 + Gx */
    zkn_fe384_t gx_plus_1;
    zkn_add_mod_384(gx_plus_1, gx_m, ctx->one, ctx->p);
    zkn_fe384_t lhs;
    zkn_mul_mont_384(lhs, gx_m, gx_plus_1, ctx->p, ctx->n0);
    zkn_fe384_t rhs;
    zkn_add_mod_384(rhs, gx2_m, gx_m, ctx->p);
    check_eq("bls: Gx*(Gx+1)=Gx^2+Gx", lhs, rhs);

    /* Inversion: Gx * Gx^{-1} = 1 */
    zkn_fe384_t gx_inv;
    zkn_inv_mont_384(gx_inv, gx_m, ctx);
    zkn_fe384_t prod;
    zkn_mul_mont_384(prod, gx_m, gx_inv, ctx->p, ctx->n0);
    check_eq("bls: Gx*Gx^{-1}=1", prod, ctx->one);

    /* Print Gx^2 for reference */
    printf("    Gx^2 = 0x");
    uint8_t gx2_be[48]; zkn_fe384_to_be(gx2_be, gx2);
    for (int i = 0; i < 48; i++) printf("%02x", gx2_be[i]);
    printf("\n");
}

/* ══════════════════════════════════════════════════════════════════════
 *  NEW: Large-value arithmetic tests
 *  All values are hand-picked 384-bit field elements (smaller than p)
 *  expressed in normal (non-Montgomery) representation.
 * ══════════════════════════════════════════════════════════════════════ */

/*
 * Three distinct large elements of BLS12-381 Fp:
 *   A ≈ p/3,  B ≈ 2p/3,  C close to p with varied bit pattern.
 * All verified < p and expressed as 12-limb LE arrays.
 *
 * A = 0x08ab56c6f52ee5b2ef4e0c52c27ab01568ad23428fd8a8bfe70e3a09a8d2ac5b5c9fb6bc4aef00000
 *   (big-endian 48 bytes below)
 */
static const uint8_t BIG_A_BE[48] = {
    0x08,0xab,0x56,0xc6,0xf5,0x2e,0xe5,0xb2,
    0xef,0x4e,0x0c,0x52,0xc2,0x7a,0xb0,0x15,
    0x68,0xad,0x23,0x42,0x8f,0xd8,0xa8,0xbf,
    0xe7,0x0e,0x3a,0x09,0xa8,0xd2,0xac,0x5b,
    0x5c,0x9f,0xb6,0xbc,0x4a,0xef,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const uint8_t BIG_B_BE[48] = {
    0x11,0x56,0xac,0x8d,0xea,0x5c,0xcb,0x64,
    0xde,0x9c,0x18,0xa5,0x84,0xf5,0x60,0x2a,
    0xd1,0x5a,0x46,0x85,0x1f,0xb1,0x51,0x7f,
    0xce,0x1c,0x74,0x13,0x50,0xa5,0x58,0xb6,
    0xb9,0x3f,0x6d,0x78,0x95,0xde,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};

static const uint8_t BIG_C_BE[48] = {
    0x19,0xff,0xfe,0xa3,0xd4,0xf3,0xe8,0x71,
    0x2b,0x3c,0x7a,0xf6,0x42,0xfe,0x87,0x12,
    0xc4,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
    0xb9,0xfe,0xff,0xff,0xff,0xff,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static void test_add_large(void)
{
    printf("\n--- add / sub with large values ---\n");
    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();
    zkn_fe384_t A, B, C;
    zkn_fe384_from_be(A, BIG_A_BE);
    zkn_fe384_from_be(B, BIG_B_BE);
    zkn_fe384_from_be(C, BIG_C_BE);

    zkn_fe384_t r, t;

    /* A + B - B = A  (mod p) */
    zkn_add_mod_384(t, A, B, ctx->p);
    zkn_sub_mod_384(r, t, B, ctx->p);
    check_eq("large: (A+B)-B=A", r, A);

    /* A - A = 0 */
    zkn_fe384_t zero = {0};
    zkn_sub_mod_384(r, A, A, ctx->p);
    check_eq("large: A-A=0", r, zero);

    /* commutativity: A+B = B+A */
    zkn_fe384_t ab, ba;
    zkn_add_mod_384(ab, A, B, ctx->p);
    zkn_add_mod_384(ba, B, A, ctx->p);
    check_eq("large: A+B=B+A", ab, ba);

    /* associativity: (A+B)+C = A+(B+C) */
    zkn_fe384_t lhs, rhs;
    zkn_add_mod_384(t, A, B, ctx->p);
    zkn_add_mod_384(lhs, t, C, ctx->p);
    zkn_add_mod_384(t, B, C, ctx->p);
    zkn_add_mod_384(rhs, A, t, ctx->p);
    check_eq("large: (A+B)+C=A+(B+C)", lhs, rhs);

    /* C + (p - C) = 0 — large wrap */
    zkn_fe384_t neg_C;
    zkn_neg_mod_384(neg_C, C, ctx->p);
    zkn_add_mod_384(r, C, neg_C, ctx->p);
    check_eq("large: C+(-C)=0", r, zero);
}

static void test_mul_large(void)
{
    printf("\n--- mul / sqr with large values ---\n");
    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();
    zkn_fe384_t A, B, C;
    zkn_fe384_from_be(A, BIG_A_BE);
    zkn_fe384_from_be(B, BIG_B_BE);
    zkn_fe384_from_be(C, BIG_C_BE);

    /* Convert to Montgomery */
    zkn_fe384_t Am, Bm, Cm;
    zkn_to_mont_384(Am, A, ctx);
    zkn_to_mont_384(Bm, B, ctx);
    zkn_to_mont_384(Cm, C, ctx);

    zkn_fe384_t r;

    /* commutativity: A*B = B*A */
    zkn_fe384_t ab, ba;
    zkn_mul_mont_384(ab, Am, Bm, ctx->p, ctx->n0);
    zkn_mul_mont_384(ba, Bm, Am, ctx->p, ctx->n0);
    check_eq("large: A*B=B*A (mont)", ab, ba);

    /* A * 1 = A */
    zkn_mul_mont_384(r, Am, ctx->one, ctx->p, ctx->n0);
    check_eq("large: A*1=A (mont)", r, Am);

    /* sqr(A) == mul(A,A) */
    zkn_fe384_t sq, mm;
    zkn_sqr_mont_384(sq, Am, ctx->p, ctx->n0);
    zkn_mul_mont_384(mm, Am, Am, ctx->p, ctx->n0);
    check_eq("large: sqr(A)==mul(A,A)", sq, mm);

    /* sqr(B) == mul(B,B) */
    zkn_sqr_mont_384(sq, Bm, ctx->p, ctx->n0);
    zkn_mul_mont_384(mm, Bm, Bm, ctx->p, ctx->n0);
    check_eq("large: sqr(B)==mul(B,B)", sq, mm);

    /* sqr(C) == mul(C,C) */
    zkn_sqr_mont_384(sq, Cm, ctx->p, ctx->n0);
    zkn_mul_mont_384(mm, Cm, Cm, ctx->p, ctx->n0);
    check_eq("large: sqr(C)==mul(C,C)", sq, mm);

    /* associativity: (A*B)*C = A*(B*C) */
    zkn_fe384_t lhs, rhs, t;
    zkn_mul_mont_384(t, Am, Bm, ctx->p, ctx->n0);
    zkn_mul_mont_384(lhs, t, Cm, ctx->p, ctx->n0);
    zkn_mul_mont_384(t, Bm, Cm, ctx->p, ctx->n0);
    zkn_mul_mont_384(rhs, Am, t, ctx->p, ctx->n0);
    check_eq("large: (A*B)*C=A*(B*C)", lhs, rhs);

    /* distributivity: A*(B+C) = A*B + A*C (in mont form) */
    zkn_fe384_t bc_sum, dist_lhs, ab_prod, ac_prod, dist_rhs;
    zkn_add_mod_384(bc_sum, Bm, Cm, ctx->p);
    zkn_mul_mont_384(dist_lhs, Am, bc_sum, ctx->p, ctx->n0);
    zkn_mul_mont_384(ab_prod, Am, Bm, ctx->p, ctx->n0);
    zkn_mul_mont_384(ac_prod, Am, Cm, ctx->p, ctx->n0);
    zkn_add_mod_384(dist_rhs, ab_prod, ac_prod, ctx->p);
    check_eq("large: A*(B+C)=A*B+A*C", dist_lhs, dist_rhs);

    /* inversion: A * inv(A) = 1 */
    zkn_fe384_t inv_A;
    zkn_inv_mont_384(inv_A, Am, ctx);
    zkn_mul_mont_384(r, Am, inv_A, ctx->p, ctx->n0);
    check_eq("large: A*inv(A)=1", r, ctx->one);

    /* inversion: B * inv(B) = 1 */
    zkn_fe384_t inv_B;
    zkn_inv_mont_384(inv_B, Bm, ctx);
    zkn_mul_mont_384(r, Bm, inv_B, ctx->p, ctx->n0);
    check_eq("large: B*inv(B)=1", r, ctx->one);
}

/* ── Main ───────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== zkn_mont384 test suite (BLS12-381 Fp) ===\n");
#ifdef ZKN_MONT384_ASM
    printf("    backend: ARM Thumb-2 ASM\n");
#else
    printf("    backend: portable C\n");
#endif
    printf("\n");

    test_n0();
    test_serialization();
    test_ctx_init();
    test_add();
    test_sub();
    test_mul_mont();
    test_sqr();
    test_redc();
    test_edge_cases();
    test_fermat();
    test_bls12381_field();

    /* ── NEW: large-value tests ── */
    test_add_large();
    test_mul_large();

    printf("\n=== Results: %d/%d passed ===\n",
           test_count - fail_count, test_count);

    return fail_count ? 1 : 0;
}
