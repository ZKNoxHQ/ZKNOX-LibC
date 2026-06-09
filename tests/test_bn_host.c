/* Host-only test — compiled solely by `make test` (which defines
 * ZKN_HOST_TESTS). The Ledger SDK app build sweeps every .c under the
 * submodule; without this guard it would try to compile this file with
 * zkn_bn_t = cx_bn_t (a handle, not an array) and fail. The guard makes
 * the file an empty translation unit in any non-host build. */
#ifdef ZKN_HOST_TESTS

/*
 * Regression tests for three SW backend bugs found while porting RAILGUN
 * to BACKEND=sw on Ledger:
 *
 *   1. zkn_bn_init ignored value_nbytes → read past end of buffer
 *   2. zkn_bn_alloc_init: same bug
 *   3. zkn_bn_reduce: single subtraction (incorrect when value > 2*modulus)
 *
 * Build:
 *   gcc -O0 -g -Wall test_zkn_bn_fixes.c zkn_bn_sw.c zkn_mont256.c -o tests
 *   ./tests
 */

#include "zkn_bn.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int tests_run = 0;
static int tests_failed = 0;

#define CHECK(cond, msg) do {                                                  \
    tests_run++;                                                               \
    if (cond) {                                                                \
        printf("  ✅ %s\n", msg);                                              \
    } else {                                                                   \
        printf("  ❌ %s\n", msg);                                              \
        tests_failed++;                                                        \
    }                                                                          \
} while (0)

static void print_bn(const char *label, const zkn_bn_t bn) {
    printf("    %s = ", label);
    for (int i = 7; i >= 0; i--) printf("%08x", bn[i]);
    printf("\n");
}

/* ============================================================ */
/*  Test 1: zkn_bn_init with full 32-byte BE value              */
/* ============================================================ */
static void test_init_full(void) {
    printf("\n── Test 1: zkn_bn_init with full 32 bytes ──\n");
    uint8_t value[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    zkn_bn_t x;
    zkn_bn_init(x, value, 32);
    /* Expected: x = 1 (LE limbs: x[0]=1, rest=0) */
    CHECK(x[0] == 1, "x[0] == 1");
    CHECK(x[1] == 0, "x[1] == 0");
    CHECK(x[7] == 0, "x[7] == 0");
}

/* ============================================================ */
/*  Test 2: zkn_bn_init with 16-byte BE value (lower half)      */
/*  This is the bug case — buggy SW would read past buffer.    */
/*  We use a stack canary to detect the bug if reintroduced.   */
/* ============================================================ */
static void test_init_short(void) {
    printf("\n── Test 2: zkn_bn_init with 16-byte value (RAILGUN scenario) ──\n");

    /* Stack layout: place a 16-byte canary immediately after the buffer
     * so that the buggy version would read it into x's low limbs. */
    struct {
        uint8_t value[16];
        uint8_t canary[16];
    } stk;

    /* Value = lower 128 bits of "1", BE encoded */
    memset(stk.value, 0, 16);
    stk.value[15] = 0x01;

    /* Canary = distinctive pattern */
    memset(stk.canary, 0xCA, 16);   /* 0xCACACA... */

    zkn_bn_t x;
    zkn_bn_init(x, stk.value, 16);

    /* Expected: x represents the integer 1 (the BE 16-byte value).
     * With the bug, x's lower 128 bits would be 0xCACACA... (the canary). */
    CHECK(x[0] == 1, "x[0] == 1  (buggy: would be 0xCACACACA)");
    CHECK(x[1] == 0, "x[1] == 0");
    CHECK(x[2] == 0, "x[2] == 0");
    CHECK(x[3] == 0, "x[3] == 0");
    CHECK(x[4] == 0, "x[4] == 0  (buggy: high limbs would hold the actual value)");
    CHECK(x[5] == 0, "x[5] == 0");
    CHECK(x[6] == 0, "x[6] == 0");
    CHECK(x[7] == 0, "x[7] == 0");
}

/* ============================================================ */
/*  Test 3: zkn_bn_init with 8-byte BE value (4MSM scenario)    */
/* ============================================================ */
static void test_init_very_short(void) {
    printf("\n── Test 3: zkn_bn_init with 8-byte value (4MSM scenario) ──\n");

    struct {
        uint8_t value[8];
        uint8_t canary[24];
    } stk;

    /* Value = 0x0123456789ABCDEF (BE 8 bytes) */
    stk.value[0] = 0x01; stk.value[1] = 0x23; stk.value[2] = 0x45; stk.value[3] = 0x67;
    stk.value[4] = 0x89; stk.value[5] = 0xAB; stk.value[6] = 0xCD; stk.value[7] = 0xEF;
    memset(stk.canary, 0xDE, 24);   /* 0xDEDEDE... */

    zkn_bn_t x;
    zkn_bn_init(x, stk.value, 8);

    /* Expected: x[0] = 0x89ABCDEF, x[1] = 0x01234567, rest = 0 */
    CHECK(x[0] == 0x89ABCDEF, "x[0] == 0x89ABCDEF");
    CHECK(x[1] == 0x01234567, "x[1] == 0x01234567");
    CHECK(x[2] == 0, "x[2] == 0  (buggy: would contain canary 0xDEDEDEDE)");
    CHECK(x[7] == 0, "x[7] == 0");
}

/* ============================================================ */
/*  Test 4: zkn_bn_alloc_init same as init (same bug)           */
/* ============================================================ */
static void test_alloc_init_short(void) {
    printf("\n── Test 4: zkn_bn_alloc_init with 16-byte value ──\n");

    struct {
        uint8_t value[16];
        uint8_t canary[16];
    } stk;
    memset(stk.value, 0, 16);
    stk.value[15] = 0x02;
    memset(stk.canary, 0xAB, 16);

    zkn_bn_t x;
    zkn_bn_alloc_init(&x, 32, stk.value, 16);

    CHECK(x[0] == 2, "x[0] == 2");
    CHECK(x[4] == 0, "x[4] == 0  (buggy: would contain canary)");
}

/* ============================================================ */
/*  Test 5: zkn_bn_reduce — value > 2*modulus                   */
/* ============================================================ */
static void test_reduce_large(void) {
    printf("\n── Test 5: zkn_bn_reduce with value > 2*modulus ──\n");

    /* BabyJubjub modulus p ~= 0.19 * 2^256 */
    zkn_bn_t p = {
        0xf0000001u, 0x43e1f593u, 0x79b97091u, 0x2833e848u,
        0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u
    };

    /* value = 0xFFFFFFFF...FF (max 256-bit) — about 5.27 * p */
    zkn_bn_t value;
    for (int i = 0; i < 8; i++) value[i] = 0xFFFFFFFFu;

    zkn_bn_t r;
    zkn_bn_reduce(r, value, p);

    /* Expected: r = (2^256 - 1) mod p */
    /* Compute expected: 2^256 - 1 = q*p + r where q is the quotient.
     *   2^256 = (q+1)*p - (p - 1 - 2^256 mod p)... well just check r < p. */

    int diff;
    zkn_bn_cmp(r, p, &diff);
    CHECK(diff < 0, "r < p  (buggy: single subtraction would leave r > p)");

    /* The exact value of 2^256-1 mod p is non-trivial to compute by hand;
     * the core property is that the single-subtraction bug would leave r > p,
     * which the `diff < 0` check above already catches. */
    print_bn("r =", r);

    /* Make sure r is not zero (it shouldn't be for value = 2^256-1) */
    int is_zero = 1;
    for (int i = 0; i < 8; i++) if (r[i] != 0) is_zero = 0;
    CHECK(!is_zero, "r != 0");
}

/* ============================================================ */
/*  Test 6: zkn_bn_reduce — value < modulus (should not change) */
/* ============================================================ */
static void test_reduce_small(void) {
    printf("\n── Test 6: zkn_bn_reduce with value < modulus (no-op) ──\n");

    zkn_bn_t p = {
        0xf0000001u, 0x43e1f593u, 0x79b97091u, 0x2833e848u,
        0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u
    };
    zkn_bn_t value = {42, 0, 0, 0, 0, 0, 0, 0};
    zkn_bn_t r;
    zkn_bn_reduce(r, value, p);

    CHECK(r[0] == 42, "r[0] == 42");
    CHECK(r[7] == 0, "r[7] == 0");
}

/* ============================================================ */
/*  Test 7: zkn_bn_reduce — value == modulus exactly            */
/* ============================================================ */
static void test_reduce_exact(void) {
    printf("\n── Test 7: zkn_bn_reduce with value == modulus ──\n");

    zkn_bn_t p = {
        0xf0000001u, 0x43e1f593u, 0x79b97091u, 0x2833e848u,
        0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u
    };
    zkn_bn_t r;
    zkn_bn_reduce(r, p, p);

    int is_zero = 1;
    for (int i = 0; i < 8; i++) if (r[i] != 0) is_zero = 0;
    CHECK(is_zero, "r == 0 (value mod itself == 0)");
}

/* ============================================================ */
/*  Test 8: zkn_bn_reduce — value = 0                           */
/* ============================================================ */
static void test_reduce_zero(void) {
    printf("\n── Test 8: zkn_bn_reduce with value == 0 ──\n");

    zkn_bn_t p = {
        0xf0000001u, 0x43e1f593u, 0x79b97091u, 0x2833e848u,
        0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u
    };
    zkn_bn_t value = {0};
    zkn_bn_t r;
    zkn_bn_reduce(r, value, p);

    int is_zero = 1;
    for (int i = 0; i < 8; i++) if (r[i] != 0) is_zero = 0;
    CHECK(is_zero, "r == 0");
}

int main(void) {
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Regression tests for SW backend bugs                         \n");
    printf("═══════════════════════════════════════════════════════════════\n");

    test_init_full();
    test_init_short();
    test_init_very_short();
    test_alloc_init_short();
    test_reduce_large();
    test_reduce_small();
    test_reduce_exact();
    test_reduce_zero();

    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("  Total: %d  Passed: %d  Failed: %d\n",
           tests_run, tests_run - tests_failed, tests_failed);
    printf("═══════════════════════════════════════════════════════════════\n");

    return tests_failed == 0 ? 0 : 1;
}

#endif /* ZKN_HOST_TESTS */
