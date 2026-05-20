/*
 * test_mul_by_014.c — Tests unitaires pour zkn_fp12_384_mul_by_014
 *
 * Principe : construire l'élément sparse b ∈ Fp12 tel que
 *   b.c0 = (b0, b1, 0)   [slots 0, 1, 2]
 *   b.c1 = ( 0, b4, 0)   [slots 3, 4, 5]
 * puis vérifier mul_by_014(f, b0, b1, b4) == mul(f, b).
 *
 * Tests :
 *   1. mul_by_014(1, b0,b1,b4) == sparse b  (f=1 : résultat = b)
 *   2. mul_by_014(f, b0,b1,b4) == mul(f, sparse(b0,b1,b4))  (random f)
 *   3. mul_by_014(f, 1,0,0)    == mul(f, (1,0,0,0,0,0))     (b1=b4=0)
 *   4. mul_by_014(f, 0,b1,0)   == mul_by_fp6_01 variant      (b0=b4=0)
 *   5. associativité :
 *      mul_by_014(mul_by_014(f,b0,b1,b4), c0,c1,c4)
 *      == mul(mul(f, sparse_b), sparse_c)
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include <stdio.h>
#include <string.h>

#include "zkn_mont384.h"
#include "zkn_fp2_384.h"
#include "zkn_fp6_384.h"
#include "zkn_fp12_384.h"

/* ── Helpers ──────────────────────────────────────────────────────── */

static int pass = 0, fail = 0;

static void check(const char *name, int ok)
{
    if (ok) { printf("  [PASS] %s\n", name); pass++; }
    else     { printf("  [FAIL] %s\n", name); fail++; }
}

/*
 * make_sparse_fp12 — construit l'élément Fp12 :
 *   c0 = (b0, b1, 0)
 *   c1 = ( 0, b4, 0)
 */
static void make_sparse_fp12(zkn_fp12_384_t *out,
                              const zkn_fp2_384_t *b0,
                              const zkn_fp2_384_t *b1,
                              const zkn_fp2_384_t *b4,
                              const zkn_mont_ctx384_t *ctx)
{
    zkn_fp6_384_zero(&out->c0);
    zkn_fp6_384_zero(&out->c1);

    if (b0) zkn_fp2_384_copy(&out->c0.c0, b0);
    if (b1) zkn_fp2_384_copy(&out->c0.c1, b1);
    if (b4) zkn_fp2_384_copy(&out->c1.c1, b4);

    (void)ctx;
}

/*
 * rand_fp2 — élément Fp2 déterministe à partir d'une graine
 * (simple, pas de sécurité, juste pour les tests)
 */
static void rand_fp2(zkn_fp2_384_t *r,
                     uint32_t seed,
                     const zkn_mont_ctx384_t *ctx)
{
    zkn_fe384_t v;
    unsigned i;

    /* Remplir v avec des mots pseudo-aléatoires simples */
    for (i = 0; i < ZKN_MONT384_NLIMBS; i++) {
        seed = seed * 1664525u + 1013904223u;
        v[i] = seed;
    }
    /* Réduire mod p via une multiplication Montgomery par 1 */
    zkn_to_mont_384(v, v, ctx);
    for (i = 0; i < ZKN_MONT384_NLIMBS; i++)
        r->c0[i] = v[i];

    for (i = 0; i < ZKN_MONT384_NLIMBS; i++) {
        seed = seed * 1664525u + 1013904223u;
        v[i] = seed;
    }
    zkn_to_mont_384(v, v, ctx);
    for (i = 0; i < ZKN_MONT384_NLIMBS; i++)
        r->c1[i] = v[i];
}

static void rand_fp12(zkn_fp12_384_t *r,
                      uint32_t seed,
                      const zkn_mont_ctx384_t *ctx)
{
    rand_fp2(&r->c0.c0, seed + 0,  ctx);
    rand_fp2(&r->c0.c1, seed + 1,  ctx);
    rand_fp2(&r->c0.c2, seed + 2,  ctx);
    rand_fp2(&r->c1.c0, seed + 3,  ctx);
    rand_fp2(&r->c1.c1, seed + 4,  ctx);
    rand_fp2(&r->c1.c2, seed + 5,  ctx);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void)
{
    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();
    zkn_fp12_384_t f, one, sparse, lhs, rhs;
    zkn_fp2_384_t  b0, b1, b4, c0, c1, c4, zero_fp2;
    int ok;

    printf("══ mul_by_014 unit tests ══\n\n");

    zkn_fp2_384_zero(&zero_fp2);
    zkn_fp12_384_one(&one, ctx);

    /* Coefficients b aléatoires */
    rand_fp2(&b0, 0x1111, ctx);
    rand_fp2(&b1, 0x2222, ctx);
    rand_fp2(&b4, 0x4444, ctx);

    /* Coefficients c pour test d'associativité */
    rand_fp2(&c0, 0xAAAA, ctx);
    rand_fp2(&c1, 0xBBBB, ctx);
    rand_fp2(&c4, 0xCCCC, ctx);

    /* f aléatoire */
    rand_fp12(&f, 0xDEAD, ctx);

    /* ── Test 1 : mul_by_014(1, b0,b1,b4) == sparse(b0,b1,b4) ── */
    zkn_fp12_384_copy(&lhs, &one);
    zkn_fp12_384_mul_by_014(&lhs, &lhs, &b0, &b1, &b4, ctx);

    make_sparse_fp12(&sparse, &b0, &b1, &b4, ctx);

    check("mul_by_014(1, b0,b1,b4) == sparse(b0,b1,b4)",
          zkn_fp12_384_eq(&lhs, &sparse));

    /* ── Test 2 : mul_by_014(f, b0,b1,b4) == mul(f, sparse) ── */
    zkn_fp12_384_copy(&lhs, &f);
    zkn_fp12_384_mul_by_014(&lhs, &lhs, &b0, &b1, &b4, ctx);

    make_sparse_fp12(&sparse, &b0, &b1, &b4, ctx);
    zkn_fp12_384_mul(&rhs, &f, &sparse, ctx);

    check("mul_by_014(f, b0,b1,b4) == mul(f, sparse(b0,b1,b4))",
          zkn_fp12_384_eq(&lhs, &rhs));

    /* ── Test 3 : b1=0, b4=0 → mul_by_014(f, b0,0,0) == mul(f, (b0,0,0,0,0,0)) ── */
    zkn_fp12_384_copy(&lhs, &f);
    zkn_fp12_384_mul_by_014(&lhs, &lhs, &b0, &zero_fp2, &zero_fp2, ctx);

    make_sparse_fp12(&sparse, &b0, NULL, NULL, ctx);
    zkn_fp12_384_mul(&rhs, &f, &sparse, ctx);

    check("mul_by_014(f, b0,0,0) == mul(f, sparse(b0,0,0))",
          zkn_fp12_384_eq(&lhs, &rhs));

    /* ── Test 4 : b0=0, b4=0 → mul_by_014(f, 0,b1,0) ── */
    zkn_fp12_384_copy(&lhs, &f);
    zkn_fp12_384_mul_by_014(&lhs, &lhs, &zero_fp2, &b1, &zero_fp2, ctx);

    make_sparse_fp12(&sparse, NULL, &b1, NULL, ctx);
    zkn_fp12_384_mul(&rhs, &f, &sparse, ctx);

    check("mul_by_014(f, 0,b1,0) == mul(f, sparse(0,b1,0))",
          zkn_fp12_384_eq(&lhs, &rhs));

    /* ── Test 5 : b0=0, b1=0 → mul_by_014(f, 0,0,b4) ── */
    zkn_fp12_384_copy(&lhs, &f);
    zkn_fp12_384_mul_by_014(&lhs, &lhs, &zero_fp2, &zero_fp2, &b4, ctx);

    make_sparse_fp12(&sparse, NULL, NULL, &b4, ctx);
    zkn_fp12_384_mul(&rhs, &f, &sparse, ctx);

    check("mul_by_014(f, 0,0,b4) == mul(f, sparse(0,0,b4))",
          zkn_fp12_384_eq(&lhs, &rhs));

    /* ── Test 6 : associativité ──
     *   mul_by_014(mul_by_014(f, b0,b1,b4), c0,c1,c4)
     *   == mul(mul(f, sparse_b), sparse_c)                         */
    {
        zkn_fp12_384_t sparse_b, sparse_c, ref;

        /* LHS : deux mul_by_014 chaînés */
        zkn_fp12_384_copy(&lhs, &f);
        zkn_fp12_384_mul_by_014(&lhs, &lhs, &b0, &b1, &b4, ctx);
        zkn_fp12_384_mul_by_014(&lhs, &lhs, &c0, &c1, &c4, ctx);

        /* RHS : deux mul génériques */
        make_sparse_fp12(&sparse_b, &b0, &b1, &b4, ctx);
        make_sparse_fp12(&sparse_c, &c0, &c1, &c4, ctx);
        zkn_fp12_384_mul(&ref,  &f,   &sparse_b, ctx);
        zkn_fp12_384_mul(&rhs,  &ref, &sparse_c, ctx);

        check("mul_by_014 x2 == mul(mul(f,b),c) (associativity)",
              zkn_fp12_384_eq(&lhs, &rhs));
    }

    /* ── Test 7 : linéarité en b ──
     *   mul_by_014(f, 2*b0, 2*b1, 2*b4) == 2 * mul_by_014(f, b0,b1,b4) ── */
    {
        zkn_fp2_384_t b0x2, b1x2, b4x2;
        zkn_fp12_384_t two_lhs;

        zkn_fp2_384_add(&b0x2, &b0, &b0, ctx);
        zkn_fp2_384_add(&b1x2, &b1, &b1, ctx);
        zkn_fp2_384_add(&b4x2, &b4, &b4, ctx);

        zkn_fp12_384_copy(&lhs, &f);
        zkn_fp12_384_mul_by_014(&lhs, &lhs, &b0x2, &b1x2, &b4x2, ctx);

        zkn_fp12_384_copy(&two_lhs, &f);
        zkn_fp12_384_mul_by_014(&two_lhs, &two_lhs, &b0, &b1, &b4, ctx);
        zkn_fp12_384_add(&rhs, &two_lhs, &two_lhs, ctx);

        check("mul_by_014(f, 2b0,2b1,2b4) == 2*mul_by_014(f, b0,b1,b4)",
              zkn_fp12_384_eq(&lhs, &rhs));
    }

    /* ── Test 8 : identité ── mul_by_014(f, 1,0,0) avec b = (1,0,0,0,0,0) ── */
    {
        zkn_fp2_384_t one_fp2;
        zkn_fp12_384_one(&one, ctx);

        /* b0 = 1 (Fp2 = 1 + 0·u) */
        zkn_fp2_384_one(&one_fp2, ctx);

        /* sparse avec b0=1 en slot 0, tout le reste 0 */
        make_sparse_fp12(&sparse, &one_fp2, NULL, NULL, ctx);
        zkn_fp12_384_mul(&rhs, &f, &sparse, ctx);

        zkn_fp12_384_copy(&lhs, &f);
        zkn_fp12_384_mul_by_014(&lhs, &lhs, &one_fp2, &zero_fp2, &zero_fp2, ctx);

        check("mul_by_014(f, 1_fp2, 0, 0) == mul(f, (1,0,0,0,0,0))",
              zkn_fp12_384_eq(&lhs, &rhs));
    }

    printf("\n══ Results: %d passed, %d failed ══\n", pass, fail);
    ok = (fail == 0);
    return ok ? 0 : 1;
}
