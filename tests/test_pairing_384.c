/*
 * test_pairing_384.c — Bilinearity tests for BLS12-381 optimal ate pairing
 *
 * Tests performed:
 *   1. e(G1, G2) != 1            (non-degeneracy)
 *   2. e(aP, Q)  == e(P, aQ)     (bilinearity G1)
 *   3. e(P, bQ)  == e(aP,Q)^?   via e(aP, bQ) == e(P,Q)^{ab}
 *   4. e(2P, Q)  == e(P,Q)²     (bilinearity, doubling)
 *   5. e(P+P, Q) == e(P,Q)*e(P,Q)  (via two Miller loops, one final_exp)
 *   6. e(-P, Q)  == conj(e(P,Q))   (negation)
 *   7. e(O, Q)   == 1, e(P, O) == 1 (identity guard)
 *
 * Scalars used: a = 2, b = 3, ab = 6  (small, no secret)
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include <stdio.h>
#include <string.h>

#include "zkn_mont384.h"
#include "zkn_g1_384.h"
#include "zkn_g2_384.h"
#include "zkn_fp12_384.h"
#include "zkn_pairing_384.h"    /* zkn_miller_doubling/addition_step     */
#include "zkn_miller.h"         /* zkn_miller_loop, zkn_miller_loop_n    */
#include "zkn_final_exp_384.h"  /* zkn_final_exp, zkn_pairing            */

/* ── Helpers ──────────────────────────────────────────────────────── */

static int pass = 0, fail = 0;

static void check(const char *name, int ok)
{
    if (ok) { printf("  [PASS] %s\n", name); pass++; }
    else     { printf("  [FAIL] %s\n", name); fail++; }
}

/* scalar_be: big-endian 48-byte encoding of a small integer */
static void scalar_be(uint8_t buf[48], uint64_t v)
{
    memset(buf, 0, 48);
    buf[47] = (uint8_t)(v & 0xff);
    buf[46] = (uint8_t)((v >> 8) & 0xff);
    buf[45] = (uint8_t)((v >> 16) & 0xff);
    buf[44] = (uint8_t)((v >> 24) & 0xff);
    buf[43] = (uint8_t)((v >> 32) & 0xff);
    buf[42] = (uint8_t)((v >> 40) & 0xff);
    buf[41] = (uint8_t)((v >> 48) & 0xff);
    buf[40] = (uint8_t)((v >> 56) & 0xff);
}

/* fp12_is_one: true iff f == 1 in GT */
static int fp12_is_one(const zkn_fp12_384_t *f,
                       const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_t one;
    zkn_fp12_384_one(&one, ctx);
    return zkn_fp12_384_eq(f, &one);
}

/* ── Main ─────────────────────────────────────────────────────────── */

int main(void)
{
    const zkn_mont_ctx384_t *ctx = zkn_bls12381_ctx();
    zkn_g1_384_t  G1, P2, P3, P6, Pneg, O1;
    zkn_g2_384_t  G2, Q2, Q3, Q6, O2;
    zkn_fp12_384_t eGG, e2G, eG2, e2G_b, eGb2, e6G, eGm, tmp, prod, one;
    uint8_t sc[48];
    int ok;

    printf("══ Pairing BLS12-381 — bilinearity tests ══\n\n");

    /* ── Context: BLS12-381 prime p ── */
    /* ── Base points ── */
    zkn_g1_384_generator(&G1, ctx);
    zkn_g2_384_generator(&G2, ctx);

    /* ── Scalar multiples ──
     *   a = 2, b = 3, ab = 6
     */
    scalar_be(sc, 2);
    zkn_g1_384_mul(&P2, &G1, sc, 48, ctx);   /* 2·G1 */
    zkn_g2_384_mul(&Q2, &G2, sc, 48, ctx);   /* 2·G2 */

    scalar_be(sc, 3);
    zkn_g1_384_mul(&P3, &G1, sc, 48, ctx);   /* 3·G1 */
    zkn_g2_384_mul(&Q3, &G2, sc, 48, ctx);   /* 3·G2 */

    scalar_be(sc, 6);
    zkn_g1_384_mul(&P6, &G1, sc, 48, ctx);   /* 6·G1 */
    zkn_g2_384_mul(&Q6, &G2, sc, 48, ctx);   /* 6·G2 */

    /* ── Negation ── */
    zkn_g1_384_neg(&Pneg, &G1, ctx);          /* −G1 */

    /* ── Identity points (Z=0) ── */
    zkn_g1_384_zero(&O1);
    zkn_g2_384_zero(&O2);

    /* ── Reference: e(G1, G2) ── */
    zkn_pairing(&eGG, &G1, &G2, ctx);

    /* ── One ── */
    zkn_fp12_384_one(&one, ctx);

    /* ── Test 1: non-degeneracy ── */
    check("e(G1,G2) != 1",
          !zkn_fp12_384_eq(&eGG, &one));

    /* ── Test 2: e(2P, Q) == e(P, 2Q) ── */
    zkn_pairing(&e2G,  &P2, &G2, ctx);
    zkn_pairing(&eG2,  &G1, &Q2, ctx);
    check("e(2G1, G2) == e(G1, 2G2)",
          zkn_fp12_384_eq(&e2G, &eG2));

    /* ── Test 3: e(2P, Q) == e(G1,G2)² ── */
    zkn_fp12_384_sqr(&tmp, &eGG, ctx);
    check("e(2G1, G2) == e(G1,G2)²",
          zkn_fp12_384_eq(&e2G, &tmp));

    /* ── Test 4: e(2P, 3Q) == e(G1,G2)^6 == e(6G1, G2) ── */
    zkn_pairing(&e2G_b, &P2, &Q3, ctx);   /* e(2G1, 3G2) */
    zkn_pairing(&e6G,   &P6, &G2, ctx);   /* e(6G1,  G2) */
    check("e(2G1, 3G2) == e(6G1, G2)",
          zkn_fp12_384_eq(&e2G_b, &e6G));

    /* ── Test 5: e(3P, 2Q) == e(2P, 3Q) ── */
    zkn_pairing(&eGb2, &P3, &Q2, ctx);
    check("e(3G1, 2G2) == e(2G1, 3G2)",
          zkn_fp12_384_eq(&eGb2, &e2G_b));

    /* ── Test 6: e(P+P, Q) == e(P,Q)·e(P,Q)
     *   Use batch Miller loop + single final_exp
     *   (product of two Miller loop outputs before final_exp)        ── */
    {
        zkn_fp12_384_t ml1, ml2;
        zkn_miller_loop(&ml1, &G1, &G2, ctx);
        zkn_miller_loop(&ml2, &G1, &G2, ctx);
        zkn_fp12_384_mul(&prod, &ml1, &ml2, ctx);
        zkn_final_exp(&prod, &prod, ctx);          /* single final_exp */

        zkn_pairing(&e2G, &P2, &G2, ctx);          /* e(2G1, G2)       */
        check("final_exp(ML(P,Q)·ML(P,Q)) == e(2P,Q)",
              zkn_fp12_384_eq(&prod, &e2G));
    }

    /* ── Test 7: e(−P, Q) == conj(e(P,Q)) ── */
    zkn_pairing(&eGm, &Pneg, &G2, ctx);
    {
        zkn_fp12_384_t conj_eGG;
        zkn_fp12_384_conjugate(&conj_eGG, &eGG, ctx);
        check("e(-G1, G2) == conj(e(G1,G2))",
              zkn_fp12_384_eq(&eGm, &conj_eGG));
    }

    /* ── Test 8: e(−P, Q) · e(P, Q) == 1 ── */
    zkn_fp12_384_mul(&tmp, &eGm, &eGG, ctx);
    check("e(-G1,G2) · e(G1,G2) == 1",
          zkn_fp12_384_eq(&tmp, &one));

    /* ── Test 9: e(O, Q) == 1 (identity G1) ── */
    zkn_pairing(&tmp, &O1, &G2, ctx);
    check("e(O_G1, G2) == 1",
          fp12_is_one(&tmp, ctx));

    /* ── Test 10: e(P, O) == 1 (identity G2) ── */
    zkn_pairing(&tmp, &G1, &O2, ctx);
    check("e(G1, O_G2) == 1",
          fp12_is_one(&tmp, ctx));

    /* ── Test 11: zkn_miller_loop_n batch (2 pairs) ─────────────────
     *   e(2G1, G2) · e(G1, G2)^{-1} ?= e(G1, G2)
     *   ↔  batch ML(2G1,G2) + ML(-G1,G2), then final_exp == e(G1,G2)  */
    {
        const zkn_g1_384_t *Ps[2] = { &P2, &Pneg };
        const zkn_g2_384_t *Qs[2] = { &G2, &G2   };
        zkn_fp12_384_t batch;

        zkn_miller_loop_n(&batch, Ps, Qs, 2, ctx);
        zkn_final_exp(&batch, &batch, ctx);
        /* e(2G1,G2)·e(-G1,G2) = e(G1,G2)^{2-1} = e(G1,G2) */
        check("miller_loop_n: e(2G1,G2)·e(-G1,G2) == e(G1,G2)",
              zkn_fp12_384_eq(&batch, &eGG));
    }

    /* ── Test 12: precompute_lines API ── */
    {
        zkn_line_raw_384_t lines[68];
        zkn_fp12_384_t f_pre;

        zkn_precompute_lines(lines, &G2, ctx);
        zkn_miller_loop_lines(&f_pre, lines, &G1, ctx);
        zkn_final_exp(&f_pre, &f_pre, ctx);
        check("precompute_lines + miller_loop_lines == e(G1,G2)",
              zkn_fp12_384_eq(&f_pre, &eGG));
    }

    /* ── Summary ── */
    printf("\n");
    ok = (fail == 0);
    printf("══ Results: %d passed, %d failed ══\n", pass, fail);
    return ok ? 0 : 1;
}
