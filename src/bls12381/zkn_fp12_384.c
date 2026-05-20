/*
 * zkn_fp12_384.c — Fp12 = Fp6[w] / (w² − v) arithmetic for BLS12-381
 *
 * Quadratic extension of Fp6 where w² = v (the Fp6 cubic indeterminate).
 * Structurally identical to Fp2 over Fp, but the "non-residue multiplication"
 * is Fp6 mul_by_v instead of Fp negation.
 *
 * Aliasing: all functions support r aliased to any input operand.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_fp12_384.h"
#include "zkn_fp4_384.h"
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 *  Constructors / comparison
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp12_384_zero(zkn_fp12_384_t *r)
{
    zkn_fp6_384_zero(&r->c0);
    zkn_fp6_384_zero(&r->c1);
}

void zkn_fp12_384_one(zkn_fp12_384_t *r, const zkn_mont_ctx384_t *ctx)
{
    zkn_fp6_384_one(&r->c0, ctx);
    zkn_fp6_384_zero(&r->c1);
}

void zkn_fp12_384_copy(zkn_fp12_384_t *r, const zkn_fp12_384_t *a)
{
    memcpy(r, a, sizeof(zkn_fp12_384_t));
}

int zkn_fp12_384_eq(const zkn_fp12_384_t *a, const zkn_fp12_384_t *b)
{
    return zkn_fp6_384_eq(&a->c0, &b->c0) &
           zkn_fp6_384_eq(&a->c1, &b->c1);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Addition / subtraction / negation / conjugation
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp12_384_add(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_fp12_384_t *b,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fp6_384_add(&r->c0, &a->c0, &b->c0, ctx);
    zkn_fp6_384_add(&r->c1, &a->c1, &b->c1, ctx);
}

void zkn_fp12_384_sub(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_fp12_384_t *b,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fp6_384_sub(&r->c0, &a->c0, &b->c0, ctx);
    zkn_fp6_384_sub(&r->c1, &a->c1, &b->c1, ctx);
}

void zkn_fp12_384_neg(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fp6_384_neg(&r->c0, &a->c0, ctx);
    zkn_fp6_384_neg(&r->c1, &a->c1, ctx);
}

void zkn_fp12_384_conjugate(zkn_fp12_384_t *r,
                            const zkn_fp12_384_t *a,
                            const zkn_mont_ctx384_t *ctx)
{
    zkn_fp6_384_copy(&r->c0, &a->c0);
    zkn_fp6_384_neg(&r->c1, &a->c1, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Multiplication — Karatsuba (3 Fp6 mul)
 *
 *  a = a0 + a1·w,   b = b0 + b1·w,   w² = v
 *
 *  v0 = a0·b0
 *  v1 = a1·b1
 *  c0 = v0 + mul_by_v(v1)           (since a1·b1·w² = a1·b1·v)
 *  c1 = (a0+a1)(b0+b1) − v0 − v1
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp12_384_mul(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_fp12_384_t *b,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fp6_384_t v0, v1;

    zkn_fp6_384_mul(&v0, &a->c0, &b->c0, ctx);
    zkn_fp6_384_mul(&v1, &a->c1, &b->c1, ctx);

    /* c1 = (a0+a1)(b0+b1) − v0 − v1 */
    zkn_fp6_384_t sa, sb, c1;
    zkn_fp6_384_add(&sa, &a->c0, &a->c1, ctx);
    zkn_fp6_384_add(&sb, &b->c0, &b->c1, ctx);
    zkn_fp6_384_mul(&c1, &sa, &sb, ctx);
    zkn_fp6_384_sub(&c1, &c1, &v0, ctx);
    zkn_fp6_384_sub(&c1, &c1, &v1, ctx);

    /* c0 = v0 + v · v1 */
    zkn_fp6_384_t v_v1;
    zkn_fp6_384_mul_by_v(&v_v1, &v1, ctx);
    zkn_fp6_384_add(&r->c0, &v0, &v_v1, ctx);

    zkn_fp6_384_copy(&r->c1, &c1);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Squaring — Karatsuba variant (3 Fp6 sqr)
 *
 *  v0 = a0²
 *  v1 = a1²
 *  c0 = v0 + mul_by_v(v1)
 *  c1 = (a0+a1)² − v0 − v1
 *
 *  3 Fp6 sqr is cheaper than 2 Fp6 sqr + 1 Fp6 mul on this tower.
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp12_384_sqr(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fp6_384_t v0, v1;

    zkn_fp6_384_sqr(&v0, &a->c0, ctx);
    zkn_fp6_384_sqr(&v1, &a->c1, ctx);

    /* c1 = (a0+a1)² − v0 − v1 */
    zkn_fp6_384_t sa, c1;
    zkn_fp6_384_add(&sa, &a->c0, &a->c1, ctx);
    zkn_fp6_384_sqr(&c1, &sa, ctx);
    zkn_fp6_384_sub(&c1, &c1, &v0, ctx);
    zkn_fp6_384_sub(&c1, &c1, &v1, ctx);

    /* c0 = v0 + v · v1 */
    zkn_fp6_384_t v_v1;
    zkn_fp6_384_mul_by_v(&v_v1, &v1, ctx);
    zkn_fp6_384_add(&r->c0, &v0, &v_v1, ctx);

    zkn_fp6_384_copy(&r->c1, &c1);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Sparse mul by line evaluation (positions 0, 1, 4)
 *
 *  b = (b_fp6_0, b_fp6_1)  where:
 *    b_fp6_0 = (b0, b1, 0)   ← sparse, only c0 and c1
 *    b_fp6_1 = (0,  b4, 0)   ← sparse, only c1
 *
 *  Karatsuba:
 *    t0 = a0 · b_fp6_0        → Fp6 mul_by_01(a0, b0, b1)
 *    t1 = a1 · b_fp6_1        → Fp6 mul_by_1(a1, b4)
 *    c0 = t0 + mul_by_v(t1)
 *    c1 = (a0+a1) · (b_fp6_0 + b_fp6_1) − t0 − t1
 *       = mul_by_01(a0+a1, b0, b1+b4) − t0 − t1
 *
 *  Cost: 2 × Fp6 mul_by_01 + 1 × Fp6 mul_by_1 + 1 × mul_by_v + adds.
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp12_384_mul_by_014(zkn_fp12_384_t *r,
                             const zkn_fp12_384_t *a,
                             const zkn_fp2_384_t *b0,
                             const zkn_fp2_384_t *b1,
                             const zkn_fp2_384_t *b4,
                             const zkn_mont_ctx384_t *ctx)
{
    zkn_fp6_384_t t0, t1;

    /* t0 = a0 · (b0, b1, 0) */
    zkn_fp6_384_mul_by_01(&t0, &a->c0, b0, b1, ctx);

    /* t1 = a1 · (0, b4, 0) */
    zkn_fp6_384_mul_by_1(&t1, &a->c1, b4, ctx);

    /* c1 = mul_by_01(a0+a1, b0, b1+b4) − t0 − t1 */
    zkn_fp6_384_t sa;
    zkn_fp6_384_add(&sa, &a->c0, &a->c1, ctx);
    zkn_fp2_384_t b14;
    zkn_fp2_384_add(&b14, b1, b4, ctx);
    zkn_fp6_384_t c1;
    zkn_fp6_384_mul_by_01(&c1, &sa, b0, &b14, ctx);
    zkn_fp6_384_sub(&c1, &c1, &t0, ctx);
    zkn_fp6_384_sub(&c1, &c1, &t1, ctx);

    /* c0 = t0 + mul_by_v(t1) */
    zkn_fp6_384_t v_t1;
    zkn_fp6_384_mul_by_v(&v_t1, &t1, ctx);
    zkn_fp6_384_add(&r->c0, &t0, &v_t1, ctx);

    zkn_fp6_384_copy(&r->c1, &c1);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Inversion via conjugate / norm
 *
 *  norm = c0² − v·c1²    (Fp6 element)
 *  a^{−1} = (c0 · norm^{−1},  −c1 · norm^{−1})
 *
 *  Cost: 2 Fp6 sqr + 1 mul_by_v + 1 Fp6 sub + 1 Fp6 inv + 2 Fp6 mul.
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp12_384_inv(zkn_fp12_384_t *r,
                      const zkn_fp12_384_t *a,
                      const zkn_mont_ctx384_t *ctx)
{
    zkn_fp6_384_t t0, t1, norm, inv_norm;

    /* norm = c0² − v·c1² */
    zkn_fp6_384_sqr(&t0, &a->c0, ctx);
    zkn_fp6_384_sqr(&t1, &a->c1, ctx);
    zkn_fp6_384_mul_by_v(&t1, &t1, ctx);
    zkn_fp6_384_sub(&norm, &t0, &t1, ctx);

    /* Invert norm in Fp6 */
    zkn_fp6_384_inv(&inv_norm, &norm, ctx);

    /* r.c0 =  c0 · inv_norm */
    zkn_fp6_384_mul(&r->c0, &a->c0, &inv_norm, ctx);

    /* r.c1 = −c1 · inv_norm */
    zkn_fp6_384_t neg_c1;
    zkn_fp6_384_neg(&neg_c1, &a->c1, ctx);
    zkn_fp6_384_mul(&r->c1, &neg_c1, &inv_norm, ctx);
}

void zkn_fp12_384_unitary_inv(zkn_fp12_384_t *r,
                              const zkn_fp12_384_t *a,
                              const zkn_mont_ctx384_t *ctx)
{
    zkn_fp12_384_conjugate(r, a, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Frobenius map  φ_{p^k}  on Fp12
 *
 *  Tower: Fp12 has basis {1, v, v², w, vw, v²w} over Fp2.
 *    v³ = ξ = 1+u,  w² = v.
 *
 *  φ_{p^k} acts on Fp2 component at position j as:
 *    1) Conjugate if k is odd (φ_p on Fp2 = conjugation since p ≡ 3 mod 4)
 *    2) Multiply by γ_j^{(k)} = ξ^{j·(p^k − 1)/6}
 *
 *  Position mapping:
 *    j=0: c0.c0 (1)     → γ = 1 (no mul)
 *    j=1: c0.c1 (v)     → γ = ξ^{(p^k−1)/6}
 *    j=2: c0.c2 (v²)    → γ = ξ^{2(p^k−1)/6} = ξ^{(p^k−1)/3}
 *    j=3: c1.c0 (w)     → γ = ξ^{3(p^k−1)/6} = ξ^{(p^k−1)/2}
 *    j=4: c1.c1 (vw)    → γ = ξ^{4(p^k−1)/6} = ξ^{2(p^k−1)/3}
 *    j=5: c1.c2 (v²w)   → γ = ξ^{5(p^k−1)/6}
 *
 *  The 5 Frobenius constants γ_1..γ_5 are computed from γ_1 by
 *  successive multiplication at init time.
 * ══════════════════════════════════════════════════════════════════════ */

/* ── Fp2 exponentiation (internal, used only for constant computation) ── */

static void fp2_pow_be(zkn_fp2_384_t *r, const zkn_fp2_384_t *base,
                       const uint8_t *exp_be, int exp_len,
                       const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t acc;
    zkn_fp2_384_one(&acc, ctx);

    int started = 0;
    for (int i = 0; i < exp_len; i++) {
        uint8_t byte = exp_be[i];
        for (int bit = 7; bit >= 0; bit--) {
            if (started)
                zkn_fp2_384_sqr(&acc, &acc, ctx);
            if ((byte >> bit) & 1) {
                if (started)
                    zkn_fp2_384_mul(&acc, &acc, base, ctx);
                else {
                    zkn_fp2_384_copy(&acc, base);
                    started = 1;
                }
            }
        }
    }
    zkn_fp2_384_copy(r, &acc);
}

/* ── Frobenius constant cache ───────────────────────────────────────── */

/*
 * frob_gamma[k][j] = ξ^{(j+1)·(p^(k+1) − 1)/6}  for k=0..2, j=0..4.
 *
 * k=0 → power=1: φ_p
 * k=1 → power=2: φ_{p²}
 * k=2 → power=3: φ_{p³}
 *
 * j+1 maps to positions 1..5 (position 0 needs no multiplication).
 */
static zkn_fp2_384_t frob_gamma[3][5];
static int frob_init_done = 0;

/*
 * Compute the exponent (p^k − 1) / 6 where p is the BLS12-381 prime.
 *
 * p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf
 *       6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
 *
 * Strategy: compute p^k in a big-integer buffer, subtract 1, divide by 6.
 * For k=1,2,3 we precompute (p^k−1)/6 as byte arrays.
 *
 * Since these are ~48k bytes, we compute p^k via multi-precision
 * arithmetic at init time rather than hardcoding the giant constants.
 */

/* Multi-precision helpers (little-endian uint32_t limbs) */
/* Max 36 limbs = 1152 bits, enough for p^3 */
#define MP_MAX_LIMBS 40

static void mp_zero(uint32_t *a, int n)
{
    for (int i = 0; i < n; i++) a[i] = 0;
}

static void mp_copy(uint32_t *r, const uint32_t *a, int n)
{
    for (int i = 0; i < n; i++) r[i] = a[i];
}

/* r = a * b, both n-limb → 2n-limb result. */
static void mp_mul(uint32_t *r, const uint32_t *a, const uint32_t *b,
                   int na, int nb)
{
    int nr = na + nb;
    mp_zero(r, nr);
    for (int i = 0; i < na; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < nb; j++) {
            uint64_t t = (uint64_t)a[i] * b[j] + r[i+j] + carry;
            r[i+j] = (uint32_t)t;
            carry = t >> 32;
        }
        r[i+nb] += (uint32_t)carry;
    }
}

/* a -= 1 (a > 0 assumed). */
static void mp_sub_1(uint32_t *a, int n)
{
    for (int i = 0; i < n; i++) {
        if (a[i] > 0) { a[i]--; return; }
        a[i] = 0xFFFFFFFF;
    }
}

/* r = a / 6, returns remainder. a is modified in-place. */
static uint32_t mp_div6(uint32_t *a, int n)
{
    uint64_t rem = 0;
    for (int i = n - 1; i >= 0; i--) {
        uint64_t t = (rem << 32) | a[i];
        a[i] = (uint32_t)(t / 6);
        rem = t % 6;
    }
    return (uint32_t)rem;
}

/* Get effective length (trim leading zero limbs). */
static int mp_len(const uint32_t *a, int n)
{
    while (n > 0 && a[n-1] == 0) n--;
    return n > 0 ? n : 1;
}

/* Export to big-endian bytes. */
static void mp_to_be(uint8_t *dst, int dst_len, const uint32_t *a, int n)
{
    memset(dst, 0, dst_len);
    for (int i = 0; i < n && i * 4 < dst_len; i++) {
        uint32_t limb = a[i];
        int base = dst_len - 1 - i * 4;
        if (base >= 0) dst[base]     = (uint8_t)(limb);
        if (base-1 >= 0) dst[base-1] = (uint8_t)(limb >> 8);
        if (base-2 >= 0) dst[base-2] = (uint8_t)(limb >> 16);
        if (base-3 >= 0) dst[base-3] = (uint8_t)(limb >> 24);
    }
}

static void frobenius_constants_init(const zkn_mont_ctx384_t *ctx)
{
    if (frob_init_done) return;

    /* p as 12 LE limbs (copy from Montgomery context) */
    uint32_t p[12];
    mp_copy(p, ctx->p, 12);

    /* ξ = 1 + u in Fp2 (Montgomery form) */
    zkn_fp2_384_t xi;
    zkn_fe384_t one_raw;
    zkn_fe384_zero(one_raw);
    one_raw[0] = 1;
    zkn_to_mont_384(xi.c0, one_raw, ctx);
    zkn_to_mont_384(xi.c1, one_raw, ctx);

    /* For each power k = 1, 2, 3: compute (p^k − 1) / 6 */
    for (int k = 1; k <= 3; k++) {
        /* Compute p^k in multi-precision */
        uint32_t pk[MP_MAX_LIMBS];
        mp_zero(pk, MP_MAX_LIMBS);
        pk[0] = 1;
        int pk_len = 1;

        for (int i = 0; i < k; i++) {
            uint32_t tmp[MP_MAX_LIMBS];
            mp_zero(tmp, MP_MAX_LIMBS);
            mp_mul(tmp, pk, p, pk_len, 12);
            pk_len = mp_len(tmp, pk_len + 12);
            mp_copy(pk, tmp, MP_MAX_LIMBS);
        }

        /* pk = p^k − 1 */
        mp_sub_1(pk, MP_MAX_LIMBS);

        /* pk = (p^k − 1) / 6 */
        mp_div6(pk, MP_MAX_LIMBS);
        int elen = mp_len(pk, MP_MAX_LIMBS);

        /* Convert to big-endian bytes for Fp2 exponentiation */
        int byte_len = elen * 4;
        uint8_t exp_be[MP_MAX_LIMBS * 4];
        mp_to_be(exp_be, byte_len, pk, elen);

        /* γ_1 = ξ^{(p^k − 1)/6} */
        zkn_fp2_384_t g1;
        fp2_pow_be(&g1, &xi, exp_be, byte_len, ctx);

        /* γ_j = γ_1^j for j = 1..5 */
        zkn_fp2_384_copy(&frob_gamma[k-1][0], &g1);

        zkn_fp2_384_t gj;
        zkn_fp2_384_copy(&gj, &g1);
        for (int j = 2; j <= 5; j++) {
            zkn_fp2_384_mul(&gj, &gj, &g1, ctx);
            zkn_fp2_384_copy(&frob_gamma[k-1][j-1], &gj);
        }
    }

    frob_init_done = 1;
}

void zkn_fp12_384_frobenius_map(zkn_fp12_384_t *r,
                                const zkn_fp12_384_t *a,
                                int power,
                                const zkn_mont_ctx384_t *ctx)
{
    if (power < 1 || power > 3) {
        zkn_fp12_384_copy(r, a);
        return;
    }

    frobenius_constants_init(ctx);

    int k = power - 1; /* index into frob_gamma */

    /*
     * 6 Fp2 components: positions 0..5
     * pos 0 = c0.c0  (basis: 1)
     * pos 1 = c0.c1  (basis: v)
     * pos 2 = c0.c2  (basis: v²)
     * pos 3 = c1.c0  (basis: w)
     * pos 4 = c1.c1  (basis: vw)
     * pos 5 = c1.c2  (basis: v²w)
     */

    /* Work on a copy to support aliasing */
    zkn_fp12_384_t tmp;

    /* Step 1: conjugate each Fp2 component if power is odd */
    if (power & 1) {
        zkn_fp2_384_conjugate(&tmp.c0.c0, &a->c0.c0, ctx);
        zkn_fp2_384_conjugate(&tmp.c0.c1, &a->c0.c1, ctx);
        zkn_fp2_384_conjugate(&tmp.c0.c2, &a->c0.c2, ctx);
        zkn_fp2_384_conjugate(&tmp.c1.c0, &a->c1.c0, ctx);
        zkn_fp2_384_conjugate(&tmp.c1.c1, &a->c1.c1, ctx);
        zkn_fp2_384_conjugate(&tmp.c1.c2, &a->c1.c2, ctx);
    } else {
        zkn_fp12_384_copy(&tmp, a);
    }

    /* Step 2: multiply positions 1..5 by γ_{j}^{(k)}
     *
     * Basis    Position   Exponent of ξ                    Index in γ₁^j
     * ─────────────────────────────────────────────────────────────────────
     * 1        0          0                                 — (skip)
     * v        1          (p^K−1)/3    = 2·(p^K−1)/6       γ₁² = [1]
     * v²       2          2(p^K−1)/3   = 4·(p^K−1)/6       γ₁⁴ = [3]
     * w        3          (p^K−1)/6    = 1·(p^K−1)/6       γ₁¹ = [0]
     * vw       4          (p^K−1)/2    = 3·(p^K−1)/6       γ₁³ = [2]
     * v²w      5          5(p^K−1)/6                       γ₁⁵ = [4]
     *
     * Derivation: v^{p^K} = v·ξ^{(p^K−1)/3}, w^{p^K} = w·ξ^{(p^K−1)/6}
     */

    /* pos 1 (c0.c1, basis v): × γ₁² = ξ^{2(p^K−1)/6} */
    zkn_fp2_384_mul(&r->c0.c1, &tmp.c0.c1, &frob_gamma[k][1], ctx);

    /* pos 2 (c0.c2, basis v²): × γ₁⁴ = ξ^{4(p^K−1)/6} */
    zkn_fp2_384_mul(&r->c0.c2, &tmp.c0.c2, &frob_gamma[k][3], ctx);

    /* pos 3 (c1.c0, basis w): × γ₁¹ = ξ^{(p^K−1)/6} */
    zkn_fp2_384_mul(&r->c1.c0, &tmp.c1.c0, &frob_gamma[k][0], ctx);

    /* pos 4 (c1.c1, basis vw): × γ₁³ = ξ^{3(p^K−1)/6} */
    zkn_fp2_384_mul(&r->c1.c1, &tmp.c1.c1, &frob_gamma[k][2], ctx);

    /* pos 5 (c1.c2, basis v²w): × γ₁⁵ = ξ^{5(p^K−1)/6} */
    zkn_fp2_384_mul(&r->c1.c2, &tmp.c1.c2, &frob_gamma[k][4], ctx);

    /* pos 0: just copy (already conjugated if needed) */
    zkn_fp2_384_copy(&r->c0.c0, &tmp.c0.c0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Cyclotomic squaring — Granger–Scott / Beuchat Algorithm 5.5.4
 *
 *  For f in GΦ₆(Fp12) with f·conj(f) = 1.
 *
 *  Sextic basis {1, W, W², W³, W⁴, W⁵} with W = w, W² = v, W⁶ = ξ:
 *    a₀ = A = c0.c0,  a₁ = D = c1.c0,  a₂ = B = c0.c1,
 *    a₃ = E = c1.c1,  a₄ = C = c0.c2,  a₅ = F = c1.c2.
 *
 *  Three Fp4 squarings with CROSSED output assignment:
 *    (A, E) → h_ae, c_ae  →  A' = 3·h_ae − 2A,  E' = 3·c_ae + 2E
 *    (B, D) → h_bd, c_bd  →  C' = 3·h_bd − 2C,  D' = 3·c_bd + 2D
 *    (C, F) → h_cf, c_cf  →  B' = 3·h_cf − 2B,  F' = 3·c_cf + 2F
 *
 *  Total: 6 Fp2 sqr + 3 mul_by_xi + 3 Fp2 sqr (Karatsuba) = 9 Fp2 sqr.
 *  No Fp2 multiplications → ~30% cheaper than generic sqr.
 * ══════════════════════════════════════════════════════════════════════ */

void zkn_fp12_384_cyclotomic_sqr(zkn_fp12_384_t *r,
                                 const zkn_fp12_384_t *a,
                                 const zkn_mont_ctx384_t *ctx)
{
    /*
     * Granger–Scott 2010 cyclotomic squaring via 3 Fp4 squarings.
     * Paires identiques à blst cyclotomic_sqr_fp12 :
     *
     *   p0 = (A=c0.c0, E=c1.c1)   s0.c0 = A²+ξE²,  s0.c1 = 2AE
     *   p1 = (D=c1.c0, C=c0.c2)   s1.c0 = D²+ξC²,  s1.c1 = 2DC
     *   p2 = (B=c0.c1, F=c1.c2)   s2.c0 = B²+ξF²,  s2.c1 = 2BF
     *
     * Reconstruction (cross-slot, la valeur "2·orig" correspond au slot
     * de SORTIE, pas au slot d'entrée de la paire) :
     *   c0.c0 = 3·s0.c0 − 2·A     (naturel)
     *   c1.c1 = 3·s0.c1 + 2·E     (naturel)
     *   c0.c1 = 3·s1.c0 − 2·B     (croisé: p1 → slot c0.c1)
     *   c1.c2 = 3·s1.c1 + 2·F     (croisé: p1 → slot c1.c2)
     *   c0.c2 = 3·s2.c0 − 2·C     (croisé: p2 → slot c0.c2)
     *   c1.c0 = 3·ξ·s2.c1 + 2·D   (croisé+ξ: p2 → slot c1.c0)
     *
     * "3t − 2a" = (t−a)·2 + t,  "3t + 2a" = (t+a)·2 + t
     * Tous les reads de *a sont avant tout write dans *r → alias-safe.
     */
    zkn_fp4_384_t p0, p1, p2, s0, s1, s2;
    zkn_fp2_384_t tmp, xi_s2c1;

    /* --- lecture complète avant toute écriture --- */
    zkn_fp2_384_copy(&p0.c0, &a->c0.c0);  /* A */
    zkn_fp2_384_copy(&p0.c1, &a->c1.c1);  /* E */
    zkn_fp2_384_copy(&p1.c0, &a->c1.c0);  /* D */
    zkn_fp2_384_copy(&p1.c1, &a->c0.c2);  /* C */
    zkn_fp2_384_copy(&p2.c0, &a->c0.c1);  /* B */
    zkn_fp2_384_copy(&p2.c1, &a->c1.c2);  /* F */

    zkn_fp4_384_sqr(&s0, &p0, ctx);
    zkn_fp4_384_sqr(&s1, &p1, ctx);
    zkn_fp4_384_sqr(&s2, &p2, ctx);

    /* ξ·s2.c1 calculé avant toute écriture (pour c1.c0) */
    zkn_fp2_384_mul_by_xi(&xi_s2c1, &s2.c1, ctx);

    /* c0.c0 = 3·s0.c0 − 2·A */
    zkn_fp2_384_sub(&tmp, &s0.c0, &p0.c0, ctx);
    zkn_fp2_384_add(&tmp, &tmp, &tmp, ctx);
    zkn_fp2_384_add(&r->c0.c0, &tmp, &s0.c0, ctx);

    /* c1.c1 = 3·s0.c1 + 2·E */
    zkn_fp2_384_add(&tmp, &s0.c1, &p0.c1, ctx);
    zkn_fp2_384_add(&tmp, &tmp, &tmp, ctx);
    zkn_fp2_384_add(&r->c1.c1, &tmp, &s0.c1, ctx);

    /* c0.c1 = 3·s1.c0 − 2·B  (croisé: p1 issu de (D,C) → slot c0.c1) */
    zkn_fp2_384_sub(&tmp, &s1.c0, &p2.c0, ctx);
    zkn_fp2_384_add(&tmp, &tmp, &tmp, ctx);
    zkn_fp2_384_add(&r->c0.c1, &tmp, &s1.c0, ctx);

    /* c1.c2 = 3·s1.c1 + 2·F  (croisé: p1 → slot c1.c2) */
    zkn_fp2_384_add(&tmp, &s1.c1, &p2.c1, ctx);
    zkn_fp2_384_add(&tmp, &tmp, &tmp, ctx);
    zkn_fp2_384_add(&r->c1.c2, &tmp, &s1.c1, ctx);

    /* c0.c2 = 3·s2.c0 − 2·C  (croisé: p2 issu de (B,F) → slot c0.c2) */
    zkn_fp2_384_sub(&tmp, &s2.c0, &p1.c1, ctx);
    zkn_fp2_384_add(&tmp, &tmp, &tmp, ctx);
    zkn_fp2_384_add(&r->c0.c2, &tmp, &s2.c0, ctx);

    /* c1.c0 = 3·ξ·s2.c1 + 2·D  (croisé+ξ: → slot c1.c0) */
    zkn_fp2_384_add(&tmp, &xi_s2c1, &p1.c0, ctx);
    zkn_fp2_384_add(&tmp, &tmp, &tmp, ctx);
    zkn_fp2_384_add(&r->c1.c0, &tmp, &xi_s2c1, ctx);
}
