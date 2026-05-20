/*
 * zkn_plonk.c — BLS12-381 PLONK proof verification (snarkjs compatible)
 *
 * Implements the GWC19 PLONK verification protocol with Fiat-Shamir
 * transcript matching snarkjs plonk_verify.js exactly.
 *
 * Transcript byte encoding (snarkjs convention):
 *   - G1 affine coordinates: little-endian 48 bytes each (non-Montgomery)
 *   - Fr scalars: big-endian 32 bytes
 *   - Hash: Keccak-256 (pre-NIST, 0x01 padding)
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include <string.h>
#include "zkn_plonk.h"
#include "zkn_keccak256.h"
#include "zkn_miller.h"
#include "zkn_final_exp_384.h"

/* ══════════════════════════════════════════════════════════════════════
 *  BLS12-381 scalar field Fr context
 *
 *  r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
 * ══════════════════════════════════════════════════════════════════════ */

static const zkn_fe384_t BLS12_381_R = {
    0x00000001u, 0xffffffffu, 0xfffe5bfeu, 0x53bda402u,
    0x09a1d805u, 0x3339d808u, 0x299d7d48u, 0x73eda753u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u
};

static const zkn_mont_ctx384_t *fr_ctx(void)
{
    static zkn_mont_ctx384_t ctx;
    static int ready = 0;
    if (!ready) {
        zkn_mont_ctx384_init(&ctx, BLS12_381_R);
        ready = 1;
    }
    return &ctx;
}

/* ══════════════════════════════════════════════════════════════════════
 *  Fr serialization helpers
 * ══════════════════════════════════════════════════════════════════════ */

/** Load 32-byte BE scalar into 48-byte (384-bit) field element. */
static void fr_from_be32(zkn_fe384_t r, const uint8_t src[32])
{
    uint8_t tmp[48];
    memset(tmp, 0, 16);
    memcpy(tmp + 16, src, 32);
    zkn_fe384_from_be(r, tmp);
}

/** Load 32-byte BE scalar → Montgomery 384-bit. */
static void fr_load(zkn_fe384_t r, const uint8_t src[32])
{
    fr_from_be32(r, src);
    zkn_to_mont_384(r, r, fr_ctx());
}

/** Store Montgomery Fr → 32-byte BE (normal form). */
static void fr_store(uint8_t dst[32], const zkn_fe384_t a)
{
    zkn_fe384_t tmp;
    zkn_from_mont_384(tmp, a, fr_ctx()->p, fr_ctx()->n0);
    uint8_t be[48];
    zkn_fe384_to_be(be, tmp);
    memcpy(dst, be + 16, 32);
}


/** Convert Fr Montgomery → 32-byte big-endian scalar for g1_mul/msm. */
static void fr_to_be32(uint8_t dst[32], const zkn_fe384_t a)
{
    fr_store(dst, a);  /* from_mont → 48-byte BE → copy last 32 bytes */
}
/** Keccak-256 hash → Fr element (Montgomery). */
static void hash_to_fr(zkn_fe384_t r, const uint8_t *data, size_t len)
{
    uint8_t hash[32];
    zkn_keccak256(hash, data, len);
    fr_load(r, hash);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Fr Montgomery arithmetic wrappers
 * ══════════════════════════════════════════════════════════════════════ */


static void fr_mul(zkn_fe384_t r, const zkn_fe384_t a, const zkn_fe384_t b)
{
    zkn_mul_mont_384(r, a, b, fr_ctx()->p, fr_ctx()->n0);
}

static void fr_sqr(zkn_fe384_t r, const zkn_fe384_t a)
{
    zkn_sqr_mont_384(r, a, fr_ctx()->p, fr_ctx()->n0);
}

static void fr_add(zkn_fe384_t r, const zkn_fe384_t a, const zkn_fe384_t b)
{
    zkn_add_mod_384(r, a, b, fr_ctx()->p);
}

static void fr_sub(zkn_fe384_t r, const zkn_fe384_t a, const zkn_fe384_t b)
{
    zkn_sub_mod_384(r, a, b, fr_ctx()->p);
}

static void fr_neg(zkn_fe384_t r, const zkn_fe384_t a)
{
    zkn_neg_mod_384(r, a, fr_ctx()->p);
}

static void fr_inv(zkn_fe384_t r, const zkn_fe384_t a)
{
    zkn_inv_mont_384(r, a, fr_ctx());
}


/* ══════════════════════════════════════════════════════════════════════
 *  Point loading helpers
 * ══════════════════════════════════════════════════════════════════════ */

/** Load G1 from 96-byte BE affine (x[48] || y[48]).
 *  All-zero input → identity point (Z=0). */
static void load_g1_be(zkn_g1_384_t *P, const uint8_t buf[96],
                       const zkn_mont_ctx384_t *ctx)
{
    /* Detect identity: all-zero bytes (snarkjs zeroAffine convention) */
    int is_zero = 1;
    for (int i = 0; i < 96 && is_zero; i++)
        if (buf[i] != 0) is_zero = 0;
    if (is_zero) {
        zkn_g1_384_zero(P);
        return;
    }
    zkn_fe384_t x, y;
    zkn_fe384_from_be(x, buf);
    zkn_fe384_from_be(y, buf + 48);
    zkn_g1_384_from_affine(P, x, y, ctx);
}

/** Load G2 from 192-byte BE affine: x.c0(48)||x.c1(48)||y.c0(48)||y.c1(48). */
static void load_g2_be(zkn_g2_384_t *Q, const uint8_t buf[192],
                       const zkn_mont_ctx384_t *ctx)
{
    zkn_fp2_384_t x, y;
    zkn_fe384_from_be(x.c0, buf);
    zkn_fe384_from_be(x.c1, buf + 48);
    zkn_fe384_from_be(y.c0, buf + 96);
    zkn_fe384_from_be(y.c1, buf + 144);
    zkn_g2_384_from_affine(Q, &x, &y, ctx);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Fiat-Shamir transcript helpers
 * ══════════════════════════════════════════════════════════════════════ */

/** Append G1 point to transcript from 96-byte BE storage.
 *  Direct copy — roundtrip through from_affine/to_affine is identity for
 *  valid points and CRASHES for zero points (inv(Z=0) is undefined). */
static void transcript_g1_from_be(uint8_t *buf, size_t *off,
                                  const uint8_t g1_be[96],
                                  const zkn_mont_ctx384_t *ctx)
{
    (void)ctx;
    memcpy(buf + *off, g1_be, 96);
    *off += 96;
}

/** Append Fr scalar to transcript (32 bytes, already in BE). */
static void transcript_fr(uint8_t *buf, size_t *off,
                          const uint8_t fr_be[32])
{
    memcpy(buf + *off, fr_be, 32);
    *off += 32;
}

/* ══════════════════════════════════════════════════════════════════════
 *  PLONK verification
 * ══════════════════════════════════════════════════════════════════════ */

int zkn_plonk_verify(const zkn_plonk_vk_t    *vk,
                     const zkn_plonk_proof_t  *proof,
                     const uint8_t            (*pub)[ZKN_PLONK_FR_BYTES],
                     int                        n_pub,
                     const zkn_mont_ctx384_t   *fp_ctx)
{
    if (n_pub != vk->n_public || n_pub < 0 || n_pub > ZKN_PLONK_MAX_PUB)
        return -1;

    const int n = 1 << vk->power;

    /* ── 0. Ensure Fr context is initialized ─────────────────────── */
    (void)fr_ctx();

    /* ── 1. Load proof points ────────────────────────────────────── */

    zkn_g1_384_t pA, pB, pC, pZ, pT1, pT2, pT3, pWxi, pWxiw;
    load_g1_be(&pA,    proof->A,    fp_ctx);
    load_g1_be(&pB,    proof->B,    fp_ctx);
    load_g1_be(&pC,    proof->C,    fp_ctx);
    load_g1_be(&pZ,    proof->Z,    fp_ctx);
    load_g1_be(&pT1,   proof->T1,   fp_ctx);
    load_g1_be(&pT2,   proof->T2,   fp_ctx);
    load_g1_be(&pT3,   proof->T3,   fp_ctx);
    load_g1_be(&pWxi,  proof->Wxi,  fp_ctx);
    load_g1_be(&pWxiw, proof->Wxiw, fp_ctx);

    /* ── 2. Load VK points ───────────────────────────────────────── */

    zkn_g1_384_t vQm, vQl, vQr, vQo, vQc, vS1, vS2, vS3;
    load_g1_be(&vQm, vk->Qm, fp_ctx);
    load_g1_be(&vQl, vk->Ql, fp_ctx);
    load_g1_be(&vQr, vk->Qr, fp_ctx);
    load_g1_be(&vQo, vk->Qo, fp_ctx);
    load_g1_be(&vQc, vk->Qc, fp_ctx);
    load_g1_be(&vS1, vk->S1, fp_ctx);
    load_g1_be(&vS2, vk->S2, fp_ctx);
    load_g1_be(&vS3, vk->S3, fp_ctx);

    zkn_g2_384_t vX2;
    load_g2_be(&vX2, vk->X2, fp_ctx);

    /* ── 3. Load proof evaluations (Fr, Montgomery) ──────────────── */

    zkn_fe384_t eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_zw;
    fr_load(eval_a,  proof->eval_a);
    fr_load(eval_b,  proof->eval_b);
    fr_load(eval_c,  proof->eval_c);
    fr_load(eval_s1, proof->eval_s1);
    fr_load(eval_s2, proof->eval_s2);
    fr_load(eval_zw, proof->eval_zw);

    /* ── 4. Load VK scalars ──────────────────────────────────────── */

    zkn_fe384_t w_mont, k1_mont, k2_mont;
    fr_load(w_mont,  vk->w);
    fr_load(k1_mont, vk->k1);
    fr_load(k2_mont, vk->k2);

    /* ── 5. Fiat-Shamir challenges ───────────────────────────────── */

    /* 5a. β = hash(Qm||Ql||Qr||Qo||Qc||S1||S2||S3||pub[0]||...||A||B||C)
     *     8 VK G1(96) + nPub Fr(32) + 3 proof G1(96) bytes              */
    zkn_fe384_t ch_beta, ch_gamma, ch_alpha, ch_xi, ch_v, ch_u;
    uint8_t beta_be[32], gamma_be[32];
    {
        uint8_t tbuf[11 * 96 + ZKN_PLONK_MAX_PUB * 32];
        size_t off = 0;
        transcript_g1_from_be(tbuf, &off, vk->Qm, fp_ctx);
        transcript_g1_from_be(tbuf, &off, vk->Ql, fp_ctx);
        transcript_g1_from_be(tbuf, &off, vk->Qr, fp_ctx);
        transcript_g1_from_be(tbuf, &off, vk->Qo, fp_ctx);
        transcript_g1_from_be(tbuf, &off, vk->Qc, fp_ctx);
        transcript_g1_from_be(tbuf, &off, vk->S1, fp_ctx);
        transcript_g1_from_be(tbuf, &off, vk->S2, fp_ctx);
        transcript_g1_from_be(tbuf, &off, vk->S3, fp_ctx);
        /* Public signals (Fr scalars, 32-byte BE) */
        for (int i = 0; i < n_pub; i++)
            transcript_fr(tbuf, &off, pub[i]);
        transcript_g1_from_be(tbuf, &off, proof->A, fp_ctx);
        transcript_g1_from_be(tbuf, &off, proof->B, fp_ctx);
        transcript_g1_from_be(tbuf, &off, proof->C, fp_ctx);
        hash_to_fr(ch_beta, tbuf, off);
        fr_store(beta_be, ch_beta);
    }

    /* 5b. γ = hash(β) */
    {
        hash_to_fr(ch_gamma, beta_be, 32);
        fr_store(gamma_be, ch_gamma);
    }

    /* 5c. α = hash(β || γ || Z) */
    uint8_t alpha_be[32];
    {
        uint8_t tbuf[32 + 32 + 96];
        size_t off = 0;
        transcript_fr(tbuf, &off, beta_be);
        transcript_fr(tbuf, &off, gamma_be);
        transcript_g1_from_be(tbuf, &off, proof->Z, fp_ctx);
        hash_to_fr(ch_alpha, tbuf, off);
        fr_store(alpha_be, ch_alpha);
    }

    /* 5d. ξ = hash(α || T1 || T2 || T3) */
    uint8_t xi_be[32];
    {
        uint8_t tbuf[32 + 3 * 96];
        size_t off = 0;
        transcript_fr(tbuf, &off, alpha_be);
        transcript_g1_from_be(tbuf, &off, proof->T1, fp_ctx);
        transcript_g1_from_be(tbuf, &off, proof->T2, fp_ctx);
        transcript_g1_from_be(tbuf, &off, proof->T3, fp_ctx);
        hash_to_fr(ch_xi, tbuf, off);
        fr_store(xi_be, ch_xi);
    }

    /* 5e. v = hash(ξ || eval_a || eval_b || eval_c || eval_s1 || eval_s2 || eval_zw) */
    {
        uint8_t tbuf[7 * 32];
        size_t off = 0;
        transcript_fr(tbuf, &off, xi_be);
        transcript_fr(tbuf, &off, proof->eval_a);
        transcript_fr(tbuf, &off, proof->eval_b);
        transcript_fr(tbuf, &off, proof->eval_c);
        transcript_fr(tbuf, &off, proof->eval_s1);
        transcript_fr(tbuf, &off, proof->eval_s2);
        transcript_fr(tbuf, &off, proof->eval_zw);
        hash_to_fr(ch_v, tbuf, off);
    }

    /* 5f. u = hash(Wxi || Wxiw) */
    {
        uint8_t tbuf[2 * 96];
        size_t off = 0;
        transcript_g1_from_be(tbuf, &off, proof->Wxi, fp_ctx);
        transcript_g1_from_be(tbuf, &off, proof->Wxiw, fp_ctx);
        hash_to_fr(ch_u, tbuf, off);
    }

    /* Powers of v: v[i] = v^(i+1) for i = 0..4 */
    zkn_fe384_t vp[5];
    memcpy(vp[0], ch_v, sizeof(zkn_fe384_t));
    for (int i = 1; i < 5; i++)
        fr_mul(vp[i], vp[i - 1], ch_v);

    /* ── 6. Compute zh = ξ^n - 1 ─────────────────────────────────── */

    zkn_fe384_t xi_n;   /* ξ^n in Montgomery */
    {
        /* ξ^n = ξ^(2^power) — just square `power` times */
        memcpy(xi_n, ch_xi, sizeof(zkn_fe384_t));
        for (int i = 0; i < vk->power; i++)
            fr_sqr(xi_n, xi_n);
    }

    zkn_fe384_t zh;     /* zh = ξ^n - 1 */
    fr_sub(zh, xi_n, fr_ctx()->one);

    /* ── 7. Compute L_1(ξ) = zh / (n · (ξ - 1)) ─────────────────── */

    zkn_fe384_t L1;
    {
        /* n in Montgomery */
        uint8_t n_be[32];
        memset(n_be, 0, 32);
        n_be[28] = (uint8_t)(n >> 24);
        n_be[29] = (uint8_t)(n >> 16);
        n_be[30] = (uint8_t)(n >> 8);
        n_be[31] = (uint8_t)(n);
        zkn_fe384_t n_mont;
        fr_load(n_mont, n_be);

        zkn_fe384_t xi_m1;
        fr_sub(xi_m1, ch_xi, fr_ctx()->one);   /* ξ - 1 */

        zkn_fe384_t denom;
        fr_mul(denom, n_mont, xi_m1);           /* n * (ξ - 1) */

        zkn_fe384_t denom_inv;
        fr_inv(denom_inv, denom);               /* 1 / (n * (ξ - 1)) */

        fr_mul(L1, zh, denom_inv);              /* zh / (n * (ξ - 1)) */
    }


    /* ── 8. Compute PI(ξ) = −Σ pub[i] · L_i(ξ) ─────────────────── */
    /*      (snarkjs convention: pi = -Σ pub[i]*L[i+1])            */

    zkn_fe384_t PI;
    zkn_fe384_zero(PI);
    {
        /* n in Montgomery (recompute) */
        uint8_t n_be[32];
        memset(n_be, 0, 32);
        n_be[28] = (uint8_t)(n >> 24);
        n_be[29] = (uint8_t)(n >> 16);
        n_be[30] = (uint8_t)(n >> 8);
        n_be[31] = (uint8_t)(n);
        zkn_fe384_t n_mont;
        fr_load(n_mont, n_be);

        zkn_fe384_t n_inv;
        fr_inv(n_inv, n_mont);                  /* 1/n */

        zkn_fe384_t w_i;                        /* ω^i, starts at ω^0 = 1 */
        memcpy(w_i, fr_ctx()->one, sizeof(zkn_fe384_t));

        for (int i = 0; i < n_pub; i++) {
            /* L_i(ξ) = (ω^i / n) · zh / (ξ - ω^i) */
            zkn_fe384_t xi_m_wi;
            fr_sub(xi_m_wi, ch_xi, w_i);       /* ξ - ω^i */

            zkn_fe384_t inv_xi_m_wi;
            fr_inv(inv_xi_m_wi, xi_m_wi);       /* 1 / (ξ - ω^i) */

            zkn_fe384_t Li;
            fr_mul(Li, w_i, zh);                /* ω^i · zh */
            fr_mul(Li, Li, n_inv);              /* ω^i · zh / n */
            fr_mul(Li, Li, inv_xi_m_wi);        /* L_i(ξ) */

            /* Accumulate: PI -= pub[i] · L_i(ξ)  (negative sum, snarkjs convention) */
            zkn_fe384_t pub_i;
            fr_load(pub_i, pub[i]);

            zkn_fe384_t term;
            fr_mul(term, pub_i, Li);
            fr_sub(PI, PI, term);

            /* ω^(i+1) */
            fr_mul(w_i, w_i, w_mont);
        }
    }

    /* ── 9. Compute r0 (scalar linearization constant) ───────────── */

    /* alpha² */
    zkn_fe384_t alpha2;
    fr_sqr(alpha2, ch_alpha);

    /* e1 = (eval_a + β·eval_s1 + γ)(eval_b + β·eval_s2 + γ)(eval_c + γ)·eval_zw */
    zkn_fe384_t r0;
    {
        zkn_fe384_t t1, t2, t3;

        /* eval_a + β·eval_s1 + γ */
        fr_mul(t1, ch_beta, eval_s1);
        fr_add(t1, t1, eval_a);
        fr_add(t1, t1, ch_gamma);

        /* eval_b + β·eval_s2 + γ */
        fr_mul(t2, ch_beta, eval_s2);
        fr_add(t2, t2, eval_b);
        fr_add(t2, t2, ch_gamma);

        /* eval_c + γ */
        fr_add(t3, eval_c, ch_gamma);

        /* e1 = t1 · t2 · t3 · eval_zw */
        zkn_fe384_t e1;
        fr_mul(e1, t1, t2);
        fr_mul(e1, e1, t3);
        fr_mul(e1, e1, eval_zw);

        /* r0 = PI(ξ) - L_1(ξ)·α² - α·e1 */
        zkn_fe384_t tmp;
        fr_mul(tmp, L1, alpha2);            /* L_1(ξ)·α² */
        fr_sub(r0, PI, tmp);                /* PI - L_1·α² */
        fr_mul(tmp, ch_alpha, e1);          /* α·e1 */
        fr_sub(r0, r0, tmp);               /* r0 = PI - L_1·α² - α·e1 */
    }

    /* ── 10. Compute [D] ∈ G1 (linearization commitment) ────────── */

    zkn_g1_384_t D;
    {
        zkn_g1_384_t tmp1;
        uint8_t sbe[32];  /* 32-byte scalars (Fr is 255 bits) */

        /* ── D1 = ea*eb·Qm + ea·Ql + eb·Qr + ec·Qo  (MSM-4) ────── */
        {
            zkn_fe384_t eab; fr_mul(eab, eval_a, eval_b);

            zkn_g1_384_t d1_pts[4];
            zkn_g1_384_copy(&d1_pts[0], &vQm);
            zkn_g1_384_copy(&d1_pts[1], &vQl);
            zkn_g1_384_copy(&d1_pts[2], &vQr);
            zkn_g1_384_copy(&d1_pts[3], &vQo);

            uint8_t d1_sc[4 * 32];
            fr_to_be32(d1_sc,      eab);
            fr_to_be32(d1_sc + 32, eval_a);
            fr_to_be32(d1_sc + 64, eval_b);
            fr_to_be32(d1_sc + 96, eval_c);

            zkn_g1_384_msm(&D, d1_pts, d1_sc, 4, fp_ctx);
            zkn_g1_384_add(&D, &D, &vQc, fp_ctx);   /* + Qc */
        }

        /* ── D2 = coeff_z · Z ────────────────────────────────────── */
        {
            zkn_fe384_t bx, t1, t2, t3, coeff_z;

            fr_mul(bx, ch_beta, ch_xi);
            fr_add(t1, eval_a, bx);    fr_add(t1, t1, ch_gamma);

            fr_mul(bx, ch_beta, k1_mont); fr_mul(bx, bx, ch_xi);
            fr_add(t2, eval_b, bx);    fr_add(t2, t2, ch_gamma);

            fr_mul(bx, ch_beta, k2_mont); fr_mul(bx, bx, ch_xi);
            fr_add(t3, eval_c, bx);    fr_add(t3, t3, ch_gamma);

            fr_mul(coeff_z, t1, t2);
            fr_mul(coeff_z, coeff_z, t3);
            fr_mul(coeff_z, coeff_z, ch_alpha);
            zkn_fe384_t la2; fr_mul(la2, L1, alpha2);
            fr_add(coeff_z, coeff_z, la2);
            fr_add(coeff_z, coeff_z, ch_u);

            fr_to_be32(sbe, coeff_z);
            zkn_g1_384_mul(&tmp1, &pZ, sbe, 32, fp_ctx);
            zkn_g1_384_add(&D, &D, &tmp1, fp_ctx);
        }

        /* ── D3 = −coeff_s3 · S3 ─────────────────────────────────── */
        {
            zkn_fe384_t t1, t2, coeff_s3;

            fr_mul(t1, ch_beta, eval_s1); fr_add(t1, t1, eval_a); fr_add(t1, t1, ch_gamma);
            fr_mul(t2, ch_beta, eval_s2); fr_add(t2, t2, eval_b); fr_add(t2, t2, ch_gamma);

            fr_mul(coeff_s3, t1, t2);
            fr_mul(coeff_s3, coeff_s3, ch_alpha);
            fr_mul(coeff_s3, coeff_s3, ch_beta);
            fr_mul(coeff_s3, coeff_s3, eval_zw);

            /* Negate: D -= coeff_s3·S3 */
            fr_neg(coeff_s3, coeff_s3);
            fr_to_be32(sbe, coeff_s3);
            zkn_g1_384_mul(&tmp1, &vS3, sbe, 32, fp_ctx);
            zkn_g1_384_add(&D, &D, &tmp1, fp_ctx);
        }

        /* ── D4 = −(zh·T1 + zh·ξⁿ·T2 + zh·ξ²ⁿ·T3)  (MSM-3) ───── */
        {
            zkn_fe384_t xi_2n; fr_sqr(xi_2n, xi_n);

            /* Merge zh into each scalar and negate */
            zkn_fe384_t s_t1, s_t2, s_t3;
            fr_neg(s_t1, zh);                                   /* −zh */
            fr_mul(s_t2, zh, xi_n);  fr_neg(s_t2, s_t2);       /* −zh·ξⁿ */
            fr_mul(s_t3, zh, xi_2n); fr_neg(s_t3, s_t3);       /* −zh·ξ²ⁿ */

            uint8_t d4_sc[3 * 32];
            fr_to_be32(d4_sc,      s_t1);
            fr_to_be32(d4_sc + 32, s_t2);
            fr_to_be32(d4_sc + 64, s_t3);

            zkn_g1_384_msm3(&tmp1,
                &pT1, d4_sc, &pT2, d4_sc + 32, &pT3, d4_sc + 64,
                fp_ctx);
            zkn_g1_384_add(&D, &D, &tmp1, fp_ctx);
        }
    }

    /* ── 11. Compute [F] = D + v·A + v²·B + v³·C + v⁴·S1 + v⁵·S2 ── */

    /* ── F = D + v·A + v²·B + v³·C + v⁴·S1 + v⁵·S2  (MSM-5) ── */
    zkn_g1_384_t F;
    {
        zkn_g1_384_t f_pts[5];
        zkn_g1_384_copy(&f_pts[0], &pA);
        zkn_g1_384_copy(&f_pts[1], &pB);
        zkn_g1_384_copy(&f_pts[2], &pC);
        zkn_g1_384_copy(&f_pts[3], &vS1);
        zkn_g1_384_copy(&f_pts[4], &vS2);

        uint8_t f_sc[5 * 32];
        for (int i = 0; i < 5; i++) fr_to_be32(f_sc + i * 32, vp[i]);

        zkn_g1_384_msm(&F, f_pts, f_sc, 5, fp_ctx);
        zkn_g1_384_add(&F, &D, &F, fp_ctx);   /* F = D + MSM result */
    }

    /* ── 12. Compute [E] = e_scalar · G1_generator ───────────────── */
    /*   e_scalar = -r0 + v·eval_a + v²·eval_b + v³·eval_c
     *                  + v⁴·eval_s1 + v⁵·eval_s2 + u·eval_zw       */

    /* ── E = e_scalar · G1_generator ──────────────────────────── */
    zkn_g1_384_t E;
    {
        zkn_fe384_t e_scalar, t;
        fr_neg(e_scalar, r0);
        fr_mul(t, vp[0], eval_a);   fr_add(e_scalar, e_scalar, t);
        fr_mul(t, vp[1], eval_b);   fr_add(e_scalar, e_scalar, t);
        fr_mul(t, vp[2], eval_c);   fr_add(e_scalar, e_scalar, t);
        fr_mul(t, vp[3], eval_s1);  fr_add(e_scalar, e_scalar, t);
        fr_mul(t, vp[4], eval_s2);  fr_add(e_scalar, e_scalar, t);
        fr_mul(t, ch_u,  eval_zw);  fr_add(e_scalar, e_scalar, t);

        uint8_t sbe[32]; fr_to_be32(sbe, e_scalar);
        zkn_g1_384_t gen; zkn_g1_384_generator(&gen, fp_ctx);
        zkn_g1_384_mul(&E, &gen, sbe, 32, fp_ctx);
    }

    /* ── 13. Pairing check ───────────────────────────────────────── */
    /*   e(A1, X2) · e(-A2, G2) == 1
     *
     *   A1 = [Wξ] + u·[Wξω]
     *   A2 = ξ·[Wξ] + u·ξ·ω·[Wξω] + [F] - [E]                   */

    /* ── A1 = Wξ + u·Wξω  (1 mul) ────────────────────────────── */
    /* ── A2 = ξ·Wξ + u·ξ·ω·Wξω + F − E  (MSM-2 + adds) ──── */
    zkn_g1_384_t A1, A2;
    {
        uint8_t sbe[32];

        /* A1 = Wxi + u·Wxiw */
        fr_to_be32(sbe, ch_u);
        zkn_g1_384_t tmp;
        zkn_g1_384_mul(&tmp, &pWxiw, sbe, 32, fp_ctx);
        zkn_g1_384_add(&A1, &pWxi, &tmp, fp_ctx);

        /* A2 = ξ·Wxi + u·ξ·ω·Wxiw  (MSM-2) */
        zkn_fe384_t uxiw;
        fr_mul(uxiw, ch_u, ch_xi);
        fr_mul(uxiw, uxiw, w_mont);

        uint8_t a2_s1[32], a2_s2[32];
        fr_to_be32(a2_s1, ch_xi);
        fr_to_be32(a2_s2, uxiw);
        zkn_g1_384_msm2(&A2, &pWxi, a2_s1, &pWxiw, a2_s2, fp_ctx);

        /* + F − E */
        zkn_g1_384_add(&A2, &A2, &F, fp_ctx);
        zkn_g1_384_neg(&tmp, &E, fp_ctx);
        zkn_g1_384_add(&A2, &A2, &tmp, fp_ctx);
    }

    /* Batch: e(-A1, X2) · e(A2, G2) == 1  (snarkjs convention) */
    zkn_g1_384_t neg_A1;
    zkn_g1_384_neg(&neg_A1, &A1, fp_ctx);

    zkn_g2_384_t G2gen;
    zkn_g2_384_generator(&G2gen, fp_ctx);

    const zkn_g1_384_t *Ps[2] = { &neg_A1, &A2    };
    const zkn_g2_384_t *Qs[2] = { &vX2,    &G2gen };

    zkn_fp12_384_t f;
    zkn_miller_loop_n(&f, Ps, Qs, 2, fp_ctx);
    zkn_final_exp(&f, &f, fp_ctx);

    /* Check f == 1 */
    zkn_fp12_384_t one;
    zkn_fp12_384_one(&one, fp_ctx);


    return zkn_fp12_384_eq(&f, &one) ? 1 : 0;
}
