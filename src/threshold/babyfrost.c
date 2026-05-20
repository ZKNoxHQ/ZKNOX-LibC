/*
 * babyfrost.c — BabyFROST threshold signing (babyfrost.ts protocol)
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "babyfrost.h"
#include "zkn_bn.h"
#include "zkn_poseidon.h"
#include <string.h>

/* ── BabyJubjub constants ────────────────────────────────────────── */

static const uint8_t BJJ_ORDER_BE[32] = {
    0x06,0x0c,0x89,0xce,0x5c,0x26,0x34,0x05,
    0x37,0x0a,0x08,0xb6,0xd0,0x30,0x2b,0x0b,
    0xab,0x3e,0xed,0xb8,0x39,0x20,0xee,0x0a,
    0x67,0x72,0x97,0xdc,0x39,0x21,0x26,0xf1
};
static const uint8_t BJJ_GEN_X_BE[32] = {
    0x0b,0xb7,0x7a,0x6a,0xd6,0x3e,0x73,0x9b,
    0x4e,0xac,0xb2,0xe0,0x9d,0x62,0x77,0xc1,
    0x2a,0xb8,0xd8,0x01,0x05,0x34,0xe0,0xb6,
    0x28,0x93,0xf3,0xf6,0xbb,0x95,0x70,0x51
};
static const uint8_t BJJ_GEN_Y_BE[32] = {
    0x25,0x79,0x72,0x03,0xf7,0xa0,0xb2,0x49,
    0x25,0x57,0x2e,0x1c,0xd1,0x6b,0xf9,0xed,
    0xfc,0xe0,0x05,0x1f,0xb9,0xe1,0x33,0x77,
    0x4b,0x3c,0x25,0x7a,0x87,0x2d,0x7d,0x8b
};

/* ── Helpers ──────────────────────────────────────────────────────── */

static void rev32(uint8_t out[32], const uint8_t in[32])
{
    for (int i = 0; i < 32; i++) out[i] = in[31 - i];
}

static void u32_to_le32(uint8_t out[32], uint32_t val)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(val);
    out[1] = (uint8_t)(val >> 8);
    out[2] = (uint8_t)(val >> 16);
    out[3] = (uint8_t)(val >> 24);
}

/* ══════════════════════════════════════════════════════════════════ */

int babyfrost_init(babyfrost_ctx_t *ctx)
{
    memcpy(ctx->order, BJJ_ORDER_BE, 32);
    memcpy(ctx->gen_x, BJJ_GEN_X_BE, 32);
    memcpy(ctx->gen_y, BJJ_GEN_Y_BE, 32);
    zkn_frost_hasher_init(&ctx->hasher, "FROST-EDBABYJUJUB-BLAKE512-v1",
                          ctx->order);
    zkn_tEdwards_curve_alloc_init(&ctx->curve, ZKN_BABYJUJUB_ID);
    zkn_tEdwards_init(&ctx->curve, (uint8_t *)ctx->gen_x,
                       (uint8_t *)ctx->gen_y, &ctx->curve.G);
    return 0;
}

void babyfrost_destroy(babyfrost_ctx_t *ctx)
{
    zkn_tEdwards_curve_destroy(&ctx->curve);
}

void babyfrost_reinit_curve(babyfrost_ctx_t *ctx)
{
    zkn_tEdwards_curve_destroy(&ctx->curve);
    zkn_tEdwards_curve_alloc_init(&ctx->curve, ZKN_BABYJUJUB_ID);
    zkn_tEdwards_init(&ctx->curve, (uint8_t *)ctx->gen_x,
                       (uint8_t *)ctx->gen_y, &ctx->curve.G);
}

/* ══════════════════════════════════════════════════════════════════
 *  Section 4.3: encodeGroupCommitmentList
 *
 *  Per signer: id_le(32) || D.x_le(32) || D.y_le(32) ||
 *              E.x_le(32) || E.y_le(32)  = 160 bytes
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_encode_commitment_list(uint8_t *out, size_t *out_len,
                                      const zkn_frost_commitment_t *comms,
                                      size_t n)
{
    *out_len = n * 160;
    for (size_t i = 0; i < n; i++) {
        uint8_t *p = out + i * 160;
        u32_to_le32(p, comms[i].id);
        rev32(p + 32,  comms[i].D_x);
        rev32(p + 64,  comms[i].D_y);
        rev32(p + 96,  comms[i].E_x);
        rev32(p + 128, comms[i].E_y);
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════
 *  Section 4.4: computeBindingFactors
 *
 *  rhoInput = SerializeElement(groupPK)      → pk_x_le(32) || pk_y_le(32)
 *           || toBytes(H4(message))           → h4_le(32)
 *           || toBytes(H5(encCommitments))    → h5_le(32)
 *           || SerializeScalar(identifier)    → id_le(32)
 *  Total: 160 bytes
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_compute_binding_factors(babyfrost_ctx_t *ctx,
                                       const uint8_t pk_x_be[32],
                                       const uint8_t pk_y_be[32],
                                       const zkn_frost_commitment_t *comms,
                                       size_t n_signers,
                                       const uint8_t msg_hash_be[32],
                                       uint8_t rho_out[][32])
{
    /* msg_le = toBytes(msgHash) */
    uint8_t msg_le[32];
    rev32(msg_le, msg_hash_be);

    /* H4(message) — message is toBytes(msgHash) in babyfrost.ts */
    uint8_t h4_be[32];
    zkn_frost_H4(&ctx->hasher, msg_le, 32, h4_be);

    /* Encode commitment list */
    uint8_t enc_comms[ZKN_FROST_MAX_SIGNERS * 160];
    size_t enc_len;
    babyfrost_encode_commitment_list(enc_comms, &enc_len, comms, n_signers);

    /* H5(encodedCommitments) */
    uint8_t h5_be[32];
    zkn_frost_H5(&ctx->hasher, enc_comms, enc_len, h5_be);

    /* Build rhoInputPrefix = SerializeElement(groupPK) || toBytes(H4) || toBytes(H5) */
    uint8_t prefix[128]; /* 64 + 32 + 32 */
    rev32(prefix,      pk_x_be);    /* pk_x LE */
    rev32(prefix + 32, pk_y_be);    /* pk_y LE */
    rev32(prefix + 64, h4_be);      /* h4 LE */
    rev32(prefix + 96, h5_be);      /* h5 LE */

    /* For each signer: rhoInput = prefix || SerializeScalar(id) */
    for (size_t i = 0; i < n_signers; i++) {
        uint8_t rho_input[160];
        memcpy(rho_input, prefix, 128);
        u32_to_le32(rho_input + 128, comms[i].id);
        zkn_frost_H1(&ctx->hasher, rho_input, 160, rho_out[i]);
    }

    return 0;
}

/* ══════════════════════════════════════════════════════════════════
 *  Section 5.1: commit (deterministic, for testing)
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_commit_deterministic(babyfrost_ctx_t *ctx,
                                    uint32_t identifier,
                                    const uint8_t d_be[32],
                                    const uint8_t e_be[32],
                                    zkn_frost_commitment_t *comm_out)
{
    comm_out->id = identifier;

    babyfrost_reinit_curve(ctx);
    zkn_frost_scalar_base_mult(&ctx->curve, d_be, comm_out->D_x, comm_out->D_y);

    babyfrost_reinit_curve(ctx);
    zkn_frost_scalar_base_mult(&ctx->curve, e_be, comm_out->E_x, comm_out->E_y);

    return 0;
}

/* ══════════════════════════════════════════════════════════════════
 *  Section 5.2: sign
 *
 *  z_i = d_i + e_i * rho_i + lambda_i * sk_i * c   mod order
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_sign(babyfrost_ctx_t *ctx,
                   uint32_t identifier,
                   const uint8_t sk_i_be[32],
                   const uint8_t pk_x_be[32],
                   const uint8_t pk_y_be[32],
                   const uint8_t d_be[32],
                   const uint8_t e_be[32],
                   const uint8_t msg_hash_be[32],
                   const zkn_frost_commitment_t *comms,
                   size_t n_signers,
                   const uint32_t *signer_ids,
                   uint8_t z_i_be[32])
{
    /* 1. Compute binding factors */
    uint8_t rho[ZKN_FROST_MAX_SIGNERS][32];
    babyfrost_compute_binding_factors(ctx, pk_x_be, pk_y_be, comms,
                                      n_signers, msg_hash_be, rho);

    /* Find this signer's rho */
    uint8_t my_rho[32];
    for (size_t i = 0; i < n_signers; i++) {
        if (comms[i].id == identifier) {
            memcpy(my_rho, rho[i], 32);
            break;
        }
    }

    /* 2. Compute group commitment R */
    babyfrost_reinit_curve(ctx);
    uint8_t R_x[32], R_y[32];
    zkn_frost_group_commitment(&ctx->curve, comms, (const uint8_t(*)[32])rho,
                                n_signers, R_x, R_y);

    /* 3. Compute challenge c = H2(R, A, msgHash) */
    uint8_t c[32];
    zkn_frost_challenge(R_x, R_y, pk_x_be, pk_y_be, msg_hash_be,
                         ctx->order, c);

    /* 4. Compute Lagrange coefficient */
    uint8_t lambda[32];
    zkn_frost_vss_lagrange_coeff(lambda, signer_ids, n_signers,
                                  identifier, ctx->order);

    /* 5. z_i = d + e*rho + lambda * sk_i * c */
    zkn_frost_sign_share(d_be, e_be, my_rho, lambda, sk_i_be, c,
                          ctx->order, z_i_be);

    return 0;
}

/* ══════════════════════════════════════════════════════════════════
 *  Section 5.3: aggregate
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_aggregate(babyfrost_ctx_t *ctx,
                        const zkn_frost_commitment_t *comms,
                        size_t n_signers,
                        const uint8_t msg_hash_be[32],
                        const uint8_t pk_x_be[32],
                        const uint8_t pk_y_be[32],
                        const uint8_t z_shares[][32],
                        zkn_frost_sig_t *sig_out)
{
    /* Recompute binding factors + group commitment */
    uint8_t rho[ZKN_FROST_MAX_SIGNERS][32];
    babyfrost_compute_binding_factors(ctx, pk_x_be, pk_y_be, comms,
                                      n_signers, msg_hash_be, rho);

    babyfrost_reinit_curve(ctx);
    zkn_frost_group_commitment(&ctx->curve, comms, (const uint8_t(*)[32])rho,
                                n_signers, sig_out->R_x, sig_out->R_y);

    /* z = sum(z_i) mod order */
    zkn_frost_aggregate_z(z_shares, n_signers, ctx->order, sig_out->z);

    return 0;
}

/* ══════════════════════════════════════════════════════════════════
 *  Verify: z * Base8 == R + (8c) * A
 * ══════════════════════════════════════════════════════════════════ */

int babyfrost_verify(babyfrost_ctx_t *ctx,
                     const zkn_frost_sig_t *sig,
                     const uint8_t pk_x_be[32],
                     const uint8_t pk_y_be[32],
                     const uint8_t msg_hash_be[32],
                     int *valid)
{
    babyfrost_reinit_curve(ctx);
    return zkn_frost_verify(&ctx->curve, sig, pk_x_be, pk_y_be,
                             msg_hash_be, ctx->order, valid);
}
