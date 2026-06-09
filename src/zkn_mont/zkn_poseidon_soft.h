/*
 * zkn_poseidon.h — Poseidon hash (circomlib-compatible) over zkn_bn
 *
 * Standalone port of the Ledger ZKNOX Poseidon implementation.
 * All cx_bn/cx_mont calls replaced with zkn_bn equivalents.
 *
 * Supports Poseidon-1 through Poseidon-7 (1..7 inputs, 2..8 state cells, pow=5).
 * Field: BN254 scalar field (BabyJubjub base field).
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#ifndef ZKN_POSEIDON_SOFT_H
#define ZKN_POSEIDON_SOFT_H

#include "zkn_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────────── */

#define POSEIDON_NROUNDS_F   8    /* full rounds (constant across arities)   */
#define POSEIDON_MAX_INPUTS  7
#define POSEIDON_MAX_CELLS   8    /* inputs + 1 */

#define POSEIDON_INITIALIZED 0xA5A5A5A5u

/* ── Types ─────────────────────────────────────────────────────────── */

typedef struct {
    size_t  nb_inputs;
    size_t  nb_state_cells;
    uint8_t pow;
    size_t  rounds_f;
    size_t  rounds_p;

    uint32_t status;

    zkn_bn_mont_ctx_t *mont;

    zkn_bn_t state[POSEIDON_MAX_CELLS];
    zkn_bn_t MixColumn[POSEIDON_MAX_CELLS * POSEIDON_MAX_CELLS];

    /* Grain LFSR for round constant generation */
    uint64_t grain_state[2];

    /* scratch space */
    zkn_bn_t temp;
    zkn_bn_t tmp[POSEIDON_MAX_CELLS];  /* must be nb_state_cells, not nb_inputs */
} poseidon_soft_ctx_t;

/* ── API ───────────────────────────────────────────────────────────── */

/**
 * Initialize Poseidon context.
 * @param ctx        Context to initialize
 * @param pow        S-box exponent (5 for circomlib)
 * @param nb_inputs  Number of hash inputs (e.g. 5)
 * @param montctx    Already-initialized Montgomery context (BJJ field)
 */
int zkn_poseidon_init(poseidon_soft_ctx_t *ctx,
                      uint32_t pow,
                      size_t nb_inputs,
                      zkn_bn_mont_ctx_t *montctx);

/**
 * Compute Poseidon hash.
 * Inputs must already be loaded into ctx->state[1..nb_inputs] in Montgomery form.
 * ctx->state[0] is set to initState (typically 0).
 * Output is in Montgomery form in ctx->state[0..sizeout-1].
 *
 * @param ctx        Initialized Poseidon context
 * @param initState  Initial state[0] value (usually 0)
 * @param out        Output array (copies from state)
 * @param sizeout    Number of outputs to copy (usually 1)
 */
int zkn_poseidon(poseidon_soft_ctx_t *ctx,
                 uint32_t initState,
                 zkn_bn_t *out,
                 size_t sizeout);

/**
 * Release every zkn_bn handle held by the context.
 *
 * On the SW backend (zkn_bn_sw) this is a no-op since zkn_bn_destroy itself
 * is a no-op there. On the Ledger cx_bn backend it returns the
 * (n+1)^2 + 2(n+1) + 1 bignums back to the BOLOS pool, which is required
 * to avoid pool exhaustion across successive calls.
 */
int zkn_poseidon_destroy(poseidon_soft_ctx_t *ctx);

/* zkn_poseidon_hash is declared in zkn_poseidon.h (backend-agnostic
 * wrapper around zkn_poseidon_init / zkn_poseidon / zkn_poseidon_destroy). */

#ifdef __cplusplus
}
#endif

#endif /* ZKN_POSEIDON_SOFT_H */
