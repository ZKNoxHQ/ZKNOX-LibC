/*
 * zkn_poseidon.h — Backend-selected Poseidon hash API.
 *
 * Exposes a single set of names regardless of which backend is compiled in:
 *
 *   typedef ...        zkn_poseidon_ctx_t;
 *   int zkn_poseidon_init   (ctx, pow, nb_inputs, montctx);
 *   int zkn_poseidon        (ctx, init_state, out, sizeout);
 *   int zkn_poseidon_destroy(ctx);
 *
 *   #define ZKN_POSEIDON_MAX_INPUTS  <max supported arity for this backend>
 *
 * Backend dispatch:
 *
 *   ZKN_BN_BACKEND_LEDGER (BACKEND=cx)
 *     - routes to the hardware-tested arity-5 implementation in
 *       src/hash/zkn_poseidon_constants.c  (`Poseidon_alloc_init`,
 *       `Poseidon`, `Poseidon_destroy`, `poseidon_ctx_t`)
 *     - ZKN_POSEIDON_MAX_INPUTS = 5
 *
 *   otherwise (BACKEND=sw)
 *     - routes to the variable-arity (1..7) implementation in
 *       src/zkn_mont/zkn_poseidon_soft.c  (`zkn_poseidon_init`,
 *       `zkn_poseidon`, `zkn_poseidon_destroy`, `poseidon_soft_ctx_t`)
 *     - ZKN_POSEIDON_MAX_INPUTS = POSEIDON_MAX_INPUTS  (= 7)
 *
 * Callers should include only this header. Including the backend-specific
 * headers (zkn_poseidon_constants.h / zkn_poseidon_soft.h) directly works
 * but bypasses the dispatch.
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#ifndef ZKN_POSEIDON_H
#define ZKN_POSEIDON_H

#include "zkn_bn.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ZKN_BN_BACKEND_LEDGER

#include "zkn_poseidon_constants.h"

typedef poseidon_ctx_t zkn_poseidon_ctx_t;

#define ZKN_POSEIDON_MAX_INPUTS  _MAX_POSEIDON_INPUT  /* 5 on CX */

static inline int zkn_poseidon_init(zkn_poseidon_ctx_t *ctx,
                                    uint32_t pow,
                                    size_t nb_inputs,
                                    zkn_bn_mont_ctx_t *montctx)
{
    return Poseidon_alloc_init(ctx, pow, nb_inputs, montctx);
}

static inline int zkn_poseidon(zkn_poseidon_ctx_t *ctx,
                               uint32_t initState,
                               zkn_bn_t *out,
                               size_t sizeout)
{
    return Poseidon(ctx, initState, out, sizeout);
}

static inline int zkn_poseidon_destroy(zkn_poseidon_ctx_t *ctx)
{
    return Poseidon_destroy(ctx);
}

#else  /* SW backend */

#include "zkn_poseidon_soft.h"

typedef poseidon_soft_ctx_t zkn_poseidon_ctx_t;

#define ZKN_POSEIDON_MAX_INPUTS  POSEIDON_MAX_INPUTS  /* 7 on SW */

/* zkn_poseidon_init / zkn_poseidon / zkn_poseidon_destroy are declared
 * directly in zkn_poseidon_soft.h with the right signatures — no wrapper
 * stubs needed. */

#endif

/**
 * Convenience one-shot hash. Hashes `nb_inputs` 32-byte big-endian field
 * elements via the backend-selected Poseidon implementation and writes the
 * 32-byte digest to `out`. Internally allocates the Montgomery context and
 * Poseidon state, then releases them via `zkn_poseidon_destroy`.
 *
 * Valid arity range depends on the backend (`ZKN_POSEIDON_MAX_INPUTS`).
 * Returns ZKN_INVALID_PARAM if `nb_inputs` is 0 or above the backend max.
 */
int zkn_poseidon_hash(const uint8_t *inputs,
                      size_t nb_inputs,
                      uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* ZKN_POSEIDON_H */
