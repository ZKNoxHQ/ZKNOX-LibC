/*
 * zkn_poseidon.c — Backend-agnostic Poseidon convenience wrapper.
 *
 * `zkn_poseidon_hash` is implemented here, on top of the dispatched API
 * defined in `zkn_poseidon.h`. By using only the wrapper names
 * (`zkn_poseidon_ctx_t`, `zkn_poseidon_init`, `zkn_poseidon`,
 * `zkn_poseidon_destroy`), this translation unit compiles cleanly against
 * both backends — Ledger cx_bn (BACKEND=cx) and software (BACKEND=sw) —
 * and routes to the right Poseidon implementation at compile time.
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#include <stdbool.h>

#include "zkn_bn.h"
#include "zkn_errors.h"
#include "zkn_common.h"
#include "zkn_poseidon.h"

/* BabyJubjub scalar-field prime (= BN254 base field), big-endian. */
static const uint8_t BJJ_PRIME_BE[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
};

/* The Ledger backend's `Poseidon` writes to `out[i]` via cx_bn_copy, which
 * requires a pre-allocated destination handle. The pool must also be locked
 * around every cx_bn / cx_mont call; cx_bn_unlock erases the pool, so per-
 * handle destroys are redundant for cleanup and would not compile against
 * the SW backend's array-typed zkn_bn_t anyway. */
int zkn_poseidon_hash(const uint8_t *inputs,
                      size_t nb_inputs,
                      uint8_t out[32])
{
    if (nb_inputs == 0 || nb_inputs > ZKN_POSEIDON_MAX_INPUTS)
        return ZKN_ERR_INVALID_PARAM;

    zkn_bn_mont_ctx_t montctx;
    zkn_poseidon_ctx_t ctx;
    zkn_bn_t modulus;
    zkn_bn_t input_raw;        /* Scratch: holds the un-reduced 32-B input. */
    zkn_bn_t result;
    bool bn_locked = false;
    bool ctx_inited = false;
    int rc = -1;

    if (zkn_bn_lock(32, 0) != ZKN_OK) goto cleanup;
    bn_locked = true;

    if (zkn_bn_alloc_init(&modulus, 32, BJJ_PRIME_BE, 32) != ZKN_OK) goto cleanup;
    if (zkn_mont_alloc(&montctx, 32) != ZKN_OK) goto cleanup;
    if (zkn_mont_init(&montctx, modulus) != ZKN_OK) goto cleanup;

    if (zkn_poseidon_init(&ctx, 5, nb_inputs, &montctx) != ZKN_OK) goto cleanup;
    ctx_inited = true;

    /* Audit: Poseidon input reduction mod p.
     *
     * The on-chain engine (circomlibjs / poseidon-lite) treats inputs as
     * field elements and reduces them mod p implicitly. Without matching
     * that on-device, a host can submit a 32-byte word ≥ p (e.g. 2^256 − 1,
     * or the prime itself) and either (a) two inputs differing by a multiple
     * of p produce the same digest — silent collision — or (b) the
     * Montgomery conversion lands the sponge in an undefined state because
     * cx_mont_to_montgomery's domain is [0, p). Reducing each input with
     * `zkn_bn_reduce` before feeding it into Montgomery form closes both.
     *
     * Some backends (cx_bn_reduce) require distinct source and destination
     * handles, so we keep a small `input_raw` scratch separate from
     * `ctx.state[i+1]`. The pool lock above means the scratch goes away
     * with `zkn_bn_unlock` in cleanup — no per-iteration destroy. */
    if (zkn_bn_alloc(&input_raw, 32) != ZKN_OK) goto cleanup;

    for (size_t i = 0; i < nb_inputs; i++) {
        if (zkn_bn_init(input_raw, inputs + 32 * i, 32) != ZKN_OK)
            goto cleanup;
        if (zkn_bn_reduce(ctx.state[i + 1], input_raw, modulus) != ZKN_OK)
            goto cleanup;
        if (zkn_mont_to_montgomery(ctx.state[i + 1],
                                   ctx.state[i + 1], &montctx) != ZKN_OK)
            goto cleanup;
    }

    if (zkn_bn_alloc(&result, 32) != ZKN_OK) goto cleanup;
    if (zkn_poseidon(&ctx, 0, &result, 1) != ZKN_OK) goto cleanup;
    if (zkn_mont_from_montgomery(result, result, &montctx) != ZKN_OK) goto cleanup;
    if (zkn_bn_export(result, out, 32) != ZKN_OK) goto cleanup;

    rc = ZKN_OK;

cleanup:
    if (ctx_inited) (void)zkn_poseidon_destroy(&ctx);
    if (bn_locked) (void)zkn_bn_unlock();
    return rc;
}
