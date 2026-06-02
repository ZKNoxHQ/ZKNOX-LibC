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

int zkn_poseidon_hash(const uint8_t *inputs,
                      size_t nb_inputs,
                      uint8_t out[32])
{
    ZKN_ERROR_INIT();

    if (nb_inputs == 0 || nb_inputs > ZKN_POSEIDON_MAX_INPUTS)
        return ZKN_ERR_INVALID_PARAM;

    /* Init Montgomery context for the BJJ scalar field. */
    zkn_bn_mont_ctx_t montctx;
    zkn_bn_t modulus;
    ZKN_CHECK(zkn_bn_alloc_init(&modulus, 32, BJJ_PRIME_BE, 32));
    ZKN_CHECK(zkn_mont_alloc(&montctx, 32));
    ZKN_CHECK(zkn_mont_init(&montctx, modulus));

    /* Init Poseidon. */
    zkn_poseidon_ctx_t ctx;
    ZKN_CHECK(zkn_poseidon_init(&ctx, 5, nb_inputs, &montctx));

    /* Load inputs into state[1..nb_inputs] in Montgomery form. */
    for (size_t i = 0; i < nb_inputs; i++) {
        ZKN_CHECK(zkn_bn_init(ctx.state[i + 1], inputs + 32 * i, 32));
        ZKN_CHECK(zkn_mont_to_montgomery(ctx.state[i + 1],
                                         ctx.state[i + 1], &montctx));
    }

    /* Hash. */
    zkn_bn_t result;
    ZKN_CHECK(zkn_poseidon(&ctx, 0, &result, 1));

    /* De-montgomerize and export. */
    ZKN_CHECK(zkn_mont_from_montgomery(result, result, &montctx));
    ZKN_CHECK(zkn_bn_export(result, out, 32));

    /* Release the bignum handles (no-op on SW backend, required on CX). */
    (void)zkn_poseidon_destroy(&ctx);

    ZKN_ERROR_CLOSE();
}
