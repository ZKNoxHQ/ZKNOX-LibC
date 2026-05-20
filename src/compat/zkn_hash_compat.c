/*
 * zkn_hash_compat.c — software hash compat (BLAKE-512, Keccak-256)
 *
 * Only compiled when ZKN_BN_BACKEND_SW is defined.
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#include "zkn_hash_compat.h"

#ifdef ZKN_BN_BACKEND_SW

#include <string.h>

int zkn_hash_init_ex(zkn_hash_t *state, zkn_md_t md, size_t output_size)
{
    if (!state) return -1;
    state->md = md;
    state->output_size = output_size;
    if (md == ZKN_BLAKE2B) {
        (void)zkn_blake512_init(&state->blake);
        return 0;
    }
    return -1;
}

int zkn_hash_update(zkn_hash_t *state, const uint8_t *data, size_t len)
{
    if (!state) return -1;
    if (state->md == ZKN_BLAKE2B) {
        (void)zkn_blake512_update(&state->blake, data, len);
        return 0;
    }
    return -1;
}

int zkn_hash_final(zkn_hash_t *state, uint8_t *out)
{
    if (!state) return -1;
    if (state->md == ZKN_BLAKE2B) {
        (void)zkn_blake512_final(&state->blake, out);
        return 0;
    }
    return -1;
}

int zkn_blake2b_512_hash(const uint8_t *in, size_t in_len, uint8_t out[64])
{
    (void)zkn_blake512(in, in_len, out);
    return 0;
}

int zkn_keccak_256_hash(const uint8_t *in, size_t in_len, uint8_t out[32])
{
    keccak256_ctx_t ctx;
    keccak256_init(&ctx);
    keccak256_update(&ctx, in, (uint32_t)in_len);
    keccak256_final(&ctx, out);
    return 0;
}

#endif /* ZKN_BN_BACKEND_SW */
