/*
 * zkn_hash_compat.h — Hash API compatibility layer
 *
 * FROST-EDBABYJUJUB-BLAKE512-v1 requires the original BLAKE-512
 * (the SHA-3 candidate), not BLAKE2b. Both BN backends therefore use the
 * local zkn_blake512 implementation. Keccak remains backend-selected.
 *
 * Public API exposed to the rest of the library:
 *   zkn_hash_t              — opaque hash state
 *   zkn_blake2b_t           — legacy type name for BLAKE-512 state
 *   zkn_hash_init_ex(...)   — initialize hash state
 *   zkn_hash_update(...)    — feed bytes
 *   zkn_hash_final(...)     — finalize and emit digest
 *   zkn_blake2b_512_hash(...) — legacy name; computes BLAKE-512
 *   zkn_keccak_256_hash(...)
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#ifndef ZKN_HASH_COMPAT_H
#define ZKN_HASH_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#include "zkn_blake512.h"

typedef enum {
    ZKN_BLAKE512 = 1,
} zkn_md_t;

/* Keep the old identifier while callers are migrated. It now names the
 * protocol's actual primitive rather than SDK BLAKE2b. */
#define ZKN_BLAKE2B ZKN_BLAKE512

typedef struct {
    zkn_md_t md;
    size_t output_size;
    zkn_blake512_ctx_t blake;
} zkn_blake2b_t;

typedef zkn_blake2b_t zkn_hash_t;

int zkn_hash_init_ex(zkn_hash_t *state, zkn_md_t md, size_t output_size);
int zkn_hash_update (zkn_hash_t *state, const uint8_t *data, size_t len);
int zkn_hash_final  (zkn_hash_t *state, uint8_t *out);

/* Legacy name retained for API compatibility; computes original BLAKE-512. */
int zkn_blake2b_512_hash(const uint8_t *in, size_t in_len, uint8_t out[64]);

#if defined(ZKN_BN_BACKEND_LEDGER)
#  include "cx.h"
#  define zkn_keccak_256_hash cx_keccak_256_hash
#elif defined(ZKN_BN_BACKEND_SW)
#  include "keccak256.h"      /* from src/mpt/ (also used standalone) */
int zkn_keccak_256_hash(const uint8_t *in, size_t in_len, uint8_t out[32]);
#else
#  error "Define ZKN_BN_BACKEND_LEDGER or ZKN_BN_BACKEND_SW"
#endif

#endif /* ZKN_HASH_COMPAT_H */
