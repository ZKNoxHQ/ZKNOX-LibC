/*
 * zkn_hash_compat.h — Hash API compatibility layer
 *
 * Wraps either the Ledger SDK hash functions (cx_blake2b_*, cx_keccak_*)
 * or the local software implementations (zkn_blake512, mpt/keccak256.h)
 * depending on the active backend.
 *
 * Public API exposed to the rest of the library:
 *   zkn_hash_t              — opaque hash state
 *   zkn_blake2b_t           — BLAKE2b state
 *   zkn_hash_init_ex(...)   — initialize hash state
 *   zkn_hash_update(...)    — feed bytes
 *   zkn_hash_final(...)     — finalize and emit digest
 *   zkn_blake2b_512_hash(...)
 *   zkn_keccak_256_hash(...)
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#ifndef ZKN_HASH_COMPAT_H
#define ZKN_HASH_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#if defined(ZKN_BN_BACKEND_LEDGER)
/* ── Ledger backend: alias cx_* to zkn_* ─────────────────────────── */
#  include "cx.h"

   typedef cx_hash_t     zkn_hash_t;
   typedef cx_blake2b_t  zkn_blake2b_t;
   typedef cx_md_t       zkn_md_t;

#  define ZKN_BLAKE2B  CX_BLAKE2B

#  define zkn_hash_init_ex          cx_hash_init_ex
#  define zkn_hash_update           cx_hash_update
#  define zkn_hash_final            cx_hash_final
#  define zkn_blake2b_512_hash      cx_blake2b_512_hash
#  define zkn_keccak_256_hash       cx_keccak_256_hash

#elif defined(ZKN_BN_BACKEND_SW)
/* ── Software backend: implemented in zkn_hash_compat.c ─────────── */
#  include "zkn_blake512.h"
#  include "keccak256.h"      /* from src/mpt/ (also used standalone) */

   /* Generic hash state — for now, only BLAKE2b is supported in SW. */
   typedef enum {
       ZKN_BLAKE2B = 1,
       /* extend with ZKN_SHA256, ZKN_KECCAK256, etc. if needed */
   } zkn_md_t;

   /* Concrete state: a discriminated union of supported hash states. */
   typedef struct {
       zkn_md_t       md;
       size_t         output_size;
       /* BLAKE2b state from zkn_blake512 (the existing implementation). */
       zkn_blake512_ctx_t blake;
   } zkn_blake2b_t;

   /* Generic alias — zknox_1905 always uses `(zkn_hash_t *)&blake_state`. */
   typedef zkn_blake2b_t zkn_hash_t;

   /* Function declarations (implemented in zkn_hash_compat.c). */
   int zkn_hash_init_ex(zkn_hash_t *state, zkn_md_t md, size_t output_size);
   int zkn_hash_update (zkn_hash_t *state, const uint8_t *data, size_t len);
   int zkn_hash_final  (zkn_hash_t *state, uint8_t *out);

   /* One-shot helpers. */
   int zkn_blake2b_512_hash(const uint8_t *in, size_t in_len, uint8_t out[64]);
   int zkn_keccak_256_hash (const uint8_t *in, size_t in_len, uint8_t out[32]);

#else
#  error "Define ZKN_BN_BACKEND_LEDGER or ZKN_BN_BACKEND_SW"
#endif

#endif /* ZKN_HASH_COMPAT_H */
