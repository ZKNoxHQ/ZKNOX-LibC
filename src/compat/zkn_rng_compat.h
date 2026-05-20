/*
 * zkn_rng_compat.h — RNG compatibility layer
 *
 * Provides zkn_rng(buf, len) that calls:
 *   - cx_rng() on Ledger
 *   - random_buffer() on Trezor (define ZKN_RNG_TREZOR additionally)
 *   - /dev/urandom on Linux/macOS host
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#ifndef ZKN_RNG_COMPAT_H
#define ZKN_RNG_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#if defined(ZKN_BN_BACKEND_LEDGER)
#  include "cx.h"
#  define zkn_rng(buf, len)            cx_rng((buf), (len))
#  define zkn_trng_get_random_data(buf, len)  cx_trng_get_random_data((buf), (len))
#else
/* Software backend: implemented in zkn_rng_compat.c
 * On Trezor:  ZKN_RNG_TREZOR  → uses random_buffer() from crypto/rand.h
 * On host:    (default)       → uses /dev/urandom */
   void zkn_rng(uint8_t *buf, size_t len);
   void zkn_trng_get_random_data(uint8_t *buf, size_t len);
#endif

#endif /* ZKN_RNG_COMPAT_H */
