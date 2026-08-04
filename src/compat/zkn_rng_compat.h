/*
 * zkn_rng_compat.h — RNG compatibility layer (v3: use cx_rng for trng too)
 *
 * Provides zkn_rng(buf, len) and zkn_trng_get_random_data(buf, len) that call:
 *   - cx_rng() on Ledger BOLOS  (ZKN_BN_BACKEND_LEDGER or ZKN_RNG_BOLOS)
 *   - random_buffer() on Trezor (define ZKN_RNG_TREZOR additionally)
 *   - /dev/urandom on Linux/macOS host (default)
 *
 * v3: zkn_trng_get_random_data is now also routed to cx_rng (not
 * cx_trng_get_random_data), which doesn't require explicit initialization.
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */
#ifndef ZKN_RNG_COMPAT_H
#define ZKN_RNG_COMPAT_H

#include <stddef.h>
#include <stdint.h>

#if defined(ZKN_BN_BACKEND_LEDGER) || defined(ZKN_RNG_BOLOS)
#  include "cx.h"
#  define zkn_rng(buf, len)                  cx_rng((buf), (len))
#  define zkn_trng_get_random_data(buf, len) cx_rng((buf), (len))
/* Checked variant: cx_get_random_bytes returns cx_err_t; 0 on success. */
#  define zkn_rng_checked(buf, len)          ((cx_get_random_bytes((buf), (len)) == CX_OK) ? 0 : -1)
#else
   void zkn_rng(uint8_t *buf, size_t len);
   void zkn_trng_get_random_data(uint8_t *buf, size_t len);
   int  zkn_rng_checked(uint8_t *buf, size_t len);
#endif

#endif /* ZKN_RNG_COMPAT_H */
