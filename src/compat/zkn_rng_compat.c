/*
 * zkn_rng_compat.c — software RNG compat
 *
 * Two strategies, selectable at build time:
 *   -DZKN_RNG_TREZOR  → calls random_buffer() from Trezor crypto/rand.h
 *   (default host)    → reads /dev/urandom
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#include "zkn_rng_compat.h"

#if !defined(ZKN_BN_BACKEND_LEDGER)

#if defined(ZKN_RNG_TREZOR)
   /* Trezor backend: random_buffer() is provided by Trezor's crypto/rand.h */
   extern void random_buffer(uint8_t *buf, size_t len);

   void zkn_rng(uint8_t *buf, size_t len) { random_buffer(buf, len); }
   void zkn_trng_get_random_data(uint8_t *buf, size_t len) {
       random_buffer(buf, len);
   }
#else
   /* Host backend: /dev/urandom */
#  include <stdio.h>
#  include <stdlib.h>

   static void read_urandom(uint8_t *buf, size_t len) {
       FILE *f = fopen("/dev/urandom", "rb");
       if (!f) { /* dev: fall back to deterministic pattern */
           for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)i;
           return;
       }
       if (fread(buf, 1, len, f) != len) {
           for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)i;
       }
       fclose(f);
   }

   void zkn_rng(uint8_t *buf, size_t len) { read_urandom(buf, len); }
   void zkn_trng_get_random_data(uint8_t *buf, size_t len) {
       read_urandom(buf, len);
   }
#endif

#endif /* !ZKN_BN_BACKEND_LEDGER */
