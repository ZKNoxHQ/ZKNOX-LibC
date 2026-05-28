/*
 * zkn_rng_compat.c — software RNG compat
 *
 * In Ledger BOLOS mode (either ZKN_BN_BACKEND_LEDGER or ZKN_RNG_BOLOS),
 * zkn_rng_compat.h provides zkn_rng / zkn_trng_get_random_data as macros
 * that expand directly to cx_rng. This file is then empty.
 *
 * For non-Ledger targets, this file provides the actual function bodies:
 *   -DZKN_RNG_TREZOR  → random_buffer() from Trezor crypto/rand.h
 *   (default host)    → /dev/urandom
 *
 * Copyright (c) 2025 ZKNOX — MIT
 */

#include "zkn_rng_compat.h"

#if !defined(ZKN_BN_BACKEND_LEDGER) && !defined(ZKN_RNG_BOLOS)

#if defined(ZKN_RNG_TREZOR)
/* Trezor backend: random_buffer() is provided by Trezor's crypto/rand.h */
extern void random_buffer(uint8_t *buf, size_t len);

void zkn_rng(uint8_t *buf, size_t len) {
    random_buffer(buf, len);
}

void zkn_trng_get_random_data(uint8_t *buf, size_t len) {
    random_buffer(buf, len);
}

#else
/* Default host: /dev/urandom */
#include <stdio.h>
#include <stdlib.h>

static void read_urandom(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)i;
        return;
    }
    if (fread(buf, 1, len, f) != len) {
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)i;
    }
    fclose(f);
}

void zkn_rng(uint8_t *buf, size_t len) {
    read_urandom(buf, len);
}

void zkn_trng_get_random_data(uint8_t *buf, size_t len) {
    read_urandom(buf, len);
}

#endif /* ZKN_RNG_TREZOR or default host */

#endif /* !ZKN_BN_BACKEND_LEDGER && !ZKN_RNG_BOLOS */
