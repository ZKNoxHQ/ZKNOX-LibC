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

int zkn_rng_checked(uint8_t *buf, size_t len) {
    random_buffer(buf, len);
    return 0;
}

#else
/* Default host: /dev/urandom */
#include <stdio.h>
#include <stdlib.h>

static int read_urandom(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    int rc = (fread(buf, 1, len, f) == len) ? 0 : -1;
    fclose(f);
    return rc;
}

void zkn_rng(uint8_t *buf, size_t len) {
    if (read_urandom(buf, len) != 0) {
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)i;
    }
}

void zkn_trng_get_random_data(uint8_t *buf, size_t len) {
    if (read_urandom(buf, len) != 0) {
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)i;
    }
}

int zkn_rng_checked(uint8_t *buf, size_t len) {
    return read_urandom(buf, len);
}

#endif /* ZKN_RNG_TREZOR or default host */

#endif /* !ZKN_BN_BACKEND_LEDGER && !ZKN_RNG_BOLOS */
