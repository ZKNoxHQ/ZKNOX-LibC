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
/* Default host: getrandom(2) when available, /dev/urandom otherwise.
 *
 * SECURITY: the previous implementation silently filled the buffer with the
 * predictable pattern 0,1,2,... when /dev/urandom could not be read (e.g. in a
 * chroot/sandbox or under fd exhaustion). Every consumer of zkn_rng() /
 * zkn_trng_get_random_data() (projective-coordinate blinding today, any key or
 * nonce generation tomorrow) would then run with attacker-known "randomness".
 * The void-returning APIs now FAIL CLOSED: they abort the process rather than
 * hand out non-random bytes. Callers that can handle an error must use
 * zkn_rng_checked(). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#if defined(__linux__)
#  include <sys/random.h>
#endif

static int read_urandom(uint8_t *buf, size_t len) {
    size_t done = 0;
#if defined(__linux__)
    while (done < len) {
        ssize_t r = getrandom(buf + done, len - done, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;                       /* e.g. ENOSYS: fall back below */
        }
        done += (size_t)r;
    }
    if (done == len) return 0;
#endif
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) goto fail;
    while (done < len) {
        size_t r = fread(buf + done, 1, len - done, f);
        if (r == 0) { fclose(f); goto fail; }
        done += r;
    }
    fclose(f);
    return 0;
fail:
    /* Never leave partial / stale bytes behind for a caller that ignores
     * the error. */
    memset(buf, 0, len);
    return -1;
}

static void rng_or_abort(uint8_t *buf, size_t len) {
    if (read_urandom(buf, len) != 0) {
        fprintf(stderr, "zknox: system RNG unavailable, aborting\n");
        abort();
    }
}

void zkn_rng(uint8_t *buf, size_t len) {
    rng_or_abort(buf, len);
}

void zkn_trng_get_random_data(uint8_t *buf, size_t len) {
    rng_or_abort(buf, len);
}

int zkn_rng_checked(uint8_t *buf, size_t len) {
    return read_urandom(buf, len);
}

#endif /* ZKN_RNG_TREZOR or default host */

#endif /* !ZKN_BN_BACKEND_LEDGER && !ZKN_RNG_BOLOS */
