#include <stdint.h>
#include <stddef.h>
/*
 * zkn_common.c — Common utilities for ZKNOX
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

#include "zkn_common.h"
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 *  rev256 — byte-swap 32 bytes in place
 * ══════════════════════════════════════════════════════════════════════ */


/* ══════════════════════════════════════════════════════════════════════
 *  zkn_reduce_512_be — reduce a 64-byte BE value modulo a 32-byte BE modulus
 *
 *  out[32] = value[64] mod modulus[32]
 * ══════════════════════════════════════════════════════════════════════ */

#ifdef ZKN_BACKEND_LEDGER

/* ── Ledger: use cx_bn 64-byte support (original code path) ──────── */

#include "zkn_bn.h"
#include "zkn_hash_compat.h"
#include "zkn_rng_compat.h"

int zkn_reduce_512_be(uint8_t       out[32],
                      const uint8_t value[64],
                      const uint8_t modulus[32])
{
    zkn_bn_t r, big_val, big_mod;
    uint8_t big_n[64];
    int err = 0;

    /* Build 64-byte modulus: 32 zero bytes || modulus[32] */
    memset(big_n, 0, 32);
    memcpy(big_n + 32, modulus, 32);

    if ((err = zkn_bn_alloc_init(&big_val, 64, value, 64)) != 0) return err;
    if ((err = zkn_bn_alloc_init(&big_mod, 64, big_n, 64)) != 0) return err;
    if ((err = zkn_bn_alloc(&r, 64)) != 0)                       return err;

    if ((err = zkn_bn_reduce(r, big_val, big_mod)) != 0)         return err;
    if ((err = zkn_bn_export(r, out, 32)) != 0)                  return err;

    zkn_bn_destroy(&big_mod);
    zkn_bn_destroy(&big_val);
    zkn_bn_destroy(&r);

    return 0;
}

#else

/* ── Software: pure arithmetic using zkn_mont256 ─────────────────── */

#include "zkn_mont256.h"

/* Local 256-bit comparison (avoids dependency on zkn_sw_bn) */
static int cmp256(const zkn_fe256_t a, const zkn_fe256_t b)
{
    for (int i = ZKN_MONT_NLIMBS - 1; i >= 0; i--) {
        if (a[i] > b[i]) return  1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

/* Local reduce: while a >= n, a -= n */
static void reduce256(zkn_fe256_t r, const zkn_fe256_t n)
{
    while (cmp256(r, n) >= 0)
        zkn_sub_mod_256(r, r, n, n);
}

/*
 * Strategy:
 *   value = hi · 2^256 + lo       (split 64 bytes into two 32-byte halves)
 *
 *   value mod n = ((hi mod n) · (2^256 mod n) + (lo mod n)) mod n
 *
 * 2^256 mod n = from_mont(R^2) because:
 *   from_mont(R^2) = R^2 · R^{-1} = R mod n = 2^256 mod n.
 */

int zkn_reduce_512_be(uint8_t       out[32],
                      const uint8_t value[64],
                      const uint8_t modulus[32])
{
    zkn_mont_ctx256_t ctx;
    zkn_fe256_t n, hi, lo, hi_r, lo_r, R_normal, term, result;

    /* Parse inputs */
    zkn_fe256_from_be(n,  modulus);
    zkn_fe256_from_be(hi, value);       /* high 32 bytes */
    zkn_fe256_from_be(lo, value + 32);  /* low 32 bytes  */

    /* Init Montgomery context for modulus */
    zkn_mont_ctx_init(&ctx, n);

    /* R_normal = 2^256 mod n = from_mont(R^2) */
    zkn_from_mont_256(R_normal, ctx.R2, ctx.p, ctx.n0);

    /* hi_r = hi mod n */
    memcpy(hi_r, hi, sizeof(zkn_fe256_t));
    reduce256(hi_r, n);

    /* lo_r = lo mod n */
    memcpy(lo_r, lo, sizeof(zkn_fe256_t));
    reduce256(lo_r, n);

    /* term = hi_r * R_normal mod n  (via Montgomery round-trip) */
    {
        zkn_fe256_t ma, mb, mr;
        zkn_mul_mont_256(ma, hi_r,    ctx.R2, ctx.p, ctx.n0);  /* to_mont(hi_r)    */
        zkn_mul_mont_256(mb, R_normal, ctx.R2, ctx.p, ctx.n0); /* to_mont(R_normal) */
        zkn_mul_mont_256(mr, ma, mb, ctx.p, ctx.n0);           /* mont_mul          */
        zkn_from_mont_256(term, mr, ctx.p, ctx.n0);            /* back to normal    */
    }

    /* result = (term + lo_r) mod n */
    zkn_add_mod_256(result, term, lo_r, n);

    /* Export */
    zkn_fe256_to_be(out, result);

    return 0;
}

#endif /* ZKN_BACKEND_LEDGER */
