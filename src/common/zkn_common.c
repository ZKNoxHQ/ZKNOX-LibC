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

/* Portable implementation used by BOTH backends.
 *
 * The file used to carry a cx_bn branch under `#ifdef ZKN_BACKEND_LEDGER`, a
 * macro that is defined nowhere (the backend switch is ZKN_BN_BACKEND_LEDGER),
 * so Ledger builds have always compiled the portable path below. The dead
 * branch was removed rather than enabled: it had never been exercised on
 * device, leaked bignum handles on every error path, and exported a 64-byte
 * bignum into a 32-byte buffer. */
/* ── Software: pure arithmetic using zkn_mont256 ─────────────────── */

#include "zkn_mont256.h"

/* Constant-time reduction of any 256-bit value modulo n:
 *   from_mont(to_mont(a)) = (a * R^2 * R^-1) * R^-1 = a mod n.
 * to_mont is valid for every a < 2^256 because R^2 mod n < n, so a * R^2 < R * n
 * and the CIOS output is < 2n before its final conditional subtraction.
 * Replaces a `while (a >= n) a -= n` loop whose iteration count depended on
 * the (potentially secret) input. */
static void reduce256_ct(zkn_fe256_t r, const zkn_fe256_t a, const zkn_mont_ctx256_t *ctx)
{
    zkn_fe256_t m;
    zkn_mul_mont_256(m, a, ctx->R2, ctx->p, ctx->n0);
    zkn_from_mont_256(r, m, ctx->p, ctx->n0);
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

    /* hi_r = hi mod n, lo_r = lo mod n (constant time) */
    reduce256_ct(hi_r, hi, &ctx);
    reduce256_ct(lo_r, lo, &ctx);

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

