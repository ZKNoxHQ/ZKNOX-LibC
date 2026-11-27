/* Host-only test — compiled solely by `make test` (which defines
 * ZKN_HOST_TESTS). The Ledger SDK app build sweeps every .c under the
 * submodule; this guard makes the file an empty translation unit there. */
#ifdef ZKN_HOST_TESTS

/*
 * test_fixedbase_blind.c — the fixed-base multiplication with a blinded
 * scalar gives the point of the plain one.
 *
 * tEdwards_fixedBase_4MSM_masked(k, lambda) computes [k + lambda * l]G over
 * 72 steps and the tables of zkn_fixedbase72_tables.c. It must equal
 * tEdwards_fixedBase_4MSM(k), 64 steps over the tables the library always
 * had, for every k and every lambda. The scalars sit on the edges of the
 * windows of both layouts and around the subgroup order; the lambdas on the
 * edges of their two 16-bit digits. Then the entry point that draws lambda
 * itself, and zkn_prv2pub, whichever of the two it is built with.
 *
 * Built only where the blinded multiplication exists:
 *
 *     make test ZKN_FIXEDBASE_FLASH_TABLE=1
 *     make test ZKN_FIXEDBASE_FLASH_TABLE=1 ZKN_FIXEDBASE_SCALAR_BLINDING=1
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "zkn_bn.h"
#include "zkn_errors.h"
#include "zkn_tEdwards.h"
#include "zkn_eddsa.h"

static int g_pass = 0, g_fail = 0;

static void chk(const char *label, int ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", label);
    if (ok) g_pass++; else g_fail++;
}

#ifdef ZKN_HAVE_FIXEDBASE_BLIND

static void pattern(uint8_t *b, size_t n, uint8_t tag)
{
    uint32_t x = 0x9E3779B9u ^ ((uint32_t)tag * 0x01000193u);
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        b[i] = (uint8_t)(x >> 11);
    }
}

/* 2^bit as 32 bytes big endian, minus `minus` (0 or 1). */
static void pow2(uint8_t k[32], unsigned bit, int minus)
{
    memset(k, 0, 32);
    if (bit < 256) k[31 - bit / 8] = (uint8_t)(1u << (bit % 8));
    if (minus) {
        if (bit >= 256) { memset(k, 0xFF, 32); return; }
        for (int i = 31; i >= 0; i--) { if (k[i]--) break; }
    }
}

/* out = order + delta, delta in -1, 0, 1. */
static void near_order(zkn_edcurve_t *c, int delta, uint8_t k[32])
{
    zkn_bn_export(c->order, k, 32);
    if (delta > 0) { for (int i = 31; i >= 0; i--) { if (++k[i]) break; } }
    if (delta < 0) { for (int i = 31; i >= 0; i--) { if (k[i]--) break; } }
}

static int plain(uint32_t id, const uint8_t k[32], uint8_t xy[64])
{
    zkn_edcurve_t c; zkn_edpoint_t R;
    int rc = tEdwards_Curve_alloc_init(&c, id);
    rc |= tEdwards_alloc(&c, &R);
    rc |= tEdwards_fixedBase_4MSM(&c, k, &R);
    rc |= tEdwards_export(&c, &R, xy, xy + 32);
    return rc;
}

static int masked(uint32_t id, const uint8_t k[32], uint32_t lambda, uint8_t xy[64])
{
    zkn_edcurve_t c; zkn_edpoint_t R;
    int rc = tEdwards_Curve_alloc_init(&c, id);
    rc |= tEdwards_alloc(&c, &R);
    rc |= tEdwards_fixedBase_4MSM_masked(&c, k, lambda, &R);
    rc |= tEdwards_export(&c, &R, xy, xy + 32);
    return rc;
}

static int blind(uint32_t id, const uint8_t k[32], uint8_t xy[64])
{
    zkn_edcurve_t c; zkn_edpoint_t R;
    int rc = tEdwards_Curve_alloc_init(&c, id);
    rc |= tEdwards_alloc(&c, &R);
    rc |= tEdwards_fixedBase_4MSM_blind(&c, k, &R);
    rc |= tEdwards_export(&c, &R, xy, xy + 32);
    return rc;
}

static const uint32_t LAMBDAS[] = {0, 1, 2, 0xFFFF, 0x10000, 0x10001, 0x7FFFFFFF, 0x80000000, 0xFFFF0000,
                                   0xFFFFFFFE, 0xFFFFFFFF, 0x9E3779B9, 0x243F6A88};
#define N_LAMBDAS (sizeof(LAMBDAS) / sizeof(LAMBDAS[0]))

int main(void)
{
    static const uint32_t CURVES[] = {_BABYJUJUB_ID, _BANDERSNATCH_ID};
    static const char *NAMES[] = {"BabyJubjub", "Bandersnatch"};
    static const unsigned BITS[] = {0, 1, 15, 16, 63, 64, 71, 72, 127, 128, 143, 144, 191, 192, 215, 216, 250, 255};
    char label[128];

    printf("== fixed-base multiplication with a blinded scalar ==\n");
    for (size_t ci = 0; ci < 2; ci++) {
        uint32_t id = CURVES[ci];
        zkn_edcurve_t c;
        uint8_t k[32], want[64], got[64];
        int bad = 0, n = 0, rc = tEdwards_Curve_alloc_init(&c, id);

        printf("\n[%s]\n", NAMES[ci]);

        /* Powers of two and their predecessors: one bit, then a run of bits,
         * on each side of the window edges of the 64-bit and 72-bit layouts. */
        for (size_t b = 0; b < sizeof(BITS) / sizeof(BITS[0]); b++) {
            for (int minus = 0; minus < 2; minus++) {
                pow2(k, BITS[b], minus);
                rc |= plain(id, k, want);
                for (size_t l = 0; l < N_LAMBDAS; l++, n++) {
                    rc |= masked(id, k, LAMBDAS[l], got);
                    if (memcmp(got, want, 64) != 0) bad++;
                }
            }
        }
        snprintf(label, sizeof(label), "%d products at the window edges equal the plain ones", n);
        chk(label, rc == 0 && bad == 0);

        /* 0, 2^256 - 1, and the subgroup order and its neighbours. */
        bad = 0; n = 0;
        for (int which = 0; which < 5; which++) {
            if (which == 0) memset(k, 0, 32);
            else if (which == 1) memset(k, 0xFF, 32);
            else near_order(&c, which - 3, k);
            rc |= plain(id, k, want);
            for (size_t l = 0; l < N_LAMBDAS; l++, n++) {
                rc |= masked(id, k, LAMBDAS[l], got);
                if (memcmp(got, want, 64) != 0) bad++;
            }
        }
        snprintf(label, sizeof(label), "%d products with k = 0, 2^256 - 1, l - 1, l, l + 1 equal the plain ones", n);
        chk(label, rc == 0 && bad == 0);

        /* The order itself gives the neutral element. */
        near_order(&c, 0, k);
        rc |= masked(id, k, 0xFFFFFFFF, got);
        memset(want, 0, 64); want[63] = 1;
        chk("[l + (2^32 - 1) l]G is the neutral element", rc == 0 && memcmp(got, want, 64) == 0);

        /* Any scalar, any lambda. */
        bad = 0; n = 0;
        for (unsigned t = 0; t < 48; t++, n++) {
            uint8_t lam[4];
            pattern(k, 32, (uint8_t)(0x10 + t));
            pattern(lam, 4, (uint8_t)(0x80 + t));
            rc |= plain(id, k, want);
            rc |= masked(id, k, ((uint32_t)lam[0] << 24) | ((uint32_t)lam[1] << 16) | ((uint32_t)lam[2] << 8) | lam[3], got);
            if (memcmp(got, want, 64) != 0) bad++;
        }
        snprintf(label, sizeof(label), "%d products with any scalar and any lambda equal the plain ones", n);
        chk(label, rc == 0 && bad == 0);

        /* The entry point that draws lambda. */
        bad = 0; n = 0;
        for (unsigned t = 0; t < 16; t++, n++) {
            pattern(k, 32, (uint8_t)(0x40 + t));
            rc |= plain(id, k, want);
            rc |= blind(id, k, got);
            if (memcmp(got, want, 64) != 0) bad++;
        }
        snprintf(label, sizeof(label), "%d products with lambda drawn by the library equal the plain ones", n);
        chk(label, rc == 0 && bad == 0);

        /* zkn_prv2pub against the plain multiplication of the same scalar:
         * s = BLAKE-512(prv)[0..32] clamped, shifted right by 3. */
        {
            uint8_t prv[32], h[64];
            zkn_edpoint_t Pub;
            unsigned carry = 0;
            pattern(prv, 32, 0x77);
            rc |= zkn_prv_hash(prv, h, 32);
            for (int i = 0; i < 32; i++) {              /* h[0..32] is big endian here */
                unsigned v = h[i];
                h[i] = (uint8_t)((v >> 3) | (carry << 5));
                carry = v & 7u;
            }
            rc |= plain(id, h, want);
            rc |= tEdwards_Curve_alloc_init(&c, id);
            rc |= tEdwards_alloc(&c, &Pub);
            rc |= zkn_prv2pub(&c, prv, &Pub);
            rc |= tEdwards_export(&c, &Pub, got, got + 32);
#ifdef ZKN_FIXEDBASE_SCALAR_BLINDING
            chk("zkn_prv2pub, built with the blinded scalar, gives the same public key", rc == 0 && memcmp(got, want, 64) == 0);
#else
            chk("zkn_prv2pub, built with the plain scalar, gives the same public key", rc == 0 && memcmp(got, want, 64) == 0);
#endif
        }
    }

    printf("\n== Results: %d/%d passed ==\n", g_pass, g_pass + g_fail);
    return g_fail ? 1 : 0;
}

#else /* !ZKN_HAVE_FIXEDBASE_BLIND */

int main(void)
{
    printf("== fixed-base multiplication with a blinded scalar ==\n");
    chk("not part of this configuration (needs ZKN_FIXEDBASE_FLASH_TABLE=1)", 1);
    printf("\n== Results: %d/%d passed ==\n", g_pass, g_pass + g_fail);
    return 0;
}

#endif
#endif /* ZKN_HOST_TESTS */
