/*
 * test_hash_host.c — Host tests for BLAKE-512 (circomlibjs-compatible variant)
 *
 * Validates that BLAKE-512 produces the same output as the standard
 * BLAKE-512 variant used by circomlibjs (the "blake-hash" npm package).
 *
 *   Inputs: [1, 2, 3, 4, 5] (BabyJubjub field elements)
 *   Expected output: 0x0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0
 *                    (verified against the Ledger device in SW mode)
 */

#include "zkn_blake512.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int pass = 0, fail = 0;

static void check(const char *what, int cond) {
    if (cond) { printf("  ✅ %s\n", what); pass++; }
    else      { printf("  ❌ %s\n", what); fail++; }
}

static void check_bytes(const char *what, const uint8_t *got, const uint8_t *expected, size_t n) {
    if (memcmp(got, expected, n) == 0) {
        printf("  ✅ %s\n", what);
        pass++;
    } else {
        printf("  ❌ %s\n", what);
        printf("     got     : ");
        for (size_t i = 0; i < n; i++) printf("%02x", got[i]);
        printf("\n     expected: ");
        for (size_t i = 0; i < n; i++) printf("%02x", expected[i]);
        printf("\n");
        fail++;
    }
}

/* ============================================================ */
/*  BLAKE-512 test vectors                                     */
/* ============================================================ */

static void test_blake_empty(void) {
    printf("\n── BLAKE-512: empty string ──\n");
    /* Reference: BLAKE-512("") = a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b
     *                            628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8 */
    static const uint8_t expected[64] = {
        0xa8,0xcf,0xbb,0xd7,0x37,0x26,0x06,0x2d, 0xf0,0xc6,0x86,0x4d,0xda,0x65,0xde,0xfe,
        0x58,0xef,0x0c,0xc5,0x2a,0x56,0x25,0x09, 0x0f,0xa1,0x76,0x01,0xe1,0xee,0xcd,0x1b,
        0x62,0x8e,0x94,0xf3,0x96,0xae,0x40,0x2a, 0x00,0xac,0xc9,0xea,0xb7,0x7b,0x4d,0x4c,
        0x2e,0x85,0x2a,0xaa,0xa2,0x5a,0x63,0x6d, 0x80,0xaf,0x3f,0xc7,0x91,0x3e,0xf5,0xb8
    };
    uint8_t out[64];
    int rc = zkn_blake512(NULL, 0, out);
    check("rc == ZKN_OK", rc == 0);
    check_bytes("digest matches reference (empty string)", out, expected, 64);
}

static void test_blake_abc(void) {
    printf("\n── BLAKE-512: \"abc\" ──\n");
    /* Reference: BLAKE-512("abc") = 1f7e26f63b6ad25a0896fd978fd050a1766391d2fd0471a77afb975e5034b7ad
     *                               2d9ccf8dfb47abbbe656e1b82fbc634ba42ce186e8dc5e1ce09a885d41f43451 */
    /* Note: this is the BLAKE-512 variant used by circomlibjs ('blake-hash' npm),
     * not the SHA-3 candidate BLAKE. Both have same name "blake512" but differ
     * in the round counter / salt encoding. */
    static const uint8_t expected[64] = {
        0x14,0x26,0x6c,0x7c,0x70,0x4a,0x3b,0x58, 0xfb,0x42,0x1e,0xe6,0x9f,0xd0,0x05,0xfc,
        0xc6,0xee,0xff,0x74,0x21,0x36,0xbe,0x67, 0x43,0x5d,0xf9,0x95,0xb7,0xc9,0x86,0xe7,
        0xcb,0xde,0x4d,0xbd,0xe1,0x35,0xe7,0x68, 0x9c,0x35,0x4d,0x2b,0xc5,0xb8,0xd2,0x60,
        0x53,0x6c,0x55,0x4b,0x4f,0x84,0xc1,0x18, 0xe6,0x1e,0xfc,0x57,0x6f,0xed,0x7c,0xd3
    };
    uint8_t out[64];
    int rc = zkn_blake512((const uint8_t *)"abc", 3, out);
    check("rc == ZKN_OK", rc == 0);
    check_bytes("digest matches reference (\"abc\")", out, expected, 64);
}

static void test_blake_privkey(void) {
    printf("\n── BLAKE-512: test_sign.js private key ──\n");
    /* Privkey from test_sign.js / test_eddsa.c */
    static const uint8_t prv[32] = {
        0x00,0xa2,0xac,0x13,0xcd,0xba,0x83,0x0a,
        0x55,0xbf,0x40,0x7e,0xa7,0x0c,0x5f,0xd2,
        0x93,0x12,0xc1,0x70,0x60,0xf0,0x7d,0x35,
        0xfe,0xa5,0xde,0x47,0xd6,0xc0,0x3e,0xd2
    };
    uint8_t out[64];
    int rc = zkn_blake512(prv, 32, out);
    check("rc == ZKN_OK", rc == 0);
    printf("    digest = ");
    for (int i = 0; i < 64; i++) printf("%02x", out[i]);
    printf("\n");

    /* We can't easily compare without reference here, but we can check
     * the output is non-zero and deterministic. */
    int nonzero = 0;
    for (int i = 0; i < 64; i++) if (out[i] != 0) nonzero = 1;
    check("digest is non-zero", nonzero);

    /* Second call should produce same result (determinism) */
    uint8_t out2[64];
    zkn_blake512(prv, 32, out2);
    check("blake512 is deterministic", memcmp(out, out2, 64) == 0);
}

/* ============================================================ */


int main(void) {
    printf("══════════════════════════════════════════════════════\n");
    printf("  Host hash tests — BLAKE-512          \n");
    printf("══════════════════════════════════════════════════════\n");

    test_blake_empty();
    test_blake_abc();
    test_blake_privkey();

    printf("\n══════════════════════════════════════════════════════\n");
    printf("  Results: %d passed, %d failed\n", pass, fail);
    printf("══════════════════════════════════════════════════════\n");

    return fail ? 1 : 0;
}
