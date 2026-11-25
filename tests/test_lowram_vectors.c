/* Host-only test — compiled solely by `make test` (which defines
 * ZKN_HOST_TESTS). The Ledger SDK app build sweeps every .c under the
 * submodule; this guard makes the file an empty translation unit there. */
#ifdef ZKN_HOST_TESTS

/*
 * test_lowram_vectors.c — fixed vectors for the paths ZKN_LOW_RAM replaces.
 *
 * ZKN_LOW_RAM swaps three implementations for smaller-footprint ones:
 *   - fixed-base scalar multiplication: 2 x 128-bit windows over the 4-entry
 *     table instead of 4 x 64-bit windows over the 16-entry one;
 *   - Poseidon mixing layer: MDS matrix read from the const table instead of
 *     a Montgomery copy held in the context;
 *   - EddsaPoseidon_Sign_final: one function per step instead of one frame.
 *
 * The expected values below were produced by the standard build; the
 * BabyJubjub rows were also checked against circomlibjs (mulPointEscalar on
 * Base8, poseidon, signPoseidon). The test must pass in both configurations:
 *
 *     make test
 *     make test ZKN_LOW_RAM=1
 *
 * Scalars straddle the window boundaries of both layouts (2^64, 2^128,
 * 2^192) on purpose.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "zkn_bn.h"
#include "zkn_errors.h"
#include "zkn_tEdwards.h"
#include "zkn_eddsa.h"
#include "zkn_poseidon.h"

static int g_pass = 0, g_fail = 0;

static void chk(const char *label, int ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", label);
    if (ok) g_pass++; else g_fail++;
}

static void unhex(const char *h, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* Deterministic filler, the same generator the vectors were made with. */
static void pattern(uint8_t *b, size_t n, uint8_t tag)
{
    uint32_t x = 0x9E3779B9u ^ ((uint32_t)tag * 0x01000193u);
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        b[i] = (uint8_t)(x >> 11);
    }
}

/* ── [k]B, k 32 bytes big-endian, affine result big-endian ───────────── */
static const struct {
    uint32_t curve;
    const char *what;
    const char *k, *x, *y;
} FIXED_BASE[] = {
    {2, "k = 0",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000001"},
    {2, "k = 1",
     "0000000000000000000000000000000000000000000000000000000000000001",
     "0bb77a6ad63e739b4eacb2e09d6277c12ab8d8010534e0b62893f3f6bb957051",
     "25797203f7a0b24925572e1cd16bf9edfce0051fb9e133774b3c257a872d7d8b"},
    {2, "k = 2^64",
     "0000000000000000000000000000000000000000000000010000000000000000",
     "2510730657da9fa17ccda5333a184130084a51bdd26eb630346aaa2f613f3628",
     "027e1bb5a3353f98f63a0f07a8605b32a9aec1df8b6348bd9ef63c756e7a9166"},
    {2, "k = 2^128 - 1",
     "00000000000000000000000000000000ffffffffffffffffffffffffffffffff",
     "2ade18ca2a6d14d60424c681951d381f28120622885bc788ea36e4afb697cbf6",
     "2d11006fac36947a97c9640e0024a778407cf79d29db60d47d4a471c1b25b617"},
    {2, "k = 2^128",
     "0000000000000000000000000000000100000000000000000000000000000000",
     "16bf5a6bb1db3f7dfab6c0d607a0e634a32f4a7de6ee3158d5981fbb56098fa0",
     "2fde880140d9049437cb546f2ea4bfa54d28eb47d0d240f986482e05ab8a7031"},
    {2, "k = 2^192",
     "0000000000000001000000000000000000000000000000000000000000000000",
     "08316129eeaa4740ce9d8111a2c21f1554bf73e67983c20c1e3c3fbea0ff52e8",
     "0039e4f2d78025eb15b850b6a0100b1bb5b9b1b738c8b2add665ac79da1c26fa"},
    {2, "k = 2^256 - 2^128",
     "ffffffffffffffffffffffffffffffff00000000000000000000000000000000",
     "0209a95191291a217453ac58378cb43bfec3a9db67a933e77ef4cfb010ea47e4",
     "06b25288207b408a0ab7b49698cf8b90600bbe496e93e52159bfd2cffccb0177"},
    {2, "k = 2^256 - 1",
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "0cf377ae33ea80b7f6c5bd2eacd99d52841637ec041aa32a13eb6d5161a5dd26",
     "288c14039b0b9f73da98a4204638409979f852bea06aa8e3b44b413ca4ca00bf"},
    {2, "k = pattern 1",
     "40fb81e3d1e2b66ef00f6433759ada6241f6236d92d8af5b481a0e1a6e2cc5d6",
     "1353cb1c15901b4b0df60dad1c78033ed002fb7664d48fc198f45ac3336fed18",
     "199538417747a52d19673f26d45fdcef0625935cfda28fb38029bbc8df536407"},
    {2, "k = pattern 2",
     "18b8642c66c0b2da5d2db73e085f699dbff84947065efc598528821e006d630b",
     "2218d79d26c28f35fc0a51ebf53b617bae9d109c09522881c729dbd96e656b08",
     "1afcefb321944664b707d5ac0ea067f51f0582f1ea4af3526d31616bd12466a9"},
    {1, "k = 0",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000001"},
    {1, "k = 1",
     "0000000000000000000000000000000000000000000000000000000000000001",
     "29c132cc2c0b34c5743711777bbe42f32b79c022ad998465e1e71866a252ae18",
     "2a6c669eda123e0f157d8b50badcd586358cad81eee464605e3167b6cc974166"},
    {1, "k = 2^64",
     "0000000000000000000000000000000000000000000000010000000000000000",
     "2c4e9183405586756e125fffcca053e192945cb2dd002f78228318982afb69c6",
     "622872dd754eb40b1eb7bb18eb36afef7e5a4184f54f977ebe6e7134c325cdc1"},
    {1, "k = 2^128 - 1",
     "00000000000000000000000000000000ffffffffffffffffffffffffffffffff",
     "031e4c9da5259b86071c713e295fcf8f3ec8ba4ec40b7f7711fb6eb97df00991",
     "58d7bf669101742a5f676d787ad6d71135e5bd92b20df1659523570f4a17b86b"},
    {1, "k = 2^128",
     "0000000000000000000000000000000100000000000000000000000000000000",
     "589628ba8ca75873f64ef940b5b1f4b669046d71eca4ef143801089a80a7f812",
     "25c70e29ec2185289b81d294231d5bf761e811a58a51187f6f8c3df7bd8fb057"},
    {1, "k = 2^192",
     "0000000000000001000000000000000000000000000000000000000000000000",
     "4ff8e098549c6a0e300bab6f4c273d1ffd847042919f421df6562378583cfb79",
     "439e3c8d4904c10aca542ad907b91adcf18ffa5a5c58b040070f0affa6215d9c"},
    {1, "k = 2^256 - 2^128",
     "ffffffffffffffffffffffffffffffff00000000000000000000000000000000",
     "3fc12dd023c5dd03e766a1ad1710fdf8eae514ed970c04a3a58ad0ecd36b2958",
     "6bbb1a282315c7f2bed25f2e0352b43eff21872985b94abbaaee265143729dbe"},
    {1, "k = 2^256 - 1",
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "5010f7dd5626dec3729548c0332971868de6e01a8052d8250188126e9812afe4",
     "3d128873ba06de6d988f7c8d252761deac74f84c3cae9ebb44d7e1ad2192aa92"},
    {1, "k = pattern 1",
     "40fb81e3d1e2b66ef00f6433759ada6241f6236d92d8af5b481a0e1a6e2cc5d6",
     "630f30c4ccb5ad947cf86a447db377a02350e9b753ab7ffdd2b47838be19116c",
     "3f3b63b086842388c34a31dd502b23025e6cdafa3eb6dbedd67ab042bccaf4db"},
    {1, "k = pattern 2",
     "18b8642c66c0b2da5d2db73e085f699dbff84947065efc598528821e006d630b",
     "25d951803510e3baaae9a20854b1b185a5831fe6a690699604533fe15ebcb722",
     "261918fe4316f84e0170dbb7bb8dbde01c7c631b042084e4f2a075e0ccc81cbe"},
};

/* ── Poseidon(n inputs = pattern(tag)) ───────────────────────────────── */
static const struct {
    size_t n;
    uint8_t tag;
    const char *digest;
} POSEIDON[] = {
    {1, 0x41, "0c6ad4457846641ba83fd8a4eeffd413f5dc282dc05b19be95c09c1e781eb97f"},
    {2, 0x42, "06e2a52d86fd43e48242e382577471022609a50f03a2f276ca3feeca7f8b9361"},
    {3, 0x43, "0a7101dcf3bfdd18c440f029f47dc581567aaf5490fc88ba32a8b7fc4e09fc60"},
    {4, 0x44, "25afa23bc9d19623ce1e27fa5493a85f40415c9cab2ff9bc0c13edf40dc46a1c"},
    {5, 0x45, "00e8b1fc8391ba35b258250945d12d0c8ac8aa70979896f50b76a10122d4935d"},
    {6, 0x46, "20f3d7f9580b9c4c20d5626dd0561ee82596ff08ceea6c1a460e4f28bfaddb72"},
    {7, 0x47, "286f62e715373d854da0ec53b690ce057c9660f1df48fb901a6396b900bfab12"},
};

/* ── EdDSA-Poseidon: prv = pattern(prv_tag), msg = pattern(msg_tag) with
 *    the top nibble cleared (little-endian field element) ───────────── */
static const struct {
    uint32_t curve;
    uint8_t prv_tag, msg_tag;
    const char *sig; /* R.x | R.y | S */
} SIGN[] = {
    {2, 0x80, 0xa0,
     "183aece4d3e93fe0a78a215cc501d564ebf363e84eac460760064e9a7ad63ba31b3350bef1255581ec543a7937037cfafb34ee5f5eefe61a9bdbb52b6e5dcc410092a45fe9d404094167edbfe923c32126ce9d70db08c9fe5b90c72d5cfdafae"},
    {2, 0x81, 0xa1,
     "00d0331eb40f4adcd9c8e61d3c0c6f05c45d745c66843f289e893782d4c35fef19deda39d945833672baa0c3fc4770535f54f03cd32b484daa4cfdc01960f6880302334c654e3bcf9edd9bc0f1d18f60875525625776e165c3caa72cd3cf869e"},
    {1, 0x80, 0xa0,
     "72be0fd6b2dc638df348df0034b741cf111683edd27bba598806a62a064a102f72f272435831ba2f6bf20efef71d6a61c55e671684e78f68f2a6d80d1fbb929c01330cf63d9d0171a69c1b5f1dd1d62a947f0be8fdae8cd0e3c697b7cf9f3ecd"},
    {1, 0x81, 0xa1,
     "6b8f5c8b90f875d726a7c2fe98d42fa1f415147fbd46d87ad8ad07acac0aa36646bf8975d3c7f2fec9d0681d5582113df8fde90c512b19b69d671231ad9eec2d002c7cf680fc9a7212d988672418c73fc64526c904e67623578a21d8a9aa7bd8"},
};

static const char *curve_name(uint32_t id)
{
    return id == _BABYJUJUB_ID ? "BabyJubjub" : "Bandersnatch";
}

int main(void)
{
    char label[128];

#ifdef ZKN_LOW_RAM
    printf("== low-RAM path vectors (ZKN_LOW_RAM build) ==\n");
#else
    printf("== low-RAM path vectors (standard build) ==\n");
#endif

    printf("\n[fixed-base scalar multiplication]\n");
    for (size_t i = 0; i < sizeof(FIXED_BASE) / sizeof(FIXED_BASE[0]); i++) {
        zkn_edcurve_t curve;
        zkn_edpoint_t R;
        uint8_t k[32], ex[32], ey[32], x[32], y[32];
        unhex(FIXED_BASE[i].k, k, 32);
        unhex(FIXED_BASE[i].x, ex, 32);
        unhex(FIXED_BASE[i].y, ey, 32);

        int rc = tEdwards_Curve_alloc_init(&curve, FIXED_BASE[i].curve);
        rc |= tEdwards_alloc(&curve, &R);
        rc |= tEdwards_fixedBase_4MSM(&curve, k, &R);
        rc |= tEdwards_export(&curve, &R, x, y);
        snprintf(label, sizeof(label), "%s: %s", curve_name(FIXED_BASE[i].curve), FIXED_BASE[i].what);
        chk(label, rc == 0 && memcmp(x, ex, 32) == 0 && memcmp(y, ey, 32) == 0);
    }

    printf("\n[Poseidon]\n");
    for (size_t i = 0; i < sizeof(POSEIDON) / sizeof(POSEIDON[0]); i++) {
        uint8_t in[7 * 32], out[32], expect[32];
        pattern(in, POSEIDON[i].n * 32, POSEIDON[i].tag);
        unhex(POSEIDON[i].digest, expect, 32);
        int rc = zkn_poseidon_hash(in, POSEIDON[i].n, out);
        snprintf(label, sizeof(label), "Poseidon-%zu", POSEIDON[i].n);
        chk(label, rc == 0 && memcmp(out, expect, 32) == 0);
    }

    printf("\n[EdDSA-Poseidon signature]\n");
    for (size_t i = 0; i < sizeof(SIGN) / sizeof(SIGN[0]); i++) {
        zkn_edcurve_t curve;
        zkn_edpoint_t Pub;
        uint8_t prv[32], msg[32], sig[96], expect[96];
        pattern(prv, 32, SIGN[i].prv_tag);
        pattern(msg, 32, SIGN[i].msg_tag);
        msg[31] &= 0x0F;
        unhex(SIGN[i].sig, expect, 96);
        memset(sig, 0, sizeof(sig));

        /* Sign_final consumes the curve: fresh one per signature. */
        int rc = tEdwards_Curve_alloc_init(&curve, SIGN[i].curve);
        rc |= tEdwards_alloc(&curve, &Pub);
        rc |= zkn_prv2pub(&curve, prv, &Pub);
        rc |= EddsaPoseidon_Sign_final(&curve, prv, &Pub, msg, 32, sig);
        snprintf(label, sizeof(label), "%s: signature %zu", curve_name(SIGN[i].curve), i);
        chk(label, rc == 0 && memcmp(sig, expect, 96) == 0);
    }

    printf("\n== Results: %d/%d passed ==\n", g_pass, g_pass + g_fail);
    return g_fail == 0 ? 0 : 1;
}

#endif /* ZKN_HOST_TESTS */
