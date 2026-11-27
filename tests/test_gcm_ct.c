/* Host-only test — compiled solely by `make test` (which defines
 * ZKN_HOST_TESTS). The Ledger SDK app build sweeps every .c under the
 * submodule; this guard makes the file an empty translation unit there. */
#ifdef ZKN_HOST_TESTS

/*
 * test_gcm_ct.c — zkn_gcm_ct (GCM over a caller-supplied block cipher).
 *
 * On device this mode runs over cx_aes_enc_block, for SDKs without
 * cx_aes_gcm_* (Ledger LNS). Here the block cipher is the host software AES,
 * so the mode itself is what gets tested:
 *   - AES-256 test cases 13 to 18 of the GCM specification (McGrew, Viega),
 *     including the 8-byte and 60-byte IVs that take the GHASH path for J0;
 *   - decryption, in place, and tag rejection;
 *   - agreement with the existing host implementation (zkn_sw_aes256_gcm_*)
 *     over every plaintext length 0..128 with assorted IV and AAD lengths.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifndef ZKN_WITH_KEYS

/* The software AES and zkn_gcm_ct are part of the keys/aes modules. */
int main(void)
{
    printf("== zkn_gcm_ct: skipped (build with WITH_KEYS=1) ==\n");
    return 0;
}

#else

#include "zkn_gcm_ct.h"

void zkn_sw_aes256_encrypt_block(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]);
void zkn_sw_aes256_gcm_encrypt_aad(const uint8_t key[32], const uint8_t *iv, size_t ivlen,
                                   const uint8_t *aad, size_t aadlen,
                                   const uint8_t *pt, size_t ptlen, uint8_t *ct, uint8_t tag[16]);

static int g_pass = 0, g_fail = 0;

static void chk(const char *label, int ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", label);
    if (ok) g_pass++; else g_fail++;
}

static size_t unhex(const char *h, uint8_t *out)
{
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static int aes_block(void *ctx, const uint8_t in[16], uint8_t out[16])
{
    zkn_sw_aes256_encrypt_block((const uint8_t *)ctx, in, out);
    return 0;
}

static int failing_block(void *ctx, const uint8_t in[16], uint8_t out[16])
{
    (void)ctx; (void)in; (void)out;
    return -1;
}

static const char K0[] = "0000000000000000000000000000000000000000000000000000000000000000";
static const char K1[] = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
static const char AAD[] = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
static const char P64[] =
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
static const char P60[] =
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";

static const struct {
    const char *name, *key, *iv, *aad, *pt, *ct, *tag;
} KAT[] = {
    {"test case 13 (empty)", K0, "000000000000000000000000", "", "",
     "", "530f8afbc74536b9a963b4f1c4cb738b"},
    {"test case 14 (one block)", K0, "000000000000000000000000", "",
     "00000000000000000000000000000000",
     "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"},
    {"test case 15 (four blocks)", K1, "cafebabefacedbaddecaf888", "", P64,
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
     "b094dac5d93471bdec1a502270e3cc6c"},
    {"test case 16 (AAD, partial block)", K1, "cafebabefacedbaddecaf888", AAD, P60,
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
     "76fc6ece0f4e1768cddf8853bb2d551b"},
    {"test case 17 (8-byte IV)", K1, "cafebabefacedbad", AAD, P60,
     "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0"
     "feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
     "3a337dbf46a792c45e454913fe2ea8f2"},
    {"test case 18 (60-byte IV)", K1,
     "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
     "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
     AAD, P60,
     "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4"
     "0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
     "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"},
};

/* deterministic filler */
static void pattern(uint8_t *b, size_t n, uint32_t tag)
{
    uint32_t x = 0x9E3779B9u ^ (tag * 0x01000193u);
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        b[i] = (uint8_t)(x >> 11);
    }
}

int main(void)
{
    char label[96];
    printf("== zkn_gcm_ct: GCM over a supplied block cipher ==\n");

    printf("\n[known answers, AES-256]\n");
    for (size_t i = 0; i < sizeof(KAT) / sizeof(KAT[0]); i++) {
        uint8_t key[32], iv[64], aad[32], pt[80], ct[80], tag[16];
        uint8_t out[80], t[16], back[80];
        unhex(KAT[i].key, key);
        size_t ivl = unhex(KAT[i].iv, iv), al = unhex(KAT[i].aad, aad);
        size_t pl = unhex(KAT[i].pt, pt);
        unhex(KAT[i].ct, ct);
        unhex(KAT[i].tag, tag);

        int rc = zkn_gcm_ct_crypt(aes_block, key, iv, ivl, aad, al, pt, pl, out, t, 1);
        snprintf(label, sizeof(label), "%s: encrypt", KAT[i].name);
        chk(label, rc == 0 && memcmp(out, ct, pl) == 0 && memcmp(t, tag, 16) == 0);

        rc = zkn_gcm_ct_crypt(aes_block, key, iv, ivl, aad, al, ct, pl, back, t, 0);
        snprintf(label, sizeof(label), "%s: decrypt", KAT[i].name);
        chk(label, rc == 0 && memcmp(back, pt, pl) == 0 && zkn_gcm_ct_tag_diff(t, tag) == 0);

        /* in place */
        memcpy(back, pt, pl);
        rc = zkn_gcm_ct_crypt(aes_block, key, iv, ivl, aad, al, back, pl, back, t, 1);
        int ok = rc == 0 && memcmp(back, ct, pl) == 0 && memcmp(t, tag, 16) == 0;
        rc = zkn_gcm_ct_crypt(aes_block, key, iv, ivl, aad, al, back, pl, back, t, 0);
        ok = ok && rc == 0 && memcmp(back, pt, pl) == 0 && zkn_gcm_ct_tag_diff(t, tag) == 0;
        snprintf(label, sizeof(label), "%s: in place, both ways", KAT[i].name);
        chk(label, ok);
    }

    printf("\n[rejection]\n");
    {
        uint8_t key[32], iv[12], aad[20], pt[60], ct[60], tag[16], t[16], back[60];
        unhex(K1, key); unhex("cafebabefacedbaddecaf888", iv);
        size_t al = unhex(AAD, aad), pl = unhex(P60, pt);
        zkn_gcm_ct_crypt(aes_block, key, iv, 12, aad, al, pt, pl, ct, tag, 1);

        ct[17] ^= 0x04;
        zkn_gcm_ct_crypt(aes_block, key, iv, 12, aad, al, ct, pl, back, t, 0);
        chk("a flipped ciphertext bit changes the tag", zkn_gcm_ct_tag_diff(t, tag) != 0);
        ct[17] ^= 0x04;

        aad[3] ^= 0x80;
        zkn_gcm_ct_crypt(aes_block, key, iv, 12, aad, al, ct, pl, back, t, 0);
        chk("a flipped AAD bit changes the tag", zkn_gcm_ct_tag_diff(t, tag) != 0);
        aad[3] ^= 0x80;

        chk("equal tags compare equal", zkn_gcm_ct_tag_diff(tag, tag) == 0);
        chk("empty IV is refused",
            zkn_gcm_ct_crypt(aes_block, key, iv, 0, aad, al, pt, pl, ct, t, 1) != 0);
        chk("NULL AAD with a length is refused",
            zkn_gcm_ct_crypt(aes_block, key, iv, 12, NULL, 4, pt, pl, ct, t, 1) != 0);

        memset(back, 0xAA, sizeof(back));
        memset(t, 0xAA, sizeof(t));
        int rc = zkn_gcm_ct_crypt(failing_block, key, iv, 12, aad, al, pt, pl, back, t, 1);
        int wiped = 1;
        for (size_t i = 0; i < pl; i++) wiped &= (back[i] == 0);
        for (size_t i = 0; i < 16; i++) wiped &= (t[i] == 0);
        chk("a cipher failure returns an error and wipes the outputs", rc != 0 && wiped);
    }

    printf("\n[against zkn_sw_aes256_gcm_*]\n");
    {
        static const size_t IVL[] = {12, 16, 1, 7, 13, 32, 60};
        static const size_t ADL[] = {0, 1, 15, 16, 17, 64, 105};
        int all = 1;
        unsigned runs = 0;
        for (size_t pl = 0; pl <= 128; pl++) {
            for (size_t a = 0; a < sizeof(ADL) / sizeof(ADL[0]); a++) {
                size_t ivl = IVL[(pl + a) % (sizeof(IVL) / sizeof(IVL[0]))];
                uint8_t key[32], iv[64], aad[128], pt[128], c1[128], c2[128], t1[16], t2[16];
                pattern(key, 32, (uint32_t)(pl * 31 + a));
                pattern(iv, ivl, (uint32_t)(pl * 17 + a + 1000));
                pattern(aad, ADL[a], (uint32_t)(pl + 2000 * (a + 1)));
                pattern(pt, pl, (uint32_t)(pl + 5000));
                zkn_sw_aes256_gcm_encrypt_aad(key, iv, ivl, aad, ADL[a], pt, pl, c1, t1);
                int rc = zkn_gcm_ct_crypt(aes_block, key, iv, ivl, aad, ADL[a], pt, pl, c2, t2, 1);
                if (rc != 0 || memcmp(c1, c2, pl) != 0 || memcmp(t1, t2, 16) != 0) all = 0;
                runs++;
            }
        }
        snprintf(label, sizeof(label), "%u encryptions agree (lengths 0..128, 7 AAD and 7 IV sizes)", runs);
        chk(label, all);
    }

    printf("\n== Results: %d/%d passed ==\n", g_pass, g_pass + g_fail);
    return g_fail == 0 ? 0 : 1;
}

#endif /* ZKN_WITH_KEYS */
#endif /* ZKN_HOST_TESTS */
