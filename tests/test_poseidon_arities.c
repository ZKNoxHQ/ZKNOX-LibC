/*
 * test_poseidon_arities.c — known answers for Poseidon-1 .. Poseidon-7
 * (circomlib, BN254), through zkn_poseidon_hash.
 *
 * Every arity reads its own window of the round-constant table
 * (zkn_poseidon_rc_bn254.h), so each one is checked: inputs 1..n and
 * p-1, p-2, .. p-n. Expected values from poseidon-lite 0.3.0 (poseidon1 ..
 * poseidon7), which matches circomlibjs. A second hash on the same inputs
 * checks the result does not depend on an earlier call.
 *
 * Host-only (compiled by `make test`, which defines ZKN_HOST_TESTS): the
 * Ledger SDK app build sweeps every .c under the submodule.
 */
#ifdef ZKN_HOST_TESTS

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "zkn_poseidon.h"

static const uint8_t P_MINUS_1[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
};

static const struct { size_t arity; int large; const char *hash; } KAT[] = {
    { 1, 0, "29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133" },
    { 1, 1, "0771743e7ade0f56f51d16544f60059ba3029ba556d63697612900fe5f020b16" },
    { 2, 0, "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a" },
    { 2, 1, "0d984fe36eaa48abd5d41748d04aec71f5a2ed436f5207fa8b13af37bd9bfba6" },
    { 3, 0, "0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732" },
    { 3, 1, "2c82fc601c507fcd087634a3ff81675c33967e662565ec3ad6482de05d020f91" },
    { 4, 0, "299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465" },
    { 4, 1, "0389b22dc74ea1215d472baf640521e4ec51d9750536db85692e52787841292e" },
    { 5, 0, "0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0" },
    { 5, 1, "2eae29afc70a7662e87c67b8bd6c66590d9cc31cdeb513771df8b1bb47916fe7" },
    { 6, 0, "2d1a03850084442813c8ebf094dea47538490a68b05f2239134a4cca2f6302e1" },
    { 6, 1, "2417d0f73f3c81dca87fe44142c217deec8ddef8b78ad819cf2fd650c6dde466" },
    { 7, 0, "1c2f3482dbb140c4ebb9ada49abdbc374a9a85fcfc6533ec2e9df45b4921c318" },
    { 7, 1, "294c99910baffcdca5053875a6f17455621eddd9a8deb88a2ec8f75af70a9d59" },
};

static void hex32(const char *s, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* out = p - 1 - k, big-endian; k is small, so only the low limb moves. */
static void p_minus(uint8_t out[32], unsigned k)
{
    memcpy(out, P_MINUS_1, 32);
    unsigned borrow = k;
    for (int i = 31; i >= 0 && borrow; i--) {
        unsigned v = out[i];
        out[i] = (uint8_t)(v - (borrow & 0xff));
        borrow = (borrow >> 8) + (v < (borrow & 0xff) ? 1 : 0);
    }
}

int main(void)
{
    int tests = 0, fails = 0;

    for (size_t k = 0; k < sizeof(KAT) / sizeof(KAT[0]); k++) {
        uint8_t in[7 * 32] = {0};
        uint8_t want[32], got[32], again[32];
        size_t n = KAT[k].arity;

        for (size_t i = 0; i < n; i++) {
            if (KAT[k].large) p_minus(in + 32 * i, (unsigned)i);
            else in[32 * i + 31] = (uint8_t)(i + 1);
        }
        hex32(KAT[k].hash, want);

        int rc = zkn_poseidon_hash(in, n, got);
        int rc2 = zkn_poseidon_hash(in, n, again);
        tests++;
        if (rc != 0 || rc2 != 0 || memcmp(got, want, 32) != 0 || memcmp(again, want, 32) != 0) {
            fails++;
            printf("[FAIL] poseidon%zu(%s) rc=%d/%d\n", n, KAT[k].large ? "p-1..p-n" : "1..n", rc, rc2);
        } else {
            printf("[PASS] poseidon%zu(%s)\n", n, KAT[k].large ? "p-1..p-n" : "1..n");
        }
    }

    printf("== Results: %d/%d passed ==\n", tests - fails, tests);
    return fails ? 1 : 0;
}

#endif /* ZKN_HOST_TESTS */
