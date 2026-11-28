/* poseidon_cli.c — Poseidon over stdin/stdout, so a test driver
 * (js/poseidon_diff.mjs) can compare the library with circomlibjs on large
 * batches of vectors. No logic here: each record goes through
 * zkn_poseidon_init / zkn_poseidon, exactly like zkn_poseidon_hash does.
 *
 *   poseidon_cli <bn254|bls12381> <nb_inputs> [nb_outputs]
 *
 * stdin : records of 4 + 32 * nb_inputs bytes:
 *           initState (uint32, big-endian), then the inputs, 32 bytes
 *           big-endian each (any 256-bit value: reduced mod the field).
 * stdout: 32 * nb_outputs bytes per record (default 1), big-endian.
 *
 * Over BN254, with initState 0 and one output, every record is also hashed
 * with zkn_poseidon_hash and both results must agree.
 *
 * Exit status: 0, 1 on a usage or library error, 2 if the two paths differ.
 *
 * Host-only: built with -DZKN_HOST_TESTS (the Ledger SDK app build sweeps
 * every .c under the submodule).
 */
#ifdef ZKN_HOST_TESTS

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "zkn_bn.h"
#include "zkn_poseidon.h"

static const uint8_t BN254_FR[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
};
static const uint8_t BLS12381_FR[32] = {
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
};

static int fail(const char *what)
{
    fprintf(stderr, "poseidon_cli: %s\n", what);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4)
        return fail("usage: poseidon_cli <bn254|bls12381> <nb_inputs> [nb_outputs]");

    int is_bn254 = strcmp(argv[1], "bn254") == 0;
    if (!is_bn254 && strcmp(argv[1], "bls12381") != 0)
        return fail("unknown field");
    size_t n = (size_t)strtoul(argv[2], NULL, 10);
    size_t nout = argc == 4 ? (size_t)strtoul(argv[3], NULL, 10) : 1;
    if (n == 0 || n > ZKN_POSEIDON_MAX_INPUTS || nout == 0 || nout > n + 1)
        return fail("bad arity or output count");

    zkn_bn_mont_ctx_t montctx;
    zkn_bn_t modulus, raw;
    zkn_bn_t out[ZKN_POSEIDON_MAX_INPUTS + 1];
    if (zkn_bn_lock(32, 0) != 0 ||
        zkn_bn_alloc_init(&modulus, 32, is_bn254 ? BN254_FR : BLS12381_FR, 32) != 0 ||
        zkn_mont_alloc(&montctx, 32) != 0 ||
        zkn_mont_init(&montctx, modulus) != 0 ||
        zkn_bn_alloc(&raw, 32) != 0)
        return fail("bignum setup");
    for (size_t i = 0; i < nout; i++)
        if (zkn_bn_alloc(&out[i], 32) != 0) return fail("bignum setup");

    uint8_t rec[4 + 32 * ZKN_POSEIDON_MAX_INPUTS];
    uint8_t res[32], check[32];
    size_t reclen = 4 + 32 * n;

    while (fread(rec, 1, reclen, stdin) == reclen) {
        uint32_t init = ((uint32_t)rec[0] << 24) | ((uint32_t)rec[1] << 16) |
                        ((uint32_t)rec[2] << 8) | rec[3];
        zkn_poseidon_ctx_t ctx;

        if (zkn_poseidon_init(&ctx, 5, n, &montctx, modulus) != 0)
            return fail("zkn_poseidon_init");
        for (size_t i = 0; i < n; i++) {
            if (zkn_bn_init(raw, rec + 4 + 32 * i, 32) != 0 ||
                zkn_bn_reduce(ctx.state[i + 1], raw, modulus) != 0 ||
                zkn_mont_to_montgomery(ctx.state[i + 1], ctx.state[i + 1], &montctx) != 0)
                return fail("input");
        }
        if (zkn_poseidon(&ctx, init, out, nout) != 0)
            return fail("zkn_poseidon");
        for (size_t i = 0; i < nout; i++) {
            if (zkn_mont_from_montgomery(out[i], out[i], &montctx) != 0 ||
                zkn_bn_export(out[i], res, 32) != 0)
                return fail("output");
            if (fwrite(res, 1, 32, stdout) != 32) return fail("write");
        }
        if (zkn_poseidon_destroy(&ctx) != 0)
            return fail("zkn_poseidon_destroy");

        if (is_bn254 && init == 0 && nout == 1) {
            if (zkn_poseidon_hash(rec + 4, n, check) != 0)
                return fail("zkn_poseidon_hash");
            if (memcmp(check, res, 32) != 0) {
                fprintf(stderr, "poseidon_cli: zkn_poseidon_hash differs\n");
                return 2;
            }
        }
    }
    if (!feof(stdin) || ferror(stdin))
        return fail("truncated record");
    return fflush(stdout) == 0 ? 0 : 1;
}

#endif /* ZKN_HOST_TESTS */
