/*
 * test_poseidon_opt.c — Poseidon, SW backend: what test_poseidon_arities.c
 * (one output, initState 0, BN254) does not cover.
 *
 *   - known answers with initState = 7 and all t outputs, Poseidon-1 ..
 *     Poseidon-7 over BN254: the last linear layer is computed row by row,
 *     for the requested outputs only;
 *   - known answers for Poseidon-5 over the BLS12-381 scalar field, the hash
 *     of EdDSA / FROST on Bandersnatch (the 255/6/8/60 instance of that
 *     field, its own constants and matrix);
 *   - a context hashes twice;
 *   - zkn_poseidon_init refuses what it has no table for.
 *
 * Inputs are 1..n or q-1, q-2, .. q-n. Expected values come from the
 * reference rounds (round constants, S-boxes, dense MDS) of
 * `python3 tools/gen_poseidon_opt.py --kat`, not from the optimized tables.
 * The random comparison with circomlibjs is `make poseidon-diff`.
 *
 * Host-only (compiled by `make test`, which defines ZKN_HOST_TESTS): the
 * Ledger SDK app build sweeps every .c under the submodule.
 */
#ifdef ZKN_HOST_TESTS

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "zkn_bn.h"
#include "zkn_poseidon.h"

static int tests = 0, fails = 0;

static void check(const char *name, int ok)
{
    tests++;
    if (!ok) fails++;
    printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
}

enum { F_BN254, F_BLS12381, F_SECP256K1 };

static const uint8_t MODULUS[3][32] = {
    { 0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
      0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01 },
    { 0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
      0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01 },
    /* a field with no Poseidon table */
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f },
};

static const struct {
    int field; size_t arity; int large; uint32_t init; size_t nout; const char *out;
} KAT[] = {
    { F_BN254, 1, 0, 7, 2,
      "1e3d28e65fca24537eda63e8dcb841dc2aaa53c4f63f74992337771e19ec60e5"
      "1ae867bb0add96c18098ee6befe820a07f1c7787ed14ad958406ac97d0dd9dc5" },
    { F_BN254, 1, 1, 7, 2,
      "1b8de5926451fa17152a4136a1f79faaf8e6de4eeb71ff51d81c2602ce3258f7"
      "240a3b33b443b95e32d36098ab51f4eac716e7cd86fc82f35dabd7276ab8c017" },
    { F_BN254, 2, 0, 7, 3,
      "10ab908ccdeecd8a8223b102d69bf12c020b3b208d6562ec36e8880f43607900"
      "14d15acb1742a29a19ea85367357215951cd67865a9640b38a1900995bce32b1"
      "08ccdf382b490f1aadf6625fcb593c423ae65369e1131d2968e46cea80b50954" },
    { F_BN254, 2, 1, 7, 3,
      "1439c8ac715067569cc253b786f935c2d6ef8392266585f305ce072662dcf223"
      "2162ef9309ebc6d71d60aefa5960698122a6c53640ab1dc05eaa00c354320b37"
      "2a3b6e43e0a0b4a5c880a4eae2b3395ca29cf79d4d72a62c8f21210dacd29ad7" },
    { F_BN254, 3, 0, 7, 4,
      "0ed821ccfdab5891f8862208c7edacfd60df3cbe3fbbf4cd0b2b99a8e901ec23"
      "11b96fffeea094c9f8c3e165f0ba47b9106d1019ff473d4da21b6d9f0ddf0f1d"
      "2d95a77bb271e6999da1e658679a91ea47be85f80932d8e0c6511205f97fbc15"
      "07c5003ecdacc13f5ccaba2ca30682f6d3a134c7f0f48dde09171ca2bde81749" },
    { F_BN254, 3, 1, 7, 4,
      "0389d164abc0c8cfe09fb09c9fdf702ab77516e6d205c9400cae471bee693fd9"
      "0489d00aac5716bada5c6c8f72d829eba453df9e17d37817534a93874559a05a"
      "02d89998ea7b7b5c5d3c34c708d4ccb00201cc5d80a66796f3a3c13694576b8f"
      "2d41e9c29f676cbd2c73b9acc279d06a981c3917363eb86c60556c60aafd897a" },
    { F_BN254, 4, 0, 7, 5,
      "0378246d3e22e3b62550a84213718b0ed9764f723aad339cbd533742ec582b2e"
      "280ebaf09f13f5de5d84f349408b351f7dca31cda060911fabccf6ea1c3202b3"
      "111d23c87d9d869250f684690afc3a8e10792cc4812885e76f46eacfc4fb1f6c"
      "26bcc61427119044554e8b4407d24444e7b7862678447e72aa1b8a91bd935f16"
      "0fa63f25c4959081ec97a376ed2f91a7fa8f666924ca18fabf5f7e8599546584" },
    { F_BN254, 4, 1, 7, 5,
      "2d1588bca0d21628b6f29b768eb61b7664b4fe0fa65f79629c194d37e80920a1"
      "2eed321df5df7f42bcc94cd0a3340bc2ce87530ce341c60ac45aacd86d59f3c4"
      "041122a23fe21fff8fdf7b341cf53d10ab37ad78f7ace20e573eeedf0388f5cc"
      "27302019bf0c992cc850c4b6c38f4ddbf20d1f11306be9dcb99e349b0fa10832"
      "05fe52669e5c28216298872e97a20794d9631f433496bdc5dfdaadf944bc047b" },
    { F_BN254, 5, 0, 7, 6,
      "15cdc62a0bb8fe4bc9cad232b4056e81ced418f270b545a51ac020090ced0a2a"
      "1b8eed8c98a124d44d4bb1c4495b52360460aa3201ea395861c6f1ecff852b29"
      "18a1b9d44f72c9476509c065305148f4793eacb1466b51d966b3dd795f68b123"
      "11aa06a9b6a3138633ae671562b18c5a34274edcff0d34cf133036c7143a1643"
      "1d700735aae56777af7e01c57fcd5278cf404477d1c3ea0fbb74351c049a3997"
      "2de5e9b8d9ce0bc5f964862fe1c89e37223539aa215e430b8d0fb69521e51738" },
    { F_BN254, 5, 1, 7, 6,
      "255f4f7a2c7fa3888e92807932b8f9139a2a74a81f8fb3eb2e6eda8e9662ff2f"
      "088afa4cf61c56f58d8606c76a73a39a00f7b18c753cddfcddacca92b8886702"
      "0e3f21abb9168370159d5b1b8a1e39cf69fb25719f18747bc672f7ee5682f78e"
      "2788e92a4f4773b8a26d01abb99d957703c5280e5ed64ab34dea2f45049f45f0"
      "235def94a0cb8f44ef0a580da6c5204e2c679260ff395600df52a716bd89dc97"
      "0f29321bbcbfcfeae5841c6210fb8ab17cd287f38ca90a57ba6aefe91d68a7f4" },
    { F_BN254, 6, 0, 7, 7,
      "098afd6d1839c2dff6612b761c45b15b668886381c4e6a5cdd6a2281bd5f9743"
      "063f2d2fd81a778f86cdb967615fbd655a9189acfcbf8cce624fc03252c1b795"
      "18daaa25bd93b9d1bf2bd84d7474f5c2e51d17af47e3f3c19032ae9a52931cbd"
      "2cbed575804ae135826c80870fbfb1dc988160e137567ac372ecf176fdf1b4ba"
      "05d542fb1e37741d5bc6235e2c18e6fc2f584678f8759cca5631410cff51125f"
      "07eada1e091bc45a03e86f8bb7ebbfca93711d130648f6e5142783c89010808a"
      "1bd0715716e1fc2a54a1be437b05f2964529a86f5b7b565b1b367794a691f83e" },
    { F_BN254, 6, 1, 7, 7,
      "3004ecac04fcd0a94d29b2d675c9510095cc56268d319c171e8999a9b8378843"
      "04c1ac0a82cea55742f5ce4d660380c241243960f681808ccf70c1779cb5f12d"
      "0f2f8177640b0d5b995673133e7c47440be90f820b0934a1ab9b5616c717f193"
      "0ca7af3b6ddb9ba5f0764903de56078d0384e853130644c1b1697379b2ce7e50"
      "02e4b22f7ef40df9e0ac84d189322e6ebf40a891a5e2b10b03c6da45bbf0700f"
      "2aa4acf077a1e22c6db148a9f7a99f101c52b0c4002312dab517c18226381090"
      "299259cc71ca33f68397b5597ee0fa530b198ac2e4864120e099c6d39d778af6" },
    { F_BN254, 7, 0, 7, 8,
      "0c4135b627010896f2a65d81530b649da138f720987aaf9f192ecabcf26b08e1"
      "0ed9f62e59a0109ce982be2efd1d1bc5dc7ae93629e6bef74803f117e210fa62"
      "2538fb5834b8660abaa590382bce19b5ba274665d58f0f24d8df4eae191bd513"
      "2b54378b91e3b25d441845db9478399df5b1bb24208f235f1c9e8d8293d20a01"
      "00a57141af27e653ea42fb96a5d0dbdc2b070935ce2caac2f4aef75372a44288"
      "1fac1b56d1bc8a82524db47e778d299c5a8ad4773cd5d0d21bd34e53fac26920"
      "0ed3262abf1b2891b8508169ebab7df7e711db2deb971d5dc7d20711526a102c"
      "1d985cb01d965b7f37a30bdf5c53d3937f6ae5062250c1798fa91aa9879aa355" },
    { F_BN254, 7, 1, 7, 8,
      "25b05a0e5c60bc7672476a16a365a56935c041022e805cac9a0349c57925e0f4"
      "18d443dc03fde84f4e9e4277deefa80d40072df58af2b34cca6665463ba3414b"
      "0c4e3eab42b9d6025771d84feba5153fbd93c32f089249c705d855330b5c4baf"
      "08d49abf256861e7b53e68412e5fbfc064c71d9ac711316d1f735738a7bd66ff"
      "113906f5bf920ea500636b9b87aba8e4cd4ec089eb48cec583bd652655494106"
      "047dc93e6a1a860978c9966e539957f20fcb21885d9f8c468b9c5a0bd0661a03"
      "06ebc44aad776e3d79a9247f1c902f598bc1ac586d2f66452608ce1a0939dd68"
      "1fbd7114bcfd08ce97428d96df69761411d819f9768938d9f75628cc5660789e" },
    { F_BLS12381, 5, 0, 0, 1,
      "104f17d24cdf5767e266bcb1ed9448ebe29d046b3211d14778ff8c7525dd0aa8" },
    { F_BLS12381, 5, 0, 7, 6,
      "176d053c069c96aefadbccf4785497afe222d4ccc3ab48c2e2321d381e899cb8"
      "3ec83f362f248f5f95cbb74138871268761fa3092b44ec3a37cd870f7dac1cbd"
      "18a203b49f7a53c503c02e1ff01204b8facb0352ae1069ca8af3941acfd614bb"
      "0a56c482540117d74d8b976f98842bcfa21c2f5c2b806138bc9b8486fbd0b468"
      "5e20190258d6907320a0ad854469879e2a502244cc2e8b49433d77b11377a721"
      "2aa0e6c14e47763557fe943f23dd347ce45a5506992dccd72c3a7f52badfc7ba" },
    { F_BLS12381, 5, 1, 0, 1,
      "385eb6ccf6513f4c22b9334f39d7e684ac9060bfd831fa2fa51ee1b6bf8b0409" },
    { F_BLS12381, 5, 1, 7, 6,
      "209a1dae896634365de3f5d1f1943f5cae77bdfa5e97f2d406eac2af9b81458c"
      "1963c89a07c514def0a06adb523fab355c92156d72461778b52da9ea47133dc4"
      "111468a2a21afed4c780a55458242b9e9b5a9ac6d0aa689c663947314bfbbbb0"
      "0c7abfed7c502f2b5e97dcb61ef3eb6b4809f6b46b17ba3a9648614130b71a09"
      "531ff321cd367b69d7fae2229a3e7c270223bd010d08e9e5c8585d267fa52788"
      "0b17074db3e9183493fa42c5ad8bdebe92b032b8b669c1f1e00a460572dacd07" },
};

static void hex32(const char *s, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* out = q - 1 - k, big-endian; k is small, so only the low bytes move. */
static void q_minus(int field, uint8_t out[32], unsigned k)
{
    memcpy(out, MODULUS[field], 32);
    unsigned borrow = k + 1;
    for (int i = 31; i >= 0 && borrow; i--) {
        unsigned v = out[i];
        out[i] = (uint8_t)(v - (borrow & 0xff));
        borrow = (borrow >> 8) + (v < (borrow & 0xff) ? 1 : 0);
    }
}

static int mont_setup(int field, zkn_bn_mont_ctx_t *montctx, zkn_bn_t *modulus)
{
    return zkn_bn_alloc_init(modulus, 32, MODULUS[field], 32) ||
           zkn_mont_alloc(montctx, 32) ||
           zkn_mont_init(montctx, *modulus);
}

static int load(zkn_poseidon_ctx_t *ctx, zkn_bn_mont_ctx_t *montctx,
                int field, size_t n, int large)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t in[32] = {0};
        if (large) q_minus(field, in, (unsigned)i);
        else in[31] = (uint8_t)(i + 1);
        if (zkn_bn_init(ctx->state[i + 1], in, 32) ||
            zkn_mont_to_montgomery(ctx->state[i + 1], ctx->state[i + 1], montctx))
            return -1;
    }
    return 0;
}

/* One known answer, hashed twice with the same context. */
static int run_kat(size_t k)
{
    zkn_bn_mont_ctx_t montctx;
    zkn_poseidon_ctx_t ctx;
    zkn_bn_t modulus;
    zkn_bn_t out[ZKN_POSEIDON_MAX_INPUTS + 1];
    int field = KAT[k].field;
    size_t n = KAT[k].arity, nout = KAT[k].nout;
    int ok = 1;

    if (mont_setup(field, &montctx, &modulus)) return 0;
    for (size_t i = 0; i < nout; i++) zkn_bn_alloc(&out[i], 32);
    if (zkn_poseidon_init(&ctx, 5, n, &montctx, modulus)) return 0;

    for (int pass = 0; pass < 2 && ok; pass++) {
        if (load(&ctx, &montctx, field, n, KAT[k].large) ||
            zkn_poseidon(&ctx, KAT[k].init, out, nout))
            return 0;
        for (size_t i = 0; i < nout; i++) {
            uint8_t got[32], want[32];
            hex32(KAT[k].out + 64 * i, want);
            if (zkn_mont_from_montgomery(out[i], out[i], &montctx) ||
                zkn_bn_export(out[i], got, 32) || memcmp(got, want, 32) != 0)
                ok = 0;
        }
    }
    return zkn_poseidon_destroy(&ctx) == 0 && ok;
}

static int init_rc(int field, uint32_t pow, size_t n)
{
    zkn_bn_mont_ctx_t montctx;
    zkn_poseidon_ctx_t ctx;
    zkn_bn_t modulus;
    if (mont_setup(field, &montctx, &modulus)) return -100;
    int rc = zkn_poseidon_init(&ctx, pow, n, &montctx, modulus);
    if (rc == 0) (void)zkn_poseidon_destroy(&ctx);
    return rc;
}

int main(void)
{
    char name[96];

    if (zkn_bn_lock(32, 0)) return 1;

    for (size_t k = 0; k < sizeof(KAT) / sizeof(KAT[0]); k++) {
        snprintf(name, sizeof(name), "%s poseidon%zu(%s) init=%u, %zu output(s), twice",
                 KAT[k].field == F_BN254 ? "BN254" : "BLS12-381 Fr", KAT[k].arity,
                 KAT[k].large ? "q-1..q-n" : "1..n", (unsigned)KAT[k].init, KAT[k].nout);
        check(name, run_kat(k));
    }

    /* What init accepts with the default arity masks, and what it refuses. */
    check("init: BN254, Poseidon-1 and Poseidon-7", init_rc(F_BN254, 5, 1) == 0 && init_rc(F_BN254, 5, 7) == 0);
    check("init: BLS12-381 Fr, Poseidon-5", init_rc(F_BLS12381, 5, 5) == 0);
    check("init refuses 0 and 8 inputs", init_rc(F_BN254, 5, 0) != 0 && init_rc(F_BN254, 5, 8) != 0);
    check("init refuses an S-box other than x^5", init_rc(F_BN254, 3, 5) != 0);
    check("init refuses BLS12-381 Fr with an arity that has no table", init_rc(F_BLS12381, 5, 2) != 0);
    check("init refuses a field that has no table", init_rc(F_SECP256K1, 5, 5) != 0);

    /* A context whose init failed does not hash. */
    {
        zkn_bn_mont_ctx_t montctx;
        zkn_poseidon_ctx_t ctx;
        zkn_bn_t modulus, out;
        memset(&ctx, 0xA5, sizeof(ctx)); /* status bytes happen to read "initialized" */
        zkn_bn_alloc(&out, 32);
        int rc = mont_setup(F_SECP256K1, &montctx, &modulus) ||
                 zkn_poseidon_init(&ctx, 5, 5, &montctx, modulus) == 0;
        check("a refused init leaves the context unusable", !rc && zkn_poseidon(&ctx, 0, &out, 1) != 0);
    }

    (void)zkn_bn_unlock();
    printf("== Results: %d/%d passed ==\n", tests - fails, tests);
    return fails ? 1 : 0;
}

#endif /* ZKN_HOST_TESTS */
