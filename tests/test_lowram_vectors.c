/* Host-only test — compiled solely by `make test` (which defines
 * ZKN_HOST_TESTS). The Ledger SDK app build sweeps every .c under the
 * submodule; this guard makes the file an empty translation unit there. */
#ifdef ZKN_HOST_TESTS

/*
 * test_lowram_vectors.c — fixed vectors for the paths ZKN_LOW_RAM replaces.
 *
 * ZKN_LOW_RAM swaps these implementations for smaller-footprint ones:
 *   - fixed-base scalar multiplication: 2 x 128-bit windows over the 4-entry
 *     table instead of 4 x 64-bit windows over the 16-entry one;
 *   - Poseidon: no variant any more, the table implementation holds no copy
 *     of the matrix in RAM; its vectors stay, they pin the digests;
 *   - EddsaPoseidon_Sign_final: one function per step instead of one frame;
 *   - BLAKE-512 compression: message words read from the block, G out of line;
 *   - zkn_bn_mod_mul: two Montgomery products, context built in place;
 *   - zkn_compute_binding_factors, zkn_partial_sig, verifyFeldmanShare: one
 *     function per step instead of one frame.
 *
 * The expected values below were produced by the standard build (for the
 * threshold rows, the unmodified library); the BabyJubjub rows of the first
 * three tables were also checked against circomlibjs (mulPointEscalar on
 * Base8, poseidon, signPoseidon). The two Bandersnatch signatures are those
 * of the library with r and S reduced modulo the order of the signing curve
 * and the challenge h hashed with the Poseidon instance of the BLS12-381
 * scalar field (255/6/8/60). They satisfy [S]B = R + [8h]A with curve
 * arithmetic and a Poseidon written apart from the library, and
 * test_security_regressions checks the same equation for both curves with
 * the hash of the library. The test must pass in both configurations:
 *
 *     make test
 *     make test ZKN_LOW_RAM=1
 *
 * Scalars straddle the window boundaries of both layouts (2^64, 2^128,
 * 2^192) on purpose.
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
#include "zkn_poseidon.h"
#include "zkn_blake512.h"
#include "zkn_frost.h"
#include "zkn_vss.h"

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
     "37ddf58844782635ad6f1512be000a6d01c334684bfeea4c8890154159e680eb0fef733949ce3d3c8ed95da88a93c59e7b6009460f33797e2ae92c353e78954305cd45f6540faff68c285f6fdd8363823470f074bb1667dabe649339743da317"},
    {1, 0x81, 0xa1,
     "0855b316bc32b08c6f83745497928e4bbd98ea4d1cb76a5029180c98f4b7ef2329d3778b0f9854ea969779e1d963cca06d03a865b0525302d493933ed53ba03317ccdcdecfb54f10bb914cd91826f00d74d1a9a552f764123d3e42eff028bae8"},
};

static const struct { size_t len; uint8_t tag; const char *digest; } BLAKE[] = {
    {0, 0x40,
     "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8"},
    {1, 0x41,
     "1d4cbb5a51c8dfe3019265a468d47d6fc82035829cf5995c1c35c956597c84a721a278944190ed9c73cda6ed0a0c52d697ad8eb58e7f41d900965790145a4bd7"},
    {55, 0x42,
     "b8a6d3aee752026ea32a1a69af487d3830251ce43a03a7da21850f1f1349403523ba0c4c50c56120a600f245a9023c4dd684046948f3ab3c06644bd96bd73f48"},
    {111, 0x43,
     "df4944c2d5a7d01e33bcdcb354c5ef85e5580b99d553e5e3ecf5d5b0b8cf1c95a981eef3554ddb8f2559a2c7fadc83e5c4141306fe190f08bfb402154504d259"},
    {112, 0x44,
     "56dc3aa062fd8ab153126babbc3696298a72654ac91c5a3de2236cc449a6b130facc7d3ab402a70a503878f8c3f4246e031147ef740de3d101f8ad7e2e4b90a3"},
    {113, 0x45,
     "a03cefebba4e4a960e7abcbb91c2d14d173cca0cbf05adbfcfb0ad1d5fc66eb0879f2a572aef8697f2e5c7f2969827dd17609c47e36a4e16e0b3f3cc964d3079"},
    {127, 0x46,
     "195e5e357aa449a5e13c490a102caf8ede51e71c8dc9f5b8be3d6cdad569d7249d879fcc6d2f508ca517ecbbc1cf8db2cb547744d42aedba785ae844d4881407"},
    {128, 0x47,
     "5bdeb195f697805bd655adace08682afa36dbd99dd62994458c25e705cd20aabc6b5f854d579ec02393cfbb3d6ac5d538b849a0a05ff9806ad84000403b0ac00"},
    {129, 0x48,
     "0845d5435fae52dd1ba7576460d79daf1927d9141448ce9e9c5b1918e0a2954193cc47381c684a731ba977da3a2cb153eb1756dcdbdaab9e0babd2efc9726325"},
    {239, 0x49,
     "37c53568b44e6d792de7837281a5bf3a3c6099d842990ead567911af000aa932bd48215e03b18d3e961971cc2bcf5d66c1b555be569d7093f2cb5d7dd772c46a"},
    {240, 0x4a,
     "cbbbe8837093507fdd3389f0664d14b3ec5aed881adfc436ff298244e3507bb6976da9ac27af316654e43be1c177b48d441a1c2fec31c5d4cc4e7123f7636294"},
    {255, 0x4b,
     "2f626d183e37eb95bce5867ad0eff47d1c34ac9b7f6cbb3b700c951954712335c466ef6b83ddb0c4d386fb8a569aaf2a834a5a1edcd05a29727fc8b053c2dae2"},
    {256, 0x4c,
     "207c292b6f9f9a3b934b9efb8130f3b9b4a4341ea90dd551024a68a514110ff9297d1507992a804cba268ccb381823b69cb0c15b6649ce2bf5b2f574fbcea61b"},
    {500, 0x4d,
     "bbe66a3891590ece8a55aa7e89ed2085cb687eb027d89aa4427ab1eb630881e6f689580fc0039a6c6726dd390dfa1b036fcb40e6dd55f8266d406aa2fd194cf4"},
};

/* which: 0 = subgroup order, 1 = field modulus. Operand kinds: 0 pattern (may
 * exceed the modulus), 1 all ones, 2 zero, 3 one, 4 modulus - 1. */
static const struct { int which; int ka, kb; uint8_t ta, tb; const char *r; } MODMUL[] = {
    {0, 0, 0, 0x60, 0x61, "026d46e16ee01ebe2b0e7dca726038c0344cf700485082b0940005bddf2fa388"},
    {0, 0, 0, 0x62, 0x63, "02f4639c63890043d14e7e167a6105e8eb9a97a91b91bd7c33233f70005a5d6e"},
    {0, 1, 1, 0x64, 0x65, "0062ecdb2e43625ef3bdbb1c8f783563a50a6d1fb4c66a2e277e1f01a6cd7933"},
    {0, 1, 0, 0x66, 0x67, "039f574509b0a756604f3e49e70d7d0b2baab0986f2bbb36a251c2c9b6d9a51a"},
    {0, 0, 1, 0x68, 0x69, "0561c13e8d220f196d09f3f2eba61bedc653ce78f515d4d7dc990f5115e218e2"},
    {0, 2, 0, 0x6a, 0x6b, "0000000000000000000000000000000000000000000000000000000000000000"},
    {0, 3, 0, 0x6c, 0x6d, "0603e0b3e05b4e1816f55cc13d52e74a0c366c03047deaece8ec769dab74977c"},
    {0, 4, 4, 0x6e, 0x6f, "0000000000000000000000000000000000000000000000000000000000000001"},
    {0, 4, 0, 0x70, 0x71, "05935625737188bff197bc0dabdf34642ae03e9b903a09ddc1335a55311326ea"},
    {0, 0, 4, 0x72, 0x73, "02a920a5d2f5b1dc97bff0666c88fad1ec5371d2fdb9de632368c0ec47922d16"},
    {0, 1, 4, 0x74, 0x75, "041b25a97a6abce03eaf76b4f8173af5c391edf19887fbbf603f81fd98918a7c"},
    {1, 0, 0, 0x61, 0x62, "2b8e292ddc517772cb8297e40ed2df5a5a345f52f46fc57eb5ea628cbba55a4c"},
    {1, 0, 0, 0x63, 0x64, "1d827974b2287f61e796a781e78ba35ff41a281c7978353eb228ffb34708f46e"},
    {1, 1, 1, 0x65, 0x66, "16662fa12c70267077bc8214e44a4c860e3935cf1e543021066e73a0fe216db3"},
    {1, 1, 0, 0x67, 0x68, "03774a2eec86edda62972d6c868f277a4f18e07107de5039c49b21dd92eca6d7"},
    {1, 0, 1, 0x69, 0x6a, "099fc9b01297afa0ded81c99e5bdd1f694744c5e91406ecdc7fcfe2f30a4b8da"},
    {1, 2, 0, 0x6b, 0x6c, "0000000000000000000000000000000000000000000000000000000000000000"},
    {1, 3, 0, 0x6d, 0x6e, "1045f47ced81cb98ed1049b7d1f2f95bd05192fc2910a64fd9e1384bdd97d474"},
    {1, 4, 4, 0x6f, 0x70, "0000000000000000000000000000000000000000000000000000000000000001"},
    {1, 4, 0, 0x71, 0x72, "1adb47df438e81f173e81341ad49a70035c81dc143a19708d1cd8dc17a0459cc"},
    {1, 0, 4, 0x73, 0x74, "0cdeb4cbea5557f6307c1f2d2e069875dd0272de68ad0f75f929fd8349a987ee"},
    {1, 1, 4, 0x75, 0x76, "2259d6b14729c0fa51e1a2470908122ef13771b2da58a367974bc177a0000007"},
};

static const struct { size_t n; size_t signer; const char *bf; const char *sig; } FROSTV[] = {
    {2, 1,
     "04bd2f9250420c3140ef6c447bc91df4b457ea6346181ab11186e580b7a9c74902ddc94369b57927626f836f9e50f20cc51db2bb98dd0d3ea3651b03e3e46514",
     "03e9a9a6d699265e640d91858b310c8c0b376a9221d9bf2ed69bc912f46905ac"},
    {2, 2,
     "04bd2f9250420c3140ef6c447bc91df4b457ea6346181ab11186e580b7a9c74902ddc94369b57927626f836f9e50f20cc51db2bb98dd0d3ea3651b03e3e46514",
     "045177c8947a3d21759a5fb67e2a04df90b9ca2c7ee6e5236bd1651c3562337e"},
    {3, 1,
     "04d756b4b9d238fcc9e8e34c26274e26660545b8f917a598e33c2125554d85c502b6dc42f0ad91a4474fcddb484ba648c7b0fec6fa51f6ad94a07b513eac769601112c36ac4daef1629f7c78f7dd5dd133a24e9bf9562ae1f95284d96dc7d158",
     "031e979cb2b9a2378f46ff34411446041ad28131c3f835b9ea7ac178637c8da6"},
    {3, 2,
     "04d756b4b9d238fcc9e8e34c26274e26660545b8f917a598e33c2125554d85c502b6dc42f0ad91a4474fcddb484ba648c7b0fec6fa51f6ad94a07b513eac769601112c36ac4daef1629f7c78f7dd5dd133a24e9bf9562ae1f95284d96dc7d158",
     "00b7ef329bc3aa6e03329ad1dc34ea27366680b3266cd2b9a86b7dc3ae4983f2"},
    {3, 3,
     "04d756b4b9d238fcc9e8e34c26274e26660545b8f917a598e33c2125554d85c502b6dc42f0ad91a4474fcddb484ba648c7b0fec6fa51f6ad94a07b513eac769601112c36ac4daef1629f7c78f7dd5dd133a24e9bf9562ae1f95284d96dc7d158",
     "002ab7ea7e461acf7559dcb698423f6e86b1db00e4b4385912975ba1e0575dc3"},
};

/* dealer 2 of 3, threshold 3, name "nanos", seed pattern(0xc0), epoch pattern(0xc1);
 * share evaluated for participant 3 */
static const char *VSS_COEFFS =
    "0398ebc36acf871e7510f44466db7691375847d2c240bd25381ec2597de00ccb06018dbf76f578358ac878d79540ee97fb5175f98ecc15debb73dc10d7f8fd7802f2a020fe4e75b89b5eed88bdd68b32d3f2d03e4b1c35059ac6853c304ef808";
static const char *VSS_COMMITS =
    "0c8a932647a219f79d2e885ceba897fd9c52f5a7e35ba9dee6589444fe87f94326c6ea2ec3ba21ac07d3de15a6fefa7f8fc65c14f5dbc14317b7fe10d96afbc60dbc667428002240b91ac8ac0cb6e75fa742ba0564f27c0244e8c678f0d578841a86306c2686a562e67d471b105aff29a4b0cb2b8a7c21a57c3e9873bf58bd201ba4457aef720cddca056fe57a8f331b7b22becba44a733b9d16e089bf216bc701236f4e58b875ff6cd7fce71e6bed5116c8a512f07fb730913ec34e7d1d9c44";
static const char *VSS_SHARE =
    "05cd71863b66a7180a7a7b9a21d7f9d0ee1d7be682bc59ab0752dea428a9ace4";

/* scalar below the BabyJubjub subgroup order (2^248 < order) */
static void scalar(uint8_t k[32], uint8_t tag) { pattern(k, 32, tag); k[0] = 0; }

static int mulG(zkn_edcurve_t *c, const uint8_t k[32], uint8_t xy[64])
{
    zkn_edpoint_t R;
    int rc = tEdwards_alloc(c, &R);
    rc |= tEdwards_fixedBase_4MSM(c, k, &R);
    rc |= tEdwards_normalize(c, &R);
    rc |= tEdwards_export(c, &R, xy, xy + 32);
    return rc;
}

/* Commitment list of n signers, group key and message of the FROSTV rows. */
static int frost_fixture(zkn_edcurve_t *c, size_t n, uint8_t *list, uint8_t gk[64], uint8_t msg[32])
{
    uint8_t k[32];
    int rc = 0;
    memset(list, 0, n * 160);
    for (size_t j = 1; j <= n; j++) {
        uint8_t *ent = list + (j - 1) * 160;
        ent[31] = (uint8_t)j;
        scalar(k, (uint8_t)(0x90 + j)); rc |= mulG(c, k, ent + 32);
        scalar(k, (uint8_t)(0xa0 + j)); rc |= mulG(c, k, ent + 96);
    }
    scalar(k, 0xb0); rc |= mulG(c, k, gk);
    pattern(msg, 32, 0xb1); msg[31] &= 0x0F;
    return rc;
}

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

#ifdef ZKN_HAVE_EDDSA_POSEIDON_SIGN
        /* The entry point that derives the public key itself. */
        memset(sig, 0, sizeof(sig));
        rc = tEdwards_Curve_alloc_init(&curve, SIGN[i].curve);
        rc |= EddsaPoseidon_Sign(&curve, prv, msg, 32, sig);
        snprintf(label, sizeof(label), "%s: signature %zu, key derived by the signer", curve_name(SIGN[i].curve), i);
        chk(label, rc == 0 && memcmp(sig, expect, 96) == 0);
#endif
    }

#ifdef ZKN_HAVE_EDDSA_POSEIDON_SIGN
    {
        /* Same refusals as EddsaPoseidon_Sign_final: length, and msg >= p. */
        zkn_edcurve_t curve;
        uint8_t prv[32], msg[32], sig[96];
        pattern(prv, 32, 0x51);
        memset(msg, 0xFF, sizeof(msg));
        int rc = tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
        chk("signer-derived key: message >= p refused", rc == 0 && EddsaPoseidon_Sign(&curve, prv, msg, 32, sig) != 0);
        msg[31] = 0;
        rc = tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
        chk("signer-derived key: 31-byte message refused", rc == 0 && EddsaPoseidon_Sign(&curve, prv, msg, 31, sig) != 0);
    }
#endif

    printf("\n[BLAKE-512]\n");
    for (size_t i = 0; i < sizeof(BLAKE) / sizeof(BLAKE[0]); i++) {
        uint8_t in[512], out[64], expect[64];
        pattern(in, BLAKE[i].len, BLAKE[i].tag);
        unhex(BLAKE[i].digest, expect, 64);
        int rc = zkn_blake512(in, BLAKE[i].len, out);
        /* same input in two updates, split inside the first block */
        zkn_blake512_ctx_t hc;
        uint8_t out2[64];
        size_t cut = BLAKE[i].len < 7 ? BLAKE[i].len : 7;
        rc |= zkn_blake512_init(&hc);
        rc |= zkn_blake512_update(&hc, in, cut);
        rc |= zkn_blake512_update(&hc, in + cut, BLAKE[i].len - cut);
        rc |= zkn_blake512_final(&hc, out2);
        snprintf(label, sizeof(label), "BLAKE-512, %zu bytes", BLAKE[i].len);
        chk(label, rc == 0 && memcmp(out, expect, 64) == 0 && memcmp(out2, expect, 64) == 0);
    }

    printf("\n[modular multiplication]\n");
    {
        zkn_edcurve_t curve;
        uint8_t mods[2][32];
        int rc0 = tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
        rc0 |= zkn_bn_export(curve.order, mods[0], 32);
        rc0 |= zkn_bn_export(curve.modulus, mods[1], 32);
        for (size_t i = 0; i < sizeof(MODMUL) / sizeof(MODMUL[0]); i++) {
            uint8_t ab[2][32], rb[32], expect[32];
            const int kinds[2] = {MODMUL[i].ka, MODMUL[i].kb};
            const uint8_t tags[2] = {MODMUL[i].ta, MODMUL[i].tb};
            const uint8_t *mod = mods[MODMUL[i].which];
            for (int s2 = 0; s2 < 2; s2++) {
                switch (kinds[s2]) {
                    case 0: pattern(ab[s2], 32, tags[s2]); break;
                    case 1: memset(ab[s2], 0xff, 32); break;
                    case 2: memset(ab[s2], 0, 32); break;
                    case 3: memset(ab[s2], 0, 32); ab[s2][31] = 1; break;
                    default: memcpy(ab[s2], mod, 32); ab[s2][31] -= 1; break;
                }
            }
            unhex(MODMUL[i].r, expect, 32);
            zkn_bn_t a, b, m, r;
            int rc = rc0 | zkn_bn_alloc_init(&a, 32, ab[0], 32) | zkn_bn_alloc_init(&b, 32, ab[1], 32)
                   | zkn_bn_alloc_init(&m, 32, mod, 32) | zkn_bn_alloc(&r, 32);
            rc |= zkn_bn_mod_mul(r, a, b, m);
            rc |= zkn_bn_export(r, rb, 32);
            /* result written over an operand */
            uint8_t rb2[32];
            rc |= zkn_bn_mod_mul(a, a, b, m);
            rc |= zkn_bn_export(a, rb2, 32);
            snprintf(label, sizeof(label), "mod %s, operands %d x %d", MODMUL[i].which ? "p" : "order",
                     MODMUL[i].ka, MODMUL[i].kb);
            chk(label, rc == 0 && memcmp(rb, expect, 32) == 0 && memcmp(rb2, expect, 32) == 0);
        }
    }

    printf("\n[FROST binding factors and signature shares]\n");
    for (size_t i = 0; i < sizeof(FROSTV) / sizeof(FROSTV[0]); i++) {
        const size_t n = FROSTV[i].n, signer = FROSTV[i].signer;
        zkn_edcurve_t curve;
        uint8_t list[3 * 160], gk[64], gkc[32], msg[32], bf[3 * 32], sig[32];
        uint8_t ebf[3 * 32], esig[32], sk[32], d[32], e[32];
        unhex(FROSTV[i].bf, ebf, 32 * n);
        unhex(FROSTV[i].sig, esig, 32);

        int rc = tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
        rc |= frost_fixture(&curve, n, list, gk, msg);
        for (size_t k = 0; k < 32; k++) gkc[k] = gk[k + 32];
        gkc[0] ^= (uint8_t)((gk[31] & 1) << 7);
        rc |= zkn_compute_binding_factors(&curve, gkc, list, n, msg, 32, bf);
        snprintf(label, sizeof(label), "binding factors, %zu signers (row %zu)", n, i);
        chk(label, rc == 0 && memcmp(bf, ebf, 32 * n) == 0);

        scalar(sk, (uint8_t)(0x80 + signer));
        scalar(d, (uint8_t)(0x90 + signer));
        scalar(e, (uint8_t)(0xa0 + signer));
        memset(sig, 0, sizeof(sig));
        rc = tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
        rc |= zkn_partial_sig(&curve, signer, sk, gk, d, e, list, n, msg, 32, NULL, sig);
        snprintf(label, sizeof(label), "signature share, signer %zu of %zu", signer, n);
        chk(label, rc == 0 && memcmp(sig, esig, 32) == 0);
        /* the nonces are single use: consumed by the call */
        uint8_t zero[32] = {0};
        snprintf(label, sizeof(label), "nonces wiped, signer %zu of %zu", signer, n);
        chk(label, memcmp(d, zero, 32) == 0 && memcmp(e, zero, 32) == 0);
    }
    {
        /* refusals keep their meaning: a commitment that is not ours, a lambda
         * that does not match the listed quorum */
        zkn_edcurve_t curve;
        uint8_t list[2 * 160], gk[64], msg[32], sig[32], sk[32], d[32], e[32], lam[32];
        int rc = tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
        rc |= frost_fixture(&curve, 2, list, gk, msg);
        scalar(sk, 0x81); scalar(d, 0x92); scalar(e, 0xa1);   /* hiding nonce of signer 2 */
        int r1 = zkn_partial_sig(&curve, 1, sk, gk, d, e, list, 2, msg, 32, NULL, sig);
        chk("signature share refused: nonce does not match the listed commitment", rc == 0 && r1 != 0);
        rc = tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
        scalar(sk, 0x81); scalar(d, 0x91); scalar(e, 0xa1);
        memset(lam, 0, 32); lam[31] = 1;
        int r2 = zkn_partial_sig(&curve, 1, sk, gk, d, e, list, 2, msg, 32, lam, sig);
        chk("signature share refused: lambda does not match the quorum", rc == 0 && r2 != 0);
    }

    printf("\n[Feldman VSS]\n");
    {
        zkn_edcurve_t curve;
        participant_t p;
        uint8_t coeffs[96], comm[192], share[32], ecoeffs[96], ecomm[192], eshare[32];
        bool valid = false;
        unhex(VSS_COEFFS, ecoeffs, 96);
        unhex(VSS_COMMITS, ecomm, 192);
        unhex(VSS_SHARE, eshare, 32);
        memset(&p, 0, sizeof(p));
        p.id = 2; p.n = 3; p.name_len = 5;
        pattern(p.seed, 32, 0xc0);
        pattern(p.epoch, VSS_EPOCH_LEN, 0xc1);
        memcpy(p.name, "nanos", 5);
        int rc = tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
        rc |= makeDealerCoeffsDeterministic(&curve, &p, 3, 0, coeffs);
        chk("dealer coefficients", rc == 0 && memcmp(coeffs, ecoeffs, 96) == 0);
        rc |= makeDealerCommitments(&curve, coeffs, 3, comm);
        chk("dealer commitments", rc == 0 && memcmp(comm, ecomm, 192) == 0);
        rc |= computeDealerShareForId(&curve, coeffs, 3, 3, share);
        chk("share for participant 3", rc == 0 && memcmp(share, eshare, 32) == 0);
        rc |= verifyFeldmanShare(&curve, 3, share, comm, 3, &valid);
        chk("share accepted against the commitments", rc == 0 && valid);
        valid = true;
        rc = verifyFeldmanShare(&curve, 2, share, comm, 3, &valid);
        chk("same share refused for another participant", rc == 0 && !valid);
        share[31] ^= 1;
        valid = true;
        rc = verifyFeldmanShare(&curve, 3, share, comm, 3, &valid);
        chk("altered share refused", rc == 0 && !valid);
        share[31] ^= 1;
        comm[64 + 5] ^= 0x40;
        valid = true;
        rc = verifyFeldmanShare(&curve, 3, share, comm, 3, &valid);
        chk("commitment off the curve refused", rc != 0 && !valid);
    }

    printf("\n== Results: %d/%d passed ==\n", g_pass, g_pass + g_fail);
    return g_fail == 0 ? 0 : 1;
}

#endif /* ZKN_HOST_TESTS */
