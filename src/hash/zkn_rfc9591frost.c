#include <stdint.h>
#include <stdlib.h>

#include "zkn_bn.h"
#include "zkn_hash_compat.h"
#include "zkn_rng_compat.h"

#include "zkn_errors.h"
#include "zkn_common.h"

/* R256 = 2^256 mod L  (L = BabyJubjub prime subgroup order), big-endian.
 * Lets us reduce the FULL 64-byte blake digest so the C matches the JS
 * reference (curves-lite): H = reduce_L( LE(digest[0:64]) ), instead of only
 * the low 32 bytes (which the 256-bit bn type previously kept). */
static const uint8_t RFC9591_R256_BE[32] = {
  0x01, 0xf1, 0x64, 0x24, 0xe1, 0xbb, 0x77, 0x24, 0xf8, 0x5a, 0x92, 0x01, 0xd8, 0x18, 0xf0, 0x15,
  0xe7, 0xac, 0xff, 0xc6, 0xa0, 0x98, 0xf2, 0x4b, 0x07, 0x33, 0x15, 0xde, 0xa0, 0x8f, 0x9c, 0x76};

/* Reduce a full 512-bit digest (passed AFTER the whole-buffer byteswap)
 * modulo `order`, matching the JS full-width little-endian reduction.
 *   lo = BE(swapped[32:64]) = LE(digest[0:32])
 *   hi = BE(swapped[0:32])  = LE(digest[32:64])
 *   H  = (lo + hi * 2^256) mod order                                        */
static int rfc9591_reduce_wide(const uint8_t *swapped, zkn_bn_t order, zkn_bn_t H)
{
  ZKN_ERROR_INIT();
  zkn_bn_t lo, hi, r256, lo_r, hi_r, prod;
  ZKN_CHECK(zkn_bn_alloc_init(&lo, 32, swapped + 32, 32));
  ZKN_CHECK(zkn_bn_alloc_init(&hi, 32, swapped, 32));
  ZKN_CHECK(zkn_bn_alloc_init(&r256, 32, RFC9591_R256_BE, 32));
  ZKN_CHECK(zkn_bn_alloc(&lo_r, 32));
  ZKN_CHECK(zkn_bn_alloc(&hi_r, 32));
  ZKN_CHECK(zkn_bn_alloc(&prod, 32));
  ZKN_CHECK(zkn_bn_reduce(lo_r, lo, order));          // lo mod order
  ZKN_CHECK(zkn_bn_reduce(hi_r, hi, order));          // hi mod order
  ZKN_CHECK(zkn_bn_mod_mul(prod, hi_r, r256, order)); // hi * 2^256 mod order
  ZKN_CHECK(zkn_bn_mod_add(H, lo_r, prod, order));    // (lo + hi*2^256) mod order
  ZKN_CHECK(zkn_bn_destroy(&lo));
  ZKN_CHECK(zkn_bn_destroy(&hi));
  ZKN_CHECK(zkn_bn_destroy(&r256));
  ZKN_CHECK(zkn_bn_destroy(&lo_r));
  ZKN_CHECK(zkn_bn_destroy(&hi_r));
  ZKN_CHECK(zkn_bn_destroy(&prod));
  ZKN_ERROR_CLOSE();
}

int RFC9591_taggedHash(const uint8_t *tag, size_t taglen, const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H)
{
  ZKN_ERROR_INIT();

  uint8_t out[64];
  uint8_t tmp2;

  zkn_blake2b_t state;

  uint8_t contextString_BabyFROST[29] = {0x46, 0x52, 0x4f, 0x53, 0x54, 0x2d, 0x45, 0x44, 0x42, 0x41, 0x42, 0x59, 0x4a, 0x55, 0x4a, 0x55, 0x42, 0x2d, 0x42, 0x4c, 0x41, 0x4b, 0x45, 0x35, 0x31, 0x32, 0x2d, 0x76, 0x31};

  ZKN_CHECK(zkn_hash_init_ex((zkn_hash_t *)&state, ZKN_BLAKE2B, 64));                                          // init for a 64 bytes size output
  ZKN_CHECK(zkn_hash_update((zkn_hash_t *)&state, contextString_BabyFROST, sizeof(contextString_BabyFROST))); // update with contextString
  ZKN_CHECK(zkn_hash_update((zkn_hash_t *)&state, tag, taglen));                                              // update with tag
  ZKN_CHECK(zkn_hash_update((zkn_hash_t *)&state, msg, msglen));                                              // update with msg

  ZKN_CHECK(zkn_hash_final((zkn_hash_t *)&state, out)); // obtain blake512(payload) with 32 output bytes
  // the ByteSwap
  for (size_t i = 0; i < 32; i++)
  {
    tmp2 = out[i];
    out[i] = out[63 - i];
    out[63 - i] = tmp2;
  }

  ZKN_CHECK(rfc9591_reduce_wide(out, order, H)); // full 64-byte reduction (matches JS reference)

  ZKN_ERROR_CLOSE();
}

int Babyfrost_H1(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H)
{
  //'rho'
  uint8_t rho[3] = {0x72, 0x68, 0x6f};
  ZKN_ERROR_INIT();
  ZKN_CHECK(RFC9591_taggedHash(rho, 3, msg, msglen, order, H));

  ZKN_ERROR_CLOSE();
}

int Babyfrost_H3(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H)
{
  //'nonce'
  uint8_t nonce[5] = {0x6e, 0x6f, 0x6e, 0x63, 0x65};
  ZKN_ERROR_INIT();
  ZKN_CHECK(RFC9591_taggedHash(nonce, 5, msg, msglen, order, H));

  ZKN_ERROR_CLOSE();
}

int Babyfrost_H4(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H)
{
  //'msg'
  uint8_t tag_msg[3] = {0x6d, 0x73, 0x67};
  ZKN_ERROR_INIT();
  ZKN_CHECK(RFC9591_taggedHash(tag_msg, 3, msg, msglen, order, H));

  ZKN_ERROR_CLOSE();
}

int Babyfrost_H5(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H)
{
  //'com'
  uint8_t com[3] = {0x63, 0x6f, 0x6d};
  ZKN_ERROR_INIT();
  ZKN_CHECK(RFC9591_taggedHash(com, 3, msg, msglen, order, H));

  ZKN_ERROR_CLOSE();
}

//to be tested
int Babyfrost_H6(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H)
{
  //'coeff' = 0x63 0x6f 0x65 0x66 0x66
  uint8_t coeff[5] = {0x63, 0x6f, 0x65, 0x66, 0x66};
  ZKN_ERROR_INIT();
  ZKN_CHECK(RFC9591_taggedHash(coeff, 5, msg, msglen, order, H));

  ZKN_ERROR_CLOSE();
}

int Babyfrost_H7(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H)
{
  //'view' = 0x76 0x69 0x65 0x77
  uint8_t view[4] = {0x76, 0x69, 0x65, 0x77};
  ZKN_ERROR_INIT();
  ZKN_CHECK(RFC9591_taggedHash(view, 4, msg, msglen, order, H));

  ZKN_ERROR_CLOSE();
}


int zkn_frost_hash_init(zkn_hash_t *state, zkn_md_t hashID, size_t Hash_S8, uint8_t *contextString, size_t context_S8, uint8_t *tag, size_t tag_S8)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_hash_init_ex(state, hashID, Hash_S8));          // init for a 64 bytes size output
  ZKN_CHECK(zkn_hash_update(state, contextString, context_S8)); // update with contextString
  ZKN_CHECK(zkn_hash_update(state, tag, tag_S8));               // update with tag

  ZKN_ERROR_CLOSE();
}

int zkn_frost_H1_init(zkn_hash_t *state)
{
  ZKN_ERROR_INIT();
  //'rho'
  uint8_t rho[3] = {0x72, 0x68, 0x6f};

  uint8_t contextString_BabyFROST[29] = {0x46, 0x52, 0x4f, 0x53, 0x54, 0x2d, 0x45, 0x44, 0x42, 0x41, 0x42, 0x59, 0x4a, 0x55, 0x4a, 0x55, 0x42, 0x2d, 0x42, 0x4c, 0x41, 0x4b, 0x45, 0x35, 0x31, 0x32, 0x2d, 0x76, 0x31};

  ZKN_CHECK(zkn_frost_hash_init(state, ZKN_BLAKE2B, 64, contextString_BabyFROST, 29, rho, 3));

  ZKN_ERROR_CLOSE();
}

int zkn_frost_H5_init(zkn_hash_t *state)
{
  uint8_t com[3] = {0x63, 0x6f, 0x6d};
  ZKN_ERROR_INIT();

  uint8_t contextString_BabyFROST[29] = {0x46, 0x52, 0x4f, 0x53, 0x54, 0x2d, 0x45, 0x44, 0x42, 0x41, 0x42, 0x59, 0x4a, 0x55, 0x4a, 0x55, 0x42, 0x2d, 0x42, 0x4c, 0x41, 0x4b, 0x45, 0x35, 0x31, 0x32, 0x2d, 0x76, 0x31};

  ZKN_CHECK(zkn_frost_hash_init(state, ZKN_BLAKE2B, 64, contextString_BabyFROST, 29, com, 3));

  ZKN_ERROR_CLOSE();
}

int zkn_frost_hash_update(zkn_hash_t *state, uint8_t *msg, size_t msglen)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_hash_update(state, msg, msglen)); // update with provided input

  ZKN_ERROR_CLOSE();
}

int zkn_frost_hash_final(zkn_hash_t *state, zkn_bn_t order, zkn_bn_t H)
{
  ZKN_ERROR_INIT();
  uint8_t out[64];
  uint8_t tmp2;

  ZKN_CHECK(zkn_hash_final(state, out)); // obtain blake512(payload) with 32 output bytes
  // the ByteSwap
  for (size_t i = 0; i < 32; i++)
  {
    tmp2 = out[i];
    out[i] = out[63 - i];
    out[63 - i] = tmp2;
  }

  ZKN_CHECK(rfc9591_reduce_wide(out, order, H)); // full 64-byte reduction (matches JS reference)

  ZKN_ERROR_CLOSE();
}
