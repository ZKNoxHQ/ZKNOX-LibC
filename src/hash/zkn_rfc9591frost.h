#ifndef _RFC9591_FROSTHASH_H
#define _RFC9591_FROSTHASH_H

#include "zkn_bn.h"
#include "zkn_hash_compat.h"

int Babyfrost_H1(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H);

int Babyfrost_H3(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H);

int Babyfrost_H4(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H);

int Babyfrost_H5(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H);

int Babyfrost_H6(const uint8_t *msg, size_t msglen, zkn_bn_t order, zkn_bn_t H);

int zkn_frost_H1_init(zkn_hash_t *state);
int zkn_frost_H5_init(zkn_hash_t *state);

int zkn_frost_hash_update(zkn_hash_t *state, uint8_t *msg, size_t msglen);

int zkn_frost_hash_final(zkn_hash_t *state, zkn_bn_t order, zkn_bn_t H);

#endif
