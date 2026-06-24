// zkn_bech32m.h — Bech32m encoder + decoder for RAILGUN 0zk addresses
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX

#ifndef ZKN_BECH32M_H
#define ZKN_BECH32M_H

#include <stdint.h>
#include <stddef.h>

// RAILGUN 0zk address decoded layout (73 bytes):
//   [0]      version          (1 byte)
//   [1..32]  masterPublicKey  (32 bytes)
//   [33..40] networkXOR       (8 bytes)
//   [41..72] viewingPublicKey (32 bytes)
#define ZKN_0ZK_DECODED_LEN   73
#define ZKN_0ZK_MPK_OFFSET    1
#define ZKN_0ZK_MPK_LEN       32
#define ZKN_0ZK_STRING_LEN    127
#define ZKN_0ZK_VERSION       0x01
#define ZKN_0ZK_NET_OFFSET    33
#define ZKN_0ZK_VK_OFFSET     41
#define ZKN_0ZK_VK_LEN        32
#define ZKN_NETWORK_ID_LEN    8

// Canonical "all chains" networkID used in the engine's share-my-address
// form: xor(0xff×8, "railgun\0"). This is what the engine's
// `xorNetworkID('ffffffffffffffff')` produces and matches the
// `buildAllNet()` helper in the JS clear-sign tests. Pick this when the
// device needs to render the user's 0zk independently of any specific
// chain (e.g. a "share my address" confirmation screen).
extern const uint8_t ZKN_NETWORK_ALLCHAINS_ID[ZKN_NETWORK_ID_LEN];

// Decode a RAILGUN 0zk address (bech32m) and extract the masterPublicKey.
//
// @param addr     0zk address string (127 ASCII chars, NOT null-terminated required)
// @param addr_len length of addr (must be 127)
// @param mpk_out  output buffer for masterPublicKey (32 bytes)
// @return 0 on success, nonzero on error (invalid charset, bad checksum, wrong HRP)
int zkn_0zk_decode_mpk(const uint8_t *addr, size_t addr_len, uint8_t *mpk_out);

// Full decode: extract all 73 bytes of decoded data.
//
// @param addr      0zk address string (127 ASCII chars)
// @param addr_len  length of addr (must be 127)
// @param data_out  output buffer (73 bytes)
// @return 0 on success, nonzero on error
int zkn_0zk_decode(const uint8_t *addr, size_t addr_len,
                   uint8_t *data_out, size_t *data_len);

// Encode a RAILGUN 0zk payload as a bech32m string with HRP "0zk".
// Output is exactly ZKN_0ZK_STRING_LEN (127) ASCII chars, NOT
// null-terminated. Caller supplies a 127-byte buffer.
//
//   payload[0]      version          (must be ZKN_0ZK_VERSION)
//   payload[1..32]  masterPublicKey  (32 bytes)
//   payload[33..40] networkID        (8 bytes; see ZKN_NETWORK_ALLCHAINS_ID
//                                     for the engine wildcard form)
//   payload[41..72] viewingPubKey    (32 bytes, RFC 8032 compressed Ed25519)
//
// @param payload  73-byte input buffer
// @param out127   127-byte output buffer
// @return 0 on success, nonzero on error
int zkn_0zk_encode(const uint8_t payload[ZKN_0ZK_DECODED_LEN],
                   uint8_t out127[ZKN_0ZK_STRING_LEN]);

#endif // ZKN_BECH32M_H
