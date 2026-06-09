// zkn_bech32m.h — Bech32m decoder for RAILGUN 0zk addresses
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

#endif // ZKN_BECH32M_H
