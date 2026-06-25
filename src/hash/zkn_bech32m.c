// zkn_bech32m.c — Bech32m encoder/decoder for RAILGUN 0zk addresses
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 ZKNOX
//
// Implements BIP-350 bech32m. The decoder extracts the masterPublicKey
// from an incoming 0zk address (OUT_TRANSFER recipient parsing). The
// encoder reverses the transform so the device can RENDER a canonical
// `0zk1…` string for user confirmation (S10, AUDIT_2026-06-22).

#include "zkn_bech32m.h"
#include <string.h>

// All-chains networkID: ff ^ "railgun\0" = 8d 9e 96 93 98 8a 91 ff.
// See header for rationale.
const uint8_t ZKN_NETWORK_ALLCHAINS_ID[ZKN_NETWORK_ID_LEN] = {
    0x8d, 0x9e, 0x96, 0x93, 0x98, 0x8a, 0x91, 0xff
};

// Bech32 charset: "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
// Maps character → 5-bit value. -1 = invalid.
static const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1, // 0-9
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // A-O (uppercase not used)
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // P-_
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1, // a-o
    1,   0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1, // p-~
};

// Bech32m checksum constant
#define BECH32M_CONST 0x2bc830a3UL

static uint32_t bech32_polymod(const uint8_t *values, size_t len)
{
    static const uint32_t GEN[5] = {
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
    };
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];
        for (int j = 0; j < 5; j++) {
            if ((top >> j) & 1)
                chk ^= GEN[j];
        }
    }
    return chk;
}

// Expand HRP for checksum: each char's high bits, then 0, then each char's low 5 bits
static size_t hrp_expand(const char *hrp, size_t hrp_len, uint8_t *out)
{
    size_t pos = 0;
    for (size_t i = 0; i < hrp_len; i++)
        out[pos++] = hrp[i] >> 5;
    out[pos++] = 0;
    for (size_t i = 0; i < hrp_len; i++)
        out[pos++] = hrp[i] & 0x1f;
    return pos;
}

// Convert 5-bit words to 8-bit bytes (BIP-173 convertbits)
static int convert_5to8(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t *out_len)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t pos = 0;

    for (size_t i = 0; i < in_len; i++) {
        if (in[i] > 31) return -1;
        acc = (acc << 5) | in[i];
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            out[pos++] = (acc >> bits) & 0xff;
        }
    }
    // Check remaining bits are zero-padded
    if (bits > 0 && ((acc << (8 - bits)) & 0xff))
        return -1;

    *out_len = pos;
    return 0;
}

int zkn_0zk_decode(const uint8_t *addr, size_t addr_len,
                   uint8_t *data_out, size_t *data_len)
{
    // RAILGUN 0zk addresses are always 127 chars: "0zk" + "1" + 123 data chars
    if (addr_len != ZKN_0ZK_STRING_LEN)
        return -1;

    // Verify HRP = "0zk" and separator = '1'
    if (addr[0] != '0' || addr[1] != 'z' || addr[2] != 'k' || addr[3] != '1')
        return -2;

    const char *hrp = "0zk";
    const size_t hrp_len = 3;
    const size_t data_part_len = addr_len - hrp_len - 1;  // 123 chars after "0zk1"

    // Decode data part characters to 5-bit values
    uint8_t values5[123];
    for (size_t i = 0; i < data_part_len; i++) {
        uint8_t c = addr[hrp_len + 1 + i];
        if (c >= 128) return -3;
        int8_t v = CHARSET_REV[c];
        if (v < 0) return -3;
        values5[i] = (uint8_t)v;
    }

    // Verify bech32m checksum
    // Checksum input: hrp_expand(hrp) || values5
    uint8_t chk_input[7 + 123];  // hrp_expand("0zk") = 7 bytes, data = 123 bytes
    size_t hrp_exp_len = hrp_expand(hrp, hrp_len, chk_input);
    memcpy(chk_input + hrp_exp_len, values5, data_part_len);

    uint32_t polymod = bech32_polymod(chk_input, hrp_exp_len + data_part_len);
    if (polymod != BECH32M_CONST)
        return -4;  // Checksum mismatch

    // Strip 6 checksum words from data
    size_t payload5_len = data_part_len - 6;  // 117 five-bit words

    // Convert 5-bit to 8-bit
    return convert_5to8(values5, payload5_len, data_out, data_len);
}

int zkn_0zk_decode_mpk(const uint8_t *addr, size_t addr_len, uint8_t *mpk_out)
{
    uint8_t decoded[ZKN_0ZK_DECODED_LEN + 4];  // slight over-allocation for safety
    size_t decoded_len = 0;

    int rc = zkn_0zk_decode(addr, addr_len, decoded, &decoded_len);
    if (rc != 0) return rc;

    if (decoded_len < ZKN_0ZK_MPK_OFFSET + ZKN_0ZK_MPK_LEN)
        return -5;  // Decoded data too short

    memcpy(mpk_out, decoded + ZKN_0ZK_MPK_OFFSET, ZKN_0ZK_MPK_LEN);
    return 0;
}

// ── Encoder ────────────────────────────────────────────────────────────

// Forward charset: 5-bit value → ASCII char. Inverse of CHARSET_REV.
// Sized as `[]` (33 incl. NUL) rather than `[32]` so the literal's
// auto-appended NUL fits and the compiler doesn't trip the
// -Wunterminated-string-initialization warning. We only index
// CHARSET[0..31]; the trailing NUL costs one byte of rodata and goes
// unread.
static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Convert 8-bit bytes to 5-bit words. Inverse of `convert_5to8`. Pads the
// final word with zero bits when the input bit-length isn't a multiple of 5.
// For the 0zk payload (73 B = 584 bits) the output is exactly 117 words
// (584 / 5 = 116 rem 4 → last word holds 4 data bits and 1 zero pad bit).
static int convert_8to5(const uint8_t *in, size_t in_len,
                        uint8_t *out, size_t *out_len)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t pos = 0;

    for (size_t i = 0; i < in_len; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[pos++] = (acc >> bits) & 0x1f;
        }
    }
    if (bits > 0)
        out[pos++] = (acc << (5 - bits)) & 0x1f;

    *out_len = pos;
    return 0;
}

int zkn_0zk_encode(const uint8_t payload[ZKN_0ZK_DECODED_LEN],
                   uint8_t out127[ZKN_0ZK_STRING_LEN])
{
    if (payload == NULL || out127 == NULL)
        return -1;

    const char *hrp = "0zk";
    const size_t hrp_len = 3;

    // 73 bytes → 117 5-bit words.
    uint8_t words5[117];
    size_t words5_len = 0;
    if (convert_8to5(payload, ZKN_0ZK_DECODED_LEN, words5, &words5_len) != 0)
        return -2;
    if (words5_len != 117)
        return -3;

    // Bech32m checksum: polymod over hrp_expand(hrp) || words5 || 6 zero
    // pad words; XOR result with BECH32M_CONST; split into 6 5-bit chunks.
    // Layout matches the decoder's checksum verification (mirror form).
    uint8_t chk_input[7 + 117 + 6];
    size_t hrp_exp_len = hrp_expand(hrp, hrp_len, chk_input);
    memcpy(chk_input + hrp_exp_len, words5, words5_len);
    memset(chk_input + hrp_exp_len + words5_len, 0, 6);

    uint32_t polymod = bech32_polymod(chk_input,
                                      hrp_exp_len + words5_len + 6) ^ BECH32M_CONST;

    uint8_t checksum5[6];
    for (int i = 0; i < 6; i++)
        checksum5[i] = (uint8_t)((polymod >> (5 * (5 - i))) & 0x1f);

    // Compose: "0zk1" || 117 data chars || 6 checksum chars = 127.
    out127[0] = '0';
    out127[1] = 'z';
    out127[2] = 'k';
    out127[3] = '1';
    for (size_t i = 0; i < 117; i++)
        out127[4 + i] = (uint8_t)CHARSET[words5[i]];
    for (size_t i = 0; i < 6; i++)
        out127[4 + 117 + i] = (uint8_t)CHARSET[checksum5[i]];

    return 0;
}
