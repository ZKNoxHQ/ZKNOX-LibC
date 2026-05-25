// zkn_keyderivation.c
//
// Key derivation for ZKNOX Ledger app.
//
// Railgun keys (spending + viewing) use SLIP-0010 extended derivation
// with HMAC seed key "babyjubjub seed", matching the Railway Wallet /
// circomlibjs reference implementation:
//
//   Master:  HMAC-SHA512(key="babyjubjub seed", data=BIP39_seed)
//   Child:   CKDpriv((key,chain), i) = HMAC-SHA512(key=chain, data=0x00||key||ser32(i'))
//
// The Ledger SDK's os_derive_bip32_with_seed_no_throw with HDW_ED25519_SLIP10
// implements exactly this derivation when given a custom seed key.

#include "os.h"
#include "cx.h"
#include <string.h>
#include <stdbool.h>
#include "zkn_errors.h"
#include "zkn_keyderivation.h"
#include "zkn_tEdwards.h"
#include "zkn_eddsa.h"

// ---------------------------------------------------------------------------
// Private key derivation
// ---------------------------------------------------------------------------

zkn_error_t derive_railgun_key(const uint32_t *path, uint8_t *out_key, uint8_t *out_chain)
{
    // SLIP-0010 extended derivation with custom seed key "babyjubjub seed".
    // CX_CURVE_Ed25519 is used for the SLIP-0010 mechanics only —
    // the 32-byte output is an opaque seed interpreted differently
    // depending on the path:
    //   - PATH_SPENDING → BabyJubjub private key (fed to zkn_prv2pub)
    //   - PATH_VIEWING  → Ed25519 private key (fed to cx_ecfp_generate_pair)
    return os_derive_bip32_with_seed_no_throw(
        HDW_ED25519_SLIP10,
        CX_CURVE_Ed25519,
        path,
        PATH_LEN,
        out_key,
        out_chain,
        (unsigned char *)BABYJUBJUB_SEED_KEY,
        BABYJUBJUB_SEED_KEY_LEN);
}

zkn_error_t derive_private_key(key_type_t type, uint32_t account, uint8_t *out_key, uint8_t *out_chain)
{
    // Build path with account index at level 2
    uint32_t path[PATH_LEN];

    switch (type)
    {
    case KEY_TYPE_ZKNOX_ID:
        // Standard BIP32 secp256k1: m/44'/9004'/account'/0'/0
        memcpy(path, PATH_ZKNOX_ID, sizeof(path));
        path[2] = account | HARDENED;
        return os_derive_bip32_no_throw(CX_CURVE_SECP256K1,
                                        path, PATH_LEN,
                                        out_key, out_chain);

    case KEY_TYPE_ETHEREUM:
        // Standard BIP32 secp256k1: m/44'/60'/0'/0/address_index
        memcpy(path, PATH_ETHEREUM, sizeof(path));
        path[4] = account; // address_index (non-hardened)
        return os_derive_bip32_no_throw(CX_CURVE_SECP256K1,
                                        path, PATH_LEN,
                                        out_key, out_chain);

    case KEY_TYPE_SPENDING:
        // SLIP-0010 extended with "babyjubjub seed": m/44'/1984'/account'/0'/0'
        memcpy(path, PATH_SPENDING, sizeof(path));
        path[2] = account | HARDENED;
        return derive_railgun_key(path, out_key, out_chain);

    case KEY_TYPE_VIEWING:
        // SLIP-0010 extended with "babyjubjub seed": m/420'/1984'/account'/0'/0'
        memcpy(path, PATH_VIEWING, sizeof(path));
        path[2] = account | HARDENED;
        return derive_railgun_key(path, out_key, out_chain);

    default:
        return ZKN_ERR_INVALID_PARAM;
    }
}

// ---------------------------------------------------------------------------
// Public key derivation — secp256k1
// ---------------------------------------------------------------------------

zkn_error_t derive_pubkey_secp256k1(const uint8_t *privkey_bytes,
                                    pubkey_format_t format,
                                    uint8_t *pubkey_out,
                                    size_t *pubkey_len)
{
    zkn_error_t err;
    cx_ecfp_private_key_t privkey;
    cx_ecfp_public_key_t pubkey;

    // Init private key structure
    err = cx_ecfp_init_private_key_no_throw(CX_CURVE_SECP256K1,
                                            privkey_bytes, 32,
                                            &privkey);
    if (err != CX_OK)
        goto cleanup;

    // Generate public key
    err = cx_ecfp_generate_pair_no_throw(CX_CURVE_SECP256K1,
                                         &pubkey,
                                         &privkey,
                                         1); // keep privkey
    if (err != CX_OK)
        goto cleanup;

    // Format output
    switch (format)
    {
    case PUBKEY_FORMAT_RAW:
        // x || y (64 bytes, no prefix)
        memcpy(pubkey_out, pubkey.W + 1, 64);
        *pubkey_len = PUBKEY_SECP256K1_RAW_LEN;
        break;

    case PUBKEY_FORMAT_COMPRESSED:
        // 02/03 || x (33 bytes)
        pubkey_out[0] = (pubkey.W[64] & 1) ? 0x03 : 0x02;
        memcpy(pubkey_out + 1, pubkey.W + 1, 32);
        *pubkey_len = PUBKEY_SECP256K1_COMPRESSED_LEN;
        break;

    case PUBKEY_FORMAT_UNCOMPRESSED:
        // 04 || x || y (65 bytes)
        memcpy(pubkey_out, pubkey.W, 65);
        *pubkey_len = PUBKEY_SECP256K1_UNCOMPRESSED_LEN;
        break;

    case PUBKEY_FORMAT_ADDRESS:
        // Ethereum address: Keccak256(x || y)[12:32] (20 bytes)
        {
            uint8_t hash[32];
            err = cx_keccak_256_hash(pubkey.W + 1, 64, hash);
            if (err != CX_OK)
                break;
            memcpy(pubkey_out, hash + 12, ADDRESS_LEN);
            *pubkey_len = ADDRESS_LEN;
        }
        break;

    default:
        err = ZKN_ERR_INVALID_PARAM;
        break;
    }

cleanup:
    explicit_bzero(&privkey, sizeof(privkey));
    return err;
}

// ---------------------------------------------------------------------------
// Public key derivation — Ed25519
// ---------------------------------------------------------------------------

zkn_error_t derive_pubkey_ed25519(const uint8_t *privkey_bytes,
                                  pubkey_format_t format,
                                  uint8_t *pubkey_out,
                                  size_t *pubkey_len)
{
    zkn_error_t err;
    cx_ecfp_private_key_t privkey;
    cx_ecfp_public_key_t pubkey;

    (void)format; // Ed25519 is always 32 bytes compressed

    // Zero-initialize structures to avoid reading uninitialized memory
    memset(&privkey, 0, sizeof(privkey));
    memset(&pubkey, 0, sizeof(pubkey));

    // Init private key structure
    err = cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519,
                                            privkey_bytes, 32,
                                            &privkey);
    if (err != CX_OK)
        goto cleanup;

    // Generate public key
    err = cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519,
                                         &pubkey,
                                         &privkey,
                                         1);
    if (err != CX_OK)
        goto cleanup;

    // Ed25519 pubkey compression:
    // SDK returns 65 bytes: W[0]=04, W[1..32]=X (big-endian), W[33..64]=Y (big-endian)
    // Compressed Ed25519 format: Y in little-endian (32 bytes) with X's sign in MSB of last byte

    // Convert Y from big-endian (W[33..64]) to little-endian
    for (int i = 0; i < 32; i++)
    {
        pubkey_out[i] = pubkey.W[64 - i]; // W[64], W[63], ..., W[33]
    }

    // Add X's sign bit: X's LSB (in normal representation) = last byte of big-endian X = W[32]
    if (pubkey.W[32] & 1)
    {
        pubkey_out[31] |= 0x80;
    }

    *pubkey_len = PUBKEY_ED25519_LEN;

cleanup:
    explicit_bzero(&privkey, sizeof(privkey));
    explicit_bzero(&pubkey, sizeof(pubkey));
    return err;
}

// ---------------------------------------------------------------------------
// Public key derivation — BabyJubjub
// ---------------------------------------------------------------------------

zkn_error_t derive_pubkey_babyjubjub(const uint8_t *privkey_bytes,
                                     pubkey_format_t format,
                                     uint8_t *pubkey_out,
                                     size_t *pubkey_len)
{
    zkn_error_t err;
    zkn_edcurve_t curve;
    zkn_edpoint_t pubkey;
    uint8_t priv_copy[32];

    // Resource tracking flags
    bool bn_locked = false;
    bool curve_allocated = false;
    bool pubkey_allocated = false;

    // Only raw format supported for BabyJubjub
    if (format != PUBKEY_FORMAT_RAW)
    {
        return ZKN_ERR_INVALID_PARAM;
    }

    // Make a copy of private key (zkn_prv2pub modifies internal buffers)
    memcpy(priv_copy, privkey_bytes, 32);
    // for(int i=0;i<32;i++) priv_copy[i]=privkey_bytes[31-i];//reverse memcpy

    // Lock BN for crypto operations
    err = zkn_bn_lock(32, 0);
    if (err != CX_OK)
        goto cleanup;
    bn_locked = true;

    // Initialize BabyJubjub curve
    err = tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
    if (err != ZKN_OK)
        goto cleanup;
    curve_allocated = true;

    // Allocate point for public key
    err = tEdwards_alloc(&curve, &pubkey);
    if (err != ZKN_OK)
        goto cleanup;
    pubkey_allocated = true;

    // Derive public key from private key using EdDSA-style derivation
    // zkn_prv2pub: hash(prv) -> scalar -> scalar * G
    err = zkn_prv2pub(&curve, priv_copy, &pubkey);
    if (err != ZKN_OK)
        goto cleanup;

    // Export x || y (64 bytes, big-endian)
    err = tEdwards_export(&curve, &pubkey, pubkey_out, pubkey_out + 32);
    if (err != ZKN_OK)
        goto cleanup;

    *pubkey_len = PUBKEY_BABYJUBJUB_LEN;

cleanup:
    // CRITICAL: Free BN resources IN REVERSE ORDER before unlocking
    if (pubkey_allocated)
    {
        tEdwards_destroy(&curve, &pubkey);
    }
    if (curve_allocated)
    {
        tEdwards_Curve_destroy(&curve);
    }
    if (bn_locked)
    {
        zkn_bn_unlock();
    }

    explicit_bzero(priv_copy, sizeof(priv_copy));
    return err;
}

// ---------------------------------------------------------------------------
// Public key derivation — dispatcher
// ---------------------------------------------------------------------------

zkn_error_t derive_public_key(key_type_t type,
                              pubkey_format_t format,
                              const uint8_t *privkey_bytes,
                              uint8_t *pubkey_out,
                              size_t *pubkey_len)
{
    switch (type)
    {
    case KEY_TYPE_ZKNOX_ID:
    case KEY_TYPE_ETHEREUM:
        return derive_pubkey_secp256k1(privkey_bytes, format, pubkey_out, pubkey_len);

    case KEY_TYPE_VIEWING:
        return derive_pubkey_ed25519(privkey_bytes, format, pubkey_out, pubkey_len);

    case KEY_TYPE_SPENDING:
        return derive_pubkey_babyjubjub(privkey_bytes, format, pubkey_out, pubkey_len);

    default:
        return ZKN_ERR_INVALID_PARAM;
    }
}
