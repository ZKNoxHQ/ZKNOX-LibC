// zkn_keyderivation.h

#ifndef ZKN_KEYDERIVATION_H
#define ZKN_KEYDERIVATION_H

#include "zkn_bn.h"
#include "zkn_hash_compat.h"

#include <stdint.h>
#include <stddef.h>
#include "zkn_errors.h"

// Key types
typedef enum
{
    KEY_TYPE_SPENDING = 3, // BabyJubjub
    KEY_TYPE_VIEWING = 4,  // Ed25519
    KEY_TYPE_DKG_COMM = 5, // Ed25519 — non-exported DKG transport identity
    KEY_TYPE_SPENDING_BANDERSNATCH = 6 // Bandersnatch, under its own seed key
} key_type_t;

// Public key output formats
typedef enum
{
    PUBKEY_FORMAT_RAW = 0,          // x||y (64 bytes secp256k1/babyjubjub) or 32 bytes (ed25519)
    PUBKEY_FORMAT_COMPRESSED = 1,   // 02/03||x (33 bytes secp256k1) or 32 bytes (ed25519)
    PUBKEY_FORMAT_UNCOMPRESSED = 2, // 04||x||y (65 bytes secp256k1) or 32 bytes (ed25519)
    PUBKEY_FORMAT_ADDRESS = 3       // Ethereum address (20 bytes, secp256k1 only)
} pubkey_format_t;

// Hardened derivation flag
#define HARDENED 0x80000000

// Purpose
#define PURPOSE_BIP44 (44 | HARDENED)
#define PURPOSE_VIEWING (420 | HARDENED)
#define PURPOSE_DKG_COMM (421 | HARDENED)

// Coin types
#define COIN_TYPE_RAILGUN (1984 | HARDENED)

// ---------------------------------------------------------------------------
// SLIP-0010 extended seed key for Railgun (BabyJubjub domain)
// Spending (BabyJubjub), viewing (Ed25519), and the isolated DKG transport
// identity (Ed25519) share this SLIP-0010 master seed key but use distinct paths.
// This matches the Railway Wallet / circomlibjs reference implementation:
//   master = HMAC-SHA512(key="babyjubjub seed", data=BIP39_seed)
//   child  = SLIP-0010 hardened derivation
// ---------------------------------------------------------------------------
#define BABYJUBJUB_SEED_KEY "babyjubjub seed"
#define BABYJUBJUB_SEED_KEY_LEN 15

// ---------------------------------------------------------------------------
// SLIP-0010 extended seed key of the Bandersnatch signing key.
// SLIP-0010 names one master key per curve ("ed25519 seed", "Nist256p1 seed",
// "Bitcoin seed"). The Bandersnatch key follows that rule instead of sharing
// the BabyJubjub master: the same 32 bytes are then never a private key on
// both curves, and neither key says anything about the other.
//   master = HMAC-SHA512(key="bandersnatch seed", data=BIP39_seed)
//   child  = SLIP-0010 hardened derivation, same path as PATH_SPENDING
// ---------------------------------------------------------------------------
#define BANDERSNATCH_SEED_KEY "bandersnatch seed"
#define BANDERSNATCH_SEED_KEY_LEN 17

// Standard paths (5 levels)
//
// Account index sits at PATH[2] (hardened) for every type.
// derive_private_key() overwrites PATH[2] with the caller's account
// before invoking the platform derivation.

static const uint32_t PATH_SPENDING[] = {
    PURPOSE_BIP44, COIN_TYPE_RAILGUN, (0 | HARDENED), (0 | HARDENED), (0 | HARDENED)}; // m/44'/1984'/0'/0'/0'  — all hardened (SLIP-0010 requirement)

static const uint32_t PATH_VIEWING[] = {
    PURPOSE_VIEWING, COIN_TYPE_RAILGUN, (0 | HARDENED), (0 | HARDENED), (0 | HARDENED)}; // m/420'/1984'/0'/0'/0'  — all hardened (SLIP-0010 requirement)

/* Dedicated, non-exported Ed25519 identity for DKG share transport.
 * It must not be a child of PATH_VIEWING: VIEWING_PRIVKEY intentionally
 * exports that path's seed to scanning software. A separate hardened purpose
 * makes possession of the viewing seed insufficient to derive this key. */
static const uint32_t PATH_DKG_COMM[] = {
    PURPOSE_DKG_COMM, COIN_TYPE_RAILGUN, (0 | HARDENED), (0 | HARDENED), (0 | HARDENED)}; // m/421'/1984'/0'/0'/0'

#define PATH_LEN 5

// Public key sizes
#define PUBKEY_SECP256K1_RAW_LEN 64
#define PUBKEY_SECP256K1_COMPRESSED_LEN 33
#define PUBKEY_SECP256K1_UNCOMPRESSED_LEN 65
#define PUBKEY_ED25519_LEN 32
#define PUBKEY_BABYJUBJUB_LEN 64 // x || y (32 + 32 bytes)
#define PUBKEY_BANDERSNATCH_LEN 64 // x || y (32 + 32 bytes)
#define ADDRESS_LEN 20

/**
 * Derive private key from seed.
 *
 * For Railgun (SPENDING, VIEWING, DKG_COMM): SLIP-0010 extended with
 * "babyjubjub seed"; every role has a distinct hardened path.
 * For SPENDING_BANDERSNATCH: SLIP-0010 extended with "bandersnatch seed",
 * on the path of SPENDING.
 * @param type       Key type (determines path, curve, and seed key)
 * @param account    Account index (path level 2: m/purpose'/coin'/account'/...)
 * @param out_key    32 bytes output for private key
 * @param out_chain  32 bytes output for chain code (can be NULL)
 * @return           Error code
 */
zkn_error_t derive_private_key(key_type_t type, uint32_t account, uint8_t *out_key, uint8_t *out_chain);

/**
 * Derive Railgun key using SLIP-0010 extended with "babyjubjub seed".
 *
 * Used for spending (BabyJubjub), viewing, and DKG transport (both Ed25519).
 * The derivation mechanics are identical — only the path differs.
 * The 32-byte output is interpreted as:
 *   - Spending: BabyJubjub private key (input to EdDSA prv2pub)
 *   - Viewing: Ed25519 private key (input to Ed25519 pubkey derivation)
 *   - DKG transport: Ed25519 private seed; never exported in production
 *
 * @param path       BIP-44 path (all levels hardened)
 * @param out_key    32 bytes output
 * @param out_chain  32 bytes chain code (can be NULL)
 * @return           Error code
 */
zkn_error_t derive_railgun_key(const uint32_t *path, uint8_t *out_key, uint8_t *out_chain);

/**
 * Derive the Bandersnatch signing key: SLIP-0010 extended with
 * "bandersnatch seed". Same mechanics and same arguments as
 * derive_railgun_key; only the HMAC key of the master differs.
 */
zkn_error_t derive_bandersnatch_key(const uint32_t *path, uint8_t *out_key, uint8_t *out_chain);

/**
 * Key type of the signing key of a twisted-Edwards curve: KEY_TYPE_SPENDING
 * for BabyJubjub, KEY_TYPE_SPENDING_BANDERSNATCH for Bandersnatch.
 *
 * @param curve_id   _BABYJUJUB_ID or _BANDERSNATCH_ID (zkn_tEdwards.h)
 * @param type       receives the key type
 * @return           ZKN_ERR_INVALID_PARAM for any other curve
 */
zkn_error_t spending_key_type(uint32_t curve_id, key_type_t *type);

/**
 * Derive secp256k1 public key from private key bytes
 */
zkn_error_t derive_pubkey_secp256k1(const uint8_t *privkey_bytes,
                                    pubkey_format_t format,
                                    uint8_t *pubkey_out,
                                    size_t *pubkey_len);

/**
 * Derive Ed25519 public key from private key bytes
 */
zkn_error_t derive_pubkey_ed25519(const uint8_t *privkey_bytes,
                                  pubkey_format_t format,
                                  uint8_t *pubkey_out,
                                  size_t *pubkey_len);

/**
 * Derive BabyJubjub public key from private key bytes
 */
zkn_error_t derive_pubkey_babyjubjub(const uint8_t *privkey_bytes,
                                     pubkey_format_t format,
                                     uint8_t *pubkey_out,
                                     size_t *pubkey_len);

/**
 * Derive Bandersnatch public key from private key bytes
 */
zkn_error_t derive_pubkey_bandersnatch(const uint8_t *privkey_bytes,
                                       pubkey_format_t format,
                                       uint8_t *pubkey_out,
                                       size_t *pubkey_len);

/**
 * Derive public key from private key based on key type
 */
zkn_error_t derive_public_key(key_type_t type,
                              pubkey_format_t format,
                              const uint8_t *privkey_bytes,
                              uint8_t *pubkey_out,
                              size_t *pubkey_len);

#endif
