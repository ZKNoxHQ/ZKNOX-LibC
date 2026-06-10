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
    KEY_TYPE_7702 = 1,     // secp256k1 — EIP-7702 delegation slot (m/7702'/1984'/account'/0/0)
    KEY_TYPE_SPENDING = 3, // BabyJubjub
    KEY_TYPE_VIEWING = 4   // Ed25519
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

// Coin types
#define COIN_TYPE_RAILGUN (1984 | HARDENED)

// Purpose for the EIP-7702 delegation slot. 7702 is not a registered
// BIP-44 purpose — it's a project-local convention chosen to isolate
// this key from any standard Ethereum (m/44'/60') key the user might
// hold elsewhere. Critical: an EIP-7702 delegation acts on the full
// EOA, so its signing key must never collide with a key signed by
// MetaMask, Ledger Live, Rabby, etc.
#define PURPOSE_7702 (7702 | HARDENED)

// ---------------------------------------------------------------------------
// SLIP-0010 extended seed key for Railgun (BabyJubjub domain)
// Both spending (BabyJubjub) and viewing (Ed25519) keys share this seed key.
// This matches the Railway Wallet / circomlibjs reference implementation:
//   master = HMAC-SHA512(key="babyjubjub seed", data=BIP39_seed)
//   child  = SLIP-0010 hardened derivation
// ---------------------------------------------------------------------------
#define BABYJUBJUB_SEED_KEY "babyjubjub seed"
#define BABYJUBJUB_SEED_KEY_LEN 15

// Standard paths (5 levels)
//
// Account index sits at PATH[2] (hardened) for every type.
// derive_private_key() overwrites PATH[2] with the caller's account
// before invoking the platform derivation.

static const uint32_t PATH_7702[] = {
    PURPOSE_7702, COIN_TYPE_RAILGUN, HARDENED, 0, 0}; // m/7702'/1984'/0'/0/0  (PATH[2] is overwritten with account')

static const uint32_t PATH_SPENDING[] = {
    PURPOSE_BIP44, COIN_TYPE_RAILGUN, (0 | HARDENED), (0 | HARDENED), (0 | HARDENED)}; // m/44'/1984'/0'/0'/0'  — all hardened (SLIP-0010 requirement)

static const uint32_t PATH_VIEWING[] = {
    PURPOSE_VIEWING, COIN_TYPE_RAILGUN, (0 | HARDENED), (0 | HARDENED), (0 | HARDENED)}; // m/420'/1984'/0'/0'/0'  — all hardened (SLIP-0010 requirement)

#define PATH_LEN 5

// Public key sizes
#define PUBKEY_SECP256K1_RAW_LEN 64
#define PUBKEY_SECP256K1_COMPRESSED_LEN 33
#define PUBKEY_SECP256K1_UNCOMPRESSED_LEN 65
#define PUBKEY_ED25519_LEN 32
#define PUBKEY_BABYJUBJUB_LEN 64 // x || y (32 + 32 bytes)
#define ADDRESS_LEN 20

/**
 * Derive private key from seed.
 *
 * For secp256k1 (KEY_TYPE_7702): standard BIP32 on m/7702'/1984'/account'/0/0.
 * For Railgun (SPENDING, VIEWING): SLIP-0010 extended with "babyjubjub seed".
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
 * Used for both spending (BabyJubjub) and viewing (Ed25519) keys.
 * The derivation mechanics are identical — only the path differs.
 * The 32-byte output is interpreted as:
 *   - Spending: BabyJubjub private key (input to EdDSA prv2pub)
 *   - Viewing: Ed25519 private key (input to Ed25519 pubkey derivation)
 *
 * @param path       BIP-44 path (all levels hardened)
 * @param out_key    32 bytes output
 * @param out_chain  32 bytes chain code (can be NULL)
 * @return           Error code
 */
zkn_error_t derive_railgun_key(const uint32_t *path, uint8_t *out_key, uint8_t *out_chain);

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
 * Derive public key from private key based on key type
 */
zkn_error_t derive_public_key(key_type_t type,
                              pubkey_format_t format,
                              const uint8_t *privkey_bytes,
                              uint8_t *pubkey_out,
                              size_t *pubkey_len);

#endif
