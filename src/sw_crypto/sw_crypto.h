// sw_crypto.h — software primitives backing the SW backend of the comms crypto.
// Bit-exact with the RAILGUN engine and the BOLOS cx_* backend.
// These are internal: callers should use the unified API instead
// (zkn_ed25519_ecdh.h / zkn_aes_gcm.h), which dispatches on the backend macro.
#ifndef ZKN_SW_CRYPTO_H
#define ZKN_SW_CRYPTO_H
#include <stdint.h>
#include <stddef.h>
void zkn_sw_sha256(const uint8_t *msg, size_t len, uint8_t out[32]);
void zkn_sw_sha512(const uint8_t *msg, size_t len, uint8_t out[64]);
void zkn_sw_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t *iv, size_t ivlen,
                               const uint8_t *pt, size_t ptlen, uint8_t *ct, uint8_t tag[16]);
// scalar is 32-byte LITTLE-endian here (the public API takes big-endian and reverses).
int zkn_sw_ed25519_scalarmul(const uint8_t scalar_le[32], const uint8_t VK[32], uint8_t out[32]);
int zkn_sw_ed25519_ecdh_kdf(const uint8_t scalar_le[32], const uint8_t VK[32], uint8_t out[32]);
#endif
