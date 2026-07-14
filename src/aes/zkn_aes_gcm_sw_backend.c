/* zkn_aes_gcm_sw_backend.c — software backend for AES-256-GCM.
 * Same API as the BOLOS cx_aes_gcm_* implementation in zkn_aes_gcm.c; selected
 * when ZKN_BN_BACKEND_SW is defined. 16-byte IV, no AAD — matching the RAILGUN
 * engine (createCipheriv('aes-256-gcm', key32, iv16)) and the Ledger backend. */
#include <stdint.h>
#include <stddef.h>

#if defined(ZKN_BN_BACKEND_SW)

#include "zkn_aes_gcm.h"

void zkn_sw_aes256_gcm_encrypt(const uint8_t key[32], const uint8_t *iv, size_t ivlen,
                               const uint8_t *pt, size_t ptlen, uint8_t *ct, uint8_t tag[16]);

int zkn_aes256_gcm_encrypt(const uint8_t *key32,
                           const uint8_t *iv16,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext,
                           uint8_t *tag16)
{
    if (!key32 || !iv16 || !tag16) return -1;
    if (plaintext_len && (!plaintext || !ciphertext)) return -1;
    zkn_sw_aes256_gcm_encrypt(key32, iv16, 16, plaintext, plaintext_len, ciphertext, tag16);
    return 0;
}


void zkn_sw_aes256_gcm_encrypt_aad(const uint8_t key[32], const uint8_t *iv, size_t ivlen,
                                   const uint8_t *aad, size_t aadlen,
                                   const uint8_t *pt, size_t ptlen, uint8_t *ct, uint8_t tag[16]);
int zkn_sw_aes256_gcm_decrypt_aad(const uint8_t key[32], const uint8_t *iv, size_t ivlen,
                                  const uint8_t *aad, size_t aadlen,
                                  const uint8_t *ct, size_t ctlen, const uint8_t tag[16],
                                  uint8_t *pt);

int zkn_aes256_gcm_encrypt_aad(const uint8_t *key32, const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *plaintext, size_t plaintext_len,
                               uint8_t *ciphertext, uint8_t *tag16)
{
    if (!key32 || !nonce || !tag16) return -1;
    zkn_sw_aes256_gcm_encrypt_aad(key32, nonce, nonce_len, aad, aad_len,
                                  plaintext, plaintext_len, ciphertext, tag16);
    return 0;
}

int zkn_aes256_gcm_decrypt_aad(const uint8_t *key32, const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               const uint8_t *tag16, uint8_t *plaintext)
{
    if (!key32 || !nonce || !tag16) return -1;
    return zkn_sw_aes256_gcm_decrypt_aad(key32, nonce, nonce_len, aad, aad_len,
                                         ciphertext, ciphertext_len, tag16, plaintext);
}

#endif /* ZKN_BN_BACKEND_SW */
