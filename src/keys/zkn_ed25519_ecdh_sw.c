/* zkn_ed25519_ecdh_sw.c — software backend for the Ed25519 ECDH-KDF.
 *
 * Same API as the Ledger (cx_*) implementation in zkn_ed25519_ecdh.c; selected
 * when ZKN_BN_BACKEND_SW is defined. Bit-exact with the RAILGUN engine's
 * `getSharedSymmetricKey`: AES_KEY = SHA-256(compressed [scalar]·VK).
 *
 * Endianness note: the public API takes `scalar_be32` (BIG-endian, already
 * reduced mod L), matching the cx_* backend. The software core works on a
 * little-endian scalar, so we reverse at this boundary — exactly once, here.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(ZKN_BN_BACKEND_SW)

#include "zkn_ed25519_ecdh.h"

/* software primitives (src/sw_crypto/) */
int zkn_sw_ed25519_scalarmul(const uint8_t scalar_le[32], const uint8_t VK[32], uint8_t out[32]);
int zkn_sw_ed25519_ecdh_kdf(const uint8_t scalar_le[32], const uint8_t VK[32], uint8_t out[32]);

static void be32_to_le32(const uint8_t *be, uint8_t le[32])
{
    for (int i = 0; i < 32; i++) le[i] = be[31 - i];
}

int zkn_ed25519_scalarmul_compressed(const uint8_t *scalar_be32,
                                     const uint8_t *compressed_in,
                                     uint8_t *compressed_out)
{
    if (!scalar_be32 || !compressed_in || !compressed_out) return -1;
    uint8_t scalar_le[32];
    be32_to_le32(scalar_be32, scalar_le);
    int rc = zkn_sw_ed25519_scalarmul(scalar_le, compressed_in, compressed_out);
    memset(scalar_le, 0, sizeof(scalar_le));
    return rc;
}

int zkn_ed25519_ecdh_kdf(const uint8_t *scalar_be32,
                         const uint8_t *VK_compressed,
                         uint8_t *aes_key_out)
{
    if (!scalar_be32 || !VK_compressed || !aes_key_out) return -1;
    uint8_t scalar_le[32];
    be32_to_le32(scalar_be32, scalar_le);
    int rc = zkn_sw_ed25519_ecdh_kdf(scalar_le, VK_compressed, aes_key_out);
    memset(scalar_le, 0, sizeof(scalar_le));
    return rc;
}

#endif /* ZKN_BN_BACKEND_SW */
