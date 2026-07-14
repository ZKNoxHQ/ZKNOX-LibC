/* vss_cli.c — expose the C VSS/DKG API (zkn_vss.h) over argv.
 *
 *   coeffs         <id> <threshold> <seed:32B> <password:32B>
 *                  -> "<a0:32B><a1:32B>..."            makeDealerCoeffsDeterministic
 *   commit         <threshold> <coeffs:threshold*32B>
 *                  -> "<C0:64B><C1:64B>..."            makeDealerCommitments
 *   share          <threshold> <id> <coeffs:threshold*32B>
 *                  -> "<s:32B>"                        computeDealerShareForId
 *   verify_feldman <threshold> <id> <share:32B> <commitments:threshold*64B>
 *                  -> "1" | "0"                        verifyFeldmanShare
 *   reconstruct    <num> <id1> <s1:32B> <id2> <s2:32B> ...
 *                  -> "<a0:32B>"                       reconstructConstantFromShares
 *
 * Requires ZKNOX_DEBUG (commit/verify_feldman use scalar mult) + ZKN_HOST_TESTS.
 */
#if defined(ZKN_HOST_TESTS) && defined(ZKNOX_DEBUG)

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "zkn_bn.h"
#include "zkn_tEdwards.h"
#include "zkn_vss.h"
#include "zkn_ed25519_ecdh.h"
#include "zkn_aes_gcm.h"

static int unhex(const char *s, uint8_t *out, size_t n)
{
  if (strlen(s) != 2 * n) return -1;
  for (size_t i = 0; i < n; i++)
    if (sscanf(s + 2 * i, "%2hhx", &out[i]) != 1) return -1;
  return 0;
}
static void phex(const uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", b[i]); }

static int cmd_coeffs(int argc, char **argv)
{
  if (argc != 4) return 2;
  participant_t p;
  p.id = (size_t)strtoul(argv[0], NULL, 10);
  size_t t = (size_t)strtoul(argv[1], NULL, 10);
  if (unhex(argv[2], p.seed, 32) || unhex(argv[3], p.password, 32)) return 2;
  zkn_edcurve_t curve;
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  uint8_t coeffs[VSS_MAX_PARTICIPANTS * 32];
  if (makeDealerCoeffsDeterministic(&curve, &p, t, 0, coeffs) != 0) return 1;
  phex(coeffs, t * 32); printf("\n");
  return 0;
}

static int cmd_commit(int argc, char **argv)
{
  if (argc != 2) return 2;
  size_t t = (size_t)strtoul(argv[0], NULL, 10);
  uint8_t coeffs[VSS_MAX_PARTICIPANTS * 32], comm[VSS_MAX_PARTICIPANTS * 64];
  if (unhex(argv[1], coeffs, t * 32)) return 2;
  zkn_edcurve_t curve;
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  if (makeDealerCommitments(&curve, coeffs, t, comm) != 0) return 1;
  phex(comm, t * 64); printf("\n");
  return 0;
}

static int cmd_share(int argc, char **argv)
{
  if (argc != 3) return 2;
  size_t t = (size_t)strtoul(argv[0], NULL, 10);
  size_t id = (size_t)strtoul(argv[1], NULL, 10);
  uint8_t coeffs[VSS_MAX_PARTICIPANTS * 32], s[32];
  if (unhex(argv[2], coeffs, t * 32)) return 2;
  zkn_edcurve_t curve;
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  if (computeDealerShareForId(&curve, coeffs, t, id, s) != 0) return 1;
  phex(s, 32); printf("\n");
  return 0;
}

static int cmd_verify_feldman(int argc, char **argv)
{
  if (argc != 4) return 2;
  size_t t = (size_t)strtoul(argv[0], NULL, 10);
  size_t id = (size_t)strtoul(argv[1], NULL, 10);
  uint8_t share[32], comm[VSS_MAX_PARTICIPANTS * 64];
  if (unhex(argv[2], share, 32) || unhex(argv[3], comm, t * 64)) return 2;
  zkn_edcurve_t curve;
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  bool valid = false;
  if (verifyFeldmanShare(&curve, id, share, comm, t, &valid) != 0) return 1;
  printf("%d\n", valid ? 1 : 0);
  return 0;
}

/* dealer <id> <seed:32B> <password:32B> <threshold> <ids_csv>
 * Models a dealer's device round 1: derives coeffs INTERNALLY (never printed),
 * outputs public commitments + one private share per recipient.
 *   -> "<commitments:threshold*64B> <share_id1:32B> <share_id2:32B> ..."      */
static int cmd_dealer(int argc, char **argv)
{
  if (argc != 5) return 2;
  participant_t p;
  p.id = (size_t)strtoul(argv[0], NULL, 10);
  if (unhex(argv[1], p.seed, 32) || unhex(argv[2], p.password, 32)) return 2;
  size_t t = (size_t)strtoul(argv[3], NULL, 10);
  size_t rids[VSS_MAX_PARTICIPANTS], nr = 0;
  for (char *tok = strtok(argv[4], ","); tok && nr < VSS_MAX_PARTICIPANTS; tok = strtok(NULL, ","))
    rids[nr++] = (size_t)strtoul(tok, NULL, 10);
  zkn_edcurve_t curve;
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  uint8_t coeffs[VSS_MAX_PARTICIPANTS * 32], comm[VSS_MAX_PARTICIPANTS * 64], s[32];
  if (makeDealerCoeffsDeterministic(&curve, &p, t, 0, coeffs) != 0) return 1;
  if (makeDealerCommitments(&curve, coeffs, t, comm) != 0) return 1;      /* public */
  phex(comm, t * 64);
  for (size_t r = 0; r < nr; r++) {
    if (computeDealerShareForId(&curve, coeffs, t, rids[r], s) != 0) return 1; /* private */
    printf(" "); phex(s, 32);
  }
  printf("\n");
  explicit_bzero(coeffs, sizeof(coeffs));                                 /* coeffs never leave */
  return 0;
}

/* finalize <n> <s1:32B> <s2:32B> ...  ->  "<skShareDiv8:32B>" (Σ received shares) */
static int cmd_finalize(int argc, char **argv)
{
  if (argc < 1) return 2;
  size_t n = (size_t)strtoul(argv[0], NULL, 10);
  if ((size_t)argc != 1 + n) return 2;
  zkn_edcurve_t curve;
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  zkn_bn_t acc, si;
  uint8_t sb[32], out[32];
  zkn_bn_alloc(&acc, 32); zkn_bn_set_u32(acc, 0); zkn_bn_alloc(&si, 32);
  for (size_t k = 0; k < n; k++) {
    if (unhex(argv[1 + k], sb, 32)) return 2;
    zkn_bn_init(si, sb, 32);
    zkn_bn_mod_add(acc, acc, si, curve.order);
  }
  zkn_bn_export(acc, out, 32);
  phex(out, 32); printf("\n");
  return 0;
}


/* ecdh <scalar_be32> <peer_pub32>  ->  shared AES key (32B)  [zkn_ed25519_ecdh_kdf] */
static int cmd_ecdh(int argc, char **argv)
{
  if (argc != 2) return 2;
  uint8_t sc[32], pub[32], key[32];
  if (unhex(argv[0], sc, 32) || unhex(argv[1], pub, 32)) return 2;
  if (zkn_ed25519_ecdh_kdf(sc, pub, key) != 0) return 1;
  phex(key, 32); printf("\n");
  return 0;
}

/* encrypt_share <key32> <nonce12> <aad_hex> <share_le32> -> ciphertext32||tag16 */
static int cmd_encrypt_share(int argc, char **argv)
{
  if (argc != 4) return 2;
  uint8_t key[32], nonce[12], aad[128], pt[32], ct[32], tag[16];
  size_t aadlen = strlen(argv[2]) / 2;
  if (aadlen > sizeof(aad)) return 2;
  if (unhex(argv[0], key, 32) || unhex(argv[1], nonce, 12) ||
      unhex(argv[2], aad, aadlen) || unhex(argv[3], pt, 32)) return 2;
  if (zkn_aes256_gcm_encrypt_aad(key, nonce, 12, aad, aadlen, pt, 32, ct, tag) != 0) return 1;
  phex(ct, 32); phex(tag, 16); printf("\n");
  return 0;
}

/* decrypt_share <key32> <nonce12> <aad_hex> <ct32||tag16> -> share_le32 | "AUTH_FAIL" */
static int cmd_decrypt_share(int argc, char **argv)
{
  if (argc != 4) return 2;
  uint8_t key[32], nonce[12], aad[128], blob[48], pt[32];
  size_t aadlen = strlen(argv[2]) / 2;
  if (aadlen > sizeof(aad)) return 2;
  if (unhex(argv[0], key, 32) || unhex(argv[1], nonce, 12) ||
      unhex(argv[2], aad, aadlen) || unhex(argv[3], blob, 48)) return 2;
  if (zkn_aes256_gcm_decrypt_aad(key, nonce, 12, aad, aadlen, blob, 32, blob + 32, pt) != 0) {
    printf("AUTH_FAIL\n"); return 0;
  }
  phex(pt, 32); printf("\n");
  return 0;
}

static int cmd_reconstruct(int argc, char **argv)
{
  if (argc < 1) return 2;
  size_t num = (size_t)strtoul(argv[0], NULL, 10);
  if ((size_t)argc != 1 + 2 * num || num > VSS_MAX_PARTICIPANTS) return 2;
  vss_share_t shares[VSS_MAX_PARTICIPANTS];
  for (size_t k = 0; k < num; k++)
  {
    shares[k].id = (size_t)strtoul(argv[1 + 2 * k], NULL, 10);
    if (unhex(argv[2 + 2 * k], shares[k].sk_share_div8, 32)) return 2;
    memset(shares[k].sk_share, 0, 32);
  }
  zkn_edcurve_t curve;
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  uint8_t a0[32];
  if (reconstructConstantFromShares(&curve, shares, num, a0) != 0) return 1;
  phex(a0, 32); printf("\n");
  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 2) { fprintf(stderr, "usage: vss_cli <coeffs|commit|share|verify_feldman|reconstruct> ...\n"); return 2; }
  const char *cmd = argv[1];
  int n = argc - 2; char **a = argv + 2;
  if (!strcmp(cmd, "coeffs"))         return cmd_coeffs(n, a);
  if (!strcmp(cmd, "commit"))         return cmd_commit(n, a);
  if (!strcmp(cmd, "share"))          return cmd_share(n, a);
  if (!strcmp(cmd, "verify_feldman")) return cmd_verify_feldman(n, a);
  if (!strcmp(cmd, "dealer"))         return cmd_dealer(n, a);
  if (!strcmp(cmd, "finalize"))       return cmd_finalize(n, a);
  if (!strcmp(cmd, "ecdh"))           return cmd_ecdh(n, a);
  if (!strcmp(cmd, "encrypt_share"))  return cmd_encrypt_share(n, a);
  if (!strcmp(cmd, "decrypt_share"))  return cmd_decrypt_share(n, a);
  if (!strcmp(cmd, "reconstruct"))    return cmd_reconstruct(n, a);
  fprintf(stderr, "unknown command: %s\n", cmd);
  return 2;
}

#else
int main(void) { return 0; }
#endif
