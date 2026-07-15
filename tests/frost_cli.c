/* frost_cli.c — thin 1:1 exposure of the frost.h API over argv, so a test
 * driver (e.g. mixed_signers.mjs) can orchestrate a multi-signer session by
 * calling the real library functions. No protocol logic lives here: each
 * subcommand parses hex args, calls one frost.h function, prints hex.
 *
 * All scalars/coords are 32-byte big-endian hex; groupkey and R8 are 64-byte
 * x||y; a commitment-list entry is 160 bytes id|hx|hy|bx|by; message is
 * little-endian (library convention).
 *
 *   commit       <sk>
 *                -> "<nonces:64B> <hiding:64B x||y> <binding:64B x||y>"
 *   partial_sign <identifier> <sk> <gk:64B> <hnonce:32B> <bnonce:32B>
 *                <clist> <len> <msg_le:32B> <lambda:32B>
 *                -> "<z:32B>"
 *   aggregate    <gk:64B> <clist> <len> <msg_le:32B> <shares:len*32B>
 *                -> "<R8:64B> <S:32B>"
 *   verify       <gk:64B> <R8:64B> <S:32B> <msg_le:32B>
 *                -> "1" | "0"
 *
 * Requires ZKNOX_DEBUG + ZKN_HOST_TESTS.
 */
#if defined(ZKN_HOST_TESTS) && defined(ZKNOX_DEBUG)

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "zkn_bn.h"
#include "zkn_tEdwards.h"
#include "zkn_frost.h"

static int unhex(const char *s, uint8_t *out, size_t n)
{
  if (strlen(s) != 2 * n) return -1;
  for (size_t i = 0; i < n; i++)
    if (sscanf(s + 2 * i, "%2hhx", &out[i]) != 1) return -1;
  return 0;
}
static void phex(const uint8_t *b, size_t n)
{
  for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static int cmd_commit(int argc, char **argv)
{
  uint8_t sk[32], nonces[64];
  if (argc != 1 || unhex(argv[0], sk, 32)) return 2;
  zkn_edcurve_t curve;
  zkn_edpoint_t comms[2];
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  tEdwards_alloc(&curve, &comms[0]);
  tEdwards_alloc(&curve, &comms[1]);
  if (zkn_frost_commit(&curve, sk, nonces, comms) != 0) return 1;
  uint8_t hx[32], hy[32], bx[32], by[32];
  tEdwards_export(&curve, &comms[0], hx, hy);
  tEdwards_export(&curve, &comms[1], bx, by);
  phex(nonces, 64); printf(" ");
  phex(hx, 32); phex(hy, 32); printf(" ");
  phex(bx, 32); phex(by, 32); printf("\n");
  return 0;
}

static int cmd_partial_sign(int argc, char **argv)
{
  /* identifier sk gk hnonce bnonce clist len msg_le lambda */
  if (argc != 9) return 2;
  size_t identifier = (size_t)strtoul(argv[0], NULL, 10);
  size_t len = (size_t)strtoul(argv[6], NULL, 10);
  uint8_t sk[32], gk[64], hn[32], bn[32], msg[32], lam[32];
  uint8_t clist[ZKN_FROST_MAX_SIGNERS * 160];
  if (unhex(argv[1], sk, 32) || unhex(argv[2], gk, 64) || unhex(argv[3], hn, 32) ||
      unhex(argv[4], bn, 32) || unhex(argv[5], clist, len * 160) ||
      unhex(argv[7], msg, 32) || unhex(argv[8], lam, 32)) return 2;
  zkn_edcurve_t curve;
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  uint8_t z[32];
  if (zkn_partial_sig(&curve, identifier, sk, gk, hn, bn, clist, len, msg, 32, lam, z) != 0) return 1;
  phex(z, 32); printf("\n");
  return 0;
}

static int cmd_aggregate(int argc, char **argv)
{
  /* gk clist len msg_le shares */
  if (argc != 5) return 2;
  size_t len = (size_t)strtoul(argv[2], NULL, 10);
  uint8_t gk[64], msg[32];
  uint8_t clist[ZKN_FROST_MAX_SIGNERS * 160], shares[ZKN_FROST_MAX_SIGNERS * 32];
  if (unhex(argv[0], gk, 64) || unhex(argv[1], clist, len * 160) ||
      unhex(argv[3], msg, 32) || unhex(argv[4], shares, len * 32)) return 2;
  zkn_edcurve_t curve;
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  uint8_t R8[64], S[32];
  if (zkn_frost_aggregate(&curve, gk, clist, len, msg, 32, shares, R8, S) != 0) return 1;
  phex(R8, 64); printf(" "); phex(S, 32); printf("\n");
  return 0;
}

static int cmd_verify(int argc, char **argv)
{
  /* gk R8 S msg_le */
  if (argc != 4) return 2;
  uint8_t gk[64], R8[64], S[32], msg[32];
  if (unhex(argv[0], gk, 64) || unhex(argv[1], R8, 64) || unhex(argv[2], S, 32) || unhex(argv[3], msg, 32))
    return 2;
  zkn_edcurve_t curve;
  tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);
  int valid = 0;
  if (zkn_frost_verify(&curve, R8, S, gk, msg, 32, &valid) != 0) return 1;
  printf("%d\n", valid ? 1 : 0);
  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 2) { fprintf(stderr, "usage: frost_cli <commit|partial_sign|aggregate|verify> ...\n"); return 2; }
  const char *cmd = argv[1];
  int n = argc - 2;
  char **a = argv + 2;
  if (!strcmp(cmd, "commit"))       return cmd_commit(n, a);
  if (!strcmp(cmd, "partial_sign")) return cmd_partial_sign(n, a);
  if (!strcmp(cmd, "aggregate"))    return cmd_aggregate(n, a);
  if (!strcmp(cmd, "verify"))       return cmd_verify(n, a);
  fprintf(stderr, "unknown command: %s\n", cmd);
  return 2;
}

#endif
