#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "zkn_errors.h"
#include "zkn_bn.h"
#include "zkn_tEdwards.h"

static int g_pass = 0, g_fail = 0;
static void chk(const char *n, int c){ printf(c?"[PASS] %s\n":"[FAIL] %s\n", n); c?g_pass++:g_fail++; }

/* k*G computed both ways must agree, byte for byte. */
static int same(zkn_edcurve_t *c, const uint8_t k[32])
{
  zkn_edpoint_t A, B;
  uint8_t ax[32], ay[32], bx[32], by[32];
  if (tEdwards_alloc(c,&A) || tEdwards_alloc(c,&B)) return -1;
  if (tEdwards_scalarMul(c, &c->G, (uint8_t*)k, 32, &A)) return -1;
  if (tEdwards_normalize(c,&A) || tEdwards_export(c,&A,ax,ay)) return -1;
  if (tEdwards_fixedBase_4MSM(c, k, &B)) return -1;
  if (tEdwards_normalize(c,&B) || tEdwards_export(c,&B,bx,by)) return -1;
  return (memcmp(ax,bx,32)==0 && memcmp(ay,by,32)==0);
}

int main(void)
{
  zkn_edcurve_t c;
  if (tEdwards_Curve_alloc_init(&c,_BABYJUJUB_ID)) { printf("curve init failed\n"); return 1; }

  uint8_t k[32];

  memset(k,0,32); k[31]=1;
  chk("k = 1", same(&c,k) == 1);

  memset(k,0,32); k[31]=2;
  chk("k = 2", same(&c,k) == 1);

  memset(k,0,32); k[30]=0x30; k[31]=0x39;          /* 12345 */
  chk("k = 12345", same(&c,k) == 1);

  memset(k,0,32); k[23]=1;                          /* 2^64 — limb boundary */
  chk("k = 2^64  (limb boundary)", same(&c,k) == 1);

  memset(k,0,32); k[15]=1;                          /* 2^128 */
  chk("k = 2^128 (limb boundary)", same(&c,k) == 1);

  memset(k,0,32); k[7]=1;                           /* 2^192 */
  chk("k = 2^192 (limb boundary)", same(&c,k) == 1);

  /* a full-width scalar below the subgroup order */
  const uint8_t big[32] = {
    0x02,0xd3,0x9c,0x1e,0x7b,0x44,0x08,0xf1, 0x55,0xa2,0x0c,0x67,0x39,0xbe,0x11,0x5c,
    0x8a,0x03,0xd7,0x42,0x6f,0x90,0x18,0xcb, 0x24,0xe5,0x7a,0x36,0x91,0x4d,0x08,0x77 };
  memcpy(k,big,32);
  chk("k = full-width scalar", same(&c,k) == 1);

  /* pseudo-random sweep */
  int ok = 1;
  uint32_t s = 0x12345678u;
  for (int i = 0; i < 64 && ok; i++) {
    for (int j = 0; j < 32; j++) { s = s*1103515245u + 12345u; k[j] = (uint8_t)(s >> 16); }
    k[0] &= 0x03;                                   /* keep it below the order */
    if (same(&c,k) != 1) ok = 0;
  }
  chk("64 pseudo-random scalars", ok);

  printf("\n== Results: %d/%d passed ==\n", g_pass, g_pass+g_fail);
  return g_fail ? 1 : 0;
}
