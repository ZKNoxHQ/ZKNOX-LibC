
#ifndef _TWEDWARDS_H
#define _TWEDWARDS_H

#include "zkn_bn.h"
#include "zkn_hash_compat.h"

#define _BANDERSNATCH_ID 1
#define _BANDSNATCH_S8 32

#define _BABYJUJUB_ID 2
#define _BABYJUJUB_S8 32

#define ECC_MAXSIZE8 64

// tEdwards curve defined by {a}*x^2 + y^2 = 1 + {d} * x^2*y^2"
typedef struct
{
  zkn_bn_t x; // montgomery representation of x
  zkn_bn_t y; // montgomery representation of y
  zkn_bn_t z; // montgomery representation of z

} zkn_edpoint_t;

// tEdwards curve defined by {a}*x^2 + y^2 = 1 + {d} * x^2*y^2"
typedef struct
{
  size_t curveID;
  size_t fieldsize8;
  zkn_bn_t modulus; // could be spared cause copied in ctx.n
  zkn_bn_t order;

  zkn_edpoint_t G; // curve generating point

  zkn_bn_t cA; // montgomery representation of a
  zkn_bn_t cD; // montgomery representation of d
  zkn_bn_mont_ctx_t ctx;
  zkn_bn_t mont_One; // representation of one in montgomery, could be precomputed and hardcoded

  // work temporary variables
  zkn_bn_t a;
  zkn_bn_t b;
  zkn_bn_t c;
  zkn_bn_t d;
  zkn_bn_t e;
  zkn_bn_t f;
  zkn_bn_t g;
  zkn_bn_t h;
  zkn_bn_t j;

  int debug;
  int debug2;

} zkn_edcurve_t;

/************************************allocations */
// curve
int tEdwards_Curve_alloc_init(zkn_edcurve_t *curve, uint32_t CURVEID);

int tEdwards_Curve_partial_destroy(zkn_edcurve_t *curve); // desallocate work temporary variables
int tEdwards_Curve_destroy(zkn_edcurve_t *curve);

// points
int tEdwards_alloc(zkn_edcurve_t *curve, zkn_edpoint_t *G);
int tEdwards_alloc_init(zkn_edcurve_t *curve, uint8_t *i_x, uint8_t *i_y, zkn_edpoint_t *o_R);
int tEdwards_alloc_init_mont(zkn_edcurve_t *curve, const uint8_t *mx, const uint8_t *my, zkn_edpoint_t *o_R);
int tEdwards_destroy(zkn_edcurve_t *curve, zkn_edpoint_t *G);

/************************************I/O */

int tEdwards_copy(zkn_edpoint_t *i_P, zkn_edpoint_t *R);
// set point from triple in normal domain to montgomery projective
int tEdwards_init(zkn_edcurve_t *curve, uint8_t *i_x, uint8_t *i_y, zkn_edpoint_t *o_R);

int tEdwards_export(zkn_edcurve_t *curve, zkn_edpoint_t *i_R, uint8_t *x, uint8_t *y);

int tEdwards_packPoint(zkn_edcurve_t *curve, zkn_edpoint_t *G, uint8_t *out, size_t len);
/************************************computations */

int tEdwards_SetNeutral(zkn_edcurve_t *curve, zkn_edpoint_t *G);
int tEdwards_double(zkn_edcurve_t *curve, zkn_edpoint_t *self, zkn_edpoint_t *R);
int tEdwards_add(zkn_edcurve_t *curve, zkn_edpoint_t *Ed_P, zkn_edpoint_t *Ed_Q, zkn_edpoint_t *R);
int tEdwards_add_affine(zkn_edcurve_t *curve, zkn_edpoint_t *Ed_P, zkn_edpoint_t *Ed_Q, zkn_edpoint_t *R);
int tEdwards_IsOnCurve(zkn_edcurve_t *curve, zkn_edpoint_t *P, bool *flag);

// randomizing projective representation of the point
int tEdwards_Coronize(zkn_edcurve_t *curve, zkn_edpoint_t *G);
// normalizing the representative to z=1
int tEdwards_normalize(zkn_edcurve_t *curve, zkn_edpoint_t *i_R);

// naive double n add, THIS IS not constant TIME : todo: replace with 4MSM
int tEdwards_scalarMul_bn(zkn_edcurve_t *curve, zkn_edpoint_t *G, zkn_bn_t *k, zkn_edpoint_t *R);
int tEdwards_scalarMul(zkn_edcurve_t *curve, zkn_edpoint_t *G, const uint8_t *k, size_t len, zkn_edpoint_t *R);

// msm
int tEdwards_2MSM_precomp_table(zkn_edcurve_t *curve, const uint8_t (*T_mx)[32], const uint8_t (*T_my)[32], const uint8_t *k1, size_t len1, const uint8_t *k2, size_t len2, zkn_edpoint_t *R);
int tEdwards_4MSM_precomp_table(zkn_edcurve_t *curve, const uint8_t (*T_mx)[32], const uint8_t (*T_my)[32], const uint8_t *k1, size_t len1, const uint8_t *k2, size_t len2, const uint8_t *k3, size_t len3, const uint8_t *k4, size_t len4, zkn_edpoint_t *R);
int tEdwards_fixedBase_2MSM(zkn_edcurve_t *curve, const uint8_t *k, zkn_edpoint_t *R);
int tEdwards_fixedBase_4MSM(zkn_edcurve_t *curve, const uint8_t *k, zkn_edpoint_t *R);

#endif
