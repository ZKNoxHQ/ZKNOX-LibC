#include <stdint.h>  // uint*_t
#include <stdbool.h> // bool
#include <stddef.h>  // size_t

#include "zkn_bn.h"
#include "zkn_hash_compat.h"
#include "zkn_rng_compat.h"
#include "zkn_errors.h"
#include "zkn_common.h"
#include "zkn_tEdwards.h"
#include "bbjj_precomp.h"
#include "bandersnatch_precomp.h"

int tEdwards_alloc(zkn_edcurve_t *curve, zkn_edpoint_t *G)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_bn_alloc(&G->x, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&G->y, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&G->z, curve->fieldsize8));

  ZKN_ERROR_CLOSE();
}

int tEdwards_destroy(zkn_edcurve_t *curve, zkn_edpoint_t *G)
{
  ZKN_ERROR_INIT();
  ZKN_UNUSED(curve);

  ZKN_CHECK(zkn_bn_destroy(&G->x));
  ZKN_CHECK(zkn_bn_destroy(&G->y));
  ZKN_CHECK(zkn_bn_destroy(&G->z));

  ZKN_ERROR_CLOSE();
}

// https://eprint.iacr.org/2008/013.pdf page 12.
// double can be done in place
int tEdwards_double(zkn_edcurve_t *curve, zkn_edpoint_t *self, zkn_edpoint_t *R)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_bn_mod_add(curve->c, self->x, self->y, curve->modulus));   // x+y
  ZKN_CHECK(zkn_mont_mul(curve->b, curve->c, curve->c, &curve->ctx));      //(x+y)^2
  ZKN_CHECK(zkn_mont_mul(curve->c, self->x, self->x, &curve->ctx));        //(x)^2
  ZKN_CHECK(zkn_mont_mul(curve->d, self->y, self->y, &curve->ctx));        //(y)^2
  ZKN_CHECK(zkn_mont_mul(curve->e, curve->cA, curve->c, &curve->ctx));     // cA*x^2
  ZKN_CHECK(zkn_bn_mod_add(curve->f, curve->e, curve->d, curve->modulus)); // e+d
  ZKN_CHECK(zkn_mont_mul(curve->h, self->z, self->z, &curve->ctx));        //(z)^2

  ZKN_CHECK(zkn_bn_mod_sub(curve->a, curve->f, curve->h, curve->modulus)); // f-h
  ZKN_CHECK(zkn_bn_mod_sub(curve->j, curve->a, curve->h, curve->modulus)); // f-2h

  ZKN_CHECK(zkn_bn_mod_sub(curve->a, curve->b, curve->c, curve->modulus)); // b-c
  ZKN_CHECK(zkn_bn_mod_sub(curve->b, curve->a, curve->d, curve->modulus)); // b-c-d
  ZKN_CHECK(zkn_mont_mul(R->x, curve->j, curve->b, &curve->ctx));          //(b-c-d)*j

  ZKN_CHECK(zkn_bn_mod_sub(curve->c, curve->e, curve->d, curve->modulus)); // e-d
  ZKN_CHECK(zkn_mont_mul(R->y, curve->f, curve->c, &curve->ctx));          //(e-d)*f
  ZKN_CHECK(zkn_mont_mul(R->z, curve->f, curve->j, &curve->ctx));          // j*f

  ZKN_ERROR_CLOSE();
}

// https://eprint.iacr.org/2008/013.pdf page 12.
// add in R
int tEdwards_add(zkn_edcurve_t *curve, zkn_edpoint_t *Ed_P, zkn_edpoint_t *Ed_Q, zkn_edpoint_t *R)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_mont_mul(curve->a, Ed_P->z, Ed_Q->z, &curve->ctx));        //   a = z_p * z_q
  ZKN_CHECK(zkn_mont_mul(curve->b, curve->a, curve->a, &curve->ctx));      //  b = a**2
  ZKN_CHECK(zkn_mont_mul(curve->c, Ed_P->x, Ed_Q->x, &curve->ctx));        // c = x_p * x_q
  ZKN_CHECK(zkn_mont_mul(curve->d, Ed_P->y, Ed_Q->y, &curve->ctx));        // d = y_p * y_q
  ZKN_CHECK(zkn_mont_mul(curve->j, curve->c, curve->d, &curve->ctx));      // e =  c * d
  ZKN_CHECK(zkn_mont_mul(curve->e, curve->j, curve->cD, &curve->ctx));     // e = self.curve.D * c * d
  ZKN_CHECK(zkn_bn_mod_sub(curve->f, curve->b, curve->e, curve->modulus)); // f = b-e
  ZKN_CHECK(zkn_bn_mod_add(curve->g, curve->b, curve->e, curve->modulus)); // g = b+e, b is free

  // x_r = a*f*((x_p+y_p) * (x_q+y_q) - c - d)
  ZKN_CHECK(zkn_bn_mod_add(curve->h, Ed_P->x, Ed_P->y, curve->modulus));   //(x_p+y_p)
  ZKN_CHECK(zkn_bn_mod_add(curve->j, Ed_Q->x, Ed_Q->y, curve->modulus));   //(x_q+y_q)
  ZKN_CHECK(zkn_mont_mul(curve->b, curve->h, curve->j, &curve->ctx));      // (x_p+y_p) * (x_q+y_q)
  ZKN_CHECK(zkn_bn_mod_sub(curve->h, curve->b, curve->c, curve->modulus)); // (x_p+y_p) * (x_q+y_q) -c
  ZKN_CHECK(zkn_bn_mod_sub(curve->j, curve->h, curve->d, curve->modulus)); // (x_p+y_p) * (x_q+y_q) -c-d
  ZKN_CHECK(zkn_mont_mul(curve->b, curve->a, curve->j, &curve->ctx));      // a((x_p+y_p) * (x_q+y_q) -c-d)
  ZKN_CHECK(zkn_mont_mul(R->x, curve->f, curve->b, &curve->ctx));          // a*f((x_p+y_p) * (x_q+y_q) -c-d)
  // y_r = a*g*(d-self.curve.a*c)
  ZKN_CHECK(zkn_mont_mul(curve->b, curve->cA, curve->c, &curve->ctx));     // self.curve.a*c
  ZKN_CHECK(zkn_bn_mod_sub(curve->j, curve->d, curve->b, curve->modulus)); // (d-self.curve.a*c)
  ZKN_CHECK(zkn_mont_mul(curve->b, curve->g, curve->j, &curve->ctx));      // g(d_self.curve.a*c)
  ZKN_CHECK(zkn_mont_mul(R->y, curve->a, curve->b, &curve->ctx));          // a*g*(d-self.curve.a*c)

  // z_r = f*g
  ZKN_CHECK(zkn_mont_mul(R->z, curve->f, curve->g, &curve->ctx)); //  z_r = f*g

  ZKN_ERROR_CLOSE();
}

/**
 * Mixed-coordinate addition: projective P + affine Q (Z_Q = 1, already in Montgomery form).
 * Saves one field multiplication vs full projective add by substituting A = Z_P directly.
 * https://eprint.iacr.org/2008/013.pdf, unified addition with Z2 = 1.
 */
int tEdwards_add_affine(zkn_edcurve_t *curve,
                        zkn_edpoint_t *Ed_P, // projective accumulator
                        zkn_edpoint_t *Ed_Q, // affine table point, Z_Q = mont_One
                        zkn_edpoint_t *R)
{
  ZKN_ERROR_INIT();

  // A = Z_P  (no multiply — Z_Q = 1, so Z_P * Z_Q = Z_P)
  // B = Z_P^2
  ZKN_CHECK(zkn_mont_mul(curve->b, Ed_P->z, Ed_P->z, &curve->ctx)); // b = Z_P^2

  // C = X_P * X_Q,  D = Y_P * Y_Q
  ZKN_CHECK(zkn_mont_mul(curve->c, Ed_P->x, Ed_Q->x, &curve->ctx)); // c = X_P*X_Q
  ZKN_CHECK(zkn_mont_mul(curve->d, Ed_P->y, Ed_Q->y, &curve->ctx)); // d = Y_P*Y_Q

  // E = d_curve * C * D,   F = B - E,   G = B + E
  ZKN_CHECK(zkn_mont_mul(curve->j, curve->c, curve->d, &curve->ctx));      // j = C*D
  ZKN_CHECK(zkn_mont_mul(curve->e, curve->j, curve->cD, &curve->ctx));     // e = d_curve*C*D
  ZKN_CHECK(zkn_bn_mod_sub(curve->f, curve->b, curve->e, curve->modulus)); // f = B-E
  ZKN_CHECK(zkn_bn_mod_add(curve->g, curve->b, curve->e, curve->modulus)); // g = B+E

  // X_R = Z_P * F * ((X_P+Y_P)*(X_Q+Y_Q) - C - D)
  ZKN_CHECK(zkn_bn_mod_add(curve->h, Ed_P->x, Ed_P->y, curve->modulus));   // h = X_P+Y_P
  ZKN_CHECK(zkn_bn_mod_add(curve->j, Ed_Q->x, Ed_Q->y, curve->modulus));   // j = X_Q+Y_Q
  ZKN_CHECK(zkn_mont_mul(curve->b, curve->h, curve->j, &curve->ctx));      // b = (X_P+Y_P)*(X_Q+Y_Q)
  ZKN_CHECK(zkn_bn_mod_sub(curve->h, curve->b, curve->c, curve->modulus)); // h = ... - C
  ZKN_CHECK(zkn_bn_mod_sub(curve->j, curve->h, curve->d, curve->modulus)); // j = ... - D
  ZKN_CHECK(zkn_mont_mul(curve->b, Ed_P->z, curve->j, &curve->ctx));       // b = Z_P * (...)
  ZKN_CHECK(zkn_mont_mul(R->x, curve->f, curve->b, &curve->ctx));          // X_R = F * Z_P*(...)

  // Y_R = Z_P * G * (D - a_curve * C)
  ZKN_CHECK(zkn_mont_mul(curve->b, curve->cA, curve->c, &curve->ctx));     // b = a_curve*C
  ZKN_CHECK(zkn_bn_mod_sub(curve->j, curve->d, curve->b, curve->modulus)); // j = D - a_curve*C
  ZKN_CHECK(zkn_mont_mul(curve->b, curve->g, curve->j, &curve->ctx));      // b = G*(D-a_curve*C)
  ZKN_CHECK(zkn_mont_mul(R->y, Ed_P->z, curve->b, &curve->ctx));           // Y_R = Z_P * G*(...)

  // Z_R = F * G
  ZKN_CHECK(zkn_mont_mul(R->z, curve->f, curve->g, &curve->ctx));

  ZKN_ERROR_CLOSE();
}

// a*x2+y2=1+d*x2*y2, montgomery domain, assumption: point is normalized
int tEdwards_IsOnCurve(zkn_edcurve_t *curve, zkn_edpoint_t *P, bool *flag)
{
  ZKN_ERROR_INIT();
  int cmp = 5;

  ZKN_CHECK(zkn_mont_mul(curve->a, P->x, P->x, &curve->ctx));                     // x^2
  ZKN_CHECK(zkn_mont_mul(curve->b, P->y, P->y, &curve->ctx));                     // y^2
  ZKN_CHECK(zkn_mont_mul(curve->c, curve->a, curve->b, &curve->ctx));             // x^2*y^2
  ZKN_CHECK(zkn_mont_mul(curve->e, curve->cA, curve->a, &curve->ctx));            // a.x^2
  ZKN_CHECK(zkn_bn_mod_add(curve->e, curve->e, curve->b, curve->modulus));        //((a.x^2+y^2))
  ZKN_CHECK(zkn_mont_mul(curve->f, curve->cD, curve->c, &curve->ctx));            // d(x^2*y^2)
  ZKN_CHECK(zkn_bn_mod_add(curve->d, curve->f, curve->mont_One, curve->modulus)); // 1+d(x^2*y^2)

  ZKN_CHECK(zkn_mont_from_montgomery(curve->d, curve->d, &curve->ctx));
  ZKN_CHECK(zkn_mont_from_montgomery(curve->e, curve->e, &curve->ctx));
  ZKN_CHECK(zkn_bn_cmp(curve->d, curve->e, &cmp)); // a.x^2+y^2 == 1+d(x^2*y^2) ?

  *flag = (bool)(cmp == 0);

  ZKN_ERROR_CLOSE();
}

// x2+y2=a2*(1+d*x2*y2)
int tEdwards_Curve_alloc_init(zkn_edcurve_t *curve, uint32_t CURVEID)
{
  ZKN_ERROR_INIT();

  uint8_t *curve_prime;
  uint8_t *curve_A;
  uint8_t *curve_D;
  uint8_t *curve_order;
  uint8_t *B8x;
  uint8_t *B8y;

  switch (CURVEID)
  {

  case _BANDERSNATCH_ID:
    curve->curveID = CURVEID;
    curve->fieldsize8 = _BANDSNATCH_S8;

    static const uint8_t bander_prime[32] = {0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01};

    static const uint8_t bander_A[32] = {0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xfc};
    static const uint8_t bander_D[32] = {0x63, 0x89, 0xc1, 0x26, 0x33, 0xc2, 0x67, 0xcb, 0xc6, 0x6e, 0x3b, 0xf8, 0x6b, 0xe3, 0xb6, 0xd8, 0xcb, 0x66, 0x67, 0x71, 0x77, 0xe5, 0x4f, 0x92, 0xb3, 0x69, 0xf2, 0xf5, 0x18, 0x8d, 0x58, 0xe7};

    static const uint8_t _B8x[32] = {0x29, 0xc1, 0x32, 0xcc, 0x2c, 0x0b, 0x34, 0xc5, 0x74, 0x37, 0x11, 0x77, 0x7b, 0xbe, 0x42, 0xf3, 0x2b, 0x79, 0xc0, 0x22, 0xad, 0x99, 0x84, 0x65, 0xe1, 0xe7, 0x18, 0x66, 0xa2, 0x52, 0xae, 0x18};
    static const uint8_t _B8y[32] = {0x2a, 0x6c, 0x66, 0x9e, 0xda, 0x12, 0x3e, 0x0f, 0x15, 0x7d, 0x8b, 0x50, 0xba, 0xdc, 0xd5, 0x86, 0x35, 0x8c, 0xad, 0x81, 0xee, 0xe4, 0x64, 0x60, 0x5e, 0x31, 0x67, 0xb6, 0xcc, 0x97, 0x41, 0x66};

    static const uint8_t bander_order[32] = {0x1c, 0xfb, 0x69, 0xd4, 0xca, 0x67, 0x5f, 0x52, 0x0c, 0xce, 0x76, 0x02, 0x02, 0x68, 0x76, 0x00, 0xff, 0x8f, 0x87, 0x00, 0x74, 0x19, 0x04, 0x71, 0x74, 0xfd, 0x06, 0xb5, 0x28, 0x76, 0xe7, 0xe1};

    curve_prime = (uint8_t *)bander_prime;
    curve_A = (uint8_t *)bander_A;
    curve_D = (uint8_t *)bander_D;
    curve_order = (uint8_t *)bander_order;
    B8x = (uint8_t *)_B8x;
    B8y = (uint8_t *)_B8y;

    break;

  case _BABYJUJUB_ID:
#define _BABYJUJUB_S8 32
    curve->curveID = CURVEID;
    curve->fieldsize8 = _BABYJUJUB_S8;
    static const uint8_t bbjj_prime[32] = {0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01};

    static const uint8_t bbjj_A[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2, 0x92, 0xfc};
    static const uint8_t bbjj_D[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2, 0x92, 0xf8};

    static const uint8_t bbjj_B8x[32] = {0x0b, 0xb7, 0x7a, 0x6a, 0xd6, 0x3e, 0x73, 0x9b, 0x4e, 0xac, 0xb2, 0xe0, 0x9d, 0x62, 0x77, 0xc1, 0x2a, 0xb8, 0xd8, 0x01, 0x05, 0x34, 0xe0, 0xb6, 0x28, 0x93, 0xf3, 0xf6, 0xbb, 0x95, 0x70, 0x51};
    static const uint8_t bbjj_B8y[32] = {0x25, 0x79, 0x72, 0x03, 0xf7, 0xa0, 0xb2, 0x49, 0x25, 0x57, 0x2e, 0x1c, 0xd1, 0x6b, 0xf9, 0xed, 0xfc, 0xe0, 0x05, 0x1f, 0xb9, 0xe1, 0x33, 0x77, 0x4b, 0x3c, 0x25, 0x7a, 0x87, 0x2d, 0x7d, 0x8b};

    static const uint8_t bbjj_order[32] = {0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05, 0x37, 0x0a, 0x08, 0xb6, 0xd0, 0x30, 0x2b, 0x0b, 0xab, 0x3e, 0xed, 0xb8, 0x39, 0x20, 0xee, 0x0a, 0x67, 0x72, 0x97, 0xdc, 0x39, 0x21, 0x26, 0xf1};

    curve_prime = (uint8_t *)bbjj_prime;
    curve_A = (uint8_t *)bbjj_A;
    curve_D = (uint8_t *)bbjj_D;
    curve_order = (uint8_t *)bbjj_order;
    B8x = (uint8_t *)bbjj_B8x;
    B8y = (uint8_t *)bbjj_B8y;

    break;

  default:
    return ZKN_NOTIMPLEMENTED;
  }

  ZKN_CHECK(zkn_bn_alloc_init(&curve->modulus, curve->fieldsize8, curve_prime, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc_init(&curve->order, curve->fieldsize8, curve_order, curve->fieldsize8));

  ZKN_CHECK(zkn_mont_alloc(&curve->ctx, 32));
  ZKN_CHECK(zkn_mont_init(&curve->ctx, curve->modulus));

  ZKN_CHECK(zkn_bn_alloc(&curve->mont_One, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_set_u32(curve->mont_One, 1));
  ZKN_CHECK(zkn_mont_to_montgomery(curve->mont_One, curve->mont_One, &curve->ctx));

  ZKN_CHECK(tEdwards_alloc(curve, &curve->G));
  ZKN_CHECK(tEdwards_init(curve, B8x, B8y, &curve->G));

  ZKN_CHECK(zkn_bn_alloc_init(&curve->cA, curve->fieldsize8, curve_A, curve->fieldsize8));
  ZKN_CHECK(zkn_mont_to_montgomery(curve->cA, curve->cA, &curve->ctx));

  ZKN_CHECK(zkn_bn_alloc_init(&curve->cD, curve->fieldsize8, curve_D, curve->fieldsize8));
  ZKN_CHECK(zkn_mont_to_montgomery(curve->cD, curve->cD, &curve->ctx));

  ZKN_CHECK(zkn_bn_alloc(&curve->a, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->b, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->c, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->d, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->e, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->f, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->g, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->h, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->j, curve->fieldsize8));

  ZKN_ERROR_CLOSE();
}

int tEdwards_Curve_destroy(zkn_edcurve_t *curve)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_bn_destroy(&curve->modulus));
  ZKN_CHECK(zkn_bn_destroy(&curve->order));

  ZKN_CHECK(zkn_bn_destroy(&curve->mont_One));
  ZKN_CHECK(tEdwards_destroy(curve, &curve->G));
  ZKN_CHECK(zkn_bn_destroy(&curve->cA));
  ZKN_CHECK(zkn_bn_destroy(&curve->cD));
  // Note: curve->ctx (zkn_bn_mont_ctx_t) holds internal BN slots allocated by
  // zkn_mont_alloc; free them here if the SDK provides zkn_mont_destroy.

  ZKN_CHECK(zkn_bn_destroy(&curve->a));
  ZKN_CHECK(zkn_bn_destroy(&curve->b));
  ZKN_CHECK(zkn_bn_destroy(&curve->c));
  ZKN_CHECK(zkn_bn_destroy(&curve->d));
  ZKN_CHECK(zkn_bn_destroy(&curve->e));
  ZKN_CHECK(zkn_bn_destroy(&curve->f));
  ZKN_CHECK(zkn_bn_destroy(&curve->g));
  ZKN_CHECK(zkn_bn_destroy(&curve->h));
  ZKN_CHECK(zkn_bn_destroy(&curve->j));

  ZKN_ERROR_CLOSE();
}

int tEdwards_Curve_partial_destroy(zkn_edcurve_t *curve)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_bn_destroy(&curve->a));
  ZKN_CHECK(zkn_bn_destroy(&curve->b));
  ZKN_CHECK(zkn_bn_destroy(&curve->c));
  ZKN_CHECK(zkn_bn_destroy(&curve->d));
  ZKN_CHECK(zkn_bn_destroy(&curve->e));
  ZKN_CHECK(zkn_bn_destroy(&curve->f));
  ZKN_CHECK(zkn_bn_destroy(&curve->g));
  ZKN_CHECK(zkn_bn_destroy(&curve->h));
  ZKN_CHECK(zkn_bn_destroy(&curve->j));

  ZKN_CHECK(tEdwards_destroy(curve, &curve->G));

  ZKN_CHECK(zkn_bn_destroy(&curve->cA));
  ZKN_CHECK(zkn_bn_destroy(&curve->cD));
  ZKN_CHECK(zkn_bn_destroy(&curve->mont_One));
  ZKN_CHECK(zkn_bn_destroy(&curve->order));

  ZKN_ERROR_CLOSE();
}

int tEdwards_Curve_partial_restore(zkn_edcurve_t *curve)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_bn_alloc(&curve->a, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->b, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->c, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->d, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->e, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->f, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->g, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->h, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&curve->j, curve->fieldsize8));

  ZKN_ERROR_CLOSE();
}

int tEdwards_SetNeutral(zkn_edcurve_t *curve, zkn_edpoint_t *G)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_bn_set_u32(G->x, 0));
  ZKN_CHECK(zkn_bn_copy(G->y, curve->mont_One));
  ZKN_CHECK(zkn_bn_copy(G->z, curve->mont_One));

  ZKN_ERROR_CLOSE();
}

// set point from triple in normal domain to montgomery projective
int tEdwards_init(zkn_edcurve_t *curve, uint8_t *i_x, uint8_t *i_y, zkn_edpoint_t *o_R)
{
  ZKN_ERROR_INIT();
  zkn_bn_t x;
  zkn_bn_t y;

  size_t size8 = curve->fieldsize8;

  ZKN_CHECK(zkn_bn_alloc_init(&x, size8, i_x, size8));
  ZKN_CHECK(zkn_bn_alloc_init(&y, size8, i_y, size8));

  ZKN_CHECK(zkn_mont_to_montgomery(o_R->x, x, &curve->ctx));
  ZKN_CHECK(zkn_mont_to_montgomery(o_R->y, y, &curve->ctx));
  ZKN_CHECK(zkn_bn_copy(o_R->z, curve->mont_One));

  ZKN_CHECK(zkn_bn_destroy(&x));
  ZKN_CHECK(zkn_bn_destroy(&y));

  ZKN_ERROR_CLOSE();
}

int tEdwards_export(zkn_edcurve_t *curve, zkn_edpoint_t *i_R, uint8_t *x, uint8_t *y)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(tEdwards_normalize(curve, i_R));
  ZKN_CHECK(zkn_mont_from_montgomery(curve->a, i_R->x, &curve->ctx));
  ZKN_CHECK(zkn_mont_from_montgomery(curve->b, i_R->y, &curve->ctx));
  ZKN_CHECK(zkn_bn_export(curve->a, x, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_export(curve->b, y, curve->fieldsize8));
  ZKN_ERROR_CLOSE();
}

int tEdwards_copy(zkn_edpoint_t *i_P, zkn_edpoint_t *R)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_bn_copy(R->x, i_P->x));
  ZKN_CHECK(zkn_bn_copy(R->y, i_P->y));
  ZKN_CHECK(zkn_bn_copy(R->z, i_P->z));

  ZKN_ERROR_CLOSE();
}

// set point from triple in normal domain to montgomery projective
int tEdwards_alloc_init(zkn_edcurve_t *curve, uint8_t *i_x, uint8_t *i_y, zkn_edpoint_t *o_R)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_bn_alloc(&o_R->x, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&o_R->y, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&o_R->z, curve->fieldsize8));

  ZKN_CHECK(tEdwards_init(curve, i_x, i_y, o_R));

  ZKN_ERROR_CLOSE();
}

// load point whose coordinates are already in Montgomery form (skips zkn_mont_to_montgomery)
int tEdwards_alloc_init_mont(zkn_edcurve_t *curve,
                             const uint8_t *mx, const uint8_t *my,
                             zkn_edpoint_t *o_R)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_bn_alloc_init(&o_R->x, curve->fieldsize8, mx, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc_init(&o_R->y, curve->fieldsize8, my, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_alloc(&o_R->z, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_copy(o_R->z, curve->mont_One));

  ZKN_ERROR_CLOSE();
}

int tEdwards_normalize(zkn_edcurve_t *curve, zkn_edpoint_t *i_R)
{
  ZKN_ERROR_INIT();

  ZKN_CHECK(zkn_mont_invert_nprime(curve->a, i_R->z, &curve->ctx)); // 1/z
  ZKN_CHECK(zkn_mont_mul(curve->b, curve->a, i_R->x, &curve->ctx)); // x/z
  ZKN_CHECK(zkn_mont_mul(curve->c, curve->a, i_R->y, &curve->ctx)); // y/z
  ZKN_CHECK(zkn_mont_mul(curve->d, curve->a, i_R->z, &curve->ctx)); // z/z=1

  ZKN_CHECK(zkn_bn_copy(i_R->x, curve->b));
  ZKN_CHECK(zkn_bn_copy(i_R->y, curve->c));
  ZKN_CHECK(zkn_bn_copy(i_R->z, curve->d));

  ZKN_ERROR_CLOSE();
}

// randomizing projective representation of the point
int tEdwards_Coronize(zkn_edcurve_t *curve, zkn_edpoint_t *G)
{
  ZKN_ERROR_INIT();
  uint8_t buf[ECC_MAXSIZE8];

  zkn_trng_get_random_data(buf, curve->fieldsize8);

  ZKN_CHECK(zkn_bn_init(curve->a, buf, curve->fieldsize8));
  ZKN_CHECK(zkn_bn_reduce(curve->b, curve->a, curve->modulus));
  ZKN_CHECK(zkn_mont_to_montgomery(curve->b, curve->b, &curve->ctx));

  ZKN_CHECK(zkn_mont_mul(curve->c, G->x, curve->b, &curve->ctx));
  ZKN_CHECK(zkn_mont_mul(curve->d, G->y, curve->b, &curve->ctx));
  ZKN_CHECK(zkn_mont_mul(curve->e, G->z, curve->b, &curve->ctx));

  ZKN_CHECK(zkn_bn_copy(G->x, curve->c));
  ZKN_CHECK(zkn_bn_copy(G->y, curve->d));
  ZKN_CHECK(zkn_bn_copy(G->z, curve->e));

  ZKN_ERROR_CLOSE();
}

// naive double and add — NOT constant time
int tEdwards_scalarMul_bn(zkn_edcurve_t *curve, zkn_edpoint_t *G, zkn_bn_t *k, zkn_edpoint_t *R)
{
  ZKN_ERROR_INIT();

  int cmp = 0;
  bool cmp2 = 0;

  ZKN_CHECK(zkn_bn_cmp_u32(*k, (uint32_t)0x00000000, &cmp));

  if (cmp == 0)
  {
    ZKN_CHECK(tEdwards_SetNeutral(curve, R));
  }

  size_t Pos;
  int pos;

  ZKN_CHECK(zkn_bn_nbytes(*k, &Pos));
  pos = (int)Pos;
  pos = (pos << 3) - 1;

  curve->debug = 2;
  while (cmp2 != 1)
  {
    ZKN_CHECK(zkn_bn_tst_bit(*k, (uint32_t)pos, &cmp2));
    pos--;
  }

  ZKN_CHECK(tEdwards_copy(G, R));
  curve->debug = 1;
  curve->debug2 = pos;

  while (pos >= 0)
  {
    ZKN_CHECK(tEdwards_double(curve, R, R));
    curve->debug = curve->debug * 2;

    ZKN_CHECK(zkn_bn_tst_bit(*k, (uint32_t)pos, &cmp2));
    if (cmp2 == 1)
    {
      ZKN_CHECK(tEdwards_add(curve, R, G, R));
      curve->debug += 1;
    }
    pos--;
  }

  ZKN_ERROR_CLOSE();
}

int tEdwards_scalarMul(zkn_edcurve_t *curve, zkn_edpoint_t *G, const uint8_t *k, size_t len, zkn_edpoint_t *R)
{
  if (len > curve->fieldsize8)
    return ZKN_NOTIMPLEMENTED;

  ZKN_ERROR_INIT();
  zkn_bn_t bnk;
  curve->debug = 0xca;
  ZKN_CHECK(zkn_bn_alloc_init(&bnk, curve->fieldsize8, k, len));
  curve->debug = 0xb3;
  ZKN_CHECK(tEdwards_scalarMul_bn(curve, G, &bnk, R));

  ZKN_CHECK(zkn_bn_destroy(&bnk));

  ZKN_ERROR_CLOSE();
}

/* ================================================================== */
/*  2MSM — table-based, on-the-fly loading                            */
/* ================================================================== */

/**
 * @brief Variable-time 2MSM loading one table point per iteration.
 *
 * T_mx[4][32] / T_my[4][32]: Montgomery-affine coordinates.
 *   T[0] = neutral (0, mont(1))
 *   T[1] = P2
 *   T[2] = P1
 *   T[3] = P1+P2
 *
 * sel = (bit_k1 << 1) | bit_k2
 *
 * Only one table point is alive at a time → minimal BN slot usage.
 */
int tEdwards_2MSM_precomp_table(zkn_edcurve_t *curve,
                                const uint8_t (*T_mx)[32],
                                const uint8_t (*T_my)[32],
                                const uint8_t *k1, size_t len1,
                                const uint8_t *k2, size_t len2,
                                zkn_edpoint_t *R)
{
  if (len1 > curve->fieldsize8 || len2 > curve->fieldsize8)
    return ZKN_NOTIMPLEMENTED;

  ZKN_ERROR_INIT();

  zkn_bn_t bnk1, bnk2;
  bool bit1, bit2;
  bool initialized = false;

  ZKN_CHECK(zkn_bn_alloc_init(&bnk1, curve->fieldsize8, k1, len1));
  ZKN_CHECK(zkn_bn_alloc_init(&bnk2, curve->fieldsize8, k2, len2));

  int cmp1 = 0, cmp2 = 0;
  ZKN_CHECK(zkn_bn_cmp_u32(bnk1, 0, &cmp1));
  ZKN_CHECK(zkn_bn_cmp_u32(bnk2, 0, &cmp2));

  if (cmp1 == 0 && cmp2 == 0)
  {
    ZKN_CHECK(tEdwards_SetNeutral(curve, R));
    goto cleanup;
  }

  size_t maxlen = len1;
  if (len2 > maxlen)
    maxlen = len2;

  int top = (int)(maxlen << 3) - 1;
  int pos = top;

  /* skip leading zero windows */
  while (pos >= 0)
  {
    ZKN_CHECK(zkn_bn_tst_bit(bnk1, (uint32_t)pos, &bit1));
    ZKN_CHECK(zkn_bn_tst_bit(bnk2, (uint32_t)pos, &bit2));
    if (bit1 || bit2)
      break;
    pos--;
  }

  if (pos < 0)
  {
    ZKN_CHECK(tEdwards_SetNeutral(curve, R));
    goto cleanup;
  }

  /* coronize table points T[1..3] into byte arrays */
  uint8_t CT_x[4][32], CT_y[4][32], CT_z[4][32];
  zkn_edpoint_t Tsel;
  ZKN_CHECK(tEdwards_alloc(curve, &Tsel));
  for (uint8_t i = 1; i < 4; i++)
  {
    ZKN_CHECK(zkn_bn_init(Tsel.x, T_mx[i], curve->fieldsize8));
    ZKN_CHECK(zkn_bn_init(Tsel.y, T_my[i], curve->fieldsize8));
    ZKN_CHECK(zkn_bn_copy(Tsel.z, curve->mont_One));
    ZKN_CHECK(tEdwards_Coronize(curve, &Tsel));
    ZKN_CHECK(zkn_bn_export(Tsel.x, CT_x[i], curve->fieldsize8));
    ZKN_CHECK(zkn_bn_export(Tsel.y, CT_y[i], curve->fieldsize8));
    ZKN_CHECK(zkn_bn_export(Tsel.z, CT_z[i], curve->fieldsize8));
  }

  /* main Shamir loop */
  while (pos >= 0)
  {
    ZKN_CHECK(zkn_bn_tst_bit(bnk1, (uint32_t)pos, &bit1));
    ZKN_CHECK(zkn_bn_tst_bit(bnk2, (uint32_t)pos, &bit2));

    uint8_t sel = (uint8_t)((bit1 ? 2u : 0u) | (bit2 ? 1u : 0u));

    if (!initialized)
    {
      if (sel != 0)
      {
        ZKN_CHECK(zkn_bn_init(R->x, CT_x[sel], curve->fieldsize8));
        ZKN_CHECK(zkn_bn_init(R->y, CT_y[sel], curve->fieldsize8));
        ZKN_CHECK(zkn_bn_init(R->z, CT_z[sel], curve->fieldsize8));
        initialized = true;
      }
      pos--;
      continue;
    }

    ZKN_CHECK(tEdwards_double(curve, R, R));

    if (sel != 0)
    {
      ZKN_CHECK(zkn_bn_init(Tsel.x, CT_x[sel], curve->fieldsize8));
      ZKN_CHECK(zkn_bn_init(Tsel.y, CT_y[sel], curve->fieldsize8));
      ZKN_CHECK(zkn_bn_init(Tsel.z, CT_z[sel], curve->fieldsize8));
      ZKN_CHECK(tEdwards_add(curve, R, &Tsel, R));
    }

    pos--;
  }
  ZKN_CHECK(tEdwards_destroy(curve, &Tsel));

  if (!initialized)
  {
    ZKN_CHECK(tEdwards_SetNeutral(curve, R));
  }

cleanup:
  ZKN_CHECK(zkn_bn_destroy(&bnk1));
  ZKN_CHECK(zkn_bn_destroy(&bnk2));

  ZKN_ERROR_CLOSE();
}

/* ================================================================== */
/*  4MSM — table-based, on-the-fly loading                            */
/* ================================================================== */

/**
 * @brief Variable-time 4MSM loading one table point per iteration.
 *
 * T_mx[16][32] / T_my[16][32]: Montgomery-affine coordinates.
 * Index = sel = (b1<<3)|(b2<<2)|(b3<<1)|b4 :
 *
 *   T[ 0] = O                T[ 8] = P1
 *   T[ 1] = P4               T[ 9] = P1+P4
 *   T[ 2] = P3               T[10] = P1+P3
 *   T[ 3] = P3+P4            T[11] = P1+P3+P4
 *   T[ 4] = P2               T[12] = P1+P2
 *   T[ 5] = P2+P4            T[13] = P1+P2+P4
 *   T[ 6] = P2+P3            T[14] = P1+P2+P3
 *   T[ 7] = P2+P3+P4         T[15] = P1+P2+P3+P4
 *
 * Only one table point is alive at a time → ~22 BN slots total.
 */
int tEdwards_4MSM_precomp_table(zkn_edcurve_t *curve,
                                const uint8_t (*T_mx)[32],
                                const uint8_t (*T_my)[32],
                                const uint8_t *k1, size_t len1,
                                const uint8_t *k2, size_t len2,
                                const uint8_t *k3, size_t len3,
                                const uint8_t *k4, size_t len4,
                                zkn_edpoint_t *R)
{
  if (len1 > curve->fieldsize8 || len2 > curve->fieldsize8 ||
      len3 > curve->fieldsize8 || len4 > curve->fieldsize8)
    return ZKN_NOTIMPLEMENTED;

  ZKN_ERROR_INIT();

  zkn_bn_t bnk1, bnk2, bnk3, bnk4;
  bool bit1, bit2, bit3, bit4;
  bool initialized = false;

  ZKN_CHECK(zkn_bn_alloc_init(&bnk1, curve->fieldsize8, k1, len1));
  ZKN_CHECK(zkn_bn_alloc_init(&bnk2, curve->fieldsize8, k2, len2));
  ZKN_CHECK(zkn_bn_alloc_init(&bnk3, curve->fieldsize8, k3, len3));
  ZKN_CHECK(zkn_bn_alloc_init(&bnk4, curve->fieldsize8, k4, len4));

  /* all-zero fast path */
  int cmp1 = 0, cmp2 = 0, cmp3 = 0, cmp4 = 0;
  ZKN_CHECK(zkn_bn_cmp_u32(bnk1, 0, &cmp1));
  ZKN_CHECK(zkn_bn_cmp_u32(bnk2, 0, &cmp2));
  ZKN_CHECK(zkn_bn_cmp_u32(bnk3, 0, &cmp3));
  ZKN_CHECK(zkn_bn_cmp_u32(bnk4, 0, &cmp4));

  if (cmp1 == 0 && cmp2 == 0 && cmp3 == 0 && cmp4 == 0)
  {
    ZKN_CHECK(tEdwards_SetNeutral(curve, R));
    goto cleanup;
  }

  size_t maxlen = len1;
  if (len2 > maxlen)
    maxlen = len2;
  if (len3 > maxlen)
    maxlen = len3;
  if (len4 > maxlen)
    maxlen = len4;

  int top = (int)(maxlen << 3) - 1;
  int pos = top;

  /* skip leading zero windows */
  while (pos >= 0)
  {
    ZKN_CHECK(zkn_bn_tst_bit(bnk1, (uint32_t)pos, &bit1));
    ZKN_CHECK(zkn_bn_tst_bit(bnk2, (uint32_t)pos, &bit2));
    ZKN_CHECK(zkn_bn_tst_bit(bnk3, (uint32_t)pos, &bit3));
    ZKN_CHECK(zkn_bn_tst_bit(bnk4, (uint32_t)pos, &bit4));
    if (bit1 || bit2 || bit3 || bit4)
      break;
    pos--;
  }

  if (pos < 0)
  {
    ZKN_CHECK(tEdwards_SetNeutral(curve, R));
    goto cleanup;
  }

  /* coronize table points T[1..15] into byte arrays */
  uint8_t CT_x[16][32], CT_y[16][32], CT_z[16][32];
  zkn_edpoint_t Tsel;
  ZKN_CHECK(tEdwards_alloc(curve, &Tsel));
  for (uint8_t i = 1; i < 16; i++)
  {
    ZKN_CHECK(zkn_bn_init(Tsel.x, T_mx[i], curve->fieldsize8));
    ZKN_CHECK(zkn_bn_init(Tsel.y, T_my[i], curve->fieldsize8));
    ZKN_CHECK(zkn_bn_copy(Tsel.z, curve->mont_One));
    ZKN_CHECK(tEdwards_Coronize(curve, &Tsel));
    ZKN_CHECK(zkn_bn_export(Tsel.x, CT_x[i], curve->fieldsize8));
    ZKN_CHECK(zkn_bn_export(Tsel.y, CT_y[i], curve->fieldsize8));
    ZKN_CHECK(zkn_bn_export(Tsel.z, CT_z[i], curve->fieldsize8));
  }

  /* main Shamir loop */
  while (pos >= 0)
  {
    ZKN_CHECK(zkn_bn_tst_bit(bnk1, (uint32_t)pos, &bit1));
    ZKN_CHECK(zkn_bn_tst_bit(bnk2, (uint32_t)pos, &bit2));
    ZKN_CHECK(zkn_bn_tst_bit(bnk3, (uint32_t)pos, &bit3));
    ZKN_CHECK(zkn_bn_tst_bit(bnk4, (uint32_t)pos, &bit4));

    uint8_t sel = (uint8_t)((bit1 ? 8u : 0u) |
                            (bit2 ? 4u : 0u) |
                            (bit3 ? 2u : 0u) |
                            (bit4 ? 1u : 0u));

    if (!initialized)
    {
      if (sel != 0)
      {
        ZKN_CHECK(zkn_bn_init(R->x, CT_x[sel], curve->fieldsize8));
        ZKN_CHECK(zkn_bn_init(R->y, CT_y[sel], curve->fieldsize8));
        ZKN_CHECK(zkn_bn_init(R->z, CT_z[sel], curve->fieldsize8));
        initialized = true;
      }
      pos--;
      continue;
    }

    ZKN_CHECK(tEdwards_double(curve, R, R));

    if (sel != 0)
    {
      ZKN_CHECK(zkn_bn_init(Tsel.x, CT_x[sel], curve->fieldsize8));
      ZKN_CHECK(zkn_bn_init(Tsel.y, CT_y[sel], curve->fieldsize8));
      ZKN_CHECK(zkn_bn_init(Tsel.z, CT_z[sel], curve->fieldsize8));
      ZKN_CHECK(tEdwards_add(curve, R, &Tsel, R));
    }

    pos--;
  }
  ZKN_CHECK(tEdwards_destroy(curve, &Tsel));

  if (!initialized)
  {
    ZKN_CHECK(tEdwards_SetNeutral(curve, R));
  }

cleanup:
  ZKN_CHECK(zkn_bn_destroy(&bnk1));
  ZKN_CHECK(zkn_bn_destroy(&bnk2));
  ZKN_CHECK(zkn_bn_destroy(&bnk3));
  ZKN_CHECK(zkn_bn_destroy(&bnk4));

  ZKN_ERROR_CLOSE();
}

int tEdwards_fixedBase_2MSM(zkn_edcurve_t *curve, const uint8_t *k, zkn_edpoint_t *R)
{

  const uint8_t (*T_mx)[32];
  const uint8_t (*T_my)[32];
  if (curve->curveID == _BABYJUJUB_ID)
  {
    bbjj_get_2msm_table(&T_mx, &T_my);
  }
  else if (curve->curveID == _BANDERSNATCH_ID)
  {
    bandersnatch_get_2msm_table(&T_mx, &T_my);
  }
  else
  {
    return ZKN_NOTIMPLEMENTED;
  }

  const uint8_t *k1 = k + 16; // lower 128 bits
  const uint8_t *k2 = k;      // upper 128 bits

  return tEdwards_2MSM_precomp_table(curve, T_mx, T_my, k1, 16, k2, 16, R);
}

int tEdwards_fixedBase_4MSM(zkn_edcurve_t *curve, const uint8_t *k, zkn_edpoint_t *R)
{
  const uint8_t (*T_mx)[32];
  const uint8_t (*T_my)[32];
  if (curve->curveID == _BABYJUJUB_ID)
  {
    bbjj_get_4msm_table(&T_mx, &T_my);
  }
  else if (curve->curveID == _BANDERSNATCH_ID)
  {
    bandersnatch_get_4msm_table(&T_mx, &T_my);
  }
  else
  {
    return ZKN_NOTIMPLEMENTED;
  }

  const uint8_t *k1 = k + 24;
  const uint8_t *k2 = k + 16;
  const uint8_t *k3 = k + 8;
  const uint8_t *k4 = k + 0;

  return tEdwards_4MSM_precomp_table(curve, T_mx, T_my, k1, 8, k2, 8, k3, 8, k4, 8, R);
}

// RFC8032 packpoint: y |=(x&1)<<255, LE representation
int tEdwards_packPoint(zkn_edcurve_t *curve, zkn_edpoint_t *G, uint8_t *out, size_t len)
{
  ZKN_UNUSED(len);
  uint8_t x[ECC_MAXSIZE8];
  ZKN_ERROR_INIT();

  // 0. normalize (divide by Z) then convert from Montgomery domain
  ZKN_CHECK(tEdwards_normalize(curve, G));
  ZKN_CHECK(zkn_mont_from_montgomery(curve->a, G->x, &curve->ctx));
  ZKN_CHECK(zkn_mont_from_montgomery(curve->b, G->y, &curve->ctx));

  // 1. get x sign bit BEFORE overwriting
  ZKN_CHECK(zkn_bn_export(curve->a, x, curve->fieldsize8)); // big-endian
  uint8_t x_sign = x[curve->fieldsize8 - 1] & 1;          // LSB of x

  // 2. export y into the OUTPUT buffer
  ZKN_CHECK(zkn_bn_export(curve->b, out, curve->fieldsize8)); // big-endian into out[]

  // 3. convert to little-endian, then embed sign
  ByteSwap(out, curve->fieldsize8);
  out[curve->fieldsize8 - 1] |= x_sign << 7;

  ZKN_ERROR_CLOSE();
}
