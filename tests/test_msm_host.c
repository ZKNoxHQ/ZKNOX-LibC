/*
 * test_msm_full.c — Full reproduction of test_msm_babyjubjub.js
 *
 * Same vectors as the device JS test, run as host C.
 *   - naive_scalar_mul: 1·G, iden3 TestMul1 on arbitrary point
 *   - fixed_base_2MSM: k=1, k=3, k=iden3
 *   - fixed_base_4MSM: k=iden3
 *   - cross-check: naive == 2MSM == 4MSM for same k
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "zkn_tEdwards.h"
#include "zkn_bn.h"
#include <stdio.h>
#include <string.h>

static const uint8_t BJJ_Gx[32] = {
    0x0b,0xb7,0x7a,0x6a,0xd6,0x3e,0x73,0x9b, 0x4e,0xac,0xb2,0xe0,0x9d,0x62,0x77,0xc1,
    0x2a,0xb8,0xd8,0x01,0x05,0x34,0xe0,0xb6, 0x28,0x93,0xf3,0xf6,0xbb,0x95,0x70,0x51
};
static const uint8_t BJJ_Gy[32] = {
    0x25,0x79,0x72,0x03,0xf7,0xa0,0xb2,0x49, 0x25,0x57,0x2e,0x1c,0xd1,0x6b,0xf9,0xed,
    0xfc,0xe0,0x05,0x1f,0xb9,0xe1,0x33,0x77, 0x4b,0x3c,0x25,0x7a,0x87,0x2d,0x7d,0x8b
};

/* iden3 TestMul1 from test_msm_babyjubjub.js */
static const uint8_t IDEN3_K[32] = {
    0x1f,0x07,0xaa,0x1b,0x3c,0x59,0x8e,0x2f, 0xf9,0xff,0x77,0x74,0x4a,0x39,0x29,0x8a,
    0x0a,0x89,0xa9,0x02,0x77,0x77,0xaf,0x9f, 0xa1,0x00,0xdd,0x44,0x8e,0x07,0x2c,0x13
};
static const uint8_t IDEN3_EXPECT_GX[32] = {
    0x0e,0xd5,0x11,0xba,0x75,0xa8,0x5f,0xbe, 0xfd,0x81,0x23,0x7f,0x8c,0x37,0x69,0xcc,
    0xef,0xa6,0xe3,0x49,0x32,0x92,0x64,0x02, 0x2f,0x66,0xa4,0xa8,0xe7,0x16,0x8b,0x70
};
static const uint8_t IDEN3_EXPECT_GY[32] = {
    0x18,0x5a,0x94,0x94,0xf3,0xfc,0x13,0x1f, 0x55,0xe5,0xee,0xe9,0x2c,0x55,0x4c,0x2c,
    0xc2,0x95,0x5e,0x03,0x9c,0xb8,0x12,0xbe, 0x4c,0xab,0x5d,0x98,0x3c,0x8b,0xcc,0x1c
};

/* iden3 TestMul1 on arbitrary base point P:
 *   P.x = 274dbce8d15179969bc0d49fa725bddf9de555e0ba6a693c6adb52fc9ee7a82c
 *   P.y = 05ce98c61b05f47fe2eae9a542bd99f6b2e78246231640b54595febfd51eb853
 *   k·P expected: (25bd7aef...c2ca5, 08e043ec...e3ab) */
static const uint8_t P_x[32] = {
    0x27,0x4d,0xbc,0xe8,0xd1,0x51,0x79,0x96, 0x9b,0xc0,0xd4,0x9f,0xa7,0x25,0xbd,0xdf,
    0x9d,0xe5,0x55,0xe0,0xba,0x6a,0x69,0x3c, 0x6a,0xdb,0x52,0xfc,0x9e,0xe7,0xa8,0x2c
};
static const uint8_t P_y[32] = {
    0x05,0xce,0x98,0xc6,0x1b,0x05,0xf4,0x7f, 0xe2,0xea,0xe9,0xa5,0x42,0xbd,0x99,0xf6,
    0xb2,0xe7,0x82,0x46,0x23,0x16,0x40,0xb5, 0x45,0x95,0xfe,0xbf,0xd5,0x1e,0xb8,0x53
};
static const uint8_t IDEN3_EXPECT_PX[32] = {
    0x25,0xbd,0x7a,0xef,0xee,0x96,0x61,0x7d, 0x4f,0x71,0x5e,0xcf,0x8e,0x50,0xef,0x9f,
    0xa1,0x02,0xee,0xb4,0x52,0x64,0x2c,0x63, 0x22,0xd3,0x8a,0xa9,0xb3,0x2c,0x2c,0xa5
};
static const uint8_t IDEN3_EXPECT_PY[32] = {
    0x08,0xe0,0x43,0xec,0x72,0x9e,0xed,0xea, 0x41,0x4b,0x63,0xde,0x47,0x4c,0x8f,0x09,
    0x30,0xea,0x96,0x67,0x33,0xae,0x28,0x3e, 0x01,0xf3,0x48,0xca,0x3c,0x35,0xe3,0xab
};

/* k=3 expected for fixed_base 2MSM:
 *   x = 061c1436d1c3008037e887c8234dcf7c33c947ad93695b8000fcb4ab70477e3e
 *   y = 21d66f0e2295ae954494f25889f9319cc1b4df71eff3f46ba9e4631b43fd7c95 */
static const uint8_t K3_EXPECT_X[32] = {
    0x06,0x1c,0x14,0x36,0xd1,0xc3,0x00,0x80, 0x37,0xe8,0x87,0xc8,0x23,0x4d,0xcf,0x7c,
    0x33,0xc9,0x47,0xad,0x93,0x69,0x5b,0x80, 0x00,0xfc,0xb4,0xab,0x70,0x47,0x7e,0x3e
};
static const uint8_t K3_EXPECT_Y[32] = {
    0x21,0xd6,0x6f,0x0e,0x22,0x95,0xae,0x95, 0x44,0x94,0xf2,0x58,0x89,0xf9,0x31,0x9c,
    0xc1,0xb4,0xdf,0x71,0xef,0xf3,0xf4,0x6b, 0xa9,0xe4,0x63,0x1b,0x43,0xfd,0x7c,0x95
};

static int pass = 0, fail = 0;

static void check_pt(const char *what, const uint8_t *gx, const uint8_t *gy,
                                       const uint8_t *ex, const uint8_t *ey) {
    int ok = memcmp(gx, ex, 32) == 0 && memcmp(gy, ey, 32) == 0;
    if (ok) { printf("    ✅ %s\n", what); pass++; }
    else    {
        printf("    ❌ %s\n", what);
        printf("       got x: "); for (int i=0;i<32;i++) printf("%02x", gx[i]); printf("\n");
        printf("       want : "); for (int i=0;i<32;i++) printf("%02x", ex[i]); printf("\n");
        fail++;
    }
}

static void run_naive_kG(zkn_edcurve_t *c, const uint8_t *k, const char *label,
                         const uint8_t *ex, const uint8_t *ey) {
    printf("  [naive] %s\n", label);
    zkn_edpoint_t R;
    tEdwards_alloc(c, &R);
    tEdwards_scalarMul(c, &c->G, k, 32, &R);
    uint8_t ox[32], oy[32];
    tEdwards_export(c, &R, ox, oy);
    check_pt(label, ox, oy, ex, ey);
    tEdwards_destroy(c, &R);
}

static void run_fixed2_kG(zkn_edcurve_t *c, const uint8_t *k, const char *label,
                          const uint8_t *ex, const uint8_t *ey) {
    printf("  [fixed_2MSM] %s\n", label);
    zkn_edpoint_t R;
    tEdwards_alloc(c, &R);
    tEdwards_fixedBase_2MSM(c, k, &R);
    uint8_t ox[32], oy[32];
    tEdwards_export(c, &R, ox, oy);
    check_pt(label, ox, oy, ex, ey);
    tEdwards_destroy(c, &R);
}

static void run_fixed4_kG(zkn_edcurve_t *c, const uint8_t *k, const char *label,
                          const uint8_t *ex, const uint8_t *ey) {
    printf("  [fixed_4MSM] %s\n", label);
    zkn_edpoint_t R;
    tEdwards_alloc(c, &R);
    tEdwards_fixedBase_4MSM(c, k, &R);
    uint8_t ox[32], oy[32];
    tEdwards_export(c, &R, ox, oy);
    check_pt(label, ox, oy, ex, ey);
    tEdwards_destroy(c, &R);
}

/* Re-init curve to clear scratch state between operations */
static zkn_edcurve_t * reset_curve(zkn_edcurve_t *c) {
    tEdwards_Curve_destroy(c);
    tEdwards_Curve_alloc_init(c, _BABYJUJUB_ID);
    return c;
}

int main(void) {
    printf("════════════════════════════════════════════════════════════\n");
    printf("  Full MSM test suite — mirrors test_msm_babyjubjub.js     \n");
    printf("════════════════════════════════════════════════════════════\n");

    zkn_edcurve_t curve;
    tEdwards_Curve_alloc_init(&curve, _BABYJUJUB_ID);

    /* k = 1 */
    uint8_t k1[32] = {0}; k1[31] = 1;
    /* k = 3 */
    uint8_t k3[32] = {0}; k3[31] = 3;

    printf("\n── Section 1: naive scalarMul ──\n");
    run_naive_kG(&curve, k1, "1·G == G", BJJ_Gx, BJJ_Gy);
    reset_curve(&curve);

    /* For naive on arbitrary P, we need a P point in curve struct first */
    {
        zkn_edpoint_t P;
        tEdwards_alloc(&curve, &P);
        tEdwards_init(&curve, (uint8_t*)P_x, (uint8_t*)P_y, &P);
        zkn_edpoint_t R;
        tEdwards_alloc(&curve, &R);
        tEdwards_scalarMul(&curve, &P, IDEN3_K, 32, &R);
        uint8_t ox[32], oy[32];
        tEdwards_export(&curve, &R, ox, oy);
        printf("  [naive] iden3 TestMul1 on P (not G)\n");
        check_pt("iden3·P", ox, oy, IDEN3_EXPECT_PX, IDEN3_EXPECT_PY);
        tEdwards_destroy(&curve, &P);
        tEdwards_destroy(&curve, &R);
    }
    reset_curve(&curve);

    printf("\n── Section 2: fixed_base 2MSM ──\n");
    run_fixed2_kG(&curve, k1, "k=1 == G",            BJJ_Gx,         BJJ_Gy);          reset_curve(&curve);
    run_fixed2_kG(&curve, k3, "k=3",                 K3_EXPECT_X,    K3_EXPECT_Y);     reset_curve(&curve);
    run_fixed2_kG(&curve, IDEN3_K, "k=iden3 TestMul1", IDEN3_EXPECT_GX, IDEN3_EXPECT_GY); reset_curve(&curve);

    printf("\n── Section 3: fixed_base 4MSM ──\n");
    run_fixed4_kG(&curve, IDEN3_K, "k=iden3 TestMul1", IDEN3_EXPECT_GX, IDEN3_EXPECT_GY); reset_curve(&curve);

    printf("\n── Section 4: cross-check naive == fixed_2MSM == fixed_4MSM ──\n");
    {
        uint8_t naive_x[32], naive_y[32];
        uint8_t f2_x[32], f2_y[32];
        uint8_t f4_x[32], f4_y[32];
        zkn_edpoint_t R;

        tEdwards_alloc(&curve, &R);
        tEdwards_scalarMul(&curve, &curve.G, IDEN3_K, 32, &R);
        tEdwards_export(&curve, &R, naive_x, naive_y);
        tEdwards_destroy(&curve, &R);
        reset_curve(&curve);

        tEdwards_alloc(&curve, &R);
        tEdwards_fixedBase_2MSM(&curve, IDEN3_K, &R);
        tEdwards_export(&curve, &R, f2_x, f2_y);
        tEdwards_destroy(&curve, &R);
        reset_curve(&curve);

        tEdwards_alloc(&curve, &R);
        tEdwards_fixedBase_4MSM(&curve, IDEN3_K, &R);
        tEdwards_export(&curve, &R, f4_x, f4_y);
        tEdwards_destroy(&curve, &R);

        int n2 = memcmp(naive_x, f2_x, 32) == 0 && memcmp(naive_y, f2_y, 32) == 0;
        int n4 = memcmp(naive_x, f4_x, 32) == 0 && memcmp(naive_y, f4_y, 32) == 0;
        if (n2) { printf("    ✅ naive == fixed_2MSM\n"); pass++; } else { printf("    ❌ naive != fixed_2MSM\n"); fail++; }
        if (n4) { printf("    ✅ naive == fixed_4MSM\n"); pass++; } else { printf("    ❌ naive != fixed_4MSM\n"); fail++; }
    }

    tEdwards_Curve_destroy(&curve);

    printf("\n════════════════════════════════════════════════════════════\n");
    printf("  Total: %d passed, %d failed\n", pass, fail);
    printf("════════════════════════════════════════════════════════════\n");
    return fail ? 1 : 0;
}
