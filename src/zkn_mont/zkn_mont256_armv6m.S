/* zkn_mont256_armv6m.S
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 ZKNOX
 *
 * 256-bit Montgomery multiplication for Thumb-1 cores (ARMv6-M: Cortex-M0,
 * M0+, SC000, i.e. the original Ledger Nano S).
 *
 *   void zkn_mul_mont_256(zkn_fe256_t r, const zkn_fe256_t a,
 *                         const zkn_fe256_t b, const zkn_fe256_t p,
 *                         zkn_limb_t n0);
 *
 * Same algorithm as the C version in zkn_mont256.c (CIOS on 8 x 32-bit limbs,
 * 9-limb accumulator, one conditional subtraction at the end), and the same
 * output for every input, reduced or not. r may alias a or b: it is written
 * last, from the accumulator.
 *
 * These cores have no 32x32->64 multiply: MULS returns the low 32 bits. The
 * compiler answers a 64-bit product with a call to __aeabi_lmul: six MULS, a
 * lot of register traffic, and in the libgcc version a branch on a carry of
 * the operands. Here each product is four 16x16 MULS, inline.
 *
 * No branch and no memory address depends on the data. MULS takes a fixed
 * number of cycles on these cores (1 or 32 depending on the multiplier the
 * chip was built with). tools/mont256_armv6m_check.py counts the same number
 * of cycles for every input.
 *
 * Enabled by itself when the file is built for an ARMv6-M target. Define
 * ZKN_MONT256_NO_ASM to keep the C version. On every other target this file
 * is an empty object.
 */

#if defined(__ARM_ARCH_ISA_THUMB) && (__ARM_ARCH_ISA_THUMB == 1) && !defined(ZKN_MONT256_NO_ASM)

    .syntax unified
    .cpu    cortex-m0plus
    .thumb

/* Stack frame, from sp:
 *    0 .. 35   t[0..8], the accumulator
 *   36         carry out of the multiplication row
 *   40         r
 *   44         end of b (b + 32)
 * then the saved r8-r11 (16 bytes) and r4-r7, lr (20 bytes); the fifth
 * argument n0 sits above them. */
#define T_OVF     36
#define F_R       40
#define F_BEND    44
#define FRAME     48
#define ARG_N0    (FRAME + 36)

/* Registers of the inner step:
 *   r0  low word of the running product
 *   r1  x, the multiplicand row (a, then p)
 *   r2  t
 *   r3, r4  high word and incoming carry, swapping roles at each step
 *   r5, r6, r7  scratch
 *   r8, r9  low and high half of the multiplier word (b[i], then m)
 *   r10 b cursor, r11 a, r12 p, lr n0
 */

/* (hi : t[tout/4]) = x[xoff/4] * y + t[tin/4] + cin
 * The sum fits: (2^32-1)^2 + 2*(2^32-1) = 2^64 - 1. */
.macro MULADD xoff, tin, tout, hi, cin, store=1
    ldr     \hi, [r1, #\xoff]
    uxth    r5, \hi                 @ xl
    lsrs    \hi, \hi, #16           @ xh
    mov     r6, r8                  @ yl
    mov     r7, r9                  @ yh
    mov     r0, r5
    muls    r0, r6, r0              @ xl*yl
    muls    r5, r7, r5              @ xl*yh
    muls    r6, \hi, r6             @ xh*yl
    muls    \hi, r7, \hi            @ xh*yh
    lsls    r7, r5, #16
    lsrs    r5, r5, #16
    adds    r0, r0, r7
    adcs    \hi, r5
    lsls    r7, r6, #16
    lsrs    r6, r6, #16
    adds    r0, r0, r7
    adcs    \hi, r6
    movs    r7, #0
    ldr     r6, [r2, #\tin]
    adds    r0, r0, r6
    adcs    \hi, r7
    adds    r0, r0, \cin
    adcs    \hi, r7
    .if \store
    str     r0, [r2, #\tout]
    .endif
.endm

    .section .text.zkn_mul_mont_256, "ax", %progbits
    .global zkn_mul_mont_256
    .type   zkn_mul_mont_256, %function
    .thumb_func
    .balign 4
zkn_mul_mont_256:
    push    {r4, r5, r6, r7, lr}
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    push    {r4, r5, r6, r7}
    sub     sp, #FRAME

    str     r0, [sp, #F_R]
    mov     r11, r1                 @ a
    mov     r10, r2                 @ b cursor
    mov     r12, r3                 @ p
    adds    r2, #32
    str     r2, [sp, #F_BEND]
    ldr     r0, [sp, #ARG_N0]
    mov     lr, r0                  @ n0

    mov     r2, sp                  @ t
    movs    r0, #0
    str     r0, [r2, #0]
    str     r0, [r2, #4]
    str     r0, [r2, #8]
    str     r0, [r2, #12]
    str     r0, [r2, #16]
    str     r0, [r2, #20]
    str     r0, [r2, #24]
    str     r0, [r2, #28]
    str     r0, [r2, #32]

.Lrow:
    /* ── t += a * b[i] ── */
    mov     r0, r10
    ldr     r6, [r0]
    adds    r0, #4
    mov     r10, r0
    uxth    r5, r6
    lsrs    r6, r6, #16
    mov     r8, r5
    mov     r9, r6
    mov     r1, r11
    movs    r3, #0
    MULADD   0,  0,  0, r4, r3
    MULADD   4,  4,  4, r3, r4
    MULADD   8,  8,  8, r4, r3
    MULADD  12, 12, 12, r3, r4
    MULADD  16, 16, 16, r4, r3
    MULADD  20, 20, 20, r3, r4
    MULADD  24, 24, 24, r4, r3
    MULADD  28, 28, 28, r3, r4
    ldr     r0, [r2, #32]           @ t[8] += carry; r7 is 0
    adds    r0, r0, r3
    str     r0, [r2, #32]
    adcs    r7, r7
    str     r7, [r2, #T_OVF]

    /* ── m = t[0] * n0; t = (t + m * p) >> 32 ── */
    ldr     r0, [r2, #0]
    mov     r5, lr
    muls    r0, r5, r0
    uxth    r5, r0
    lsrs    r0, r0, #16
    mov     r8, r5
    mov     r9, r0
    mov     r1, r12
    movs    r3, #0
    MULADD   0,  0,  0, r4, r3, 0   @ low word is zero by construction
    MULADD   4,  4,  0, r3, r4
    MULADD   8,  8,  4, r4, r3
    MULADD  12, 12,  8, r3, r4
    MULADD  16, 16, 12, r4, r3
    MULADD  20, 20, 16, r3, r4
    MULADD  24, 24, 20, r4, r3
    MULADD  28, 28, 24, r3, r4
    ldr     r0, [r2, #32]           @ t[7] = t[8] + carry; r7 is 0
    adds    r0, r0, r3
    str     r0, [r2, #28]
    adcs    r7, r7
    ldr     r6, [r2, #T_OVF]
    adds    r7, r7, r6
    str     r7, [r2, #32]           @ t[8] = carry out + carry of the first row

    mov     r0, r10
    ldr     r6, [r2, #F_BEND]
    cmp     r0, r6
    beq     .Lreduce
    b       .Lrow

.Lreduce:
    /* ── r = t - p if t >= p, else t ──
     * First pass: borrow of t[0..7] - p. */
    mov     r1, r12
    ldr     r0, [r2, #0]
    ldr     r6, [r1, #0]
    subs    r0, r0, r6
    ldr     r0, [r2, #4]
    ldr     r6, [r1, #4]
    sbcs    r0, r6
    ldr     r0, [r2, #8]
    ldr     r6, [r1, #8]
    sbcs    r0, r6
    ldr     r0, [r2, #12]
    ldr     r6, [r1, #12]
    sbcs    r0, r6
    ldr     r0, [r2, #16]
    ldr     r6, [r1, #16]
    sbcs    r0, r6
    ldr     r0, [r2, #20]
    ldr     r6, [r1, #20]
    sbcs    r0, r6
    ldr     r0, [r2, #24]
    ldr     r6, [r1, #24]
    sbcs    r0, r6
    ldr     r0, [r2, #28]
    ldr     r6, [r1, #28]
    sbcs    r0, r6
    sbcs    r0, r0                  @ r0 = -borrow
    /* t < p exactly when the low words borrow and t[8] is 0. */
    ldr     r6, [r2, #32]
    rsbs    r5, r6, #0
    orrs    r5, r6
    lsrs    r5, r5, #31             @ 1 when t[8] != 0
    movs    r7, #1
    eors    r5, r7                  @ 1 when t[8] == 0
    ands    r5, r0                  @ 1 when t < p
    subs    r5, #1                  @ all ones when p must be subtracted

    /* Second pass: r = t - (p & mask). ANDS, LDR and STR leave C alone. */
    ldr     r3, [r2, #F_R]
    ldr     r0, [r2, #0]
    ldr     r6, [r1, #0]
    ands    r6, r5
    subs    r0, r0, r6
    str     r0, [r3, #0]
    ldr     r0, [r2, #4]
    ldr     r6, [r1, #4]
    ands    r6, r5
    sbcs    r0, r6
    str     r0, [r3, #4]
    ldr     r0, [r2, #8]
    ldr     r6, [r1, #8]
    ands    r6, r5
    sbcs    r0, r6
    str     r0, [r3, #8]
    ldr     r0, [r2, #12]
    ldr     r6, [r1, #12]
    ands    r6, r5
    sbcs    r0, r6
    str     r0, [r3, #12]
    ldr     r0, [r2, #16]
    ldr     r6, [r1, #16]
    ands    r6, r5
    sbcs    r0, r6
    str     r0, [r3, #16]
    ldr     r0, [r2, #20]
    ldr     r6, [r1, #20]
    ands    r6, r5
    sbcs    r0, r6
    str     r0, [r3, #20]
    ldr     r0, [r2, #24]
    ldr     r6, [r1, #24]
    ands    r6, r5
    sbcs    r0, r6
    str     r0, [r3, #24]
    ldr     r0, [r2, #28]
    ldr     r6, [r1, #28]
    ands    r6, r5
    sbcs    r0, r6
    str     r0, [r3, #28]

    add     sp, #FRAME
    pop     {r4, r5, r6, r7}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    mov     r11, r7
    pop     {r4, r5, r6, r7, pc}
    .size   zkn_mul_mont_256, . - zkn_mul_mont_256

#endif /* Thumb-1 only */
