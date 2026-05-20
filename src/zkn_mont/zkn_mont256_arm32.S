/*
 * zkn_mont256_arm32.S — ARM Thumb-2 Montgomery arithmetic for 256-bit
 *
 * Targets: ARM Cortex-M3/M4/M33, SC300 (Ledger Nano S+, Nano X)
 * ISA:     ARMv7-M Thumb-2 (unified syntax)
 *
 * Provides ASM replacements for:
 *   zkn_mul_mont_256   — Montgomery multiplication (CIOS, stack-based)
 *   zkn_sqr_mont_256   — Montgomery squaring (delegates to mul)
 *   zkn_add_mod_256    — Modular addition
 *   zkn_sub_mod_256    — Modular subtraction
 *   zkn_from_mont_256  — Convert out of Montgomery domain
 *
 * Build (Ledger):
 *   Assembled automatically by the SDK when listed in SOURCE_FILES.
 *
 * Build (QEMU test — see Makefile):
 *   Requires changing .cpu to .arch armv7-a for the Linux ARM linker.
 *   The Makefile handles this via sed automatically.
 *
 * Compile zkn_mont256.c with -DZKN_MONT256_ASM to disable C versions.
 *
 * Copyright (c) 2025 ZKNOX / Kohaku
 */

    .syntax unified
    .thumb
    .cpu cortex-m3

    .text

/* ══════════════════════════════════════════════════════════════════════
 * void zkn_mul_mont_256(uint32_t r[8],
 *                       const uint32_t a[8],
 *                       const uint32_t b[8],
 *                       const uint32_t p[8],
 *                       uint32_t n0);
 *
 * AAPCS: r0=r, r1=a, r2=b, r3=p, [sp]=n0
 * ══════════════════════════════════════════════════════════════════════ */

    .global zkn_mul_mont_256
    .type   zkn_mul_mont_256, %function
    .align  2
    .thumb_func

zkn_mul_mont_256:
    b       zkn_mul_mont_256_stk
    .size   zkn_mul_mont_256, . - zkn_mul_mont_256


/* ══════════════════════════════════════════════════════════════════════
 * Stack-based CIOS Montgomery multiplication
 *
 * Accumulator t[0..8] lives on the stack. Trades ~128 extra load/store
 * cycles (vs full-register) for clean, auditable, correct code.
 * On SC300 with 1-cycle SRAM: ~800-1000 cycles total.
 *
 * Stack layout (60 bytes local + 36 pushed):
 *   sp+0..35  : t[0..8]  (9 words)
 *   sp+36     : saved result ptr
 *   sp+40     : saved a ptr
 *   sp+44     : saved b ptr
 *   sp+48     : saved p ptr
 *   sp+52     : n0
 *   sp+56     : loop counter i
 *   sp+60..95 : pushed {r4-r11, lr}
 *   sp+96     : caller's n0 argument
 * ══════════════════════════════════════════════════════════════════════ */

    .global zkn_mul_mont_256_stk
    .type   zkn_mul_mont_256_stk, %function
    .align  2
    .thumb_func

zkn_mul_mont_256_stk:
    push    {r4-r11, lr}
    sub     sp, sp, #60

    str     r0, [sp, #36]
    str     r1, [sp, #40]
    str     r2, [sp, #44]
    str     r3, [sp, #48]
    ldr     r0, [sp, #96]          /* n0 from caller                     */
    str     r0, [sp, #52]

    /* Zero t[0..8] */
    movs    r0, #0
    str     r0, [sp, #0]
    str     r0, [sp, #4]
    str     r0, [sp, #8]
    str     r0, [sp, #12]
    str     r0, [sp, #16]
    str     r0, [sp, #20]
    str     r0, [sp, #24]
    str     r0, [sp, #28]
    str     r0, [sp, #32]
    str     r0, [sp, #56]          /* i = 0                              */

/* ── Outer loop: 8 iterations ──────────────────────────────────────── */
.L_outer:

    /* r11 = b[i] */
    ldr     r0, [sp, #44]
    ldr     r1, [sp, #56]
    ldr     r11, [r0, r1, lsl #2]

    ldr     r1, [sp, #40]          /* r1 = a ptr                         */

    /* ── Step 1: t[j] += a[j] * b[i], j=0..7 ── */
    movs    r12, #0

    .irp    IDX, 0, 4, 8, 12, 16, 20, 24, 28
    ldr     r0, [r1, #\IDX]
    ldr     r4, [sp, #\IDX]
    umull   r0, lr, r0, r11
    adds    r0, r0, r4
    adcs    lr, lr, #0
    adds    r0, r0, r12
    adcs    r12, lr, #0
    str     r0, [sp, #\IDX]
    .endr

    /* t[8] += carry, capture overflow in r4 */
    ldr     r0, [sp, #32]
    adds    r0, r0, r12
    movs    r4, #0
    adcs    r4, r4, #0
    str     r0, [sp, #32]

    /* ── Step 2: Montgomery reduce + right-shift ── */
    /* m = t[0] * n0 */
    ldr     r0, [sp, #0]
    ldr     r5, [sp, #52]
    mul     r11, r0, r5

    ldr     r3, [sp, #48]          /* p ptr                              */

    /* j=0: (carry, _) = t[0] + m*p[0]  — discarded (shift) */
    ldr     r5, [r3, #0]
    umull   r12, lr, r11, r5
    adds    r12, r0, r12
    adcs    r12, lr, #0

    /* j=1..7: t[j-1] = t[j] + m*p[j] + carry */
    .irp    J, 1, 2, 3, 4, 5, 6, 7
    ldr     r5, [r3, #(4*\J)]
    ldr     r0, [sp, #(4*\J)]
    umull   r6, lr, r11, r5
    adds    r6, r0, r6
    adcs    lr, lr, #0
    adds    r6, r6, r12
    adcs    r12, lr, #0
    str     r6, [sp, #(4*(\J - 1))]
    .endr

    /* t[7] = t[8] + carry; t[8] = overflow */
    ldr     r0, [sp, #32]
    adds    r0, r0, r12
    adcs    r12, r4, #0
    str     r0, [sp, #28]
    str     r12, [sp, #32]

    /* ── Loop control ── */
    ldr     r0, [sp, #56]
    adds    r0, r0, #1
    str     r0, [sp, #56]
    cmp     r0, #8
    bne     .L_outer

/* ── Final conditional subtraction: if t >= p then t -= p ──────────── */
    ldr     r3, [sp, #48]

    /* tmp = t - p  (subs/sbcs chain) */
    ldr     r0, [sp, #0]
    ldr     r1, [r3, #0]
    subs    r4, r0, r1

    ldr     r0, [sp, #4]
    ldr     r1, [r3, #4]
    sbcs    r5, r0, r1

    ldr     r0, [sp, #8]
    ldr     r1, [r3, #8]
    sbcs    r6, r0, r1

    ldr     r0, [sp, #12]
    ldr     r1, [r3, #12]
    sbcs    r7, r0, r1

    ldr     r0, [sp, #16]
    ldr     r1, [r3, #16]
    sbcs    r8, r0, r1

    ldr     r0, [sp, #20]
    ldr     r1, [r3, #20]
    sbcs    r9, r0, r1

    ldr     r0, [sp, #24]
    ldr     r1, [r3, #24]
    sbcs    r10, r0, r1

    ldr     r0, [sp, #28]
    ldr     r1, [r3, #28]
    sbcs    r11, r0, r1

    /* Subtract borrow from t[8] */
    ldr     r0, [sp, #32]
    sbcs    r0, r0, #0

    /* mask = 0 if C=1 (use sub), 0xFFFFFFFF if C=0 (keep original) */
    movs    r1, #0
    sbc     r1, r1, #0

    ldr     r3, [sp, #36]          /* result ptr                         */

    /* r[i] = (tmp[i] & ~mask) | (orig[i] & mask) */
    .macro  CT_SEL  off, tmpreg
    ldr     r0, [sp, #\off]
    bic     r12, \tmpreg, r1
    and     r0, r0, r1
    orr     r0, r0, r12
    str     r0, [r3, #\off]
    .endm

    CT_SEL  0,  r4
    CT_SEL  4,  r5
    CT_SEL  8,  r6
    CT_SEL  12, r7

    /* High regs need mov to r12 first */
    ldr     r0, [sp, #16]
    mov     r12, r8
    bic     r12, r12, r1
    and     r0, r0, r1
    orr     r0, r0, r12
    str     r0, [r3, #16]

    ldr     r0, [sp, #20]
    mov     r12, r9
    bic     r12, r12, r1
    and     r0, r0, r1
    orr     r0, r0, r12
    str     r0, [r3, #20]

    ldr     r0, [sp, #24]
    mov     r12, r10
    bic     r12, r12, r1
    and     r0, r0, r1
    orr     r0, r0, r12
    str     r0, [r3, #24]

    ldr     r0, [sp, #28]
    mov     r12, r11
    bic     r12, r12, r1
    and     r0, r0, r1
    orr     r0, r0, r12
    str     r0, [r3, #28]

    .purgem CT_SEL

    add     sp, sp, #60
    pop     {r4-r11, pc}

    .size   zkn_mul_mont_256_stk, . - zkn_mul_mont_256_stk


/* ══════════════════════════════════════════════════════════════════════
 * void zkn_sqr_mont_256(uint32_t r[8],
 *                       const uint32_t a[8],
 *                       const uint32_t p[8],
 *                       uint32_t n0);
 *
 * AAPCS: r0=r, r1=a, r2=p, r3=n0
 * Rearranges args to call mul_mont_stk(r, a, a, p, n0).
 * ══════════════════════════════════════════════════════════════════════ */

    .global zkn_sqr_mont_256
    .type   zkn_sqr_mont_256, %function
    .align  2
    .thumb_func

zkn_sqr_mont_256:
    push    {lr}
    push    {r3}                   /* n0 as 5th arg on stack              */
    mov     r3, r2                 /* r3 = p                             */
    mov     r2, r1                 /* r2 = b = a                         */
    bl      zkn_mul_mont_256_stk
    add     sp, sp, #4
    pop     {pc}

    .size   zkn_sqr_mont_256, . - zkn_sqr_mont_256


/* ══════════════════════════════════════════════════════════════════════
 * void zkn_add_mod_256(uint32_t r[8],
 *                      const uint32_t a[8],
 *                      const uint32_t b[8],
 *                      const uint32_t p[8]);
 *
 * r = (a + b) mod p, constant-time.
 * ══════════════════════════════════════════════════════════════════════ */

    .global zkn_add_mod_256
    .type   zkn_add_mod_256, %function
    .align  2
    .thumb_func

zkn_add_mod_256:
    push    {r4-r9, lr}

    /* r = a + b */
    ldr     r4, [r1, #0]
    ldr     r5, [r2, #0]
    adds    r4, r4, r5
    str     r4, [r0, #0]

    .irp    OFF, 4, 8, 12, 16, 20, 24, 28
    ldr     r4, [r1, #\OFF]
    ldr     r5, [r2, #\OFF]
    adcs    r4, r4, r5
    str     r4, [r0, #\OFF]
    .endr

    movs    r5, #0
    adcs    r5, r5, #0             /* r5 = carry_out                     */

    /* Trial: tmp = r - p (using subs/sbcs) */
    ldr     r4, [r0, #0]
    ldr     r6, [r3, #0]
    subs    r4, r4, r6
    mov     r8, r4

    ldr     r4, [r0, #4]
    ldr     r6, [r3, #4]
    sbcs    r4, r4, r6
    mov     r9, r4

    ldr     r4, [r0, #8]
    ldr     r6, [r3, #8]
    sbcs    r7, r4, r6

    /* tmp[3..7] on stack */
    .irp    OFF, 12, 16, 20, 24, 28
    ldr     r4, [r0, #\OFF]
    ldr     r6, [r3, #\OFF]
    sbcs    r4, r4, r6
    push    {r4}
    .endr

    sbcs    r5, r5, #0

    /* mask: 0 = use subtracted, -1 = keep original */
    movs    r1, #0
    sbc     r1, r1, #0

    /* Commit results (pop in reverse: tmp[7], tmp[6], ..., tmp[3]) */
    .irp    OFF, 28, 24, 20, 16, 12
    pop     {r4}
    ldr     r6, [r0, #\OFF]
    bic     r4, r4, r1
    and     r6, r6, r1
    orr     r4, r4, r6
    str     r4, [r0, #\OFF]
    .endr

    /* tmp[2] in r7 */
    ldr     r6, [r0, #8]
    bic     r7, r7, r1
    and     r6, r6, r1
    orr     r7, r7, r6
    str     r7, [r0, #8]

    /* tmp[1] in r9 */
    ldr     r6, [r0, #4]
    mov     r4, r9
    bic     r4, r4, r1
    and     r6, r6, r1
    orr     r4, r4, r6
    str     r4, [r0, #4]

    /* tmp[0] in r8 */
    ldr     r6, [r0, #0]
    mov     r4, r8
    bic     r4, r4, r1
    and     r6, r6, r1
    orr     r4, r4, r6
    str     r4, [r0, #0]

    pop     {r4-r9, pc}

    .size   zkn_add_mod_256, . - zkn_add_mod_256


/* ══════════════════════════════════════════════════════════════════════
 * void zkn_sub_mod_256(uint32_t r[8],
 *                      const uint32_t a[8],
 *                      const uint32_t b[8],
 *                      const uint32_t p[8]);
 *
 * r = (a - b) mod p.  If a < b, adds p back (constant-time).
 * ══════════════════════════════════════════════════════════════════════ */

    .global zkn_sub_mod_256
    .type   zkn_sub_mod_256, %function
    .align  2
    .thumb_func

zkn_sub_mod_256:
    push    {r4-r7, lr}

    ldr     r4, [r1, #0]
    ldr     r5, [r2, #0]
    subs    r4, r4, r5
    str     r4, [r0, #0]

    .irp    OFF, 4, 8, 12, 16, 20, 24, 28
    ldr     r4, [r1, #\OFF]
    ldr     r5, [r2, #\OFF]
    sbcs    r4, r4, r5
    str     r4, [r0, #\OFF]
    .endr

    /* mask: -1 if borrow (C=0), 0 if no borrow */
    movs    r4, #0
    sbc     r4, r4, #0

    /* Conditional add: r += p & mask */
    ldr     r5, [r0, #0]
    ldr     r6, [r3, #0]
    and     r6, r6, r4
    adds    r5, r5, r6
    str     r5, [r0, #0]

    .irp    OFF, 4, 8, 12, 16, 20, 24, 28
    ldr     r5, [r0, #\OFF]
    ldr     r6, [r3, #\OFF]
    and     r6, r6, r4
    adcs    r5, r5, r6
    str     r5, [r0, #\OFF]
    .endr

    pop     {r4-r7, pc}

    .size   zkn_sub_mod_256, . - zkn_sub_mod_256


/* ══════════════════════════════════════════════════════════════════════
 * void zkn_from_mont_256(uint32_t r[8],
 *                        const uint32_t a[8],
 *                        const uint32_t p[8],
 *                        uint32_t n0);
 *
 * Convert out of Montgomery: r = a * R^{-1} mod p.
 * Implemented as mul_mont(r, a, {1,0,...,0}, p, n0).
 *
 * AAPCS: r0=r, r1=a, r2=p, r3=n0
 *
 * Stack frame:
 *   sp+0..31  : b_one[8] = {1,0,...,0}
 *   sp+32     : saved n0
 *   sp+36     : saved lr
 * ══════════════════════════════════════════════════════════════════════ */

    .global zkn_from_mont_256
    .type   zkn_from_mont_256, %function
    .align  2
    .thumb_func

zkn_from_mont_256:
    push    {lr}
    sub     sp, sp, #36
    str     r3, [sp, #32]

    /* b_one = {1, 0, 0, 0, 0, 0, 0, 0} */
    movs    r3, #0
    str     r3, [sp, #4]
    str     r3, [sp, #8]
    str     r3, [sp, #12]
    str     r3, [sp, #16]
    str     r3, [sp, #20]
    str     r3, [sp, #24]
    str     r3, [sp, #28]
    movs    r3, #1
    str     r3, [sp, #0]

    /* mul_mont_stk(r0=r, r1=a, r2=&b_one, r3=p, [sp]=n0) */
    mov     r3, r2                 /* r3 = p                             */
    mov     r2, sp                 /* r2 = &b_one                        */
    ldr     r12, [sp, #32]
    push    {r12}                  /* n0 as 5th arg                      */
    bl      zkn_mul_mont_256_stk
    add     sp, sp, #4
    add     sp, sp, #36
    pop     {pc}

    .size   zkn_from_mont_256, . - zkn_from_mont_256

    .section .note.GNU-stack, "", %progbits

    .end
