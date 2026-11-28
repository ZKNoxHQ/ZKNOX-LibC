/*
 * zkn_config.h — build configuration of the library, resolved in one place.
 *
 * zkn_bn.h includes this file first, so every source that uses the bignums
 * sees the same options. The few files that test an option without the
 * bignums include it themselves.
 *
 * Three inputs, in this order.
 *
 * 1. The file of the application. An application that sizes the library for
 *    its own use names a header on the command line,
 *        -DZKN_CONFIG_FILE='"my_config.h"'
 *    and that header is included here, before the defaults below. It holds
 *    #define lines only (POSEIDON_MAX_INPUTS, ZKN_POSEIDON_ARITIES,
 *    ZKN_FROST_MAX_SIGNERS, or any option of this file). Without it the
 *    library keeps its defaults. An option given with -D still wins when the
 *    file guards its lines with #ifndef.
 *
 * 2. ZKN_LOW_RAM, the one switch of a port to a target with a few kilobytes
 *    of RAM (Ledger Nano S: 4.6 KB for statics and stack together). In the
 *    sources it selects the low-RAM variants: signing and the threshold paths
 *    in phases, compact BLAKE-512 and mod_mul, a quorum of 5. Here it adds
 *    what goes with them on the software bignums:
 *
 *      ZKN_FIXEDBASE_FLASH_TABLE      fixed-base multiplication over the
 *                                     16-entry table read from flash, 64
 *                                     steps, no table in RAM
 *      ZKN_FIXEDBASE_SCALAR_BLINDING  the public key derivation multiplies by
 *                                     the private scalar plus a random
 *                                     multiple of the subgroup order
 *
 *    Each of the two is still an option of its own. Defined without
 *    ZKN_LOW_RAM it applies alone. ZKN_FIXEDBASE_NO_FLASH_TABLE and
 *    ZKN_FIXEDBASE_NO_SCALAR_BLINDING take it out of the profile: without the
 *    flash table the fixed-base multiplication of ZKN_LOW_RAM is the one of
 *    the cx backend, two windows and a randomized table in RAM.
 *
 * 3. The target. What depends on the chip or on its SDK follows the target,
 *    with no switch to set:
 *
 *      ZKN_AES_GCM_OVER_CX_AES   Nano S: the cxng of its SDK has no
 *                                cx_aes_gcm_*, GCM is built on the AES block
 *                                syscall (aes/zkn_gcm_ct.c). Set below.
 *      ZKN_CX_NO_ALIAS           Nano S, cx backend: two faults of the
 *      ZKN_CX_UNREDUCED          coprocessor worked around. Set in zkn_bn.h,
 *                                next to the code they select.
 *      Montgomery multiplication the Thumb-1 assembly enables itself on an
 *                                ARMv6-M core, and ZKN_MONT256_ASM (Thumb-2
 *                                assembly) is dropped on a core without
 *                                Thumb-2. Both in zkn_mont/zkn_mont256.c.
 */
#ifndef ZKN_CONFIG_H
#define ZKN_CONFIG_H

/* ── 1. The file of the application ─────────────────────────────────── */
#if defined(ZKN_CONFIG_FILE)
#  include ZKN_CONFIG_FILE
#endif

/* ── 2. The low-RAM profile ─────────────────────────────────────────── */
#if defined(ZKN_FIXEDBASE_FLASH_TABLE) && defined(ZKN_FIXEDBASE_NO_FLASH_TABLE)
#  error "ZKN_FIXEDBASE_FLASH_TABLE and ZKN_FIXEDBASE_NO_FLASH_TABLE are both defined"
#endif
#if defined(ZKN_FIXEDBASE_SCALAR_BLINDING) && defined(ZKN_FIXEDBASE_NO_SCALAR_BLINDING)
#  error "ZKN_FIXEDBASE_SCALAR_BLINDING and ZKN_FIXEDBASE_NO_SCALAR_BLINDING are both defined"
#endif

#if defined(ZKN_LOW_RAM) && defined(ZKN_BN_BACKEND_SW)
#  if !defined(ZKN_FIXEDBASE_FLASH_TABLE) && !defined(ZKN_FIXEDBASE_NO_FLASH_TABLE)
#    define ZKN_FIXEDBASE_FLASH_TABLE 1
#  endif
#  if defined(ZKN_FIXEDBASE_FLASH_TABLE) && !defined(ZKN_FIXEDBASE_SCALAR_BLINDING) \
      && !defined(ZKN_FIXEDBASE_NO_SCALAR_BLINDING)
#    define ZKN_FIXEDBASE_SCALAR_BLINDING 1
#  endif
#endif

/* ── 3. The target ──────────────────────────────────────────────────── */
/* A device build has the SDK on its include path, and the SDK names the
 * target in bolos_target.h. A host build (ZKN_HOST_BUILD, the Makefile of the
 * library) has neither. */
#if !defined(ZKN_HOST_BUILD) && !defined(__ASSEMBLER__) && defined(__has_include)
#  if __has_include("bolos_target.h")
#    include "bolos_target.h"
#  endif
#endif

#if defined(TARGET_NANOS) && !defined(ZKN_AES_GCM_OVER_CX_AES)
#  define ZKN_AES_GCM_OVER_CX_AES 1
#endif

#endif /* ZKN_CONFIG_H */
