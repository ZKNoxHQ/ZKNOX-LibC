# ══════════════════════════════════════════════════════════════════════
#  modules.mk — source file groupings
#
#  Each group is a logical chunk of the library. They can be opted in
#  or out independently from the root Makefile via WITH_* variables.
# ══════════════════════════════════════════════════════════════════════

# Core: error codes, common helpers
SRCS_CORE      := src/common/zkn_common.c

# Big number backends
SRCS_BN_SW     := src/bn/zkn_bn_sw.c
SRCS_BN_LEDGER := src/bn/zkn_bn_ledger.c

# Hash + RNG compat (only built in SW mode; on Ledger the SDK provides everything)
SRCS_COMPAT    := src/compat/zkn_hash_compat.c src/compat/zkn_rng_compat.c

# Montgomery 256-bit (used by bn_sw + Poseidon soft + Fp2 256)
SRCS_MONT256   := src/zkn_mont/zkn_mont256.c
SRCS_FP2_256   := src/zkn_mont/zkn_fp2.c
SRCS_POSEIDON_SOFT := src/zkn_mont/zkn_poseidon_soft.c

# Montgomery 384-bit (BLS12-381 field arithmetic)
SRCS_MONT384   := src/bls12381/zkn_sw_mont384.c

# BLS12-381 pairing
SRCS_PAIRING   := src/bls12381/zkn_fp2_384.c \
                  src/bls12381/zkn_fp4_384.c \
                  src/bls12381/zkn_fp6_384.c \
                  src/bls12381/zkn_fp12_384.c \
                  src/bls12381/zkn_g1_384.c \
                  src/bls12381/zkn_g2_384.c \
                  src/bls12381/zkn_miller.c \
                  src/bls12381/zkn_pairing_384.c \
                  src/bls12381/zkn_final_exp_384.c

# Groth16 verifier
SRCS_GROTH16   := src/bls12381/zkn_groth16.c

# PLONK verifier (optional, depends on Keccak)
SRCS_PLONK     := src/bls12381/zkn_plonk.c \
                  src/bls12381/zkn_keccak256.c

# Hash functions.
# zkn_poseidon_constants.c carries the production-tested arity-5 Poseidon
# (Poseidon_alloc_init / Poseidon / Poseidon_destroy, poseidon_ctx_t). Its
# body is guarded by `#ifdef ZKN_BN_BACKEND_LEDGER`, so the .o is empty on
# SW-backend builds. The SW-backend variable-arity equivalent lives in
# SRCS_POSEIDON_SOFT, guarded by `#ifndef ZKN_BN_BACKEND_LEDGER`. Callers
# include `zkn_poseidon.h`, a thin wrapper that picks the right backend.
SRCS_HASH      := src/hash/zkn_blake512.c \
                  src/hash/zkn_poseidon.c \
                  src/hash/zkn_poseidon_constants.c \
                  src/hash/zkn_rfc9591frost.c \
                  src/hash/zkn_bech32m.c

# AES-GCM (Ledger-only wrapper over BOLOS cx_aes_gcm_*; gated by WITH_KEYS)
SRCS_AES       := src/aes/zkn_aes_gcm.c

# Curve operations: twisted Edwards (BabyJubjub, Bandersnatch)
SRCS_CURVE     := src/ecc/zkn_tEdwards.c \
                  src/ecc/bbjj_precomp.c \
                  src/ecc/bandersnatch_precomp.c

# EdDSA-Poseidon signing
SRCS_EDDSA     := src/ecc/zkn_eddsa.c

# FROST threshold signatures + VSS
SRCS_FROST     := src/ecc/zkn_frost.c \
                  src/ecc/zkn_vss.c


# Ledger BIP32 key derivation (Ledger-only)
SRCS_KEYS      := src/keys/zkn_keyderivation.c \
                  src/keys/zkn_ed25519_scalar.c \
                  src/keys/zkn_ed25519_ecdh.c
