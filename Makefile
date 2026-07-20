# ══════════════════════════════════════════════════════════════════════
#  zknox-libc — Makefile racine
#
#  Targets:
#    make            ─ build libzknox.{a,so} in build/   (default: host SW)
#    make test       ─ build and run tests in bin/
#    make test-arm32 ─ cross-compile + run under qemu-user
#    make clean      ─ remove build/ and bin/
#    make help       ─ show variables
#
#  Variables:
#    WITH_PLONK=1/0     include PLONK + Keccak + Fp2_256  (default: 1)
#    WITH_KEYS=1/0      include keys/ module              (default: 0, needs SDK)
#    WITH_MPT=1/0       include mpt/ module               (default: 1)
#    DEBUG=1/0          -O0 -g vs -O2                     (default: 0)
#
#  Backends (mutually exclusive, choose ONE):
#    ZKN_BN_BACKEND_SW       ─ pure software (default)
#    ZKN_BN_BACKEND_LEDGER   ─ Ledger SDK cx_bn_* (not usable from this Makefile)
#
#  Copyright (c) 2025 ZKNOX — MIT
# ══════════════════════════════════════════════════════════════════════

include make/modules.mk

# ── Defaults ──────────────────────────────────────────────────────────
WITH_PLONK ?= 1
WITH_KEYS  ?= 0
WITH_MPT   ?= 1
DEBUG      ?= 0
ZKNOX_DEBUG ?= 0    # 1 → compile ZKNOX_DEBUG-only code (VSS Feldman helpers, DKG)

# ── Toolchain ─────────────────────────────────────────────────────────
CC      ?= cc
AR      ?= ar
ARFLAGS  = rcs

# ── Flags ─────────────────────────────────────────────────────────────
CFLAGS  := -Wall -Wextra -Wno-unused-parameter
CFLAGS  += -DZKN_BN_BACKEND_SW
# Host-only build marker: the firmware sweeps these .c files itself and never
# uses this Makefile, so this define cleanly separates host from device.
CFLAGS  += -DZKN_HOST_BUILD
CFLAGS  += -I src/common -I src/bn -I src/compat
CFLAGS  += -I src/zkn_mont -I src/bls12381 -I src/ecc -I src/hash
CFLAGS  += -I src/mpt -I src/keys -I src/threshold -I src/aes
ifeq ($(DEBUG),1)
  CFLAGS += -O0 -g
else
  CFLAGS += -O2
endif

# makeDealerCommitments / verifyFeldmanShare (and the rest of the DKG-facing
# VSS helpers) are gated #ifdef ZKNOX_DEBUG: the DKG is a debug-only feature,
# production needs constant-time versions first. The sim passes ZKNOX_DEBUG=1
# here when built with MODE=debug, so the archive actually contains them.
ifeq ($(ZKNOX_DEBUG),1)
  CFLAGS += -DZKNOX_DEBUG
endif

# Position-independent code for the .so build
LIBFLAGS := -fPIC

# ── Output dirs ───────────────────────────────────────────────────────
BUILD := build
BIN   := bin
OBJ   := $(BUILD)/obj

# ── Sources selection based on WITH_* ─────────────────────────────────
SRCS  := $(SRCS_CORE) $(SRCS_BN_SW) $(SRCS_COMPAT)
SRCS  += $(SRCS_MONT256) $(SRCS_MONT384)
SRCS  += $(SRCS_PAIRING) $(SRCS_GROTH16)
SRCS  += $(SRCS_HASH) $(SRCS_POSEIDON_SOFT)
SRCS  += $(SRCS_CURVE) $(SRCS_EDDSA)
SRCS  += $(SRCS_FROST)
# THRESHOLD (babyfrost) needs port to zknox_1905 API — disabled for now
ifeq ($(WITH_PLONK),1)
  SRCS += $(SRCS_PLONK) $(SRCS_FP2_256)
  CFLAGS += -DZKN_WITH_PLONK
endif
ifeq ($(WITH_MPT),1)
  # mpt is .h-only for now; nothing to add to SRCS
  CFLAGS += -DZKN_WITH_MPT
endif
# ── keys/ + aes/ : comms crypto (Ed25519 ECDH-KDF, AES-256-GCM) ──────
# Both backends expose the SAME API (zkn_ed25519_ecdh.h, zkn_aes_gcm.h):
#   ZKN_BN_BACKEND_SW      → software (src/sw_crypto/, host-testable)
#   ZKN_BN_BACKEND_LEDGER  → BOLOS cx_* syscalls (device/Speculos only)
SRCS_SW_CRYPTO := src/sw_crypto/zkn_sha256_sw.c   \
                  src/sw_crypto/zkn_sha512_sw.c   \
                  src/sw_crypto/zkn_ed25519_sw.c  \
                  src/sw_crypto/zkn_aes_gcm_sw.c
SRCS_KEYS_SW   := src/keys/zkn_ed25519_ecdh_sw.c
SRCS_AES_SW    := src/aes/zkn_aes_gcm_sw_backend.c
SRCS_KEYS_CX   := src/keys/zkn_ed25519_ecdh.c
SRCS_AES_CX    := src/aes/zkn_aes_gcm.c src/aes/zkn_aes_ctr.c

ifeq ($(WITH_KEYS),1)
  # host build uses the software backend; the cx_* sources are compiled only
  # under ZKN_BN_BACKEND_LEDGER (they are #if-gated on it).
  SRCS += $(SRCS_SW_CRYPTO) $(SRCS_KEYS_SW) $(SRCS_AES_SW)
  CFLAGS += -DZKN_WITH_KEYS -I src/sw_crypto
endif

OBJS := $(SRCS:%.c=$(OBJ)/%.o)

# ── Default target ────────────────────────────────────────────────────
.PHONY: all
all: $(BUILD)/libzknox.a $(BUILD)/libzknox.so

# ── Static library ────────────────────────────────────────────────────
$(BUILD)/libzknox.a: $(OBJS)
	@echo "  AR   $@"
	@$(AR) $(ARFLAGS) $@ $^

# ── Shared library ────────────────────────────────────────────────────
$(BUILD)/libzknox.so: $(OBJS:.o=.pic.o)
	@echo "  LD   $@"
	@$(CC) -shared -o $@ $^

# ── Object rules ──────────────────────────────────────────────────────
$(OBJ)/%.o: %.c
	@mkdir -p $(dir $@)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.pic.o: %.c
	@mkdir -p $(dir $@)
	@echo "  CC-PIC $<"
	@$(CC) $(CFLAGS) $(LIBFLAGS) -c $< -o $@

# ── Tests (Phase 1) ───────────────────────────────────────────────────
include make/tests.mk

# ── House keeping ─────────────────────────────────────────────────────
.PHONY: clean
clean:
	@rm -rf $(BUILD) $(BIN)
	@echo "  CLEAN"

.PHONY: help
help:
	@echo "zknox-libc Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make              - build libzknox.{a,so} in build/"
	@echo "  make test         - build and run tests in bin/"
	@echo "  make clean        - remove build/ and bin/"
	@echo ""
	@echo "Variables (current values):"
	@echo "  WITH_PLONK = $(WITH_PLONK)"
	@echo "  WITH_KEYS  = $(WITH_KEYS)"
	@echo "  WITH_MPT   = $(WITH_MPT)"
	@echo "  DEBUG      = $(DEBUG)"
	@echo "  CC         = $(CC)"
	@echo ""
	@echo "Backend: ZKN_BN_BACKEND_SW (host build)"
