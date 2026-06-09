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

# ── Toolchain ─────────────────────────────────────────────────────────
CC      ?= cc
AR      ?= ar
ARFLAGS  = rcs

# ── Flags ─────────────────────────────────────────────────────────────
CFLAGS  := -Wall -Wextra -Wno-unused-parameter
CFLAGS  += -DZKN_BN_BACKEND_SW
CFLAGS  += -I src/common -I src/bn -I src/compat
CFLAGS  += -I src/zkn_mont -I src/bls12381 -I src/ecc -I src/hash
CFLAGS  += -I src/mpt -I src/keys -I src/threshold -I src/aes
ifeq ($(DEBUG),1)
  CFLAGS += -O0 -g
else
  CFLAGS += -O2
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
ifeq ($(WITH_KEYS),1)
  SRCS += $(SRCS_KEYS) $(SRCS_AES)
  $(warning keys/ and aes/ modules need the Ledger SDK; SW build will fail.)
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
