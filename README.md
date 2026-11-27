# zknox-libc

Portable C library of zero-knowledge cryptographic primitives, designed
to be embedded on hardware wallets (Ledger, Trezor) and to run on
desktop hosts for testing.

## Features

* **BLS12-381**: full pairing (Miller loop + final exp), G1/G2 arithmetic,
  Fp/Fp2/Fp4/Fp6/Fp12 tower
* **Groth16** verifier
* **PLONK** verifier (optional)
* **Poseidon** hash with circom-compatible constants
* **BLAKE-512**
* **Keccak-256**
* **BabyJubjub** and **Bandersnatch** twisted-Edwards curves
* **EdDSA-Poseidon** signing
* **FROST** threshold signatures + VSS
* **MPT** (Merkle Patricia Trie) helpers for Ethereum-style clear-signing

## Backends

The library compiles for two big-number backends, selected at build time:

| Define                     | Backend                                              |
| -------------------------- | ---------------------------------------------------- |
| `-DZKN_BN_BACKEND_LEDGER`  | Ledger SDK `cx_bn_*` (consumed by Ledger apps)       |
| `-DZKN_BN_BACKEND_SW`      | Pure software (host, Trezor firmware, qemu)          |

The high-level code (`src/ecc/`, `src/bls12381/`, etc.) is **identical**
between backends — only the bignum and hash primitives are switched.

## Build (host SW backend)

```bash
make                            # builds build/libzknox.a + build/libzknox.so
make WITH_PLONK=0               # exclude the PLONK verifier
make help                       # show all variables
```

## Configuration

The options of a build are resolved in one header,
[src/common/zkn_config.h](src/common/zkn_config.h), included first by
`zkn_bn.h`:

* An application names its own configuration header with
  `-DZKN_CONFIG_FILE='"file.h"'` (`make ZKN_CONFIG_FILE=path`). It is included
  before the defaults and holds `#define` lines: `POSEIDON_MAX_INPUTS`,
  `ZKN_POSEIDON_ARITIES`, `ZKN_FROST_MAX_SIGNERS`, or any option below.
* `ZKN_LOW_RAM` (`make ZKN_LOW_RAM=1`) is the one switch of a port to a
  target with a few kilobytes of RAM, such as the Ledger Nano S: signing and
  the threshold paths in phases, compact BLAKE-512 and `mod_mul`, and with
  the software bignums the fixed-base table read from flash
  (`ZKN_FIXEDBASE_FLASH_TABLE`) and the blinded key scalar
  (`ZKN_FIXEDBASE_SCALAR_BLINDING`). `make ZKN_FIXEDBASE_FLASH_TABLE=0` or
  `ZKN_FIXEDBASE_SCALAR_BLINDING=0` takes one out, `=1` sets it without
  `ZKN_LOW_RAM`.
* What depends on the chip or on its SDK follows the target: on Nano S, GCM
  over the AES block syscall, the two work-arounds of the cx backend and the
  Thumb-1 multiplication.

See [DECISIONS.md](DECISIONS.md), ADR-003.

License: MIT.

## Integration

This repository is intended to be consumed as a **git submodule** by:

* `zknox-ledger-app` — Ledger app uses `cx_bn_*` backend (sources picked
  up automatically by the SDK glob since they live in subdirectories)
* `zknox-trezor-firmware` — Trezor fork uses the `SW` backend
* Standalone tests on host x86 (this Makefile) and qemu-user ARM32 (TBD)

## Status

See `STATUS.md` for the current state of the convergence work and what
remains to be done.
