# zknox-libc status

## What works (v0.2.5)

### v0.2.5 — Guard host tests with #ifdef ZKN_HOST_TESTS

When zknox-libc is consumed as a submodule by a Ledger app, the SDK's
recursive source glob picks up everything under `src/zknox/`, including
`src/zknox/tests/test_*.c`. These test programs are written for the SW
backend (`zkn_bn_t = uint32_t[8]`) and don't compile against the Ledger
backend (`zkn_bn_t = uint32_t` handle).

The standard SDK exclusion mechanism (`APP_SOURCES_EXCLUDE`) appears not
to be recognized in the current Ledger app builder image, so the only
robust fix is at the source level.

Fix: wrap every `tests/test_*.c` in `#ifdef ZKN_HOST_TESTS ... #endif`.
The libC's own Makefile passes `-DZKN_HOST_TESTS` when compiling tests
(make/tests.mk). Other consumers (Ledger, Trezor) see the files as
empty `.o` artifacts when their recursive glob picks them up.

## What works (v0.2.4)

### v0.2.4 — Self-contained error codes in zkn_poseidon_soft

* `src/zkn_mont/zkn_poseidon_soft.c` uses `ZKN_OK` and `ZKN_INVALID_PARAM`
  but only declared `ZKN_NOT_INITIALIZED` in its own block. On SW
  builds, the missing symbols come transitively from `zkn_bn_sw.h`.
  On Ledger builds, neither is provided, causing
  "use of undeclared identifier 'ZKN_OK'" errors.

  Fix: declare all three codes with `#ifndef` guards (so the file remains
  standalone regardless of include order or backend).

## What works (v0.2.3)

### v0.2.3 — Two more Ledger build fixes

* `src/bn/zkn_bn.h`: added missing `zkn_mont_pow` alias for the Ledger
  backend. The function was implemented in `zkn_bn_sw.h` but not aliased
  to `cx_mont_pow` for the Ledger backend, causing
  "warning: implicit declaration of function 'zkn_mont_pow'" when
  `zkn_poseidon_constants.c` was compiled in Ledger mode.

* `src/threshold/babyfrost.{c,h}`: wrapped both files entirely in
  `#ifdef ZKN_WITH_BABYFROST`. Since the file targets the old sources.zip
  API (zkn_poseidon.h, zkn_frost_hasher.h, zkn_frost_vss.h — none of
  which exist in zknox_1905), it cannot compile in Ledger builds.
  The guard makes the .o silently empty unless the consumer opts in
  via `DEFINES += ZKN_WITH_BABYFROST`. This is more robust than relying
  on the Makefile's `APP_SOURCES_EXCLUDE` which doesn't seem to be
  recognized by all versions of the Ledger SDK.

## What works (v0.2.2)

### v0.2.2 — Missing typedef in Ledger backend router

* `src/bn/zkn_bn.h`: the Ledger backend section was missing the
  `zkn_bn_mont_ctx_t` alias. The SW backend's `zkn_bn_sw.h` exposes
  this name, but the Ledger router only had `zkn_mont_ctx_t`
  (different name with no `_bn_`). High-level code in
  `zkn_tEdwards.h`, `zkn_poseidon_constants.h`, etc. uses
  `zkn_bn_mont_ctx_t`, so Ledger build failed with
  "unknown type name 'zkn_bn_mont_ctx_t'".
  Fix: added `typedef cx_bn_mont_ctx_t zkn_bn_mont_ctx_t` alongside
  the existing `zkn_mont_ctx_t` typedef. Both names now resolve in
  both backends.

## What works (v0.2.1)

### v0.2.1 — Critical comment fix

* `src/bn/zkn_bn.h` line 24: a `*/` inside a block comment was prematurely
  closing the comment, causing the compiler to try parsing the text that
  followed as C code. This produced cryptic errors like
  "error: unknown type name 'cx_mont_'" and Unicode character errors when
  the same file was consumed via submodule by the Ledger app build.
  The fix: replaced `cx_bn_*/cx_mont_*` with `cx_bn_ and cx_mont_` in the
  comment text. Audited entire codebase: no other instances of the same
  bug.

## What works (v0.2.0)

### v0.2.0 — Aligned with ZKN-NANOBOX main branch
* Imported Simon's "Coronize +" optimization (commit `363f2d6` in
  ZKN-NANOBOX) in `tEdwards_fixedBase_2MSM` and `tEdwards_fixedBase_4MSM`:
  table points T[1..n] are now coronized once into byte arrays (`CT_x`,
  `CT_y`, `CT_z`) and reused, instead of re-coronizing on each iteration.
  Reduces RAM pressure and compute time in the inner MSM loop.
* All previous tests still pass (432 / 432).

### Phase 0 — Skeleton (v0.1.0)
* Modular structure (`src/{bls12381,bn,ecc,hash,keys,mpt,zkn_mont,threshold,common,compat}/`)
* Dual-backend big-number layer (`ZKN_BN_BACKEND_LEDGER/_SW`)
* Compat layer (hash, RNG)
* ~500 lines of `cx_*` → `zkn_*` bulk conversion
* `make` produces `build/libzknox.{a,so}` on host x86

### Phase 1 — Primitives tests (v0.1.1)
* 11 standalone test programs
* 349/356 algebraic tests pass (7 documented test-design flaws)

### Phase 2 — Renamed APIs (v0.1.2)
* `test_poseidon_soft`, `test_poseidon`, `test_rfc9591frost`, `test_vss`
* +81/81 passing

### v0.1.3/v0.1.4 — GCC 14+ compatibility
* Fix incompatible-pointer-types in zkn_frost.c, zkn_eddsa.c
* Fix dangling-pointer in tEdwards_Curve_alloc_init (static const arrays)
* Fix unused-function on keccak256 helpers
* Fix implicit-declaration in test_miller_384.c

### Total: 432 tests passing, zero warnings, zero errors on GCC 14.

## Convergence status vs ZKN-NANOBOX main

After diff against Simon's `ZKN-NANOBOX/src/zknox/`:
* Most files identical after `cx_*` → `zkn_*` normalization.
* Only meaningful divergence was the "Coronize +" optimization in
  `zkn_tEdwards.c` → now integrated in v0.2.0.
* Our GCC 14+ fixes are preserved (they should be back-merged to
  ZKN-NANOBOX as well to keep the two trees in sync).

## What does NOT work yet

* **Phase 3 tests** (`test_babyfrost`, `test_eddsa`, `test_groth16`,
  `test_plonk`, `test_frost_full`) — need new APIs and port of
  `babyfrost.{c,h}` (still using sources.zip API)
* **`src/threshold/babyfrost.{c,h}`** — EXCLUDED from default build
* **6 of 7 VSS functions** declared in `zkn_vss.h` but not implemented
* **qemu-user ARM32** not wired up
* **JS test harness** not yet created

## Roadmap

1. ✅ Phase 0 — Skeleton + bulk conversion      (v0.1.0)
2. ✅ Phase 1 — Primitives tests                (v0.1.1)
3. ✅ Phase 2 — Renamed APIs                    (v0.1.2)
4. ✅ v0.1.3/v0.1.4 — GCC 14+ compatibility
5. ✅ v0.2.0 — Aligned with ZKN-NANOBOX main
6. Phase 3 — Migrate RAILGUN to submodule (uses v0.2.0)
7. Phase 4 — qemu-user ARM32 + ARM asm           (~½ day)
8. Phase 5 — JS test harness                      (~2 days)
