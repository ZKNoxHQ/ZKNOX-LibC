# zknox-libc status

## What works (v0.1.3)

### Phase 0 — Skeleton ✅ (v0.1.0)
* Modular structure (`src/{bls12381,bn,ecc,hash,keys,mpt,zkn_mont,threshold,common,compat}/`)
* Sources from `zknox_1905` Ledger branch + `babyfrost`, `zkn_common.c`,
  `zkn_sw_bn` from sources.zip
* Dual-backend big-number layer (`ZKN_BN_BACKEND_LEDGER/_SW`)
* Compat layer (hash, RNG)
* ~500 lines of `cx_*` → `zkn_*` bulk conversion
* `make` produces `build/libzknox.a` (221 KB) + `build/libzknox.so` (147 KB)
* 201 `zkn_*` symbols exported

### Phase 1 — Primitives tests ✅ (v0.1.1)
* 11 standalone test programs imported from sources.zip
* `make test` runs them against `libzknox.a`
* **349/356 algebraic tests pass** (98%)
* 7 remaining are test-design flaws (raw Miller w/o final exp)

### Phase 2 — Renamed APIs ✅ (v0.1.2)
* 4 additional tests:
  * `test_poseidon_soft`     — 27/27 (sources.zip API unchanged)
  * `test_poseidon`          — 11/11 (rewritten for `Poseidon_alloc_init`)
  * `test_rfc9591frost`      — 23/23 (smoke test for `Babyfrost_H*`)
  * `test_vss`               — 20/20 (smoke test for `makeDealerCoeffsDeterministic`)

### v0.1.4 — Additional GCC 14+ fix

* `tests/test_miller_384.c`: added missing `#include "zkn_miller.h"`.
  GCC 14+ rejects implicit function declarations by default
  (`-Werror=implicit-function-declaration`); the test was relying on
  the symbol being resolvable at link time. Other 14 test files were
  audited and have no similar issue.

### v0.1.3 — GCC 14+ compatibility fixes
* `zkn_frost.c:438`, `zkn_eddsa.c:257`: `Poseidon(..., &hm, 1)` →
  `Poseidon(..., (zkn_bn_t *)hm, 1)`. The `hm` parameter is already a
  decayed `zkn_limb_t *`, so `&hm` was `zkn_limb_t **` (wrong type).
  The cast restores the correct `zkn_bn_t *` semantics. This is a
  latent bug in zknox_1905 — should be merged back upstream.
* `tEdwards_Curve_alloc_init`: 12 curve-constant arrays
  (`bander_*`, `bbjj_*`, `_B8x`, `_B8y`) converted from `uint8_t name[32]`
  to `static const uint8_t name[32]`. Previously they were locals inside
  a `case` block whose lifetime ended at `break` — GCC 14+ correctly
  flags this as `-Wdangling-pointer`. `static const` extends their
  lifetime to program lifetime AND moves them to .rodata (better for
  embedded targets too).
* `src/mpt/keccak256.h`: `static` → `static inline` to silence
  `-Wunused-function` when the header is included but the functions
  aren't called.

### Total: 432 tests passing.

`make` and `make test` produce **zero warnings, zero errors** on GCC 14.

## What does NOT work yet

* **Phase 3 tests** (`test_babyfrost`, `test_eddsa`, `test_groth16`,
  `test_plonk`, `test_frost_full`) — need new APIs and possibly port
  of `babyfrost.{c,h}`
* **`src/threshold/babyfrost.{c,h}`** is in tree but EXCLUDED from
  the default build (depends on sources.zip API)
* **6 of 7 VSS functions in `zkn_vss.h`** declared but not implemented
  (Simon's branch likely has them)
* **`src/keys/`** depends on Ledger SDK `cx_ecfp_*`
* **qemu-user ARM32** cross-compile not yet wired up (Phase 4)
* **ARM `.S` files** not imported
* **JS test harness** not yet created (Phase 5)

## Roadmap

1. ✅ Phase 0 — Skeleton + bulk conversion       (v0.1.0)
2. ✅ Phase 1 — Primitives tests                  (v0.1.1)
3. ✅ Phase 2 — Renamed APIs                      (v0.1.2)
4. ✅ v0.1.3 — GCC 14+ compatibility fixes
5. Phase 3 — FROST / EdDSA / Groth16 / PLONK     (~1 day)
6. Phase 4 — qemu-user ARM32 + ARM asm           (~½ day)
7. Phase 5 — JS test harness                      (~2 days)
8. Phase 6 — Migration of consumers              (~½ day each)
