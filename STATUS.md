# zknox-libc status

## What works (v0.1.2)

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
* 7 remaining are documented test-design flaws (raw Miller without final exp)

### Phase 2 — Renamed APIs ✅ (v0.1.2)
* 4 additional tests now in the suite:
  * `test_poseidon_soft`     — 27/27 (unchanged from sources.zip)
  * `test_poseidon`          — 11/11 (rewritten for `Poseidon_alloc_init` API)
  * `test_rfc9591frost`      — 23/23 (new smoke test for `Babyfrost_H*`)
  * `test_vss`               — 20/20 (smoke test, scope-limited)
* **432 total tests pass**
* `make test` exits 0 with `ALL PHASE 1 TESTS PASSED (15 suites)`

## What does NOT work yet

* **Phase 3 tests** (`test_babyfrost`, `test_eddsa`, `test_groth16`,
  `test_plonk`, `test_frost_full`) need the new APIs and possibly
  port of `babyfrost.{c,h}` to `zkn_rfc9591frost`/`zkn_vss`/`zkn_poseidon_constants`
* **`src/threshold/babyfrost.{c,h}`** is in tree but EXCLUDED from
  the default build — depends on sources.zip API
* **6 of 7 VSS functions in `zkn_vss.h`** are declared but not yet
  implemented in `zkn_vss.c` (likely on Simon's branch)
* **`src/keys/`** depends on Ledger SDK `cx_ecfp_*`; built only with
  `WITH_KEYS=1` and Ledger backend
* **qemu-user ARM32** cross-compile not yet wired up (Phase 4)
* **ARM `.S` files** not imported (`zkn_mont256_arm32.S`, `zkn_sw_mont384_arm32.S`)
* **JS test harness** not yet created (Phase 5)

## Roadmap

1. ✅ Phase 0 — Skeleton + bulk conversion       (v0.1.0)
2. ✅ Phase 1 — Primitives tests                  (v0.1.1)
3. ✅ Phase 2 — Renamed APIs                      (v0.1.2)
4. Phase 3 — FROST / EdDSA / Groth16 / PLONK     (~1 day)
5. Phase 4 — qemu-user ARM32 + ARM asm           (~½ day)
6. Phase 5 — JS test harness                      (~2 days)
7. Phase 6 — Migration of consumers              (~½ day each)
