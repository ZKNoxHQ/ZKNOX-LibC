# zknox-libc tests — Phase 1 + Phase 2

This directory contains 15 standalone C test programs. Each is built
against `build/libzknox.a` via `make test`.

## Coverage

### Phase 1 — Primitives (algebraic property tests)

| Test                     | Tests | Status |
| ------------------------ | ----- | ------ |
| `test_mont384`           |   46  | ✅ PASS |
| `test_fp2_384`           |   42  | ✅ PASS |
| `test_fp4_384`           |   25  | ✅ PASS |
| `test_fp6_384`           |   46  | ✅ PASS |
| `test_fp12_384`          |   61  | ✅ PASS |
| `test_g1_384`            |   45  | ✅ PASS |
| `test_g2_384`            |   47  | ✅ PASS |
| `test_miller_384`        | 9/16  | ⚠️  see below |
| `test_final_exp_384`     |   10  | ✅ PASS |
| `test_mul_by_014`        |    8  | ✅ PASS |
| `test_pairing_384`       |   12  | ✅ PASS |

**Subtotal: 349/356 passing.**

### Phase 2 — Renamed APIs (smoke tests)

| Test                | Tests | Origin | Notes |
| ------------------- | ----- | ------ | ----- |
| `test_poseidon_soft`|   27  | sources.zip, unchanged | API unchanged between branches |
| `test_poseidon_arities`| 14 | known answers from poseidon-lite | Poseidon-1 .. Poseidon-7 through `zkn_poseidon_hash`: each arity has its own table |
| `test_poseidon_opt` | 25 | known answers from the reference rounds of `tools/gen_poseidon_opt.py --kat` | initState and all t outputs over BN254, Poseidon-5 over BLS12-381 Fr (Bandersnatch), context reuse, what `zkn_poseidon_init` refuses |
| `test_poseidon`     |   11  | rewritten for zknox_1905 | New `Poseidon_alloc_init/Poseidon` API |
| `test_rfc9591frost` |   23  | written from scratch   | Tests `Babyfrost_H1/H3/H4/H5/H6` (domain separation, determinism) |
| `test_vss`          |   20  | written from scratch   | Tests `makeDealerCoeffsDeterministic`; full VSS pending (only 1 of 7 functions implemented in `zkn_vss.c`) |

**Subtotal: 106/106 passing.**

### Total: 457 tests passing.

### Poseidon against circomlibjs (`make poseidon-diff`)

Not part of `make test` (needs node, and `npm install` in `js/`).
`js/poseidon_diff.mjs` draws vectors from the OS CSPRNG, hashes them with the
library through `tests/poseidon_cli.c` and compares every output:

* BN254, Poseidon-1 .. Poseidon-7: 10000 vectors per arity against
  circomlibjs `buildPoseidon` (wasm) and `buildPoseidonReference`, then 1000
  with a random initState, all t outputs and inputs above p;
* BLS12-381 Fr, Poseidon-5: the same batches against the reference rounds in
  BigInt with the circomlibjs constants (circomlibjs is BN254 only).

`make poseidon-diff POSEIDON_DIFF_ARGS="--count 1000"` for a shorter run.

The default tables have no sparse round (see `tools/gen_poseidon_opt.py
--sparse`), so neither `make test` nor this target runs the sparse linear
layer. After regenerating the tables with sparse rounds, run both.

## Note on `test_miller_384`

7 of the 16 cases in `test_miller_384` are mathematically invalid as
written. They test bilinearity properties of the BLS12-381 pairing on
the **raw** Miller loop output, without applying the final exponentiation.
This is wrong: the raw Miller output is not in the order-r subgroup, so
bilinearity doesn't hold until `final_exp` projects it correctly.

The same properties **do** pass in `test_pairing_384` (which uses
`zkn_pairing()` = Miller + final exp). The cryptography is correct; only
the test file has a design flaw inherited from sources.zip.

## Note on VSS

`zkn_vss.h` (from zknox_1905) declares 7 public functions, but only
`makeDealerCoeffsDeterministic` is currently implemented in `zkn_vss.c`.
The 6 others (`evalPolySubgroup`, `makeDealerCommitments`,
`computeDealerShareForId`, `verifyFeldmanShare`, `deriveInterpolatingValue`,
`reconstructConstantFromShares`) are declared but lack implementation.
`test_vss.c` is scoped to the implemented function pending the others.

## Note on stack usage

Several tests in Phase 2 (`test_poseidon`) use `static` storage for
large bignum locals to avoid stack-frame overflow detected by
`-fstack-protector-strong`. The combination of:
  - `zkn_bn_t` = 32 bytes (vs 4-byte handle on Ledger)
  - `poseidon_ctx_t` ~ 1600 bytes
  - `Poseidon_alloc_init` declaring a 1152-byte local `MixColumn[]`
…easily exceeds default stack frames. This is documented for future
attention on embedded targets where stack budgets are tight.
