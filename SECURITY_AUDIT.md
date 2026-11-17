# zknox-libc — Security review and fixes

| | |
|---|---|
| Repository | `zkNoxHQ/ZKNOX-libc` |
| Reviewed commit | `2b1b212` ("Remove 7702") |
| Date | 2026-11-17 |
| Scope | All of `src/` (bignum/Montgomery, BabyJubjub/Bandersnatch, EdDSA-Poseidon, FROST, VSS, BLS12-381 pairing, Groth16, PLONK, Poseidon, BLAKE-512, Keccak, bech32m, RLP/MPT, key derivation, Ed25519 ECDH, AES-GCM, RNG) plus the test CLIs |
| Method | Manual code review; proof-of-concept exploits for the most severe findings, run against the original code; fixes; regression tests; full suite under ASan + UBSan |

## Summary

| ID | Severity | Component | Finding | PoC on original code |
|---|---|---|---|---|
| C-1 | Critical | `ecc/zkn_eddsa.c` | Signer trusts the caller's public key: **private key recovery** from two signatures | Key recovered |
| C-2 | Critical | `bls12381/zkn_miller.c` | Batched Miller loop leaves its output **uninitialised** when a pair is the point at infinity; PLONK's second pair can be steered to infinity | Output untouched |
| C-3 | Critical | `bls12381/zkn_groth16.c`, `zkn_plonk.c` | No validation of proof points (curve, subgroup, canonical) and **public inputs ≥ r accepted** (input aliasing) | `x + r` accepted |
| C-4 | Critical | `ecc/zkn_frost.c` | `zkn_partial_sig` does not consume nonces and **accepts all-zero nonces**: one extra request reveals the key share | — (by inspection) |
| H-1 | High | `ecc/zkn_vss.c` | `computeDealerShareForId(id = 0 or 2^32)` returns the **dealer's secret a0** | Secret returned |
| H-2 | High | FROST, VSS, RLP/MPT | Stack buffer overflows / out-of-bounds reads from unchecked lengths | Stack smash; 4 GiB item |
| H-3 | High | `zkn_frost_verify` | S malleable (S + order), no on-curve checks, **S = 0 hangs** the verifier | — |
| H-4 | High | FROST signing / share verification | Commitment list not validated (id 0, duplicates, ordering, own commitment, encodings); λᵢ not tied to the list | — |
| H-5 | High | `compat/zkn_rng_compat.c` | Host RNG falls back to the **predictable bytes 0,1,2,…** on failure | — |
| M-1 | Medium | `ecc/zkn_vss.c` | Feldman check: `threshold = 0` OOB read, no curve/subgroup checks; Lagrange λ = 0 on duplicate / aliased ids | — |
| M-2 | Medium | Ed25519 ECDH (both backends) | Small-order peer keys accepted, so the note-encryption key is a public constant | — |
| M-3 | Medium | `bn/zkn_bn_sw.c` | `zkn_bn_reduce` variable-time on secrets, infinite loop on a zero modulus | — |
| M-4 | Medium | EdDSA, FROST | Messages ≥ p silently reduced: one signature valid for two 32-byte messages | — |
| M-5 | Medium | `mpt/storage_proof.h`, `rlp.h` | Leaf accepted without consuming the whole key; non-canonical RLP accepted | — |
| M-6 | Medium | PLONK, Poseidon | `1 << vk->power` undefined behaviour; `zkn_poseidon(sizeout)` OOB read | — |
| L-1 … L-5 | Low | various | Broken `ByteSwap`, dead/misnamed Ledger branch, missing secret wiping, signed-overflow UB, AES/SHA argument checks | — |
| I-1 … I-8 | Info | various | Not changed (see the end of this report) | — |

All findings C-1 to L-5 are fixed on branch `security-audit-fixes`. The full
list of edits is in `git diff 2b1b212`.

---

## Critical

### C-1 — EdDSA-Poseidon: "double public key" signing oracle → private key recovery
`src/ecc/zkn_eddsa.c`, `EddsaPoseidon_Sign_final`

The nonce is deterministic, `r = BLAKE-512(prv_hi ‖ msg)`, but the challenge
`hm = Poseidon(R, Pub, msg)` includes `Pub`, which the caller passes in. If
the same message is signed twice with two different `Pub` values (for example
a host-supplied "public key"), the two signatures share `r` and
`s = (S₁ − S₂)/(h₁ − h₂) mod ℓ`.

**PoC.** Running against the original library, two calls with different `Pub`
recovered the exact secret scalar.

**Fix.** The signer re-derives the public key from `prv` (constant-time
fixed-base MSM) and refuses to sign if the caller's `Pub` differs. Secret
intermediates (nonce scalar, `s`, `s·hm`) are wiped. **Cost:** one extra
fixed-base MSM per signature.

### C-2 — Batched Miller loop returns uninitialised memory
`src/bls12381/zkn_miller.c`, `zkn_miller_loop_n`

Pairs that involve the point at infinity are skipped with `continue`. A batch
was only flushed when the buffer filled or when `j == n − 1`, so:

- **trailing infinity:** if the last pair was trivial, the pending pairs were
  never processed and `*f` was returned unwritten (stale stack contents);
- **leading infinity:** "first batch" was decided by `j < MILLER_N_MAX`, so
  after a skipped leading pair the result was multiplied into the
  uninitialised `*f`.

In the PLONK verifier the pairs are `(−A1, [x]₂), (A2, G₂)`. A prover can
choose `Wξω = O`, `[Z] = eval_zw·G` and `Wξ = −ξ⁻¹·X` so that `A2 = O`; the
verdict then depends on whatever is left on the stack, for example the
accepting `f` of a previous verification in the same frame. The generic
Groth16 verifier was affected with `π.A = 0` (the all-zero encoding was turned
into infinity).

**PoC.** `[(P,Q), (O,Q)]` left a sentinel-filled output untouched.

**Fix.** Flush when the buffer is full, flush the remainder after the loop,
track explicitly whether `f` holds a value, and return 1 for an empty
product. Proof points at infinity are also rejected where they are not legal
(Groth16).

### C-3 — Groth16 / PLONK: unvalidated inputs and public-input aliasing
`src/bls12381/zkn_groth16.c`, `src/bls12381/zkn_plonk.c`

- Proof points went through `from_affine()` only. There was no check that
  coordinates are `< p`, that the point is on the curve or twist, or that it
  is in the order-r subgroup (invalid-curve and small-subgroup inputs to the
  pairing).
- Public inputs (and PLONK evaluations) were not checked to be `< r`. Since
  `x` and `x + r` give the same `vk_x`, **a proof for statement x verifies
  for x + r**. This is the classic aliasing bug behind several nullifier
  double-spends.

**PoC.** A toy VK with known trapdoor: the valid proof for `pub = 23` was also
accepted with `pub = 23 + r`.

**Fix.** New `zkn_g1_384_from_be_checked` / `zkn_g2_384_from_be_checked`
(canonical + on-curve + optional `[r]P == O`) and
`zkn_bls12381_fr_is_canonical`. Groth16 (hardcoded and generic) rejects
infinity and non-subgroup proof points and non-canonical public inputs. PLONK
validates all proof points (infinity allowed, matching snarkjs `zeroAffine`),
public inputs and evaluations. VK points are checked for well-formedness.
**Cost on device (hardcoded Groth16):** 2 G1 and 1 G2 scalar multiplications
by r.

### C-4 — FROST signing: nonces not consumed, zero nonces accepted
`src/ecc/zkn_frost.c`, `zkn_partial_sig`

RFC 9591 nonces are single use. The library left the caller's nonce buffers
intact, so a second request with the same stored nonces gives two linear
equations in `(d, e, sk)`. Worse, the API did not reject `d = e = 0`. An
application that "safely" zeroes its nonces after use and then receives
another signing request returns `z = λ·sk·c`, which is the key share itself.

**Fix.**
- The nonces are wiped on every exit path once signing has started.
- All-zero and non-canonical nonces are refused.
- Opt-out: define `ZKN_FROST_NO_NONCE_WIPE` only if the nonces live in
  storage that cannot be written directly (NVM). The caller must then erase
  them itself.

---

## High

### H-1 — VSS returns the dealer secret for identifier 0
`computeDealerShareForId(curve, coeffs, t, id = 0)` evaluates `p(0) = a₀`. The
same happens for `id = 2³²`, because ids are truncated with `(uint32_t)`. Both
were demonstrated. Ids are now required to be in `[1, 2³²−1]`, and the
threshold to be in `[1, VSS_MAX_THRESHOLD]` (`threshold = 0` made
`threshold − 1` wrap).

### H-2 — Memory-safety bugs reachable from untrusted lengths
| Location | Bug | Fix |
|---|---|---|
| `zkn_frost_aggregate`, `zkn_frost_verify_share` | `len` unchecked; writes `len·32` bytes into `bfs[16·32]` (+ `ids[16]`). **Stack smash demonstrated** with `len = 40` | `1 ≤ len ≤ ZKN_FROST_MAX_SIGNERS` |
| `reconstructConstantFromShares` | `num_shares` unchecked against `ids[VSS_MAX_PARTICIPANTS]` | bounded |
| `rlp_decode` (long forms) | `1 + llen + slen > buf_len` computed in `uint32_t` wraps. `0xbb ff ff ff ff` in an 8-byte buffer returned an item of length 0xFFFFFFFF; up to 8 length bytes silently truncated | subtraction-based checks, `llen ≤ 4`, canonical-form checks |
| `spf_decode_compact` | writes `2·(len−1)+1` nibbles into a 128-nibble stack buffer with no bound | path ≤ 33 bytes, buffer capacity checked, flag nibble validated |
| `tests/frost_cli.c` | `len` from argv sized the hex decode into fixed buffers | bounded |

### H-3 — `zkn_frost_verify` did none of circomlib's input checks
- `(S + ℓ)·G == S·G`, so every valid signature had a second valid encoding.
  Now `S < ℓ` is required.
- `R8` and `A` were not checked to be on the curve. They are now loaded with
  the new `tEdwards_init_checked`.
- `S = 0` sent `tEdwards_scalarMul_bn` into an endless loop: after
  `SetNeutral` it fell through into a leading-bit search that never
  terminates. This was a remote DoS of any verifier. Fixed at the root.
- `8·hm·A` was computed as `((8·hm) mod ℓ)·A`. It is now `hm·(8·A)`, which
  matches circomlib exactly when `A` has a torsion component.
- Malformed input now yields `*valid = 0` with `ZKN_OK`.

### H-4 — FROST commitment list and λᵢ not validated
RFC 9591 §5.2 requires the signer to validate `commitment_list`. Added
`zkn_frost_validate_commitment_list`, used by signing, aggregation and share
verification:

- identifiers non-zero, `< ℓ`, strictly increasing (sorted and unique);
- every commitment canonical (`< p`) and on the curve. A non-canonical `x + p`
  used to change the binding factors without changing the point.

Signing also:

- recomputes `(d·G, e·G)` and requires it to equal the signer's own entry (RFC
  9591 MUST). Opt-out: `ZKN_FROST_NO_OWN_COMMITMENT_CHECK`. **Cost:** two
  fixed-base MSMs.
- **derives λᵢ from the identifiers in the list.** The `lambda_i` parameter is
  now optional (`NULL` allowed); if given, it must match.
- `zkn_frost_verify_share` now binds `commitment_i` to the list entry of
  `identifier`. Before, the binding factor and the Lagrange coefficient could
  come from different participants.
- `zkn_frost_interpolate` rejects a zero denominator, which Fermat silently
  "inverted" to 0.

### H-5 — Predictable host RNG on failure
`zkn_rng` / `zkn_trng_get_random_data` filled the buffer with `0,1,2,…` when
`/dev/urandom` could not be read (sandbox, fd exhaustion). They now use
`getrandom(2)` with a `/dev/urandom` fallback, handle short reads, and
**abort** rather than return non-random bytes. `zkn_rng_checked` zeroes the
buffer on failure.

---

## Medium

- **M-1 VSS Feldman verification:** `threshold = 0` read
  `commitments[−64]`. Commitments are now required to be canonical, on the
  curve and in the prime-order subgroup (a torsion C₀ is rejected), and
  shares must be `< ℓ`. `deriveInterpolatingValue` rejects duplicate ids, ids
  aliasing mod 2³², and `x_i` outside the quorum (all of which gave a silent
  λ = 0). Secrets are wiped on all exit paths.
- **M-2 Ed25519 ECDH:** the scalar (the note `random`) is not clamped, so a
  low-order "viewing key" (e.g. the identity `01 00…00`) made the shared point,
  and the AES key `SHA-256(shared)`, a public constant. Both the SW and
  `cx_*` backends now reject peer points with `[8]P = O` and identity
  results. The SW backend also rejects non-canonical `y`.
- **M-3 `zkn_bn_reduce`:** the old `while (r ≥ m) r −= m` ran up to ~32
  iterations depending on the top bits of secret inputs (H3 nonce
  derivation, blinding factors, Poseidon inputs) and looped forever on
  `m = 0`. It is now a constant-time restoring division whose iteration count
  depends only on the modulus. `zkn_reduce_512_be` uses a constant-time
  Montgomery round trip.
- **M-4 Message aliasing:** EdDSA and FROST hashed `msg mod p` while the
  caller saw the raw 32 bytes. Messages must now be field elements.
- **M-5 Storage proofs:** a leaf whose path did not reach the end of
  `keccak(slot)` was accepted. The leaf value is now parsed strictly, and the
  node must be exactly one RLP list. (Exploitation needs an
  attacker-controlled root, but the parser should not depend on that.)
  `spf_verify` is now `static`: it is defined in a header.
- **M-6** PLONK `vk->power` is restricted to `1..28` (`1 << 31` is UB).
  `zkn_poseidon` checks `sizeout ≤` the state width.

## Low

- **L-1 `ByteSwap`:** it swapped `data[i]` with `data[len/2 − i]`, so for 32
  bytes it only exchanged bytes 0 and 16. `tEdwards_packPoint` then OR-ed the
  sign bit into the low byte of `y` (non-injective encoding; no in-tree
  callers). Fixed. `zkn_prv_hash` now uses it instead of an unaligned
  `uint64_t*` cast (strict-aliasing UB; `LDRD` faults on unaligned addresses
  on ARMv7-M).
- **L-2 `zkn_common.c`:** the Ledger branch was guarded by
  `ZKN_BACKEND_LEDGER`, which is defined nowhere, so it never compiled. It
  also leaked handles and exported a 64-byte bignum into 32 bytes. Removed;
  the portable path is used everywhere and is now constant-time.
- **L-3 Secret hygiene:** `zkn_prv2pub` left the private scalar on the stack,
  `Sign_final` left the nonce scalar there, and `zkn_partial_sig` left its
  bignums (SW) there. The Ledger `zkn_aes256_gcm_encrypt` left the plaintext
  copy, and the SW GCM left the key schedule. All are now wiped.
  `Sign_final` also destroys four bignum handles it used to leak on the
  `cx_bn` backend.
- **L-4** `tEdwards_Coronize` fell back to factor 1 if the random blinding
  factor reduced to 0, which would otherwise give `(0:0:0)`. A leftover
  `curve->debug *= 2` counter overflowed a signed `int` (UB, flagged by UBSan)
  and was removed.
- **L-5** AES-GCM now rejects an empty nonce and `aad == NULL` with
  `aad_len > 0` (both backends). SW SHA-256/512 abort on `calloc` failure
  instead of dereferencing NULL.

## Informational (not changed)

- **I-1** `tEdwards_2MSM_precomp_table` / `tEdwards_fixedBase_2MSM` are
  variable-time. Only tests use them; a warning was added to the header.
  Secret scalars must keep using `tEdwards_fixedBase_4MSM`.
- **I-2** FROST commitments are checked on-curve but not for subgroup
  membership. This is the design decision documented in the code: torsion can
  only make the final signature fail, which is a DoS the coordinator can cause
  anyway.
- **I-3** The SW AES uses table lookups (cache-timing). It is host-only.
- **I-4** On the `cx_bn` backend several functions leak pool handles on error
  paths, and `zkn_frost_challenge` never frees its throwaway curve. This is
  pool exhaustion, not disclosure, since `cx_bn_unlock` wipes the pool.
- **I-5** `zkn_bn_mod_add/sub` perform one conditional subtraction, so
  operands must already be reduced. Inputs are now validated at the API
  boundaries; keep this contract in mind for new code.
- **I-6** `zkn_0zk_decode` does not check the version byte or the network ID.
- **I-7** `test_miller_384`: 7 checks fail exactly as before. They are the
  "known-invalid" cases documented in `tests/README.md`, because the raw
  Miller loop is not bilinear before the final exponentiation.
- **I-8 Not covered here:** the Ledger (`cx_*`) build. There is no Ledger SDK
  in this environment, so the edits to `zkn_ed25519_ecdh.c` and
  `zkn_aes_gcm.c` are compile-untested. PLONK was not tested end-to-end
  because the repo has no snarkjs vectors; its changes are input validation
  plus the shared Miller-loop fix.

---

## Behaviour changes integrators must know about

1. **`zkn_partial_sig` consumes the nonces**: both nonce buffers are zeroed,
   so they must be writable. See `ZKN_FROST_NO_NONCE_WIPE` above.
2. `zkn_partial_sig` additionally:
   - rejects zero or non-canonical nonces, `sk ≥ ℓ` and `msg ≥ p`;
   - requires the commitment list sorted by strictly increasing non-zero id;
   - checks the signer's own commitment (`ZKN_FROST_NO_OWN_COMMITMENT_CHECK`
     opts out);
   - treats `lambda_i` as optional and requires it to match the list.
3. **`EddsaPoseidon_Sign_final` requires `Pub` to be the key of `prv`** and
   `msg < p`.
4. `zkn_frost_verify` returns `valid = 0` for `S ≥ ℓ`, off-curve points and
   `msg ≥ p`.
5. Groth16/PLONK verification is stricter and slower. See C-3 for the cost.
6. RLP has a new error, `RLP_ERR_NONCANONICAL`. `spf_verify` is `static`.
7. On a failing host RNG, `zkn_rng`/`zkn_trng_get_random_data` abort.
8. VSS functions reject id 0, ids above 2³²−1, `threshold = 0` and oversized
   inputs.
9. Two test vectors were corrected:
   - `test_frost_host`: a "nonce" that was larger than the subgroup order.
   - `test_sign_host`: variant B signs a message ≥ p, which is now refused,
     as it should be.
10. New APIs:
    - `tEdwards_init_checked`, `tEdwards_IsNeutral`, `tEdwards_IsInSubgroup`
    - `zkn_g{1,2}_384_from_be_checked`, `zkn_g{1,2}_384_in_subgroup`
    - `zkn_bls12381_fr_is_canonical`, `zkn_bls12381_fp_is_canonical`,
      `zkn_bls12381_r_be`

## Verification

- `make test` (FROST + debug): **24/24 suites pass**, including the new
  `tests/test_security_regressions.c` with **65 checks**, one or more per
  finding. A `WITH_KEYS=1` build adds the ECDH section (68/68).
- The same suite with the library and tests built with
  `-fsanitize=address,undefined` reports **no ASan or UBSan errors**.
- `make`, `make WITH_PLONK=0` and `make ZKNOX_DEBUG=1 ZKN_FROST=1` build with
  **zero warnings**. The 8 warnings in `WITH_KEYS=1` builds predate these
  changes.
- Existing KATs still pass: circomlibjs public key, Poseidon, BLAKE-512, RFC
  9591 hashes, pairing and final-exponentiation vectors.
- The proof-of-concepts for C-1, C-2, C-3, H-1 and H-2 succeed on `2b1b212`
  and fail on the patched tree.

## Follow-up: second review of the fixes

The fixes were reviewed again, finding by finding: exhaustive Miller-loop
infinity masks, independently generated off-subgroup BLS12-381 points,
`zkn_bn_reduce` against big-int references on ~24k vectors, genuine MPT
storage proofs, RLP fuzzing under ASan, small-order Ed25519 encodings, and
non-contiguous FROST quorums with derived λ. All findings hold. The gaps found
were fixed on top:

- **UBSan in `WITH_KEYS=1` builds** (the original sanitizer run did not cover
  them): left shift of a negative value in `car25519` (TweetNaCl port) and
  `uint8_t << 24` overflowing `int` in SW SHA-256. Both predate the review.
- **M-6:** the Ledger `Poseidon()` path had no `sizeout` bound either.
- **L-3:** EdDSA signing (SW backend) now also wipes `bn_hi`/`bn_lo` (the
  BLAKE-512 nonce halves) and `hm` (holds r before S is computed); SW
  `zkn_bn_alloc_init` wipes its staging buffer. The SW GCM key schedule and
  SW ECDH scratch were wiped with `memset`, which GCC removes at `-O2` as
  dead stores; now `explicit_bzero`.
- **C-4 / H-4:** the canonicality check on the secret nonces and `sk` in
  `zkn_partial_sig` is now a constant-time borrow compare.
- `spf_verify` checks for a NULL node before hashing it.
- Docs: `zkn_frost.h` (nonces consumed, `lambda_i` optional) and
  `zkn_groth16.h` (public inputs must be reduced mod r).
  `tests/verify_sigs.mjs` now expects sigB (msg ≥ p) to be refused; sigA
  still verifies against circomlibjs.

`make WITH_KEYS=1 test` under ASan + UBSan: 24 suites, 68/68 regressions, no
reports.

Open, to check on a device (cannot be built here):

- FROST signing on `cx_bn`: the λ derivation holds `len` + 4 handles while the
  curve is allocated. Large quorums (≳ 8) may exceed the previous pool peak.
- Ed25519 ECDH on `cx_*`: if the firmware blinds the scalar as `k + r·ℓ`
  rather than randomising coordinates, the `[8]P = O` small-order test is
  unreliable (the identity input is still rejected).
- No snarkjs fixtures exist for the hardcoded Groth16 or PLONK verifiers, so
  valid-proof acceptance is only covered by the generic Groth16 toy VK.
