# Phase 6: mitigating the CWEs that remain under Rust and Corten

Status: **in progress** (started 2026-11-01). The plan is [`../residual-mitigation.md`](../residual-mitigation.md); the per-CWE map is [`../residual-cwes.md`](../residual-cwes.md). Owner decisions on 2026-11-01: spec section 8, questions 13 to 15, the recommendation on all three. Nothing below is a result until its row says so.

Each item ships the way earlier phases did:
- a corpus case per CWE it claims, with every known way of writing the weakness as a `bad-*.rs`;
- detection and false-rejection rates with their totals (AGENTS.md rule 2);
- mutation checks for each new control;
- the Linux checks in the container (AGENTS.md).

A strategy that only strengthens C moves no bucket.

## Batches

| Batch | Strategies (proposal numbers) | Status | Blocked on |
| --- | --- | --- | --- |
| 1 | Decision 3: the ledger's `strategy` column, checked by `corten-ledger check` | **done** (2026-11-01, below) | |
| 2 | 15 lints; 9 labels on errors, logs and debug output | lints **done** (2026-11-01, below); labels not started | |
| 3 | 4 budgets and timeouts; 3 safe deserialization and `ConfigCap`; 8 DirCap extensions | not started | |
| 4 | 2 authorization and authentication proof types: prototype, adopt only at 0 false rejections (question 14) | not started | |
| 5 | 10 cryptography and randomness; 7 TLS and network capabilities (question 13) | strategy 10 **done** (2026-11-01, below): `corten_std::crypto`, `corten_std::random`, weak-primitive bans; strategy 7 (TLS, `NetCap`) not started | Strategy 7: owner decisions on the manifest grant, the address and DNS policy, and timeouts |
| 6 | 6 web types; 11 credentials; 12 strict parsers; 13 contracts; 5 runtime; 14 supply chain | not started | |
| — | 1 the independent encoder review (25 rows) | blocked | The owner naming a reviewer (AGENTS.md rule 1: not the encoders' author; the AI pre-review is not the review of record) |
| — | 16 code-quality metrics; 17 assurance tooling; 18 out of scope | reported, not gated | Spec section 7 |

## Batch 1 result (2026-11-01)

- **Ledger.** `ledger/cwe-ledger.csv` gains a `strategy` column. 641 rows carry one of the 18 strategies in `audit/residual/strategies.csv`; the other 303 are empty. Apart from the new column, the ledger is byte-identical (checked by removing the column again).
- **Gate.** `corten-ledger check` now also requires a known strategy on every CWE safe Rust can still write under Corten, and refuses one on a CWE safe Rust cannot write. A verified E row may keep its strategy, so `--mark-verified` never leaves the gate failing.
- **Gate refusals, each watched on a copy of the real ledger:**
  - blanking the 16 `authz-types` rows: 16 problems, exit 1;
  - a strategy on CWE-787, which safe Rust cannot write: exit 1;
  - renaming `budgets` to an unknown value: 24 problems, exit 1;
  - removing `strategies.csv`: exit 2.
- **Unit tests.** They cover each rule and the missing-column error.
- **Single source.** The first assignment file (`audit/residual/assignment.csv`) was folded into the ledger and removed. `scripts/residual-map.py` now reads the ledger, and its output is unchanged apart from its header.

## Batch 2, lints result (2026-11-01)

15 lints added to the checker's forbidden lists (`crates/cargo-corten/src/profile.rs`). They are aids: they move no bucket and claim no elimination.

| Lint | CWE |
| --- | --- |
| rustc `dead_code` | 561 |
| rustc `deprecated` | 477 |
| `clippy::precedence` | 783 |
| `clippy::float_cmp`, `float_cmp_const` | 1077 |
| `clippy::dbg_macro`, `todo`, `unimplemented` | 489 |
| `clippy::eq_op`, `absurd_extreme_comparisons`, `impossible_comparisons`, `redundant_comparisons`, `overly_complex_bool_expr`, `nonminimal_bool` | 570, 571 |
| `clippy::short_circuit_statement` | 768 |

Each lint was checked three ways:

1. **The name is known to Clippy 0.1.99.** A probe forbade every candidate plus a made-up name; only the made-up one was reported unknown. An unknown lint is only a warning, so a misspelled lint would be an inert control.
2. **It fires.** One program with an instance of each weakness gave 16 errors, one per candidate, `unused_assignments` included.
3. **It rejects no good program.** Linux, corpus run: with all 16 candidates, 169 of 169 detected and **1 of 169** falsely rejected. `unused_assignments` (CWE-563) rejected `corpus/CWE-482/good.rs`, a benign dead store, so it was dropped rather than the good program changed. With the 15 kept: **169 of 169 detected, 0 of 169 falsely rejected**. Also on Linux: `cargo-corten` tests 57 of 57, Clippy clean, hermetic smoke test 3 of 3.

Not covered by this batch: CWE-563 (its lint was dropped, above), and the other CWEs in the `lints` group for which no candidate was tried. They keep their strategy until a lint or a prelude change covers them.

## Batch 5, step 1: licences and supply chain (measured 2026-11-01)

Question 13 asks for this review before the owner approves any crate. Nothing is added to the workspace by it.

**Method.**
- Releases and licences come from the crates.io API on 2026-11-01.
- Each candidate set is a scratch crate (edition 2024, Rust 1.99.1) checked with the repository's own `deny.toml`: `cargo deny check advisories bans licenses sources`, cargo-deny 0.20.2, advisory database at commit `2295466` (2026-10-30).
- "Packages" counts `[[package]]` entries in the set's `Cargo.lock`: every target platform, and the scratch crate itself.
- Native code is counted in the downloaded sources.
- Building the sets runs their build scripts, so it was measured afterwards in the container (Build measurements, below).

### Releases and licences

| Crate | Latest | Released | Licence |
| --- | --- | --- | --- |
| `chacha20poly1305` | 0.11.0 | 2026-06-28 | Apache-2.0 OR MIT |
| `aes-gcm-siv` | 0.12.1 | 2026-08-21 | MIT OR Apache-2.0 |
| `argon2` | 0.6.0 | 2026-08-27 | MIT OR Apache-2.0 |
| `getrandom` | 0.4.3 | 2026-06-17 | MIT OR Apache-2.0 |
| `ed25519-compact` (in the TCB already) | 2.6.0 | 2026-09-25 | MIT |
| `ring` | 0.17.14 | **2025-03-11** | Apache-2.0 AND ISC |
| `aws-lc-rs` | 1.19.0 | 2026-10-28 | ISC AND (Apache-2.0 OR ISC) |
| `aws-lc-sys` | 0.47.0 | 2026-10-28 | seven terms, all permissive (ISC, Apache-2.0, MIT, BSD-3-Clause, MIT-0) |
| `rustls` | 0.23.46 | 2026-10-14 | Apache-2.0 OR ISC OR MIT |
| `rustls-webpki` | 0.103.16 | 2026-10-20 | ISC |
| `rustls-native-certs` | 0.8.5 | 2026-10-13 | Apache-2.0 OR ISC OR MIT |
| `rustls-platform-verifier` | 0.7.1 | 2026-09-24 | MIT OR Apache-2.0 |
| `webpki-roots` | 1.0.11 | 2026-10-23 | **CDLA-Permissive-2.0** |

### Candidate sets against `deny.toml`

| Set | Packages | `cargo deny` | Native code |
| --- | ---: | --- | --- |
| RustCrypto: `chacha20poly1305`, `aes-gcm-siv`, `argon2`, `getrandom`, `ed25519-compact` | 32 | passes | none |
| `ring` | 20 | passes | `cc`; 145 C, assembly and Perl files; 57 prebuilt object files (Windows) |
| `aws-lc-rs` | 17 | passes | `cc` and `cmake`; 1,493 C, assembly and Perl files; 97 prebuilt object files (Windows) |
| `rustls` on `ring` + `rustls-native-certs` | 36 | passes | as `ring` |
| `rustls` on `aws-lc-rs` + `rustls-native-certs` | 45 | passes | as `aws-lc-rs` |
| `rustls` on `ring` + `rustls-platform-verifier` | 61 | **refused**: `webpki-root-certs` is CDLA-Permissive-2.0 | as `ring` |
| `rustls` (default, `aws-lc-rs`) + `webpki-roots` | 37 | **refused**: `webpki-roots` is CDLA-Permissive-2.0 | as `aws-lc-rs` |
| RustCrypto set (no `aes-gcm-siv`) + `rustls` on `ring` + `rustls-native-certs` | 60 | **refused**: `ring` needs `getrandom` 0.2, the prelude 0.4 (`multiple-versions = "deny"`) | as `ring` |
| RustCrypto set (no `aes-gcm-siv`) + `rustls` on `aws-lc-rs` + `rustls-native-certs` | 67 | passes | as `aws-lc-rs` |

The refusals show the gate can fail; every passing set passed all four checks.

### Findings

- **Every bundled root store is CDLA-Permissive-2.0**, so a TLS client with built-in roots needs that licence allowed. The operating system's store (`rustls-native-certs`) passes today; it needs a CA bundle on the host, which a minimal container may lack.
- **`ring`:** no release since 0.17.14 (2025-03-11). Commits continue (the latest on 2026-07-22). The "unmaintained" advisory RUSTSEC-2025-0007 was withdrawn two days after it was filed. `ring` offers PBKDF2 and no memory-hard password hash (no `argon2` or `scrypt` in its source), so password hashing needs another crate either way. Its `getrandom` 0.2 cannot sit beside the prelude's `getrandom` 0.4 under the current policy.
- **`aws-lc-rs`:** released often, and the default provider of `rustls`. It is the largest native code base here and needs `cmake` at build time. It has five advisories in 2026 (RUSTSEC-2026-0044 to 0048, against `aws-lc-sys`), all fixed in 0.39.0 and later. Its README describes a FIPS build (26 mentions); Corten needs FIPS only if a deployer asks for it.
- **`rustls`:** five advisories in 2026 and `rustls-webpki` five, all fixed in the versions above. Four `rustls` advisories and the fixed release landed the same day (2026-10-14). CI's weekly `cargo deny` run is what would catch the next one.
- **RustCrypto:** pure Rust, no build scripts that compile C. According to its README, `chacha20poly1305` has had one NCC Group audit with no significant findings. `aes-gcm-siv`'s README says the crate itself has never been audited. `argon2`'s README mentions no audit.

### Options for the owner (question 13)

1. **Prelude cryptography (strategy 10).**
   - (a) RustCrypto: `chacha20poly1305` used only as XChaCha20-Poly1305, so a random 192-bit nonce per message is safe and the library can manage nonces; `argon2` with a cost floor; `getrandom` for OS randomness; `ed25519-compact`, already in the TCB, for `Verified<T>`. No native code. `aes-gcm-siv` is not needed beside XChaCha20 and is unaudited, so it is left out.
   - (b) The TLS provider's own primitives for the AEAD, plus `argon2`. One cryptographic implementation fewer in the TCB, but the prelude's AEAD then rests on C and assembly.
2. **TLS provider (strategy 7).**
   - (a) `aws-lc-rs`. It passes beside the RustCrypto set, is released often and is `rustls`'s default. Costs: `cmake` and a C toolchain in the hermetic build, and the largest native code base.
   - (b) `ring`. It is smaller, but its `getrandom` 0.2 would need a `skip` in `deny.toml`, and it has not been released for 20 months.
3. **Root certificates.**
   - (a) The operating system's store only (`rustls-native-certs`). It passes today.
   - (b) Allow CDLA-Permissive-2.0 for `webpki-roots`, so built-in roots work where the host has none. This adds a licence to the policy, which is an owner decision.

**Recommendation:** 1(a), 2(a) and 3(a).
- 1(a) keeps the prelude's own cryptography in safe, native-free code.
- 2(a) is the only provider that passes beside it without a policy exception.
- 3(a) needs no licence change. 3(b) can be revisited when a deployment needs roots on a host without a CA bundle.

**Decision (owner, 2026-11-01):** 1(a), 2(a) and 3(a), the recommendation.

### Build measurements (Linux, 2026-11-01)

The chosen set (`chacha20poly1305`, `argon2`, `getrandom`, `ed25519-compact`, `rustls` on `aws-lc-rs`, `rustls-native-certs`; 67 packages) was built as an application crate.
- **Environment:** `docker.io/library/rust:1.99.1-slim-bookworm`, kernel 6.17.7, gcc 12.2.0, **no `cmake` installed**.
- **Checker:** built from this repository at `92b947c`, with `corten-driver` from `scripts/build-driver.sh`.

| Step | Result |
| --- | --- |
| Plain `cargo build --release` | passes. `aws-lc-sys` 0.47.0 reports `Building with: CC`: its `cc` builder, no `cmake` binary. The `cmake` crate is compiled but runs nothing |
| `cargo corten check`, policy admitting nothing (control) | refused, exit 1 |
| `cargo corten check`, policy admitting the six crates | **refused, exit 1**: 7 more packages need admission (`aead`, `crypto-common`, `hybrid-array`, `inout`, `rand_core`, `rustls-pki-types`, `typenum`) |
| `cargo corten check`, policy admitting those 13 | passes |
| `cargo corten build`, same 13 | passes inside `corten-sandbox`. The binary is built, and the provenance records `"sandboxed":true` |

**What this adds to the review.**
- **Admission is wider than the direct dependencies.** Layer 3 counts the packages an admitted crate re-exports as reachable (`crates/cargo-corten/src/deps.rs`), so an operator admitting these crates directly admits 13.
- **Wrap, never re-export.** When `corten-std` wraps them, its public API must not re-export their types, or every application using the prelude meets the same requirement.
- **No `cmake` binary.** `cmake` is not needed on Linux x86-64, so the sandbox's system-directory grant is enough.
- **The condition holds.** The decision's condition (a `cmake` build the sandbox refuses would reopen 2(a)) did not arise.

## Batch 5, strategy 10 result (2026-11-01)

`corten-std` gains two modules. No ledger row moves: the strategy strengthens C, and an E claim for prelude users needs corpus cases first (below).

- **`corten_std::random`.** Randomness comes only from the operating system's generator, through `getrandom`. There is no seedable generator, and a failure is an error, never a weaker source.
- **`corten_std::crypto`:**
  - `AeadKey`: XChaCha20-Poly1305. The library picks a random 192-bit nonce for every message, so the caller cannot choose or reuse one. A sealed message is a format-version byte, the nonce, the ciphertext and the tag. `open` returns one opaque error for every failure, and both directions are bounded at 16 MiB.
  - `password`: Argon2id at OWASP's recommended 19 MiB, 2 iterations, 1 lane, with a 16-byte salt (RFC 9106). `verify` refuses a stored hash below all five of OWASP's minimum configurations, and anything but Argon2id version 19. Values checked against the raw pages on 2026-11-01.
  - `verify_signed` returns `Verified<T>`, which only a successful Ed25519 check (or `map` on another `Verified`) can produce.
  - No dependency type appears in the public API, so an application using the prelude does not have to admit the crates (Build measurements, above).
- **Bans.** `docs/dep-policy.example` gains 24 ban lines:
  - MD5 (`md-5` and `md5`), SHA-1, DES and triple DES, RC4;
  - `SeedableRng::seed_from_u64` and `from_seed`;
  - the non-cryptographic generators in `rand`, `rand_pcg` and `rand_xorshift`.

  Each path was checked against the crate's source on 2026-11-01.

**Evidence.**
- **Unit tests:** 14 of 14, including:
  - every single-bit flip of a sealed message is refused (denominator asserted);
  - the RFC 8032 section 7.1 test vector, checked against the RFC text;
  - each floor line passes at its value and is refused one iteration below it.
- **Mutations** (each control disabled in turn, tests re-run): 9 of 9 caught.

  A tenth control, a 256-byte bound on stored hashes, was removed instead: no test could make it fire, because the PHC parser already holds every field in a fixed-size buffer, and the bound would have refused a valid maximum-size hash.
- **Bans, on Linux** (`cargo corten check` with the example policy plus the 19 admitted packages):
  - 24 of 24 fire, each with its own `use of a disallowed type` or `method` diagnostic;
  - the same programs pass with the same admissions and no bans;
  - a benign program passes with the bans.
- **CI** (run 41356524543, Linux):
  - nextest: 202 of 202 passed;
  - corpus: 169 of 169 detected, 0 of 169 falsely rejected;
  - hermetic smoke test: 3 of 3;
  - `cargo deny`: passes with 23 more packages in the lockfile (56 to 79).
- **A defect caught on the way.** The first CI run falsely rejected 83 of 169. An exported `password::meets_floor(u32, u32)` broke the driver's labelled-parameters lint, and `corten-std` must pass its own profile, so every case that uses it failed to build. The function is now private.

**Not done in this batch:**
- Corpus cases for the strategy 10 CWEs. These come before any E claim; the strategy only says "E candidate for prelude users".
- Key derivation (HKDF) and key agreement (X25519).
- Strategy 7.
