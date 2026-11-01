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
| 5 | 10 cryptography and randomness; 7 TLS and network capabilities (question 13) | licence and supply-chain review **done**; crates chosen (owner, 2026-11-01, below); nothing built | The build measurements in the container |
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
- **Not measured:** building the sets (that runs their build scripts, so it belongs in the container), `cargo corten check` admitting them on Linux, and `cargo corten build` compiling their C inside the sandbox.

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

**Before building:** take the three measurements listed under Method as not measured, in the container. A `cmake` build that the sandbox refuses would reopen 2(a).
