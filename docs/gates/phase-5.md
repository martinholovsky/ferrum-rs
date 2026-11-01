# Phase 5: dependency effects, encoder fixes, verification tools

Status: **done** (2026-10-28; results below each part). Planned 2026-10-27. Final Linux run: lint UI tests, clippy, 204 tests passed and 0 failed, hermetic smoke test 3 of 3, corpus 169 of 169 detected, 0 of 169 false rejections, 143 of 169 verified. Owner decisions on that date: the recommendations for decisions 1 to 3 of [`claimed-eliminations.md`](claimed-eliminations.md), and the tool survey (Kani, Flux and others) with a licence and supply-chain review first. Results are added below each part as it completes; nothing here is a result until it says so.

## Part 1: dependencies are refused by default (decision 1)

**Problem.** An E claim that rests on the prelude (78 rows have `prelude_only = yes`, 52 of them verified) or on a checker ban (for example `JoinHandle::join`) is bypassed by a dependency that offers the raw API, such as a crate taking SQL as a string. `corpus/CWE-78`, `CWE-89` and `CWE-396` each have a `bad-dep.rs` that passes today.

**Mechanism.**
1. **The operator's dependency policy.** `cargo corten check` and `build` read it from `--dep-policy FILE` or `CORTEN_DEP_POLICY`, never from the checked repository. The format:
   ```text
   corten-dep-policy 1
   allow NAME              # admit a crate (any version) as a direct dependency
   allow NAME@VERSION      # or one version
   ban PATH REASON...      # a raw entry point of an admitted crate, e.g. ban my_db::query raw SQL string
   ```
2. **Deny by default.** A dependency that local code can reach (a direct dependency of a local package, or one a reachable package re-exports) and that the policy does not `allow` is refused: "not on the operator's dependency allowlist". Local path packages and the standard library need no entry.
3. **Admitted is not trusted.** An admitted crate still goes through every existing layer 3 check (unsafe-emitting macros, procedural macros, the name ban list). `--allow-dep` keeps its meaning: an override for a specific finding, not admission.
4. **Raw entry points are banned in local code.** Each `ban` line joins the checker's `disallowed-methods`, so calling it is refused like `std::process::Command::new`.
5. **What the trusted base gains.** The operator's `ban` lines must name every raw entry point of every admitted crate that bypasses a prelude or checker claim. This goes into `docs/tcb.md` as an assumption of those claims.

**Tests.**
- Unit tests in `deps.rs` and an integration test in `cargo-corten/tests/check.rs`: an unlisted crate is refused; a listed one is accepted; a `ban` line refuses the call. Each with a live control.
- Corpus: the runner gains `//@ dep-policy: LINE` (written to a policy file it passes to the checker). The three `bad-dep.rs` variants must then be refused. `corpus/CWE-89/bad-dep-listed.rs` admits its crate and must be refused by the `ban` line.
- The 0% false-rejection gate must hold.

**Docs.** `cargo-corten` README, `docs/tcb.md`, spec section 10 (layer 3), `action.yml` (an input for the policy file), CHANGELOG.

**Result (2026-10-28).**
- `crates/cargo-corten/src/dep_policy.rs`: the parser, 4 unit tests, and the shipped example policy (`docs/dep-policy.example`) parsing.
- `deps.rs`: deny by default. 2 new unit tests covering three behaviours: unadmitted refused and admission skipping no check (one test), and the prelude's dependencies exempt only at the checker's own `corten-std` directory, not by name.
- `tests/check.rs`: an unadmitted crate is refused and admitted passes; a `ban` line refuses the call (control: without it, it passes); a malformed policy exits 2.
- Corpus: `CWE-78`, `CWE-89` and `CWE-396` `bad-dep.rs`, and `CWE-89/bad-dep-listed.rs`, are refused.
- The first corpus run after the change falsely rejected 83 of 169 good programs: every one depending on `corten-std` by path, whose own dependencies looked like the application's. That was fixed by identifying the prelude by directory, and the run then gave 0 of 169.
- The hermetic smoke test and `action.yml` pass a policy (`dep-policy` input).

## Part 2: CWE-252 to C (decision 2)

Move the row to C with its reason in the ledger: the `bool` rule stays as an aid, and `bad-std-option.rs` records why no narrower rule closes it.

**Result (2026-10-28).** Moved, reason in the ledger. E 169, C 727.

## Part 3: fix the five encoder escapes (decision 3)

From [`encoder-prereview.md`](encoder-prereview.md). Each fix must make its corpus variant fail to build and keep every good program building.

| Encoder | Fix | Variant that must fail |
| --- | --- | --- |
| `html!` tokeniser | Follow WHATWG for bogus comments: `<?`, `<!` not followed by `--` or `DOCTYPE`, and `</` followed by a non-letter all open a comment that ends at the first `>`. Treat `<!DOCTYPE` in the body the same way. Refuse a placeholder right after `<`, `<!`, `<!-` or `</` | `CWE-79/bad-bogus-comment.rs`, `bad-comment-opener.rs` |
| `html!` composition | Check every template, including those with no placeholders. A template must end in the data state, outside any tag, attribute, comment or raw-text element; otherwise it does not compile | `CWE-79/bad-composition.rs`, `CWE-83/bad-composition.rs` |
| `ldap_filter!` / `ldap_dn!` | A placeholder only in value position: after `=`, `~=`, `>=` or `<=` up to `)` in a filter, after `=` up to `,` or `+` in a DN | `CWE-90/bad-attribute-position.rs` |
| `xquery!` / `xpath!` | Refuse a placeholder inside a direct element constructor or a `(: … :)` comment | `CWE-652/bad-element-content.rs` |
| `process` | `Options` constructible only by `process!`. The field becomes private, and the constructor is a hidden function the macro calls with a literal slice | A new `bad-options.rs`; CWE-88 stays C |
| `sql!` (template side) | Refuse a placeholder inside `$$…$$`, backticks, `[…]`, `--` or `/* */`, and a placeholder directly followed by a digit | Unit tests (no value reaches the text, so no CWE row changes) |

**Result (2026-10-28).** All five fixed. `[…]` was not refused in `sql!` (PostgreSQL arrays use it); it is documented in `sql.rs`.

| Check | Result |
| --- | --- |
| The 26 pre-review probes against the fixed prelude | Every probe that asserted an escape now fails to compile with the intended message: `html!` 8, `ldap_filter!` 2, `sql!` 1, `xpath!` 1, `xquery!` 2, `Options` 6 (private field) |
| Corpus variants (`CWE-79` ×3, `CWE-83`, `CWE-90`, `CWE-652`) | Refused for the expected reason |
| New unit tests | `html.rs` (bogus comments, `<!-`, closedness), `ldap.rs` (value position), `xpath.rs` (comments, string and element constructors), `sql.rs` (dollar quoting, backticks, comments, `{}0`), and a compile-fail doctest for `Options` |
| Property tests | 10 of 10 |

Corpus after Parts 1 to 3, on Linux: **169 of 169 detected, 0 of 169 falsely rejected**. `--mark-verified` after a dry run: 143 of 169 verified (CWE-396 newly). The other 26 pass and wait for the encoder review. Workspace tests: 194 passed, 0 failed. Hermetic smoke test: 3 of 3.

Then re-run the property tests and the 26 pre-review probes. Each probe that asserted an escape must now fail to compile or show no escape. Record the result in `encoder-prereview.md`.

## Part 4: verification and analysis tools

1. **Licence and supply chain first.** For each candidate (Kani, Flux, Verus, Creusot, Prusti, lockbud, CodeQL, Semgrep, dylint):
   - the licence of the tool **and of what it downloads or links** (solvers, CBMC, fixpoint engines);
   - how many packages it pulls in and from where;
   - whether it needs network access at install time;
   - its maintenance status.
2. **Build or adopt.** For each capability, decide whether a small in-house check in `corten-driver` or the prelude covers what Corten needs with less supply chain. Candidates:
   - interval analysis for overflow, instead of Flux plus a solver;
   - lock-order and double-lock checks, instead of lockbud;
   - per-crate method bans from Part 1, instead of Semgrep's Rust rules;
   - a few targeted lints for C rows CodeQL covers (hard-coded credentials, disabled TLS verification).
3. **Write the tool plan** with the decisions and their reasons, then execute it: the Flux or in-house overflow trial on the numeric rows, Kani or equivalent proofs of the encoders, and the advisory CI profile. Each gets measured false-rejection and detection numbers.

### Part 4, step 1: licences and supply chain (measured 2026-10-28)

From the GitHub API and each project's own files on 2026-10-28. "Packages" counts `[[package]]` entries in the project's `Cargo.lock`.

| Tool | Latest release | Licence | Packages | What else it needs | Toolchain |
| --- | --- | --- | ---: | --- | --- |
| Kani | 0.68.0, 2026-09-16 | Apache-2.0 / MIT | 308 | CBMC: **BSD-4-Clause style, with an advertising clause**. `cargo kani setup` downloads a prebuilt bundle | nightly-2026-10-23 |
| Flux | **none** (source only) | MIT | 209 | liquid-fixpoint (BSD-3-Clause, Haskell, about 30 direct Hackage dependencies, **nightly binaries only**) and z3 4.15+ (MIT) or cvc5 | nightly-2026-10-22 |
| Verus | rolling | MIT | 393 | z3 | own build |
| Creusot | v0.14.0 | **LGPL-2.1** | 192 | Why3 and solvers | nightly |
| Prusti | rolling | MPL-2.0 (Rust parts) | 446 | Viper (MPL-2.0, Java) and z3 | nightly |
| lockbud | **none** | BSD-3-Clause | 83 | none | **nightly-2026-02-07**, eight months behind |
| MIRAI, Rudra | archived | | | | |
| CodeQL | CLI 2.27.3 | **GitHub CodeQL Terms** (not OSI; free for open source) | n/a | GitHub's engine | n/a |
| Semgrep | v1.182.0 | engine LGPL-2.1; rules licence not OSI | n/a | Python | n/a |
| dylint | v6.2.0 | Apache-2.0 / MIT | 250 | none | per-library nightly |

### Part 4, step 2: build or adopt (decisions)

| Capability | Decision | Why |
| --- | --- | --- |
| Encoder proofs (the trusted base) | *Superseded 2026-10-28 by the Kani result below: in-house exhaustive tests.* **Adopt Kani, development-only.** Proof harnesses under `#[cfg(kani)]` in `corten-std`, so no dependency enters `Cargo.toml` or `deny.toml`. A manual CI job pins 0.68.0 and the checksum of its bundle | Bounded proofs over every input up to a size are stronger evidence for the review than property tests. Kani is not shipped or linked, so CBMC's advertising clause does not reach Corten's users; it is recorded here |
| Overflow and range proofs (CWE-190, 191, 128 and others) | **Trial Flux, do not adopt yet.** Measure false rejections with `check-overflow` on the numeric corpus programs in a throwaway container. No in-house substitute | No releases, a nightly Haskell back end and a solver are a larger trusted base than any other tool here. A ban cannot prove absence of overflow, which the E bar needs: checked arithmetic already turns overflow into an error or a panic |
| Deadlock detection (lockbud) | **Reject.** No in-house analysis now | Stale nightly pin and no releases. Corten's `OrderedMutex` already rules out lock-order cycles for code that uses it; deadlock stays C |
| Taint analysis (CodeQL) | **Reject as part of Corten** (licence). The owner may still enable GitHub code scanning in the repository settings; nothing in the tree depends on it | Not OSI |
| Pattern rules (Semgrep) | **Reject; build in-house.** Its Rust rules are method bans, which Part 1's per-crate `ban` lines express. Ship a reviewed example policy with bans for known raw entry points (disabled TLS verification, string SQL) | Rules licence not OSI; duplicates Corten's bans |
| Hard-coded credentials (CWE-798) | **Build in-house:** a `corten_secret_literal` lint refusing a `Secret` built from a literal | A narrow, sound check of Corten's own API; the row stays C (literals can still reach other sinks) |
| Lint hosting (dylint) | **Not needed** | `corten-driver` already hosts Corten's lints |

### Part 4, step 3: execution

1. Kani harnesses for the encoders' escaping functions (LDAP filter and DN, XPath and XQuery literals, CSV cell, HTML escaping, log escaping), run in a container on 0.68.0, with results recorded.
2. The Flux trial: `check-overflow` on the numeric corpus programs (the bad and good programs of the C rows CWE-190, 191, 128, 369, 129, 193, 1335, 681, 197), recording what it reports and how many good programs it rejects.
3. `docs/dep-policy.example`: a reviewed example policy with `ban` lines for known raw entry points.
4. `corten_secret_literal` in `corten-lints`, with a UI test and a corpus-style control.

**Kani result (2026-10-28): adoption withdrawn; replaced in-house.**
- **Setup:** Kani 0.68.0, its bundle checked against the published SHA-256 before `cargo kani setup --use-local-bundle`. Harnesses over every string of up to 3 Unicode scalar values (2 for log records), in a 24 GiB, 8-CPU podman VM.
- **Result:** the CSV harness failed because CBMC ran out of memory: "CBMC appears to have run out of memory" after 117 s of symbolic execution over 733,605 steps. That is not a property violation. The HTML harness was still running about six hours later and was stopped. The others never started.
- **Removed:** the harnesses, the `cfg(kani)` lint entry and the manual workflow. A proof that cannot finish is an inert control.
- **Replacement:** `crates/corten-std/tests/encoder_properties.rs` checks each of the 10 encoder properties exhaustively on the empty string, every Unicode scalar value alone (1,112,064) and every pair of ASCII characters (16,384). That is 1,128,449 inputs per property; the denominator is asserted. The encoders map characters independently apart from position (a DN's first and last character, a CSV cell's first), so this covers each character class completely: what a bounded proof of length 1 would have shown, in 23 s on a debug build, with no supply chain.
- **Positive control:** dropping U+2029 from the log encoder (on a copy) fails the exhaustive test, while the random-alphabet test passes.
- Kani stays an option for multi-character interactions if a harness is stubbed small enough; it would need a new measurement.

**Flux trial result (2026-10-28).**
- **Setup:** Flux at commit `9fe62fab` (main, 2026-10-27; it has no releases), liquid-fixpoint nightly (2026-10-16) and z3 5.3.2. Both binaries were checked against their published SHA-256 before use. Debian Trixie, because z3's Linux build needs glibc 2.39. The source tree was mounted read-only. Log: one line per program, with Flux's exit status and its first error.

| Mode | Numeric programs refused (CWE-128, 129, 1335, 190, 191, 193 to 197, 248, 369, 617, 681, 839) | Good programs refused (the 88 corpus `good.rs` with no dependency) |
| --- | --- | --- |
| `-Fcheck-overflow=strict` | **6 of 15**: CWE-128, 129, 190, 191, 369, 839 | **3 of 88** (3.4%), all **internal Flux errors** (`flux-refineck/src/checker.rs:1736`), not findings |
| `-Fno-panic` | 6 of 15 | **87 of 88**: `println!` and other std calls "may panic" |

**Reading.**
- Overflow checking finds what it targets: overflow, division by zero and out-of-bounds indexing.
- It does not see conversions (`as`, which Corten already bans), shifts, off-by-one logic, assertions or panics. `no-panic` is unusable without annotating std.
- Three crashes in 88 programs mean a rejection could be a tool fault, which would conflict with fail-closed reporting.
- **Decision stands: not adopted.** Re-run the trial when Flux publishes a release and its crash rate on the corpus is 0. Candidate rows then: CWE-128, 129, 190, 191, 369, 839, which stay C until then.

## Order

Part 1 and Part 2, then Part 3. Re-run the full Linux check, the corpus with `--mark-verified` (after a dry run), the applicability table and the chart. Then Part 4.

## Open after Phase 5 (2026-10-28)

Resolved the same day: `CWE-1037.rs` removed by the owner. The table, the generated docs and the chart were regenerated: 787 with `unsafe`, 724 safe, 641 under Corten (83 verified, 25 claimed, 616 if every claim held).

Resolved 2026-10-29 (owner decision): CWE-1113 to 1117 moved from N to C, with the reason in the ledger. `corten-ledger totals`: E 169 / C 732 / O 26 / N 17. The headline counts do not change (787, 724, 641), since the Corten count does not depend on C versus N.

Also resolved 2026-10-29 (owner decisions): Landlock ABI v6 signal and abstract-socket scoping is requested wherever the kernel has it, with v4 kept as the hard requirement (branch `wasm-out-of-process`, PR #11); CI regenerates `docs/rust-comparison.md` after fetching only its baseline commit (branch `rust-applicability-audit`, PR #10).

| Item | Blocked on | Where it is tracked |
| --- | --- | --- |
| The independent review of the encoders, for the 26 rows that pass but stay unverified | The owner naming a reviewer | `docs/gates/phase-2.md` section 5, `docs/gates/encoder-prereview.md` |
| UDP is not restricted for brokered processes (the `landlock` crate 0.4.7 has no UDP right) | A Landlock UDP right in the crate and the kernel, or a separate mechanism (seccomp, a network namespace) | `docs/tcb.md`, "What a confined program can still reach" |
| Flux re-trial: CWE-128, 129, 190, 191, 369, 839 | A Flux release, and 0 internal errors on the corpus | Part 4 above |
| Publish the GitHub Action (`action.yml`) to the Marketplace (owner, 2026-10-30: track, not now) | PRs #10 to #12 merged; the action renamed to fit AGENTS.md rule 9 (names) (it is `name: corten`); a first release cut as a signed tag (`git tag -s`) from `main`, then the release created from that tag | This row |
