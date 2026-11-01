# Proposal: mitigating the CWEs that remain under Rust and Corten

Status: **accepted as the plan for Phase 6, 2026-11-01** ([`gates/phase-6.md`](gates/phase-6.md) tracks what is built). The three decisions at the end were taken that day (spec section 8, questions 13 to 15). Every count below comes from `scripts/residual-map.py`; the per-CWE map is [`residual-cwes.md`](residual-cwes.md).

## What remains

Safe Rust can write 724 of the 944 CWEs. Corten's verified eliminations take out 83 of them, which leaves **641**:

| | CWEs |
| --- | ---: |
| Claimed eliminations (E, not yet verified) | 25 |
| Checkable (C): Corten has a mechanism or a policy, but the weakness can still be written | 590 |
| Out of reach (O) | 26 |
| **Total** | **641** |

Of these, 522 are Base or Variant weaknesses. The other 119 are Pillars, Classes or Compounds that overlap their children, so counting them as separate exposures overstates the residue.

**Exploitability.** 17 of MITRE's 2025 Top 25 remain: CWE-79, 89, 352, 862, 78, 94, 434, 502, 863, 20, 284, 200, 306, 918, 77, 639, 770. So do 6 of the 2025 Top 10 KEV weaknesses (those exploited in the wild): CWE-78, 306, 502, 94, 288, 79. What Corten has removed are the memory-safety and path entries (CWE-787, 22, 416, 125, 120, 476, 121, 122 are verified or need `unsafe`). What remains is injection outside the prelude's grammars, authorization, deserialization, resource limits and request forgery.

**A gap in the ledger.** 610 of the 641 rows name no mechanism: most C rows say "checkable" without saying by what. This proposal gives every residual row a strategy, now recorded in the ledger's `strategy` column and enforced by `corten-ledger check` (decision 3 below).

## Strategies, in proposed order

The order weighs Top 25 and KEV exposure against cost. Each strategy is one way to reduce a group; the first assignment and should be revised as each one is designed.

| # | Strategy | CWEs | Top 25 | KEV | Effect |
| ---: | --- | ---: | --- | --- | --- |
| 1 | Finish the independent encoder review | 25 | 79, 89, 78, 77 | 78, 79 | claimed E becomes verified E |
| 2 | Authorization and authentication as proof types | 16 | 862, 863, 284, 306, 639 | 306, 288 | E candidate for prelude handlers |
| 3 | Safe-deserialization profile and `ConfigCap` | 14 | 502 | 502 | stronger C |
| 4 | Mandatory resource budgets and timeouts | 24 | 770 | | stronger C |
| 5 | Least privilege from the manifest, release attestation | 20 | 94 | 94 | stronger C |
| 6 | Secure-by-default HTTP types | 30 | 352 | | stronger C |
| 7 | Verified-by-default TLS and network capabilities | 24 | 918 | | E candidate for prelude users |
| 8 | DirCap extensions | 31 | 434 | | stronger C |
| 9 | Labels on errors, logs and debug output | 21 | 200 | | stronger C |
| 10 | Misuse-resistant cryptography and randomness | 42 | | | E candidate for prelude users |
| 11 | Credentials | 26 | | | stronger C |
| 12 | More typed sinks and strict parsers | 91 | 20 | | stronger C |
| 13 | Refinement types, typestate, lock order | 41 | | | stronger C |
| 14 | Dependency policy, vetting, advisories | 14 | | | stronger C |
| 15 | More checker-owned lints | 38 | | | aid |
| 16 | Code-quality metrics | 63 | | | aid, not exploitable alone |
| 17 | Design, protocol and logic: assurance | 90 | | | not mechanised |
| 18 | UI, hardware, other platforms | 31 | | | documented only |

[`residual-cwes.md`](residual-cwes.md) lists every CWE under these strategies, in the same order.

"E candidate" means the strategy could support a verified elimination for code that uses the prelude for that effect, under AGENTS.md rule 1 (a failing build for the weakness and a passing build for the benign twin). The same limit as today's E rows applies: a program that bypasses the prelude through an admitted dependency is governed by the operator's dependency policy, not by the E claim.

### 1. Finish the independent encoder review (25)

**Today.** The 25 rows pass their corpus cases but stay unverified (`review = required`): the sinks for SQL, HTML, LDAP, XPath, XQuery, CSV, templates, logs and headers. An AI pre-review found five escapes, which Phase 5 fixed; it is not the review of record.

**Proposal.** Name an independent reviewer (not the encoders' author). Give them `docs/gates/encoder-prereview.md`, the property tests (`crates/corten-std/tests/encoder_properties.rs`, 10 properties over 1,128,449 inputs each) and the corpus variants. Record the review link in the ledger's `review` column, then run `corten-corpus --mark-verified`.

**Why first.** It turns four Top 25 entries and two KEV entries from claimed to verified with no new code. It is blocked only on the owner naming a reviewer.

### 2. Authorization and authentication as proof types (16)

**Today.** Nothing. Spec section 7 lists the authorization matrix as something Corten cannot decide, and that stays true. But whether a check *happened* is mechanical.

**Proposal.** A prelude module (working name `corten_std::authz`):
- `Authenticated<P>`: a principal, constructible only by an authenticator the manifest names.
- `Authorized<A, R>`: a proof that action `A` on resource `R` passed a policy, constructible only through `Policy::check(&Authenticated<P>, A, &R)`.
- Prelude sinks that change or reveal protected state take the proof as a required parameter. A handler that skips the check does not compile (CWE-862, 306, 288, 638). A resource looked up by a caller-supplied key must be checked against that key (CWE-639, 566).
- A checker lint refusing hand-built proofs, the same pattern as `corten_direct_template`.

**Claim.** E for "missing authorization or authentication before a prelude sink", with a corpus case per CWE. The policy itself (CWE-863, 285, 284: an incorrect rule) stays C, because Corten cannot know the intended matrix.

**Cost and risk.** Medium. It is an API design question first: how it composes with web frameworks (which are dependencies, governed by the dependency policy) and how much ceremony it adds. Prototype it on the corpus before committing.

### 3. Safe-deserialization profile and `ConfigCap` (14)

**Today.** Spec section 5 lists both as P1 safer defaults, not built.

**Proposal.** As specified there. Wire types declare a version, a nesting bound and a size bound; unknown fields are rejected; there is no blanket `Deserialize` for prelude-bound data (CWE-502, 915). Ban the formats that run code or build arbitrary object graphs through the dependency policy's `ban` lines. Configuration enters only through a `ConfigCap` with a schema and a provenance label (CWE-15, 453, 454, 1188, 526); XML parsing without DTDs (CWE-611, 776, 827, 112).

**Claim.** Stronger C: what an application accepts is still policy.

### 4. Mandatory resource budgets and timeouts (24)

**Today.** Spec section 5 P1 and the one unbuilt Phase 3 item. The brokers, the IPC decoder and the checker's JSON parser are already bounded.

**Proposal.** A `Budget` type (bytes, items, depth, time) is a required parameter of every prelude parse, decode, allocate and network entry point. A lint refuses unbounded `Vec::with_capacity` from untrusted lengths, and requires timeouts on blocking I/O through capabilities (CWE-1088). Authentication attempts get a rate budget (CWE-307).

**Claim.** Stronger C: Corten can force a budget to exist, not decide its size (spec section 7, "acceptable operational budgets").

### 5. Least privilege from the manifest, release attestation (20)

**Today.** `corten-sandbox --manifest` turns a signed capability manifest into Landlock rules. Wasm modules run out of process.

**Proposal.**
- Generate the deployment's sandbox from the same manifest that grants capabilities in code, so code and OS agree (CWE-250, 269 to 274, 653, 668).
- Make `dynamic_code` an effect that has to be declared, and run it only in the Wasm broker (CWE-94, 96: code injection becomes code that runs inside a sandbox).
- Refuse a release build without its provenance statement, and the provenance records the profile (CWE-1269).
- Request Landlock's UDP rights when the kernel and the `landlock` crate support them (open item in `docs/gates/phase-5.md`).

### 6. Secure-by-default HTTP types (30)

**Today.** `corten_std::http` has typed header names and values, and cookies that are always `Secure`, `HttpOnly` and `__Host-`, with `SameSite` chosen explicitly (CWE-1004, 614, 1275 are covered for prelude cookies).

**Proposal.** Add the pieces still missing:
- A `Redirect` type built only from a relative path or an allowlisted origin (CWE-601).
- A CSRF token tied to the session and required by state-changing prelude handlers (CWE-352).
- Session rotation on login, and an expiry carried in the type (CWE-384, 613).
- A response builder whose security headers (frame options, CORS with no wildcard alongside credentials, no-store for sensitive responses) are on unless explicitly declined (CWE-1021, 942, 524, 525).

### 7. Verified-by-default TLS and network capabilities (24)

**Today.** No network API in the prelude; `std::net` is banned by the checker.

**Proposal.** A `NetCap` granted by the manifest: allowed destinations (hosts and ports, with private ranges and the metadata address refused unless granted) and allowed bind addresses (CWE-918, 1327, 941). A TLS client that offers no way to turn certificate or hostname verification off, with a minimum protocol version (CWE-295 to 299, 297, 319, 757, 1428). The library is a dependency decision: candidates are checked for licence and supply chain first, as in Phase 5.

**Claim.** E candidate for "TLS without verification" and "a request to an ungranted destination" through the prelude.

### 8. DirCap extensions (31)

**Today.** `DirCap` opens beneath a root with `openat2` and `RESOLVE_BENEATH`, so the path family is verified.

**Proposal.** Temporary files created only through `DirCap`, with mode 0600 and `O_EXCL` (CWE-377, 379). Creation modes are explicit in the type, never defaulted (CWE-276, 732). An upload sink that stores under a generated name and records the declared type, never the client's file name (CWE-434, 646). An opt-in refusal of hard links (CWE-62, 65).

### 9. Labels on errors, logs and debug output (21)

**Today.** `corten_std::label` checks labels at write, log, respond and serialize, per value (Phase 4).

**Proposal.** Errors carry the highest label of the data they mention. The respond sink renders only `Public` error detail and a generic message otherwise (CWE-209, 210, 211, 550). The log sink refuses `Secret` and `Confidential` values (CWE-532, 215, 1295).

### 10. Misuse-resistant cryptography and randomness (42)

**Today.** None in the prelude. `Secret` is locked in memory and compares in constant time.

**Proposal.**
- `corten_std::crypto`, with no algorithm choice: one AEAD with nonces managed by the library (CWE-323, 329, 1204), password hashing with a floor on its cost (CWE-916, 759, 760), and a signature check that returns `Verified<T>` (CWE-347, 353, 354).
- `corten_std::random`: OS randomness only, with no seedable generator in the prelude, and seedable generators banned through the dependency policy (CWE-330 to 344, 338).
- Weak primitives banned by name in the example dependency policy (CWE-327, 328, 326, 780).
- Timing: secrets compared with `ct_eq` (CWE-208).

The crate choices are dependency and trusted-base decisions (decision 1).

### 11. Credentials (26)

**Today.** `corten_secret_literal` refuses a `Secret` built from a literal (an aid for CWE-798); gitleaks runs in CI.

**Proposal.**
- Extend the lint to string literals that are passed where a credential is expected (CWE-259, 321, 798, 1392 to 1394, 547).
- Ship secret scanning in the GitHub Action for callers (CWE-540, 531, 615).
- Make every explicit wipe observable, as spec section 5 asks (CWE-14, 733, 244).

### 12. More typed sinks and strict parsers (91)

**Today.** Typed sinks for nine grammars.

**Proposal.** Most of these 91 are generic neutralization and parsing classes (CWE-138 to 168, 228 to 241, 172 to 177). Corten cannot type every grammar, but it can make the prelude's parsers strict: reject missing, extra, duplicate or undefined elements; canonicalize before validating (CWE-179 to 181); and give a parser-combinator helper whose defaults are strict. Add a URL type (the one missing Phase 2 sink). Request smuggling (CWE-444) belongs to whichever HTTP library is admitted.

### 13. Refinement types, typestate, lock order (41)

**Today.** Overflow, out-of-bounds indexing and division by zero already panic and are contained by the supervision tree, so these are availability problems, not memory corruption. `refine` (Phase 4) and `OrderedMutex` exist.

**Proposal.** Use refinement types at prelude boundaries (CWE-1284, 1285, 606, 839), typestate for workflows (CWE-837, 841), and `OrderedMutex` wherever the prelude locks (CWE-833, 667). Re-run the Flux trial when its trigger fires (a release, and 0 internal errors on the corpus).

### 14. Dependency policy, vetting, advisories (14)

**Today.** Dependencies are refused by default; `cargo deny` and `cargo audit` run in CI.

**Proposal.** Ship advisory checks and `cargo vet` in the GitHub Action for callers (CWE-1395, 1357), and require vendored, hash-pinned builds for releases (CWE-494, 829, 830). Malicious code (CWE-506 to 512) stays out of reach: dependency policy lowers the odds, and review is what covers it.

### 15 and 16. Lints and code-quality metrics (38 and 63)

**Proposal.** A checker-owned set of Clippy lints chosen against the corpus's false-rejection rate (AGENTS.md rule 2): `precedence`, `float_cmp`, `dbg_macro`, `todo`, `deprecated` as errors, `cognitive_complexity`, `needless_bool` and others (CWE-783, 1077, 489, 477, 561, 570, 571, 1121). Code-quality metrics (CWE-1041 to 1126, mostly architecture and style) can be reported but should not fail a build: they are not exploitable on their own.

### 17 and 18. Not mechanised (90 and 31)

These are the residue spec section 7 already names: authentication design, business workflows, protocol correctness, races in application logic, UI, hardware and microarchitecture, and other platforms (Android, ActiveX, Windows messaging). They are covered by the controls in that section, not by the language.

What Corten can add is tooling:
- A test-harness template for an authorization matrix (every route against every role).
- A fuzzing target per prelude parser, run in the Action.
- A threat-model checklist keyed to these CWEs.

## How each strategy is verified

As AGENTS.md requires for any claim:
- A corpus case per CWE, with every known way of writing it as a `bad-*.rs`.
- The false-rejection rate reported beside every detection number, with the totals.
- Mutation checks for each new control.

A strategy that only strengthens C moves no bucket. It records its mechanism in the ledger (decision 3), so "checkable" names what checks it.

## Decisions (owner, 2026-11-01: the recommendation on all three)

1. **Prelude cryptography, randomness and TLS (strategies 7 and 10).** These add dependencies to `corten-std` and to the trusted base.
   - (a) Adopt audited crates behind a minimal prelude API, after the licence and supply-chain review Phase 5 used. **Recommended:** these are the largest groups with an E candidate, and hand-written cryptography is worse.
   - (b) Keep them out of the prelude, and ban weak primitives through the example policy only. Cheaper, but leaves 66 rows with no mechanism.
2. **Authorization proof types (strategy 2).**
   - (a) Prototype on the corpus first, and adopt only if the false-rejection rate stays at 0 and the API composes with an admitted web framework. **Recommended:** highest Top 25 and KEV payoff, but the most design risk.
   - (b) Document authorization as assurance-only (strategy 17).
3. **A mechanism for every C row.**
   - (a) Add `strategy` to the ledger, checked by `corten-ledger check`. **Chosen.** The first assignment moved into the ledger, which is now its only source. it closes the 610-row gap and makes "checkable" mean something.
   - (b) Keep a separate assignment file as an audit record only.

Strategies 1, 3 and 4 need no new decision: 1 waits on the reviewer, and 3 and 4 are already in spec section 5.
