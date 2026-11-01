# Trusted computing base and implementation-defined behaviour

Status: Phase 0 specification, 2026-10-26; Phase 3 components added 2026-10-27. Required by the ratification amendments "State the TCB explicitly and fail closed" and "Implementation-defined behaviour" (spec section 5). Every E claim in the ledger names the parts of this list it rests on, in its `tcb_assumption` column. A bug in any of them is outside every E claim.

## 1. What is trusted

| Component | Trusted to | E claims that rest on it |
| --- | --- | --- |
| rustc front end (parser, type checker, borrow checker) and LLVM | Reject programs the language forbids; compile the rest without introducing unsoundness | All `language` claims; the ownership claims |
| Rust `std` (safe API) | Be sound: no undefined behaviour reachable from safe code | Ownership claims |
| `cargo-corten` (the checker) | Supply its own flags and lint configuration and override every configuration source the checked repository controls (crate README) | All `checker` claims |
| Clippy | Implement each lint the checker turns on as documented | Claims whose mechanism names a Clippy lint |
| `corten-driver` and rustc's front end from `nightly-2026-10-26` (owner decision 10) | Implement the eight `corten_*` lints as documented (crates/corten-lints); hold the checked code to stable's feature gates under `RUSTC_BOOTSTRAP=-1` | CWE-493, 500, 607, 1091, 1322; the dependency-macro condition on the `unsafe` claims |
| `corten-std` | Implement the DirCap monitor (docs/pathseg.md), the typed sinks' encoders, `Secret<T>`, the broker protocol, and (Phase 4) the label lattice, declassification record and lock-order traits correctly. Encoder-backed rows carry `review = required` until an independent review is recorded | Path, sink and broker claims (`prelude_only = yes`) |
| `corten-std`'s dependencies: `rustix` 1.1.5 (Linux syscalls, including `openat2`), `region` 3.0.2 (`mlock`), `zeroize` 1.9.1, `subtle` 2.6.1, `ed25519-compact` 2.6.0 (no default features, no further dependencies), and since Phase 6 batch 5 `chacha20poly1305` 0.11.0, `argon2` 0.6.0 and `getrandom` 0.4.3 (owner decision, 2026-11-01; the cryptographic provider, below) | Be correct; each is a dependency of every application that uses the prelude | Path, secret and manifest claims |
| Linux kernel | Implement `openat2` resolve flags and Landlock (ABI v4) as documented | Path and broker claims; the hermetic build |
| `corten-sandbox` and the `landlock` crate 0.4.7 | Turn each grant into exactly the Landlock rule it names, and apply the ruleset before running the program. Landlock's read grant (`from_read`) includes execute, so every read-only path is also executable. Refuse to start while a descriptor above 2 lacks close-on-exec (read from `/proc/self/fdinfo`): Landlock does not restrict a descriptor that is already open | Broker claims; the hermetic build and check; layer 5 |
| `corten-broker` | Clear the environment, enforce the deadline and quotas, and check IPC frame sizes before allocating. Run every Wasm module in `corten-wasm-runner` under `corten-sandbox`, never in the caller's process. It does not close descriptors; `corten-sandbox` refuses to start while one without close-on-exec is open | Broker claims |
| `wasmi` 2.0.0 (owner decision 12), inside `corten-wasm-runner` | Enforce fuel, the memory limit and the absence of imports, and validate modules (`validate`, `extra-checks` features). A module that escapes `wasmi` holds the runner process, which `corten-sandbox` confines (below) | Wasm broker claims |
| `corten-runtime` | Restart and stop children as its policy says; contain a panic to the child's thread | Availability claims that rest on supervision |
| `cargo` (vendor and build) | Vendor exactly the locked sources, and build offline from them | The hermetic build and its provenance |
| Cryptographic provider: `chacha20poly1305` 0.11.0 (XChaCha20-Poly1305), `argon2` 0.6.0 (Argon2id), `ed25519-compact` 2.6.0 (Ed25519) and `getrandom` 0.4.3 (the operating system's generator), behind `corten_std::crypto` and `corten_std::random` | Implement the primitives they offer correctly and in constant time where they say so; the operating system's generator is unpredictable | None: cryptography is C (spec 4.10). The prelude makes the misuse it targets harder to write; it proves nothing about the primitives |
| The operator's dependency policy (`--dep-policy`, since 2026-10-28) | Admit only reviewed crates, and `ban` every entry point of an admitted crate that offers what a prelude or checker claim removes (a string-SQL query, a shell runner, a join handle that returns a panic as a value). Unadmitted dependencies are refused by the checker; this row is about the admitted ones | Every claim with `prelude_only = yes`, and every claim resting on a checker ban of a `std` API |
| Capability-manifest verifier and its signing key | Accept only manifests signed by the deployer's key | Every claim about capabilities handed to `main` |
| Hardware | Execute instructions as specified | All claims; transient execution is C |

**Not trusted, and outside every E claim:**

- Dependencies' own code. Registry and git dependencies are built with `--cap-lints allow`, so the profile does not reach them. What local code may call in them is governed: a dependency the operator's policy does not admit is refused, and the policy's `ban` lines forbid an admitted crate's raw entry points (docs/gates/phase-5.md). Layer 3 (spec section 10) and the dependency policy govern them; until then, a dependency can do anything Rust allows.
- **Dependencies' macros, inside the checked crate.** Measured (docs/gates/phase-1.md): a `macro_rules!` exported by a registry dependency can expand to an `unsafe` block in the checked crate, and rustc does not report `unsafe_code` in external macro expansions. Layer 3 (`crates/cargo-corten/src/deps.rs`, Phase 3) refuses a reachable dependency whose `unsafe`-emitting macro or proc macro the local code mentions, and `corten_unsafe_from_macro` (Phase 3b) refuses the expansion itself, including from an allowlisted dependency. The cause, read in the compiler source: rustc drops a lint inside an external macro unless it is declared `report_in_external_macro`.
- Known unsoundness in rustc. Bugs tracked under the `I-unsound` label can produce memory errors in safe code; any E claim fails for a program that exploits one. The bypass hunt records which ones were tried.
- **What a confined program can still reach.** `corten-sandbox` requires Landlock ABI v4, which governs the filesystem and TCP bind and connect. Since 2026-10-29 (owner decision) it also requests ABI v6 scoping wherever the kernel has it (Linux 6.12 and later): the program cannot signal a process outside the sandbox or connect to an abstract UNIX socket created outside it. On a kernel with ABI v4 or v5 the sandbox still runs, without those scopes; v4 stays the floor, so no kernel gets less than before. UDP is not restricted: the `landlock` crate 0.4.7 has no UDP access right (its `AccessNet` is TCP bind and connect only). A brokered process, or a Wasm module that escapes `wasmi` into its runner, can use UDP everywhere, and signals and abstract sockets below ABI v6.
- **Transient execution across processes.** The Wasm broker runs each module in its own process (`corten-wasm-runner`), so a speculative read inside `wasmi` (CWE-1420) can reach only the runner's own memory: the module, its input and the interpreter, not the caller's secrets. That moved out of process on 2026-10-27, after the applicability audit found the module sharing the caller's address space. Attacks that cross a process boundary (for example branch-target injection) rest on the kernel's and the processor's mitigations; transient execution stays C.
- Build scripts and procedural macros run with the build's privileges (crates/cargo-corten/README.md), and so does anything a repository's `[env]` table injects into the compiler process (for example `LD_PRELOAD`). The checker resists configuration that weakens the profile; it does not resist a repository that executes code during the build. On Linux, `cargo corten build` and `cargo corten check` run cargo inside `corten-sandbox` (no network, writes only beneath `target/`). Off Linux, `check` runs them with the caller's privileges and says so; `build` refuses.

## 2. Fail closed

A target that cannot provide a primitive an operation needs refuses the operation with an error. It never falls back to a weaker one. Today this means:

- DirCap: no `openat2`, no file access (docs/pathseg.md section 2).
- Brokers and hermetic builds: no Landlock ABI v4, no sandboxed process. `corten-sandbox` exits 3, and `cargo corten build` refuses to build off Linux.
- `corten-sandbox`: a descriptor above 2 open without close-on-exec, no program (exit 3). The parent closes it first (`scripts/close-leaked-fds.sh`).
- Checker: a toolchain it cannot locate is a usage error (exit 2), not an unchecked build.

## 3. Implementation-defined behaviour, enumerated

Corten has no undefined behaviour in the profile. Behaviour that varies by implementation is listed here and either fixed by the profile or exposed as a typed choice. CWE-758 is C, per the amendment.

| Behaviour | Corten's position |
| --- | --- |
| Integer overflow | Fixed: checked. The checker passes `-C overflow-checks=on` and bans unchecked arithmetic operators (`clippy::arithmetic_side_effects`); `Wrapping<T>` and `Saturating<T>` are explicit types |
| Integer width of `usize`/`isize` | Target pointer width. Conversions to fixed widths go through `TryFrom`; `as` is banned |
| Endianness | Target-defined; byte conversions name it (`to_be_bytes`, `from_le_bytes`), and native-endian conversions are an explicit choice |
| Floating point | IEEE 754 binary32/binary64 with round-to-nearest-even; no implicit fused multiply-add; NaN payload bits are unspecified and must not be relied on |
| Float to integer `as` casts | Banned with `as`; use explicit rounding then `TryFrom` |
| Character and string encoding | `char` is a Unicode scalar value; `str` is UTF-8 |
| `HashMap` iteration order | Unspecified (randomly seeded); code must not depend on it |
| Struct layout | Unspecified for `repr(Rust)`; reinterpretation needs `unsafe`, which is forbidden |
| Operating-system error codes | Surfaced as `std::io::ErrorKind`; raw codes are platform-specific and must not drive security decisions |
| Panic strategy | `unwind`, so the supervision tree (Phase 3) can contain a failed component |
| Thread scheduling and timing | Unspecified; concurrency correctness beyond data races is C |
