# cargo-corten

`cargo corten check` builds a crate under the Corten profile, with flags and a Clippy configuration the checker supplies itself (spec section 10, layer 2). The profile is in [`src/profile.rs`](src/profile.rs):

- `-C overflow-checks=on`;
- forbidden rustc lints: `unsafe_code`, `unused_must_use`, and since Phase 6 `dead_code` and `deprecated`;
- forbidden Clippy lints: `disallowed_methods`, `disallowed_types`, `arithmetic_side_effects`, `as_conversions`, `let_underscore_must_use`, `mem_forget`, and since Phase 6 `precedence`, `float_cmp`, `float_cmp_const`, `dbg_macro`, `todo`, `unimplemented`, `eq_op`, `absurd_extreme_comparisons`, `impossible_comparisons`, `redundant_comparisons`, `overly_complex_bool_expr`, `nonminimal_bool`, `short_circuit_statement` (aids for the CWEs in `docs/gates/phase-6.md`; they move no bucket);
- a Clippy configuration banning ambient filesystem, environment, process, network and clock APIs, `catch_unwind`, and the APIs that skip a destructor. This is a denylist over `std`, so it can miss an API; the closed prelude (`corten-std`) is the deny-by-default answer.

"Forbidden" means `-F`: an in-source `allow` or `expect` cannot lower it (E0453). The Clippy toolchain component is required.

```console
$ cargo install --path crates/cargo-corten --locked
$ cargo corten check                         # in the crate to check
$ cargo corten check --manifest-path path/to/Cargo.toml
$ cargo corten build --sbom sbom.json --provenance provenance.json   # Linux
```

It runs `cargo check --workspace --all-targets` with `clippy-driver` wrapping every crate. Clippy disables itself for registry and git dependencies (built with `--cap-lints allow`), so only the workspace and local path dependencies are linted. The checker writes its `clippy.toml` into a fresh private directory (`create_dir`, mode 0700) and removes it afterwards. Exit status: 0 the build passed, 1 it failed (a profile rule or an ordinary compile error; they are not told apart yet), 2 usage or environment error.

## Dependency policy (layer 3)

Before building, both subcommands read `cargo metadata` and refuse:

- a reachable dependency (a direct dependency of a local package, or one a reachable package re-exports) that the operator's dependency policy does not admit: **dependencies are refused by default** (since 2026-10-28, [`docs/gates/phase-5.md`](../../docs/gates/phase-5.md));
- a package on the ban list ([`src/deps.rs`](src/deps.rs): backtracking regex engines, `libxml`);
- a reachable dependency (a direct dependency of a local package, or one it re-exports) that exports a `macro_rules!` whose expansion can contain `unsafe`, or a proc macro, when the local code mentions that macro;
- any package the scan cannot read within its limits (fail closed).

The operator's dependency policy is a file passed with `--dep-policy FILE` or `CORTEN_DEP_POLICY` ([`src/dep_policy.rs`](src/dep_policy.rs)):

```text
corten-dep-policy 1
allow serde                  # admit a crate (or NAME@VERSION)
ban my_db::query raw SQL     # forbid an admitted crate's raw entry point in local code
ban-type my_db::RawClient raw client
```

Admission does not exempt a crate from the other checks. Each `ban` joins the checker's `disallowed-methods` (and `ban-type` its `disallowed-types`), which the profile forbids, so the operator closes the raw entry points of the crates it admits: a database crate's string-query function, a shell runner, an async runtime's join handle that returns a panic as a value. Every E claim that rests on the prelude or on a checker ban assumes those lines are complete (`docs/tcb.md`). Parsing is strict; a malformed policy is a usage error (exit 2).

`--allow-dep NAME` (repeatable) or `CORTEN_ALLOW_DEPS=a,b` accepts a package refused for its macros or by the ban list, after review; it does not admit a package. Nothing is read from the checked repository. On the corpus this refuses no benign program (0 of 174). A name the ban list does not know passes (docs/gates/phase-3.md).

## Hermetic build (`cargo corten build`, Linux) and the sandboxed check

1. The profile check and the dependency policy, as above.
2. `cargo vendor --locked --respect-source-config` into `target/corten-vendor`, outside the sandbox: the only step with network access.
3. `cargo build --release --locked --offline` from the vendored sources, inside `corten-sandbox` (Landlock): no network; read and execute on the system directories and the toolchain; read-only on the workspace, the checker's configuration, `/proc` and `/dev/urandom`; read-write on `/dev/null` and `target/`. `CARGO_HOME` and `TMPDIR` are private directories under `target/`. Build scripts and proc macros run in here.
4. `--sbom FILE`: CycloneDX 1.5 of every package in the graph. `--provenance FILE`: an unsigned in-toto v1 statement with a SLSA v1 predicate: SHA-256 of each built binary, of `Cargo.lock`, `rustc -vV`, the profile flags, and whether the build was sandboxed. Sign it in CI (layer 4).

`cargo corten check` takes the same path on Linux: steps 1 to 3 with `cargo check --workspace --all-targets --locked --offline` in the sandbox. Its vendor step runs without `--locked`, so it may write `Cargo.lock` as plain `cargo check` would. Local path dependencies outside the workspace, and the `Cargo.toml` files above them (cargo reads those for inherited fields), are granted read-only. The checker's configuration directory is read-only inside the sandbox, so a build script cannot rewrite the ban list.

`corten-sandbox` is found through `CORTEN_SANDBOX` or beside the `cargo-corten` binary; on Linux, without it, both subcommands refuse. It refuses to start while the process holds a descriptor above 2 without close-on-exec: wrap the call in `scripts/close-leaked-fds.sh` when the parent leaks some (the GitHub runner does). Off Linux, `build` refuses to run unconfined and `check` runs with a warning. `scripts/hermetic-smoke.sh` tests it end to end: a benign build's digest equals `sha256sum`'s, and a dependency build script that opens a TCP connection or writes outside `target/` fails (each with a control under plain cargo).

## What it overrides

A repository can carry cargo configuration that changes what rustc receives. Cargo reads `.cargo/config.toml` from the **current directory** and every ancestor, then `$CARGO_HOME`; not from the `--manifest-path` directory. The checker sets the child's environment so none of it can weaken the profile:

| Source | How it could weaken the profile | What the checker does | Test |
| --- | --- | --- | --- |
| `RUSTFLAGS`, `[build] rustflags`, `[target.*] rustflags` | Add `-A unsafe_code` | Sets `CARGO_ENCODED_RUSTFLAGS`, which replaces all of them; removes `RUSTFLAGS` and `CARGO_BUILD_RUSTFLAGS` | `operator_rustflags_cannot_lower_the_profile`, `config_rustflags_cannot_lower_the_profile` |
| `[build] rustc-wrapper` | A wrapper drops `-F unsafe_code` before calling rustc | Sets `RUSTC_WRAPPER` to the toolchain's `clippy-driver` | `config_rustc_wrapper_is_not_run` |
| `[build] rustc-workspace-wrapper` | Same, for workspace members only | Sets `RUSTC_WORKSPACE_WRAPPER` to the empty string | `config_rustc_workspace_wrapper_is_not_run` |
| `clippy.toml` or `.clippy.toml` in the repository | An empty ban list | Sets `CLIPPY_CONF_DIR` to the checker's own directory | `repository_clippy_toml_cannot_empty_the_ban_list` |
| `[env] CLIPPY_CONF_DIR = { value = "...", force = true }` | Points Clippy at the repository's own (empty) ban list; cargo sets `[env]` for every compiler it runs, overriding the checker's variable | Pins it with `--config env.CLIPPY_CONF_DIR.value=... --config env.CLIPPY_CONF_DIR.force=true`, which outranks configuration files | `forced_env_clippy_conf_dir_cannot_replace_the_ban_list` |
| `[env] RUSTC_BOOTSTRAP = { value = "1", force = true }` | Enables nightly features on stable, such as `allow_internal_unsafe` | Pins `RUSTC_BOOTSTRAP=-1` the same way | `forced_env_rustc_bootstrap_cannot_unlock_nightly_features` |
| A banned call in a local path dependency outside the workspace | Clippy ran on workspace members only | `clippy-driver` wraps every crate | `local_path_dependency_outside_the_workspace_is_linted` |
| `[build] rustc` | A replacement rustc ignores the flags | Sets `RUSTC` to the operator's `RUSTC`, or the `rustc` beside the running `cargo` | `config_rustc_replacement_is_not_run` |

`[target.*] rustflags` is covered by cargo's documented precedence (`CARGO_ENCODED_RUSTFLAGS` first, the sources mutually exclusive) and has no test of its own yet.

Each hostile-configuration test first shows the configuration bypasses plain `cargo check` with the same flags (the control), then that the checker rejects the bad program and still accepts the matched safe one. Removing the wrapper overrides makes all three wrapper tests fail, and restricting `clippy-driver` to workspace members makes the path-dependency test fail (both mutation-checked 2026-10-26).

Measured on cargo 1.99.1, 2026-10-26: `--config 'env.CLIPPY_CONF_DIR={value=...,force=true}'` (an inline table) did not override the repository's forced entry; the dotted keys `env.CLIPPY_CONF_DIR.value` and `env.CLIPPY_CONF_DIR.force` did.

Measured on cargo 1.99.1, 2026-10-26: with `[build] rustc-wrapper` pointing at a script that drops `-F`, `CARGO_ENCODED_RUSTFLAGS="-F unsafe_code" cargo check` built an unsafe block; adding `RUSTC_WRAPPER=` made it fail with E0453.

A side effect: an operator's own wrapper, such as `sccache`, is not used under the checker.

## Corten's own lints (second pass)

A passing check runs a second `cargo check` with `corten-driver` as the compiler and only `-F corten_*` flags ([`src/profile.rs`](src/profile.rs) `FORBIDDEN_CORTEN_LINTS`), into `target/corten-lints`, in the sandbox on Linux; `build` runs it before building. The driver is required (owner decision 10): it is found through `CORTEN_DRIVER` or beside `cargo-corten`, and without it both subcommands fail. Build it with `scripts/build-driver.sh`, which installs the nightly pinned in [`crates/corten-lints`](../corten-lints) and prints the binary's path ([`docs/gates/phase-3b.md`](../../docs/gates/phase-3b.md)).

## What it does not cover yet

These are known gaps, not claims. Each needs a test before it can be called handled.

- **The toolchain is chosen by the checked repository.** Run as `cargo corten`, the rustup proxy has already picked the toolchain from the repository's `rust-toolchain.toml`, and rustup documents a `path` key there that names a custom toolchain. Neither the key nor its effect on the checker has been tested here.
- **Off Linux, build scripts and proc macros run unsandboxed during `check`**, with the operator's privileges; the checker warns. On Linux they run in the sandbox (`check_confines_dependency_build_scripts`).
- **Build scripts of workspace crates are linted too** (measured: `std::env::var` in a `build.rs` is rejected), so a build script that reads its environment or files does not pass. Corten's spec does not allow unrestricted build scripts; whether to exempt them is open.
- **`unsafe` produced by a macro from an allowlisted dependency is not reported.** Measured: rustc does not report `unsafe_code` inside expansions of external macros. The dependency policy refuses such a dependency (`dependency_exporting_an_unsafe_macro_is_refused`, `procedural_macro_dependency_is_refused`), so the bypass remains only for packages the operator allows.
- **A repository's `[env]` table can still set other variables for the compiler**, for example `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES`, which run code inside rustc. Only `CLIPPY_CONF_DIR` and `RUSTC_BOOTSTRAP` are pinned. Like build scripts, this is code execution by the checked repository; on Linux the sandbox contains it, elsewhere nothing does.
- **Registry and git dependencies** are compiled by cargo with `--cap-lints allow` (cargo's documented behaviour for non-local packages; not measured here), so the profile does not reach their code. Layer 3 governs which ones may be used; it does not lint them.
