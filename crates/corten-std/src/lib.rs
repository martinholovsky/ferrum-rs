//! Corten's capability-oriented prelude (spec section 4; Phase 2).
//!
//! Application code under `cargo corten check` cannot reach ambient
//! filesystem, network, process, environment or clock authority in `std`.
//! This crate is what it uses instead:
//!
//! - [`manifest::Capabilities`]: the signed capability manifest, the only
//!   source of authority;
//! - [`fs::DirCap`] and [`path::PathSeg`]: files only beneath a granted
//!   directory, resolved by `openat2` (Linux; refused elsewhere);
//! - typed sinks with compile-time templates and no raw constructors:
//!   [`sql!`], [`html!`], [`process!`], [`log_record!`], [`text!`],
//!   [`ldap_filter!`], [`ldap_dn!`], [`xpath!`], [`xquery!`], plus
//!   [`http::HeaderValue`], [`http::SetCookie`] and [`csv::CsvCell`];
//! - [`secret::Secret`]: wiped, locked, non-printable secret bytes.
//! - [`thread::spawn`] and [`thread::Handle::join`]: threads whose panic
//!   propagates to the joiner instead of coming back as a value.
//! - [`crypto`] and [`random`]: authenticated encryption with
//!   library-managed nonces, Argon2id password hashes with a cost floor,
//!   signature checks that return [`crypto::Verified`], and operating-system
//!   randomness only (Phase 6, batch 5).
//!
//! Every encoder here is part of Corten's trusted base (`docs/tcb.md`). The
//! roadmap requires an independent review of them before any E claim that
//! rests on one is marked verified.
//!
//! This crate passes the Corten profile itself: it has no `unsafe`, no
//! unchecked arithmetic and no banned `std` API, and the compile-fail corpus
//! builds it as a path dependency under `cargo corten check`.

pub mod crypto;
pub mod csv;
pub mod fs;
pub mod html;
pub mod http;
pub mod label;
pub mod ldap;
pub mod log;
pub mod manifest;
pub mod path;
pub mod process;
pub mod random;
pub mod refine;
pub mod secret;
pub mod sql;
pub mod sync;
pub mod template;
pub mod text;
pub mod thread;
pub mod xpath;
