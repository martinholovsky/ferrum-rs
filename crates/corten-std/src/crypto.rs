//! Misuse-resistant cryptography (Phase 6, strategy 10; spec section 8,
//! question 13).
//!
//! No algorithm choice and no knobs that weaken a primitive:
//!
//! - [`AeadKey`]: authenticated encryption with XChaCha20-Poly1305. The
//!   library picks a fresh random 192-bit nonce for every message and stores
//!   it in front of the ciphertext, so a caller cannot reuse a nonce
//!   (CWE-323, 329, 1204). Opening fails on any change to the ciphertext, the
//!   nonce or the associated data, without saying which (CWE-353, 354).
//! - [`password`]: Argon2id password hashes with a cost floor
//!   (CWE-916, 759, 760).
//! - [`verify_signed`]: an Ed25519 signature check whose only success value
//!   is [`Verified`], so unchecked data cannot be passed where checked data
//!   is required (CWE-347).
//!
//! The primitives come from the `RustCrypto` crates `chacha20poly1305` and
//! `argon2` and from `ed25519-compact` (owner decision, 2026-11-01;
//! `docs/gates/phase-6.md`). None of their types appear in this module's
//! public API: an application using the prelude need not admit them in its
//! dependency policy (layer 3 counts re-exported crates as reachable).

use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::random::{self, RandomError};
use crate::secret::{Secret, SecretError};

/// Key length of [`AeadKey`], in bytes.
pub const KEY_LEN: usize = 32;
/// The first byte of every sealed message: the format (XChaCha20-Poly1305,
/// 24-byte nonce, 16-byte tag). [`AeadKey::open`] refuses any other value, so
/// a later algorithm change is a new version rather than a silent break.
pub const FORMAT_VERSION: u8 = 1;
/// Bytes [`AeadKey::seal`] adds to the plaintext: version, nonce and tag.
pub const OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;
/// Length of the nonce [`AeadKey::seal`] stores in front of the ciphertext.
pub const NONCE_LEN: usize = 24;
/// Length of the authentication tag after the ciphertext.
pub const TAG_LEN: usize = 16;
/// Largest plaintext [`AeadKey::seal`] accepts, and largest sealed message
/// [`AeadKey::open`] reads: 16 MiB. A bound, so an attacker-supplied length
/// cannot make the prelude allocate without limit (CWE-770).
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// Why a cryptographic operation failed.
#[derive(Debug)]
pub enum CryptoError {
    /// The operating system's random generator failed.
    Random(RandomError),
    /// A key could not be held as a [`Secret`].
    Secret(SecretError),
    /// A key had the wrong length.
    KeyLength,
    /// The message is longer than [`MAX_MESSAGE`].
    TooLarge,
    /// Opening failed: the message is too short, or it, its nonce or its
    /// associated data was changed, or the key is wrong. Deliberately one
    /// variant, so the failure reveals nothing about which.
    Open,
    /// Encryption failed inside the cipher.
    Seal,
    /// A stored password hash is not a well-formed Argon2id hash.
    HashFormat,
    /// A stored password hash's cost is below the floor
    /// ([`password::FLOOR`]).
    WeakHash,
    /// The password does not match the stored hash.
    Mismatch,
    /// A signature or public key is malformed, or the signature does not
    /// verify.
    Signature,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(e) => write!(f, "{e}"),
            Self::Secret(e) => write!(f, "{e}"),
            Self::KeyLength => write!(f, "a key must be {KEY_LEN} bytes"),
            Self::TooLarge => write!(f, "message longer than {MAX_MESSAGE} bytes"),
            Self::Open => write!(f, "the sealed message could not be opened"),
            Self::Seal => write!(f, "encryption failed"),
            Self::HashFormat => write!(f, "not an Argon2id password hash"),
            Self::WeakHash => write!(f, "the password hash's cost is below the floor"),
            Self::Mismatch => write!(f, "the password does not match"),
            Self::Signature => write!(f, "the signature does not verify"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<RandomError> for CryptoError {
    fn from(e: RandomError) -> Self {
        Self::Random(e)
    }
}

impl From<SecretError> for CryptoError {
    fn from(e: SecretError) -> Self {
        Self::Secret(e)
    }
}

/// Associated data: authenticated but not encrypted. A label (spec 4.2), so
/// it cannot be swapped with the plaintext.
#[derive(Debug, Clone, Copy)]
pub struct Aad<'a>(pub &'a [u8]);

/// An XChaCha20-Poly1305 key, held as a [`Secret`] (locked, wiped, never
/// printed). See the module documentation.
pub struct AeadKey(Secret);

impl AeadKey {
    /// A new random key from the operating system's generator.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`] or [`CryptoError::Secret`].
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = vec![0u8; KEY_LEN];
        random::fill(&mut bytes)?;
        Ok(Self(Secret::new(bytes)?))
    }

    /// Uses existing key material, which must be exactly [`KEY_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyLength`].
    pub fn from_secret(key: Secret) -> Result<Self, CryptoError> {
        if key.len() == KEY_LEN {
            Ok(Self(key))
        } else {
            Err(CryptoError::KeyLength)
        }
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, CryptoError> {
        self.0
            .expose(XChaCha20Poly1305::new_from_slice)
            .map_err(|_| CryptoError::KeyLength)
    }

    /// Encrypts and authenticates `plaintext`, and authenticates `aad`.
    /// Returns [`FORMAT_VERSION`], nonce, ciphertext and tag, in that order.
    ///
    /// # Errors
    ///
    /// [`CryptoError::TooLarge`], [`CryptoError::Random`] or
    /// [`CryptoError::Seal`].
    pub fn seal(&self, plaintext: &[u8], Aad(aad): Aad<'_>) -> Result<Vec<u8>, CryptoError> {
        if plaintext.len() > MAX_MESSAGE {
            return Err(CryptoError::TooLarge);
        }
        let nonce_bytes = random::array::<NONCE_LEN>()?;
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = self
            .cipher()?
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Seal)?;
        let mut out = Vec::with_capacity(OVERHEAD.saturating_add(plaintext.len()));
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Checks and decrypts a message from [`AeadKey::seal`] with the same
    /// `aad`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::TooLarge`], or [`CryptoError::Open`] for every other
    /// failure.
    pub fn open(&self, sealed: &[u8], Aad(aad): Aad<'_>) -> Result<Vec<u8>, CryptoError> {
        if sealed.len() > MAX_MESSAGE.saturating_add(OVERHEAD) {
            return Err(CryptoError::TooLarge);
        }
        let (version, rest) = sealed.split_first().ok_or(CryptoError::Open)?;
        if *version != FORMAT_VERSION {
            return Err(CryptoError::Open);
        }
        let (nonce_bytes, ciphertext) =
            rest.split_at_checked(NONCE_LEN).ok_or(CryptoError::Open)?;
        let nonce_array: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| CryptoError::Open)?;
        let nonce = XNonce::from(nonce_array);
        self.cipher()?
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::Open)
    }
}

/// Data whose signature has been checked. The only way to get one is
/// [`verify_signed`] (or [`Verified::map`] on another `Verified`), so a
/// function that takes `Verified<T>` cannot be handed unchecked data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    /// The checked value.
    pub fn get(&self) -> &T {
        &self.0
    }

    /// The checked value, consuming the wrapper.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Parses or transforms the checked value; the result stays `Verified`,
    /// because it was derived only from checked data.
    ///
    /// # Errors
    ///
    /// Whatever `f` returns.
    pub fn map<U, E>(self, f: impl FnOnce(T) -> Result<U, E>) -> Result<Verified<U>, E> {
        f(self.0).map(Verified)
    }
}

/// An Ed25519 signature: a label, so it cannot be passed where the key
/// belongs (spec 4.2).
#[derive(Debug, Clone, Copy)]
pub struct SignatureBytes<'a>(pub &'a [u8]);

/// An Ed25519 public key: a label, as [`SignatureBytes`].
#[derive(Debug, Clone, Copy)]
pub struct VerifyingKey<'a>(pub &'a [u8]);

/// Checks an Ed25519 signature over `message` and returns the message as
/// [`Verified`].
///
/// # Errors
///
/// [`CryptoError::Signature`] if the key or signature is malformed or the
/// signature does not verify; [`CryptoError::TooLarge`] beyond
/// [`MAX_MESSAGE`].
pub fn verify_signed(
    message: Vec<u8>,
    SignatureBytes(signature): SignatureBytes<'_>,
    VerifyingKey(public_key): VerifyingKey<'_>,
) -> Result<Verified<Vec<u8>>, CryptoError> {
    if message.len() > MAX_MESSAGE {
        return Err(CryptoError::TooLarge);
    }
    let key =
        ed25519_compact::PublicKey::from_slice(public_key).map_err(|_| CryptoError::Signature)?;
    let sig =
        ed25519_compact::Signature::from_slice(signature).map_err(|_| CryptoError::Signature)?;
    key.verify(&message, &sig)
        .map_err(|_| CryptoError::Signature)?;
    Ok(Verified(message))
}

/// Argon2id password hashes (CWE-916, 759, 760).
///
/// [`hash`](password::hash) uses a fresh 16-byte random salt (RFC 9106, section 3.1) and
/// OWASP's recommended Argon2id configuration (19 MiB, 2 iterations, 1 lane;
/// Password Storage Cheat Sheet, checked 2026-11-01). [`verify`](password::verify) refuses a
/// stored hash below every one of OWASP's minimum configurations, so a weak
/// hash planted in storage or kept from an older system cannot be accepted.
pub mod password {
    use std::fmt;

    use argon2::password_hash::phc::PasswordHash as Phc;
    use argon2::password_hash::{PasswordHasher, PasswordVerifier};
    use argon2::{Algorithm, Argon2, Params, Version};

    use super::CryptoError;
    use crate::random;
    use crate::secret::Secret;

    /// Salt length, in bytes (RFC 9106: 16 bytes recommended).
    pub const SALT_LEN: usize = 16;
    /// Memory cost of new hashes, in KiB (19 MiB).
    pub const M_COST: u32 = 19 * 1024;
    /// Iterations of new hashes.
    pub const T_COST: u32 = 2;
    /// Lanes of new hashes.
    pub const P_COST: u32 = 1;
    /// OWASP's minimum Argon2id configurations as (memory in KiB,
    /// iterations); each gives an equal level of defence.
    pub const FLOOR: [(u32, u32); 5] = [
        (47_104, 1),
        (19_456, 2),
        (12_288, 3),
        (9_216, 4),
        (7_168, 5),
    ];

    /// A stored password hash in the PHC string format
    /// (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`). Not secret, but
    /// printed only through [`PasswordHash::as_str`].
    #[derive(Clone, PartialEq, Eq)]
    pub struct PasswordHash(String);

    impl PasswordHash {
        /// The PHC string, for storage.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }

        /// Wraps a PHC string read from storage. It is checked by
        /// [`verify`], not here.
        #[must_use]
        pub fn from_stored(text: String) -> Self {
            Self(text)
        }
    }

    impl fmt::Debug for PasswordHash {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("PasswordHash(..)")
        }
    }

    /// Whether Argon2id costs `m_cost` (KiB) and `t_cost` meet at least one
    /// of OWASP's minimum configurations ([`FLOOR`]).
    fn meets_floor(m_cost: u32, t_cost: u32) -> bool {
        FLOOR.iter().any(|&(m, t)| m_cost >= m && t_cost >= t)
    }

    fn hasher(params: Params) -> Argon2<'static> {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }

    /// Hashes `password` with a fresh random salt.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`], or [`CryptoError::HashFormat`] if hashing
    /// fails inside the library.
    pub fn hash(password: &Secret) -> Result<PasswordHash, CryptoError> {
        let salt = random::array::<SALT_LEN>()?;
        let params =
            Params::new(M_COST, T_COST, P_COST, None).map_err(|_| CryptoError::HashFormat)?;
        let phc = password
            .expose(|pw| hasher(params).hash_password_with_salt(pw, &salt))
            .map_err(|_| CryptoError::HashFormat)?;
        Ok(PasswordHash(phc.to_string()))
    }

    /// Checks `password` against a stored hash.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::HashFormat`]: not a well-formed Argon2id (version 19)
    ///   PHC string (the parser holds every field in a fixed-size buffer, so
    ///   a long input is refused without a large allocation);
    /// - [`CryptoError::WeakHash`]: its cost is below [`FLOOR`];
    /// - [`CryptoError::Mismatch`]: the password does not match.
    pub fn verify(password: &Secret, stored: &PasswordHash) -> Result<(), CryptoError> {
        let phc = Phc::new(&stored.0).map_err(|_| CryptoError::HashFormat)?;
        if phc.algorithm.as_str() != "argon2id" || phc.version != Some(0x13) {
            return Err(CryptoError::HashFormat);
        }
        let params = Params::try_from(&phc).map_err(|_| CryptoError::HashFormat)?;
        if !meets_floor(params.m_cost(), params.t_cost()) {
            return Err(CryptoError::WeakHash);
        }
        password
            .expose(|pw| hasher(params).verify_password(pw, &phc))
            .map_err(|_| CryptoError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::password::{self, PasswordHash};
    use super::*;

    fn secret(bytes: &[u8]) -> Secret {
        Secret::new(bytes.to_vec()).unwrap()
    }

    #[test]
    fn seal_then_open_round_trips() {
        let key = AeadKey::generate().unwrap();
        let sealed = key.seal(b"attack at dawn", Aad(b"msg-1")).unwrap();
        assert_eq!(sealed.len(), OVERHEAD + 14);
        assert_eq!(sealed[0], FORMAT_VERSION);
        assert_eq!(key.open(&sealed, Aad(b"msg-1")).unwrap(), b"attack at dawn");
    }

    #[test]
    fn every_seal_uses_a_new_nonce() {
        let key = AeadKey::generate().unwrap();
        let a = key.seal(b"same", Aad(b"")).unwrap();
        let b = key.seal(b"same", Aad(b"")).unwrap();
        assert_ne!(a[1..=NONCE_LEN], b[1..=NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn open_refuses_every_single_bit_flip() {
        let key = AeadKey::generate().unwrap();
        let sealed = key.seal(b"payload", Aad(b"ad")).unwrap();
        // Denominator: every bit of version, nonce, ciphertext and tag.
        let mut refused = 0usize;
        for i in 0..sealed.len() * 8 {
            let mut t = sealed.clone();
            t[i / 8] ^= 1 << (i % 8);
            if matches!(key.open(&t, Aad(b"ad")), Err(CryptoError::Open)) {
                refused += 1;
            }
        }
        assert_eq!(refused, sealed.len() * 8);
    }

    #[test]
    fn open_refuses_other_aad_other_key_and_short_input() {
        let key = AeadKey::generate().unwrap();
        let sealed = key.seal(b"payload", Aad(b"ad")).unwrap();
        assert!(matches!(
            key.open(&sealed, Aad(b"other")),
            Err(CryptoError::Open)
        ));
        let other = AeadKey::generate().unwrap();
        assert!(matches!(
            other.open(&sealed, Aad(b"ad")),
            Err(CryptoError::Open)
        ));
        assert!(matches!(
            key.open(&sealed[..OVERHEAD - 1], Aad(b"ad")),
            Err(CryptoError::Open)
        ));
        assert!(matches!(
            key.open(&sealed[..OVERHEAD], Aad(b"ad")),
            Err(CryptoError::Open)
        ));
        assert!(matches!(key.open(&[], Aad(b"ad")), Err(CryptoError::Open)));
    }

    #[test]
    fn sizes_are_bounded() {
        let key = AeadKey::generate().unwrap();
        let big = vec![0u8; MAX_MESSAGE + 1];
        assert!(matches!(
            key.seal(&big, Aad(b"")),
            Err(CryptoError::TooLarge)
        ));
        assert!(matches!(
            key.open(&vec![0u8; MAX_MESSAGE + OVERHEAD + 1], Aad(b"")),
            Err(CryptoError::TooLarge)
        ));
    }

    #[test]
    fn keys_of_the_wrong_length_are_refused() {
        assert!(matches!(
            AeadKey::from_secret(secret(&[7; 31])),
            Err(CryptoError::KeyLength)
        ));
        assert!(matches!(
            AeadKey::from_secret(secret(&[7; 33])),
            Err(CryptoError::KeyLength)
        ));
        assert!(AeadKey::from_secret(secret(&[7; 32])).is_ok());
    }

    // RFC 8032, section 7.1, TEST 2.
    const PK: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const SIG: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                       085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8032_vector_verifies_and_tampering_does_not() {
        let (pk, sig) = (hex(PK), hex(SIG));
        let v = verify_signed(vec![0x72], SignatureBytes(&sig), VerifyingKey(&pk)).unwrap();
        assert_eq!(v.get(), &vec![0x72]);
        assert!(matches!(
            verify_signed(vec![0x73], SignatureBytes(&sig), VerifyingKey(&pk)),
            Err(CryptoError::Signature)
        ));
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(matches!(
            verify_signed(vec![0x72], SignatureBytes(&bad), VerifyingKey(&pk)),
            Err(CryptoError::Signature)
        ));
        assert!(matches!(
            verify_signed(vec![0x72], SignatureBytes(&sig[..63]), VerifyingKey(&pk)),
            Err(CryptoError::Signature)
        ));
    }

    #[test]
    fn verified_map_keeps_the_wrapper() {
        let (pk, sig) = (hex(PK), hex(SIG));
        let v = verify_signed(vec![0x72], SignatureBytes(&sig), VerifyingKey(&pk)).unwrap();
        let n: Verified<usize> = v.map(|m| Ok::<_, ()>(m.len())).unwrap();
        assert_eq!(n.into_inner(), 1);
    }

    #[test]
    fn password_hash_round_trips_and_uses_the_configured_cost() {
        let h = password::hash(&secret(b"correct horse")).unwrap();
        assert!(
            h.as_str().starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{}",
            h.as_str()
        );
        password::verify(&secret(b"correct horse"), &h).unwrap();
        assert!(matches!(
            password::verify(&secret(b"correct horsf"), &h),
            Err(CryptoError::Mismatch)
        ));
        assert_eq!(format!("{h:?}"), "PasswordHash(..)");
    }

    #[test]
    fn two_hashes_of_one_password_differ() {
        let a = password::hash(&secret(b"pw")).unwrap();
        let b = password::hash(&secret(b"pw")).unwrap();
        assert_ne!(a, b);
    }

    /// A hash below the floor, made with the library directly, as a weak
    /// legacy hash in storage would be.
    fn hash_with(m: u32, t: u32, alg: argon2::Algorithm) -> PasswordHash {
        use argon2::password_hash::PasswordHasher;
        let params = argon2::Params::new(m, t, 1, None).unwrap();
        let phc = argon2::Argon2::new(alg, argon2::Version::V0x13, params)
            .hash_password_with_salt(b"pw", b"0123456789abcdef")
            .unwrap();
        PasswordHash::from_stored(phc.to_string())
    }

    #[test]
    fn verify_refuses_hashes_below_the_floor() {
        let pw = secret(b"pw");
        // Just below each floor line, and at it.
        for &(m, t) in &password::FLOOR {
            if t > 1 {
                assert!(matches!(
                    password::verify(&pw, &hash_with(m, t - 1, argon2::Algorithm::Argon2id)),
                    Err(CryptoError::WeakHash)
                ));
            }
            password::verify(&pw, &hash_with(m, t, argon2::Algorithm::Argon2id)).unwrap();
        }
        assert!(matches!(
            password::verify(&pw, &hash_with(7_167, 5, argon2::Algorithm::Argon2id)),
            Err(CryptoError::WeakHash)
        ));
    }

    #[test]
    fn verify_refuses_other_algorithms_and_garbage() {
        let pw = secret(b"pw");
        for alg in [argon2::Algorithm::Argon2i, argon2::Algorithm::Argon2d] {
            assert!(matches!(
                password::verify(&pw, &hash_with(19_456, 2, alg)),
                Err(CryptoError::HashFormat)
            ));
        }
        for text in [
            "",
            "plain",
            "$argon2id$v=16$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaA",
        ] {
            assert!(matches!(
                password::verify(&pw, &PasswordHash::from_stored(text.to_owned())),
                Err(CryptoError::HashFormat)
            ));
        }
    }
}
