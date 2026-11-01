//! Operating-system randomness (Phase 6, strategy 10; CWE-330 to 344).
//!
//! The only source of random bytes in the prelude is the operating system's
//! cryptographically secure generator, read through the `getrandom` crate.
//! There is no seedable or user-supplied generator here, so a program using
//! the prelude cannot pick a predictable seed (CWE-335, 336, 337) or a
//! non-cryptographic generator (CWE-338). Seedable generators in other crates
//! are kept out by the operator's dependency policy, not by this module.
//!
//! A failure of the operating system's generator is returned as an error,
//! never replaced by a weaker source (`docs/tcb.md`, section 2).

use std::fmt;

/// The operating system's generator failed.
#[derive(Debug)]
pub struct RandomError(String);

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the operating system's random generator failed: {}",
            self.0
        )
    }
}

impl std::error::Error for RandomError {}

/// Fills `dest` with random bytes from the operating system.
///
/// # Errors
///
/// [`RandomError`] if the operating system's generator fails.
pub fn fill(dest: &mut [u8]) -> Result<(), RandomError> {
    getrandom::fill(dest).map_err(|e| RandomError(e.to_string()))
}

/// `N` random bytes from the operating system.
///
/// # Errors
///
/// [`RandomError`] if the operating system's generator fails.
pub fn array<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// A random `u64` from the operating system.
///
/// # Errors
///
/// [`RandomError`] if the operating system's generator fails.
pub fn u64() -> Result<u64, RandomError> {
    array::<8>().map(u64::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_and_differs() {
        let a = array::<32>().expect("random");
        let b = array::<32>().expect("random");
        // 2^-256 chance of a false failure.
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn u64_values_differ() {
        let a = u64().expect("random");
        let b = u64().expect("random");
        assert_ne!(a, b);
    }
}
