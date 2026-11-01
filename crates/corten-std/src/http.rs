//! HTTP header and cookie types (spec 4.5, 4.6; CWE-93, 113, 644).
//!
//! A header name is an RFC 9110 token; a header value is visible ASCII,
//! space and tab, with no CR, LF or NUL. Neither has a raw constructor.
//! Cookies are always `Secure`, `HttpOnly`, `Path=/` with no `Domain`, and
//! carry the `__Host-` prefix, so the browser itself enforces those
//! attributes and a sibling subdomain cannot plant or override the cookie.
//! `SameSite` must be chosen explicitly.

use std::fmt;

/// Longest header value accepted, in bytes.
pub const MAX_HEADER_VALUE: usize = 8192;

/// Why text is not a valid header name or value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// Empty or too long.
    Length,
    /// A character the grammar does not allow (CR, LF and NUL among them).
    Character,
    /// Leading or trailing whitespace in a value.
    Whitespace,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "header text is empty or too long",
            Self::Character => "header text contains a character its grammar forbids",
            Self::Whitespace => "header value has leading or trailing whitespace",
        })
    }
}

impl std::error::Error for HeaderError {}

const fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// An HTTP header field name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderName(String);

impl HeaderName {
    /// Accepts an RFC 9110 token of 1 to 256 bytes.
    ///
    /// # Errors
    ///
    /// [`HeaderError`] for anything else.
    pub fn parse(text: &str) -> Result<Self, HeaderError> {
        if text.is_empty() || text.len() > 256 {
            return Err(HeaderError::Length);
        }
        if !text.bytes().all(is_tchar) {
            return Err(HeaderError::Character);
        }
        Ok(Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An HTTP header field value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderValue(String);

impl HeaderValue {
    /// Accepts visible ASCII, space and tab, with no leading or trailing
    /// whitespace, up to [`MAX_HEADER_VALUE`] bytes.
    ///
    /// # Errors
    ///
    /// [`HeaderError`] for anything else, including CR, LF, NUL and
    /// non-ASCII text (encode it first, for example per RFC 8187).
    pub fn parse(text: &str) -> Result<Self, HeaderError> {
        if text.len() > MAX_HEADER_VALUE {
            return Err(HeaderError::Length);
        }
        if !text
            .bytes()
            .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
        {
            return Err(HeaderError::Character);
        }
        if text.starts_with([' ', '\t']) || text.ends_with([' ', '\t']) {
            return Err(HeaderError::Whitespace);
        }
        Ok(Self(text.to_owned()))
    }

    /// The value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `SameSite` policy a cookie must state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// `SameSite=Strict`.
    Strict,
    /// `SameSite=Lax`.
    Lax,
}

/// Longest cookie name plus value browsers keep (RFC 6265bis); longer ones
/// are dropped silently, so they are refused here.
pub const MAX_COOKIE_LEN: usize = 4096;

/// A cookie's name: a label (spec 4.2), so it cannot be swapped with the
/// value.
#[derive(Debug, Clone, Copy)]
pub struct CookieName<'a>(pub &'a str);

/// A cookie's value: a label, as [`CookieName`].
#[derive(Debug, Clone, Copy)]
pub struct CookieValue<'a>(pub &'a str);

/// A `Set-Cookie` value: always `__Host-` prefixed, `Secure; HttpOnly`,
/// `Path=/`, no `Domain`, no expiry (a session cookie), and an explicit
/// `SameSite`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCookie(HeaderValue);

impl SetCookie {
    /// Builds the header value for cookie `__Host-{name}`. The name is a
    /// token; the value is RFC 6265 `cookie-octet`s (no space, quote, comma,
    /// semicolon or backslash).
    ///
    /// # Errors
    ///
    /// [`HeaderError::Character`] if either breaks its grammar;
    /// [`HeaderError::Length`] if name and value exceed [`MAX_COOKIE_LEN`].
    pub fn new(
        CookieName(name): CookieName<'_>,
        CookieValue(value): CookieValue<'_>,
        same_site: SameSite,
    ) -> Result<Self, HeaderError> {
        let name = HeaderName::parse(&format!("__Host-{}", name.trim_start_matches("__Host-")))?;
        if name.as_str().len().saturating_add(value.len()) > MAX_COOKIE_LEN {
            return Err(HeaderError::Length);
        }
        let octet =
            |b: u8| matches!(b, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e);
        if !value.bytes().all(octet) {
            return Err(HeaderError::Character);
        }
        let policy = match same_site {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
        };
        HeaderValue::parse(&format!(
            "{}={value}; Path=/; Secure; HttpOnly; SameSite={policy}",
            name.as_str()
        ))
        .map(Self)
    }

    /// The header value.
    #[must_use]
    pub fn value(&self) -> &HeaderValue {
        &self.0
    }
}

/// What an HTTP response implements. It accepts only typed headers and
/// cookies.
pub trait HeaderWriter {
    /// The writer's error.
    type Error;
    /// Adds a header field.
    ///
    /// # Errors
    ///
    /// The writer's error.
    fn insert(&mut self, name: &HeaderName, value: &HeaderValue) -> Result<(), Self::Error>;
    /// Adds a `Set-Cookie` field.
    ///
    /// # Errors
    ///
    /// The writer's error.
    fn set_cookie(&mut self, cookie: &SetCookie) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_reject_line_breaks_and_nul() {
        for bad in [
            "a\r\nSet-Cookie: x=1",
            "a\nb",
            "a\rb",
            "a\0b",
            " lead",
            "trail\t",
            "é",
        ] {
            assert!(HeaderValue::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            HeaderValue::parse("text/html; charset=utf-8")
                .unwrap()
                .as_str(),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn names_are_tokens() {
        assert!(HeaderName::parse("X-Request-Id").is_ok());
        for bad in ["", "a b", "a:b", "a\r\n", "(x)"] {
            assert!(HeaderName::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn cookies_are_always_secure() {
        let c = SetCookie::new(CookieName("sid"), CookieValue("abc123"), SameSite::Strict).unwrap();
        assert_eq!(
            c.value().as_str(),
            "__Host-sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"
        );
        let again =
            SetCookie::new(CookieName("__Host-sid"), CookieValue("v"), SameSite::Lax).unwrap();
        assert!(again.value().as_str().starts_with("__Host-sid=v;"));
        assert!(
            SetCookie::new(
                CookieName("sid"),
                CookieValue(&"a".repeat(4096)),
                SameSite::Lax
            )
            .is_err()
        );
        assert!(SetCookie::new(CookieName("sid"), CookieValue("a;b"), SameSite::Lax).is_err());
        assert!(SetCookie::new(CookieName("sid"), CookieValue("a\r\nb"), SameSite::Lax).is_err());
    }
}
