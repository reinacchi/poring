//! Security policy declarations, the compile-time policy checker and runtime enforcement.
//!
//! * [`PolicySpec`] is the `const` declaration emitted by macros (`policy(..)` DSL).
//! * [`check::check_app`] is a `const fn` evaluated by `poring_app!` at compile time.
//! * [`resolve()`] merges app, group and route declarations into an [`EffectivePolicy`]
//!   at startup using the same rules.
//! * [`enforce`] holds the runtime checks (authentication, authorisation, CSRF, CORS,
//!   rate limiting) that run on **every** request; they are never skipped because a
//!   declaration was statically valid.

pub mod auth;
pub mod check;
pub mod enforce;
pub mod resolve;

pub use auth::{AuthError, AuthRequest, Authenticator, Credential, Identity, NoAuth};
pub use resolve::{CsrfMode, EffectivePolicy, resolve};

/// Authentication requirement at one declaration level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthSpec {
    /// Not declared at this level; inherit from the parent.
    Inherit,
    /// An authenticated principal is required.
    Required,
    /// Anonymous access is allowed. `reason` documents an explicit exception and is
    /// mandatory under a strict (`deny_anonymous`) ancestor.
    Public {
        /// Why this endpoint is public (empty if not given).
        reason: &'static str,
    },
}

/// CSRF declaration at one level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsrfSpec {
    /// Not declared; inherit (the default is to enforce).
    Inherit,
    /// Enforce double-submit CSRF protection for cookie-authenticated unsafe requests.
    Enforce,
    /// Explicitly exempt, with a mandatory documented reason.
    Exempt {
        /// Why CSRF protection is not needed (e.g. "HMAC-signed webhook").
        reason: &'static str,
    },
}

/// Timeout declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutSpec {
    /// Inherit (default: [`DEFAULT_TIMEOUT_MS`]).
    Inherit,
    /// Explicitly no timeout.
    Disabled,
    /// Timeout in milliseconds.
    Ms(u64),
}

/// Which key a rate-limit bucket is partitioned by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateKey {
    /// The peer IP address (or the first trusted `X-Forwarded-For` hop if configured).
    Ip,
    /// The authenticated principal's subject (falls back to IP when anonymous).
    Principal,
}

impl RateKey {
    /// Manifest name.
    pub const fn as_str(self) -> &'static str {
        match self {
            RateKey::Ip => "ip",
            RateKey::Principal => "principal",
        }
    }
}

/// A token-bucket rate limit: `requests` per `per_ms` milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitSpec {
    /// Bucket capacity / requests per window.
    pub requests: u32,
    /// Window length.
    pub per_ms: u64,
    /// Partition key.
    pub key: RateKey,
}

/// One level (app, group/plugin, or route) of policy declaration.
///
/// Normally produced by the `policy(..)` DSL in macros; all fields are `const`-friendly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicySpec {
    /// Authentication requirement.
    pub auth: AuthSpec,
    /// `deny_anonymous`: descendants may only be public with an explicit reason.
    pub strict: bool,
    /// Required scopes (union across levels).
    pub scopes: &'static [&'static str],
    /// Required roles (union across levels).
    pub roles: &'static [&'static str],
    /// Max body size in bytes. Narrowing only: a descendant may not raise it.
    pub body_limit: Option<u64>,
    /// Allowed request content types (most specific level wins).
    pub content_types: &'static [&'static str],
    /// CSRF mode.
    pub csrf: CsrfSpec,
    /// Timeout.
    pub timeout: TimeoutSpec,
    /// Rate limit (most specific level wins).
    pub rate_limit: Option<RateLimitSpec>,
}

impl PolicySpec {
    /// A level that declares nothing.
    pub const INHERIT: PolicySpec = PolicySpec {
        auth: AuthSpec::Inherit,
        strict: false,
        scopes: &[],
        roles: &[],
        body_limit: None,
        content_types: &[],
        csrf: CsrfSpec::Inherit,
        timeout: TimeoutSpec::Inherit,
        rate_limit: None,
    };
}

/// Default maximum request body size when nothing is declared: 1 MiB.
pub const DEFAULT_BODY_LIMIT: u64 = 1024 * 1024;
/// Default request timeout when nothing is declared: 30 s.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Parses a size like `"64KiB"`, `"1MiB"`, `"512"` (bytes), `"10KB"`.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().ok()?;
    let mul: u64 = match unit.trim() {
        "" | "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        "KB" | "kB" => 1000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        _ => return None,
    };
    n.checked_mul(mul)
}

/// Parses a duration like `"250ms"`, `"5s"`, `"2m"` into milliseconds.
pub fn parse_duration_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().ok()?;
    let mul = match unit.trim() {
        "ms" => 1,
        "s" | "" => 1000,
        "m" | "min" => 60_000,
        "h" => 3_600_000,
        _ => return None,
    };
    n.checked_mul(mul)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_durations() {
        assert_eq!(parse_size("64KiB"), Some(65536));
        assert_eq!(parse_size("1MiB"), Some(1 << 20));
        assert_eq!(parse_size("10"), Some(10));
        assert_eq!(parse_size("10XB"), None);
        assert_eq!(parse_duration_ms("250ms"), Some(250));
        assert_eq!(parse_duration_ms("5s"), Some(5000));
        assert_eq!(parse_duration_ms("x"), None);
    }
}
