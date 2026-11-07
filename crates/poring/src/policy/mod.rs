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
pub mod proxy;
pub mod rate_limit;
pub mod resolve;
pub(crate) mod ws_origin;

pub use auth::{AuthError, AuthRequest, Authenticator, Credential, Identity, NoAuth};
pub use owned::{Cors, Policy};
pub use proxy::TrustedProxies;
pub use rate_limit::{RateLimit, RateLimitDecision, RateLimitStatus, RateScope};
pub use resolve::{CsrfMode, EffectivePolicy, resolve};
pub use ws_origin::WsOrigins;
// `WsOriginsSpec` is defined in this module (next to `PolicySpec`).

mod owned;
pub(crate) use owned::{Level, LevelAuth, LevelCsrf, LevelKind};

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

/// A token-bucket rate limit: a burst of `requests` refilled continuously over `per_ms`
/// milliseconds (see [`rate_limit`] for the exact semantics).
///
/// Declared by `policy(rate_limit = ..)` in macros, or by [`RateLimit`] and
/// [`Policy::rate_limit`] in the fluent API. Construct it with [`RateLimitSpec::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitSpec {
    /// Burst capacity and requests per window.
    pub requests: u32,
    /// Window length in milliseconds.
    pub per_ms: u64,
    /// Partition key.
    pub key: RateKey,
    /// Bucket sharing.
    pub scope: RateScope,
    /// Whether responses carry `RateLimit`/`RateLimit-Policy` headers.
    pub headers: bool,
}

impl RateLimitSpec {
    /// A route-scoped limit without quota headers.
    pub const fn new(requests: u32, per_ms: u64, key: RateKey) -> Self {
        RateLimitSpec {
            requests,
            per_ms,
            key,
            scope: RateScope::Route,
            headers: false,
        }
    }

    /// Sets the bucket scope.
    pub const fn with_scope(mut self, scope: RateScope) -> Self {
        self.scope = scope;
        self
    }

    /// Enables or disables quota headers.
    pub const fn with_headers(mut self, headers: bool) -> Self {
        self.headers = headers;
        self
    }
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
    /// Origins allowed to open WebSocket connections (most specific level wins).
    pub ws_origins: WsOriginsSpec,
}

/// WebSocket handshake origins declared at one level (`policy(ws_origins = ..)`).
///
/// Same-origin handshakes, handshakes without `Origin` and origins listed explicitly in the
/// app's CORS configuration are always accepted; see [`WsOrigins`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsOriginsSpec {
    /// Not declared; inherit (ultimately the app's `.ws_origins(..)` configuration).
    Inherit,
    /// `ws_origins = any`: no origin check. Rejected with a cookie-capable authenticator.
    Any,
    /// `ws_origins = ["https://a.example", ..]`: these origins in addition to same-origin.
    Allow(&'static [&'static str]),
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
        ws_origins: WsOriginsSpec::Inherit,
    };

    /// Borrowed view used by the resolver.
    pub(crate) fn level(&self) -> Level<'static> {
        Level {
            auth: match self.auth {
                AuthSpec::Inherit => LevelAuth::Inherit,
                AuthSpec::Required => LevelAuth::Required,
                AuthSpec::Public { reason } => LevelAuth::Public(reason),
            },
            strict: self.strict,
            scopes: self.scopes.to_vec(),
            roles: self.roles.to_vec(),
            body_limit: self.body_limit,
            content_types: self.content_types.to_vec(),
            csrf: match self.csrf {
                CsrfSpec::Inherit => LevelCsrf::Inherit,
                CsrfSpec::Enforce => LevelCsrf::Enforce,
                CsrfSpec::Exempt { reason } => LevelCsrf::Exempt(reason),
            },
            timeout: self.timeout,
            rate_limit: self.rate_limit,
            ws_origins: match self.ws_origins {
                WsOriginsSpec::Inherit => None,
                WsOriginsSpec::Any => Some(WsOrigins::any()),
                WsOriginsSpec::Allow(list) => Some(WsOrigins::new().allow(list.iter().copied())),
            },
        }
    }
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
