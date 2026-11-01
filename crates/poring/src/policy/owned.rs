//! Owned policy and CORS declarations for routes registered at runtime (the fluent API).
//!
//! These are the runtime counterparts of the `policy(..)` and `cors(..)` macro DSLs. They
//! are resolved with the same merge rules ([`super::resolve()`]) and enforced by the same
//! runtime pipeline. Inconsistencies that the macros reject at compile time are rejected
//! when the app is built, before it listens.

use std::time::Duration;

use super::{RateKey, RateLimitSpec, TimeoutSpec};

/// Authentication requirement of one borrowed level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LevelAuth<'a> {
    Inherit,
    Required,
    Public(&'a str),
}

/// CSRF declaration of one borrowed level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LevelCsrf<'a> {
    Inherit,
    Enforce,
    Exempt(&'a str),
}

/// One policy level as seen by the resolver, borrowed from a `const` [`super::PolicySpec`]
/// or from an owned [`Policy`].
#[derive(Clone, Debug)]
pub(crate) struct Level<'a> {
    pub(crate) auth: LevelAuth<'a>,
    pub(crate) strict: bool,
    pub(crate) scopes: Vec<&'a str>,
    pub(crate) roles: Vec<&'a str>,
    pub(crate) body_limit: Option<u64>,
    pub(crate) content_types: Vec<&'a str>,
    pub(crate) csrf: LevelCsrf<'a>,
    pub(crate) timeout: TimeoutSpec,
    pub(crate) rate_limit: Option<RateLimitSpec>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Auth {
    #[default]
    Inherit,
    Required,
    Public(Option<String>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Csrf {
    #[default]
    Inherit,
    Enforce,
    Exempt(String),
}

/// A security policy for an app, a group or a route registered through the fluent API.
///
/// Levels merge exactly as in the `policy(..)` macro DSL: scopes and roles accumulate,
/// body limits may only narrow, and the most specific declaration of the other settings
/// wins. Contradictions are reported by `build()` before the server binds.
///
/// ```
/// use std::time::Duration;
/// use poring::policy::{Policy, RateKey};
///
/// let admin = Policy::new()
///     .authenticated()
///     .roles(["admin"])
///     .body_limit(16 * 1024)
///     .rate_limit(10, Duration::from_secs(60), RateKey::Principal);
/// # let _ = admin;
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    auth: Auth,
    strict: bool,
    scopes: Vec<String>,
    roles: Vec<String>,
    body_limit: Option<u64>,
    content_types: Vec<String>,
    csrf: Csrf,
    timeout: Option<TimeoutSpec>,
    rate_limit: Option<RateLimitSpec>,
}

impl Policy {
    /// A policy that declares nothing and inherits every setting.
    pub fn new() -> Self {
        Policy::default()
    }

    /// Requires an authenticated principal.
    pub fn authenticated(mut self) -> Self {
        self.auth = Auth::Required;
        self
    }

    /// Requires authentication and makes descendants public only with a documented
    /// reason (`deny_anonymous`). Valid on app and group policies only.
    pub fn deny_anonymous(mut self) -> Self {
        self.auth = Auth::Required;
        self.strict = true;
        self
    }

    /// Allows anonymous access.
    pub fn public(mut self) -> Self {
        self.auth = Auth::Public(None);
        self
    }

    /// Allows anonymous access as a documented exception (required under
    /// `deny_anonymous`, and to drop inherited scopes or roles).
    pub fn public_with_reason(mut self, reason: impl Into<String>) -> Self {
        self.auth = Auth::Public(Some(reason.into()));
        self
    }

    /// Requires every listed scope (accumulates across levels).
    pub fn scopes<I, T>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.scopes.extend(scopes.into_iter().map(Into::into));
        self
    }

    /// Requires every listed role (accumulates across levels).
    pub fn roles<I, T>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.roles.extend(roles.into_iter().map(Into::into));
        self
    }

    /// Maximum request body size in bytes. A level may only narrow an inherited limit.
    pub fn body_limit(mut self, bytes: u64) -> Self {
        self.body_limit = Some(bytes);
        self
    }

    /// Allowed request content types (the most specific level wins).
    pub fn content_types<I, T>(mut self, types: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.content_types = types.into_iter().map(Into::into).collect();
        self
    }

    /// Enforces double-submit CSRF protection for cookie-authenticated unsafe requests
    /// (the default whenever the authenticator uses cookies).
    pub fn enforce_csrf(mut self) -> Self {
        self.csrf = Csrf::Enforce;
        self
    }

    /// Exempts from CSRF protection, with a mandatory documented reason.
    pub fn csrf_exempt(mut self, reason: impl Into<String>) -> Self {
        self.csrf = Csrf::Exempt(reason.into());
        self
    }

    /// Request timeout (covers hooks, extraction and the handler).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(TimeoutSpec::Ms(timeout.as_millis().min(u64::MAX as u128) as u64));
        self
    }

    /// Disables the request timeout.
    pub fn no_timeout(mut self) -> Self {
        self.timeout = Some(TimeoutSpec::Disabled);
        self
    }

    /// Token-bucket rate limit of `requests` per `per`, partitioned by `key`.
    pub fn rate_limit(mut self, requests: u32, per: Duration, key: RateKey) -> Self {
        let per_ms = per.as_millis().min(u64::MAX as u128) as u64;
        self.rate_limit = Some(RateLimitSpec { requests, per_ms, key });
        self
    }

    /// Checks rules that the macro DSL enforces within a single level.
    pub(crate) fn validate(&self, level: LevelKind) -> Result<(), String> {
        let public = matches!(self.auth, Auth::Public(_));
        if let Auth::Public(Some(r)) = &self.auth
            && r.trim().is_empty()
        {
            return Err("public exception reason must not be empty".into());
        }
        if public && level == LevelKind::App {
            return Err("app defaults cannot be public; omit authentication instead".into());
        }
        if self.strict && level == LevelKind::Route {
            return Err("`deny_anonymous` applies to apps and groups, not individual routes".into());
        }
        if public && self.strict {
            return Err("`deny_anonymous` contradicts `public` at the same level".into());
        }
        if public && (!self.scopes.is_empty() || !self.roles.is_empty()) {
            return Err("a public endpoint cannot require scopes or roles".into());
        }
        if let Csrf::Exempt(r) = &self.csrf
            && r.trim().is_empty()
        {
            return Err("a CSRF exemption needs a documented reason".into());
        }
        if let Some(r) = &self.rate_limit {
            if r.requests == 0 {
                return Err("rate_limit count must be > 0".into());
            }
            if r.per_ms == 0 {
                return Err("rate_limit window must be at least 1 ms".into());
            }
        }
        if self.content_types.iter().any(|c| c.trim().is_empty() || !c.contains('/')) {
            return Err("content types must look like `type/subtype`".into());
        }
        Ok(())
    }

    pub(crate) fn level(&self) -> Level<'_> {
        Level {
            auth: match &self.auth {
                Auth::Inherit => LevelAuth::Inherit,
                Auth::Required => LevelAuth::Required,
                Auth::Public(r) => LevelAuth::Public(r.as_deref().unwrap_or("")),
            },
            strict: self.strict,
            scopes: self.scopes.iter().map(String::as_str).collect(),
            roles: self.roles.iter().map(String::as_str).collect(),
            body_limit: self.body_limit,
            content_types: self.content_types.iter().map(String::as_str).collect(),
            csrf: match &self.csrf {
                Csrf::Inherit => LevelCsrf::Inherit,
                Csrf::Enforce => LevelCsrf::Enforce,
                Csrf::Exempt(r) => LevelCsrf::Exempt(r),
            },
            timeout: self.timeout.unwrap_or(TimeoutSpec::Inherit),
            rate_limit: self.rate_limit,
        }
    }

    /// Owned copy of a `const` macro declaration.
    pub(crate) fn from_spec(p: &super::PolicySpec) -> Self {
        use super::{AuthSpec, CsrfSpec};
        Policy {
            auth: match p.auth {
                AuthSpec::Inherit => Auth::Inherit,
                AuthSpec::Required => Auth::Required,
                AuthSpec::Public { reason } => Auth::Public((!reason.is_empty()).then(|| reason.to_owned())),
            },
            strict: p.strict,
            scopes: p.scopes.iter().map(|s| (*s).to_owned()).collect(),
            roles: p.roles.iter().map(|s| (*s).to_owned()).collect(),
            body_limit: p.body_limit,
            content_types: p.content_types.iter().map(|s| (*s).to_owned()).collect(),
            csrf: match p.csrf {
                CsrfSpec::Inherit => Csrf::Inherit,
                CsrfSpec::Enforce => Csrf::Enforce,
                CsrfSpec::Exempt { reason } => Csrf::Exempt(reason.to_owned()),
            },
            timeout: (p.timeout != TimeoutSpec::Inherit).then_some(p.timeout),
            rate_limit: p.rate_limit,
        }
    }
}

/// Which declaration level a [`Policy`] is attached to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LevelKind {
    App,
    Group,
    Route,
}

/// Cross-origin resource sharing for a fluent app (the counterpart of `cors(..)` in
/// `poring_app!`).
///
/// ```
/// use std::time::Duration;
/// use poring::policy::Cors;
///
/// let cors = Cors::new()
///     .origins(["https://app.example.com"])
///     .credentials(true)
///     .max_age(Duration::from_secs(600));
/// # let _ = cors;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cors {
    pub(crate) origins: Vec<String>,
    pub(crate) credentials: bool,
    pub(crate) headers: Vec<String>,
    pub(crate) max_age_secs: u64,
}

impl Default for Cors {
    fn default() -> Self {
        Cors { origins: Vec::new(), credentials: false, headers: Vec::new(), max_age_secs: 600 }
    }
}

impl Cors {
    /// No allowed origins yet; preflight responses are cached for 10 minutes.
    pub fn new() -> Self {
        Cors::default()
    }

    /// Allowed origins (exact matches). `"*"` is only valid without credentials.
    pub fn origins<I, T>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.origins.extend(origins.into_iter().map(Into::into));
        self
    }

    /// Allows credentialed requests.
    pub fn credentials(mut self, on: bool) -> Self {
        self.credentials = on;
        self
    }

    /// Request headers allowed in preflight requests (default: `content-type`,
    /// `authorization`, `x-csrf-token`, `x-request-id`).
    pub fn headers<I, T>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.headers.extend(headers.into_iter().map(Into::into));
        self
    }

    /// Preflight cache lifetime.
    pub fn max_age(mut self, age: Duration) -> Self {
        self.max_age_secs = age.as_secs();
        self
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.origins.is_empty() {
            return Err("CORS needs at least one allowed origin".into());
        }
        if self.credentials && self.origins.iter().any(|o| o == "*") {
            return Err("credentialed CORS cannot use the wildcard origin `*`; list explicit origins".into());
        }
        Ok(())
    }

    pub(crate) fn from_spec(c: &crate::descriptor::CorsSpec) -> Self {
        Cors {
            origins: c.origins.iter().map(|s| (*s).to_owned()).collect(),
            credentials: c.credentials,
            headers: c.headers.iter().map(|s| (*s).to_owned()).collect(),
            max_age_secs: c.max_age_secs,
        }
    }
}
