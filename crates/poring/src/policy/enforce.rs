//! Runtime enforcement primitives: CORS and CSRF. The rate limiter lives in
//! [`super::rate_limit`] and is re-exported here.

use http::{HeaderMap, HeaderValue};

use crate::descriptor::CorsSpec;

/// Name of the CSRF double-submit cookie.
pub const CSRF_COOKIE: &str = "poring-csrf";
/// Name of the CSRF request header.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Checks the double-submit CSRF token: the `x-csrf-token` header must equal the
/// `poring-csrf` cookie, and the token must be at least 16 bytes.
pub fn csrf_ok(headers: &HeaderMap) -> bool {
    let Some(cookie) = crate::extract::cookie::find_cookie(headers, CSRF_COOKIE) else {
        return false;
    };
    let Some(header) = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    cookie.len() >= 16 && ct_eq(cookie.as_bytes(), header.as_bytes())
}

/// Generates a random 32-hex-char CSRF token and the `Set-Cookie` value carrying it.
///
/// The cookie is `SameSite=Strict; Secure; Path=/` and deliberately *not* `HttpOnly`
/// (the double-submit pattern requires client script to read it).
pub fn issue_csrf_token() -> Result<(String, HeaderValue), getrandom::Error> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw)?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let cookie = format!("{CSRF_COOKIE}={token}; Path=/; SameSite=Strict; Secure");
    let value = HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""));
    Ok((token, value))
}

/// Runtime CORS configuration.
#[derive(Clone, Debug)]
pub struct CorsRuntime {
    origins: Vec<String>,
    wildcard: bool,
    credentials: bool,
    allow_headers: HeaderValue,
    max_age: HeaderValue,
}

impl CorsRuntime {
    /// Builds from a compile-time spec.
    pub fn from_spec(spec: &CorsSpec) -> Self {
        let headers = if spec.headers.is_empty() {
            "content-type, authorization, x-csrf-token, x-request-id".to_owned()
        } else {
            spec.headers.join(", ")
        };
        CorsRuntime {
            origins: spec.origins.iter().map(|s| (*s).to_owned()).collect(),
            wildcard: spec.origins.contains(&"*"),
            credentials: spec.credentials,
            allow_headers: HeaderValue::from_str(&headers)
                .unwrap_or_else(|_| HeaderValue::from_static("content-type")),
            max_age: HeaderValue::from(spec.max_age_secs),
        }
    }

    /// Builds from an owned fluent declaration.
    pub fn from_cors(c: &crate::policy::Cors) -> Self {
        let headers = if c.headers.is_empty() {
            "content-type, authorization, x-csrf-token, x-request-id".to_owned()
        } else {
            c.headers.join(", ")
        };
        CorsRuntime {
            origins: c.origins.clone(),
            wildcard: c.origins.iter().any(|o| o == "*"),
            credentials: c.credentials,
            allow_headers: HeaderValue::from_str(&headers)
                .unwrap_or_else(|_| HeaderValue::from_static("content-type")),
            max_age: HeaderValue::from(c.max_age_secs),
        }
    }

    /// Whether `origin` is allowed.
    pub fn allows(&self, origin: &str) -> bool {
        (self.wildcard && !self.credentials) || self.origins.iter().any(|o| o == origin)
    }

    /// Adds CORS response headers for an allowed `origin`.
    pub fn apply(&self, origin: &HeaderValue, headers: &mut HeaderMap) {
        use http::header::*;
        if self.wildcard && !self.credentials {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        } else {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
            headers.append(VARY, HeaderValue::from_static("origin"));
        }
        if self.credentials {
            headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
    }

    /// Adds preflight headers.
    pub fn apply_preflight(
        &self,
        origin: &HeaderValue,
        allow: &HeaderValue,
        headers: &mut HeaderMap,
    ) {
        use http::header::*;
        self.apply(origin, headers);
        headers.insert(ACCESS_CONTROL_ALLOW_METHODS, allow.clone());
        headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, self.allow_headers.clone());
        headers.insert(ACCESS_CONTROL_MAX_AGE, self.max_age.clone());
    }
}

pub use super::rate_limit::{RateKeyValue, RateLimiter};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_double_submit() {
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            HeaderValue::from_static("poring-csrf=0123456789abcdef0123"),
        );
        assert!(!csrf_ok(&h));
        h.insert(
            CSRF_HEADER,
            HeaderValue::from_static("0123456789abcdef0123"),
        );
        assert!(csrf_ok(&h));
        h.insert(
            CSRF_HEADER,
            HeaderValue::from_static("0123456789abcdef0124"),
        );
        assert!(!csrf_ok(&h));
    }
}
