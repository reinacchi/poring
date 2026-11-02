//! Dynamically registered routes (used by Wasm guests).
//!
//! Dynamic routes are **not** verified by the host's Rust compilation. Their policy is
//! supplied at registration time, validated at startup with the same merge rules as
//! static routes, and enforced by the same runtime pipeline (authentication,
//! authorisation, CSRF, rate limiting, body limits, timeouts) before the endpoint runs.

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use http::{HeaderMap, Method, Uri};

use std::time::Duration;

use crate::policy::{Identity, Policy, RateLimitSpec};
use crate::response::Response;

/// A boxed, sendable future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The request handed to a dynamic endpoint after policy enforcement. The body has
/// already been collected under the route's effective body limit.
#[derive(Debug)]
pub struct DynRequest {
    /// Method.
    pub method: Method,
    /// URI.
    pub uri: Uri,
    /// Headers. `authorization` and `cookie` are removed before the endpoint sees them,
    /// so untrusted guests never receive raw credentials.
    pub headers: HeaderMap,
    /// Body.
    pub body: Bytes,
    /// Decoded path parameters.
    pub params: Vec<(String, String)>,
    /// Authenticated identity, if the route required authentication.
    pub identity: Option<Identity>,
    /// Correlation ID.
    pub request_id: String,
}

/// A dynamically dispatched endpoint.
pub trait DynEndpoint: Send + Sync + 'static {
    /// Handles one request.
    fn call(&self, req: DynRequest) -> BoxFuture<'static, Response>;

    /// Metadata for manifests/graphs (e.g. `guest_version`). Read at manifest time.
    fn metadata(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}

/// Owned policy for a dynamic route.
#[derive(Clone, Debug, Default)]
pub struct DynPolicy {
    /// Require authentication. `None` inherits app defaults.
    pub auth_required: Option<bool>,
    /// Reason, when public.
    pub public_reason: Option<String>,
    /// Required scopes.
    pub scopes: Vec<String>,
    /// Required roles.
    pub roles: Vec<String>,
    /// Body limit.
    pub body_limit: Option<u64>,
    /// Allowed content types.
    pub content_types: Vec<String>,
    /// Timeout in ms (`Some(0)` disables).
    pub timeout_ms: Option<u64>,
    /// Rate limit.
    pub rate_limit: Option<RateLimitSpec>,
}

impl DynPolicy {
    /// The equivalent owned [`Policy`], resolved with the same rules as fluent routes.
    pub(crate) fn to_policy(&self) -> Policy {
        let mut p = Policy::new();
        p = match (self.auth_required, self.public_reason.as_deref()) {
            (Some(true), _) => p.authenticated(),
            (Some(false), Some(r)) if !r.is_empty() => p.public_with_reason(r),
            (Some(false), _) => p.public(),
            (None, _) => p,
        };
        p = p
            .scopes(self.scopes.iter().cloned())
            .roles(self.roles.iter().cloned());
        if let Some(l) = self.body_limit {
            p = p.body_limit(l);
        }
        if !self.content_types.is_empty() {
            p = p.content_types(self.content_types.iter().cloned());
        }
        p = match self.timeout_ms {
            None => p,
            Some(0) => p.no_timeout(),
            Some(ms) => p.timeout(Duration::from_millis(ms)),
        };
        if let Some(r) = &self.rate_limit {
            p = p.with_rate_limit(crate::policy::RateLimit::from_spec(r));
        }
        p
    }
}

/// A dynamic route registration.
pub struct DynamicRoute {
    /// Method.
    pub method: crate::descriptor::Method,
    /// Canonical path.
    pub path: String,
    /// Display name (e.g. guest name).
    pub name: String,
    /// Policy.
    pub policy: DynPolicy,
    /// Endpoint.
    pub endpoint: std::sync::Arc<dyn DynEndpoint>,
}

impl std::fmt::Debug for DynamicRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicRoute")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Validates a dynamic route path with the same rules the macros apply at compile time.
pub fn validate_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err("path must start with `/`".into());
    }
    if path.contains("//") || path.contains(['?', '#', ' ']) {
        return Err("path must not contain `//`, `?`, `#` or spaces".into());
    }
    let segs: Vec<&str> = path.split('/').skip(1).collect();
    for (i, s) in segs.iter().enumerate() {
        if *s == "." || *s == ".." {
            return Err("dot segments are not allowed".into());
        }
        if s.contains('%') {
            return Err("static segments must not be percent-encoded".into());
        }
        if s.starts_with('{') {
            let inner = s
                .strip_prefix('{')
                .and_then(|x| x.strip_suffix('}'))
                .ok_or("unterminated parameter")?;
            let (catch_all, name) = match inner.strip_prefix('*') {
                Some(n) => (true, n),
                None => (false, inner),
            };
            if catch_all && i + 1 != segs.len() {
                return Err("catch-all must be the last segment".into());
            }
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err("invalid parameter name".into());
            }
        } else if s.contains(['{', '}']) {
            return Err("parameters must span a whole segment".into());
        }
    }
    Ok(())
}
