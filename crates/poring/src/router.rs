//! Immutable, startup-built router (matchit radix tree + per-path method table).
//!
//! Canonical path DSL: `{name}` (whole segment) and `{*rest}` (final segment). The
//! `:name` and trailing `*` forms are accepted by the macros as sugar and normalised to the
//! canonical form at compile time. Matching is strict: no trailing-slash folding, no case
//! folding, no decoding of static segments.

use std::collections::BTreeMap;
use std::sync::Arc;

use http::HeaderValue;

use crate::ctx::Params;
use crate::descriptor::Method;
use crate::dynamic::DynEndpoint;
use crate::policy::EffectivePolicy;

/// Ordered runtime checks (shared vocabulary with the static graph).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// CORS origin check for unsafe methods.
    Cors,
    /// Rate limit.
    RateLimit,
    /// Authentication.
    Auth,
    /// Scope/role authorisation.
    Authz,
    /// CSRF double-submit.
    Csrf,
    /// Content-Length/Content-Type gate.
    BodyGate,
}

impl Check {
    pub(crate) fn parse(s: &str) -> Option<Check> {
        Some(match s {
            "cors" => Check::Cors,
            "rate_limit" => Check::RateLimit,
            "auth" => Check::Auth,
            "authz" => Check::Authz,
            "csrf" => Check::Csrf,
            "body_gate" => Check::BodyGate,
            _ => return None,
        })
    }
}

/// What serves a route.
#[derive(Clone)]
pub enum Target {
    /// A macro-generated, statically dispatched handler (index into the app's dispatch match).
    Static(u16),
    /// A dynamically registered endpoint (e.g. a Wasm guest), boxed-dispatched.
    Dynamic(Arc<dyn DynEndpoint>),
    /// A typed native handler registered through the fluent API (index into the app's
    /// native handler table).
    Native(u32),
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Static(i) => write!(f, "Static({i})"),
            Target::Dynamic(_) => f.write_str("Dynamic(..)"),
            Target::Native(i) => write!(f, "Native({i})"),
        }
    }
}

/// Runtime data of one route, built once at startup.
#[derive(Debug)]
pub struct RouteRuntime {
    /// Stable route ID.
    pub id: String,
    /// Index (rate-limiter partition).
    pub index: u32,
    /// Method.
    pub method: Method,
    /// Full canonical path.
    pub path: String,
    /// Effective policy.
    pub policy: EffectivePolicy,
    /// Precomputed check sequence.
    pub checks: Vec<Check>,
    /// Target.
    pub target: Target,
    /// Rate limits resolved at startup (`None` when the route is not rate limited).
    pub(crate) rate: Option<crate::policy::rate_limit::RouteRate>,
}

#[derive(Debug)]
pub(crate) struct PathEntry {
    methods: [Option<u32>; 7],
    pub(crate) allow: HeaderValue,
}

/// Result of a lookup.
pub(crate) enum Lookup<'r> {
    Found(u32, Params<'r>),
    NotFound,
    MethodNotAllowed(&'r PathEntry),
    /// OPTIONS on a path without an explicit OPTIONS route.
    AutoOptions(&'r PathEntry),
}

/// The immutable router.
#[derive(Debug)]
pub struct Router {
    inner: matchit::Router<PathEntry>,
}

/// Startup error building the router.
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    /// Two registrations collide.
    #[error("route `{method} {path}` is registered twice")]
    Duplicate {
        /// Method.
        method: &'static str,
        /// Path.
        path: String,
    },
    /// matchit rejected the path.
    #[error("route `{path}` cannot be inserted: {source}")]
    Insert {
        /// Path.
        path: String,
        /// matchit error.
        #[source]
        source: matchit::InsertError,
    },
}

impl Router {
    /// Builds from `(method, path, route index)` triples.
    pub(crate) fn build(routes: &[RouteRuntime]) -> Result<Router, RouterError> {
        let mut by_path: BTreeMap<&str, [Option<u32>; 7]> = BTreeMap::new();
        // Preserve registration order for deterministic conflict reporting.
        let mut order: Vec<&str> = Vec::new();
        for r in routes {
            let e = by_path.entry(&r.path).or_insert_with(|| {
                order.push(&r.path);
                [None; 7]
            });
            let slot = &mut e[r.method.index()];
            if slot.is_some() {
                return Err(RouterError::Duplicate {
                    method: r.method.as_str(),
                    path: r.path.clone(),
                });
            }
            *slot = Some(r.index);
        }
        let mut inner = matchit::Router::new();
        for path in order {
            let methods = by_path[path];
            let mut allow: Vec<&str> = Vec::new();
            for m in Method::ALL {
                let present = methods[m.index()].is_some()
                    || (m == Method::Head && methods[Method::Get.index()].is_some())
                    || m == Method::Options;
                if present {
                    allow.push(m.as_str());
                }
            }
            let allow = HeaderValue::from_str(&allow.join(", "))
                .unwrap_or_else(|_| HeaderValue::from_static("OPTIONS"));
            inner
                .insert(path, PathEntry { methods, allow })
                .map_err(|source| RouterError::Insert {
                    path: path.to_owned(),
                    source,
                })?;
        }
        Ok(Router { inner })
    }

    pub(crate) fn lookup<'r>(&'r self, path: &str, method: &http::Method) -> Lookup<'r> {
        let Ok(m) = self.inner.at(path) else {
            return Lookup::NotFound;
        };
        let entry = m.value;
        let wanted = Method::from_http(method);
        let idx = match wanted {
            Some(w) => entry.methods[w.index()].or(if w == Method::Head {
                entry.methods[Method::Get.index()]
            } else {
                None
            }),
            None => None,
        };
        match idx {
            Some(i) => {
                let mut params = Params::new();
                let base = path.as_ptr() as usize;
                for (k, v) in m.params.iter() {
                    let start = (v.as_ptr() as usize).saturating_sub(base);
                    // Route keys live as long as the router (`'r`).
                    if !params.push(k, start, start + v.len()) {
                        break;
                    }
                }
                Lookup::Found(i, params)
            }
            None if wanted == Some(Method::Options) => Lookup::AutoOptions(entry),
            None => Lookup::MethodNotAllowed(entry),
        }
    }
}

/// Canonicalises a runtime-registered route path with the rules the route macros apply
/// at compile time: `{name}` and final `{*rest}` parameters (the `:name` and trailing `*`
/// shorthands are normalised), no `//`, dot segments, percent-encoded static segments,
/// `?`, `#` or whitespace, and at most [`crate::ctx::MAX_PARAMS`] parameters.
///
/// Returns the canonical path and the parameter names in order.
pub fn canonicalise(path: &str) -> Result<(String, Vec<String>), String> {
    if !path.starts_with('/') {
        return Err(format!("route path `{path}` must start with `/`"));
    }
    if path.contains("//") {
        return Err(format!("route path `{path}` must not contain `//`"));
    }
    if path.contains(['?', '#']) || path.chars().any(char::is_whitespace) {
        return Err(format!(
            "route path `{path}` must not contain `?`, `#` or whitespace"
        ));
    }
    if path.contains("{{") || path.contains("}}") {
        return Err("escaped braces `{{`/`}}` are not supported in Poring route paths".into());
    }
    let segs: Vec<&str> = path[1..].split('/').collect();
    let mut out = String::with_capacity(path.len());
    let mut params: Vec<String> = Vec::new();
    for (i, seg) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        out.push('/');
        if *seg == "." || *seg == ".." {
            return Err(format!("route path `{path}` must not contain dot segments"));
        }
        if seg.contains('%') {
            return Err(format!(
                "route path `{path}`: static segments must not be percent-encoded (Poring matches the raw path)"
            ));
        }
        let (name, catch_all) = if let Some(n) = seg.strip_prefix(':') {
            (Some(n), false)
        } else if *seg == "*" {
            (Some("rest"), true)
        } else if let Some(inner) = seg.strip_prefix('{') {
            let inner = inner
                .strip_suffix('}')
                .ok_or_else(|| format!("route path `{path}`: unterminated parameter `{seg}`"))?;
            match inner.strip_prefix('*') {
                Some(n) => (Some(n), true),
                None => (Some(inner), false),
            }
        } else {
            if seg.contains(['{', '}', ':', '*']) {
                return Err(format!(
                    "route path `{path}`: parameters must span a whole segment (`/{{id}}`), found `{seg}`"
                ));
            }
            (None, false)
        };
        match name {
            None => out.push_str(seg),
            Some(n) => {
                if n.is_empty()
                    || !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    || n.starts_with(|c: char| c.is_ascii_digit())
                {
                    return Err(format!(
                        "route path `{path}`: invalid parameter name `{n}` (use [A-Za-z_][A-Za-z0-9_]*)"
                    ));
                }
                if params.iter().any(|p| p == n) {
                    return Err(format!("route path `{path}`: duplicate parameter `{n}`"));
                }
                if catch_all && !last {
                    return Err(format!(
                        "route path `{path}`: catch-all `{{*{n}}}` must be the last segment"
                    ));
                }
                params.push(n.to_owned());
                if catch_all {
                    out.push_str("{*");
                } else {
                    out.push('{');
                }
                out.push_str(n);
                out.push('}');
            }
        }
    }
    if params.len() > crate::ctx::MAX_PARAMS {
        return Err(format!(
            "route path `{path}` has more than {} parameters",
            crate::ctx::MAX_PARAMS
        ));
    }
    Ok((out, params))
}

/// Validates a static group prefix (the rules `poring_app!` applies to `group(..)`).
pub fn validate_prefix(prefix: &str) -> Result<String, String> {
    let (canon, params) =
        canonicalise(prefix).map_err(|e| e.replacen("route path", "group prefix", 1))?;
    if !params.is_empty() {
        return Err(format!(
            "group prefix `{prefix}` must be static (no parameters)"
        ));
    }
    if canon.len() > 1 && canon.ends_with('/') {
        return Err(format!("group prefix `{prefix}` must not end with `/`"));
    }
    Ok(canon)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_runtime_paths() {
        assert_eq!(
            canonicalise("/users/{id}").unwrap(),
            ("/users/{id}".into(), vec!["id".into()])
        );
        assert_eq!(
            canonicalise("/users/:id/*").unwrap().0,
            "/users/{id}/{*rest}"
        );
        for bad in [
            "users",
            "/a//b",
            "/a/{*r}/b",
            "/a/{1x}",
            "/a/x{id}",
            "/a/%2F",
            "/a/..",
            "/a?b",
            "/{a}/{a}",
        ] {
            assert!(canonicalise(bad).is_err(), "{bad}");
        }
        assert!(validate_prefix("/api").is_ok());
        assert!(validate_prefix("/api/").is_err());
        assert!(validate_prefix("/api/{v}").is_err());
    }
}
