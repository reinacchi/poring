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
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Static(i) => write!(f, "Static({i})"),
            Target::Dynamic(_) => f.write_str("Dynamic(..)"),
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
                return Err(RouterError::Duplicate { method: r.method.as_str(), path: r.path.clone() });
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
            let allow =
                HeaderValue::from_str(&allow.join(", ")).unwrap_or_else(|_| HeaderValue::from_static("OPTIONS"));
            inner
                .insert(path, PathEntry { methods, allow })
                .map_err(|source| RouterError::Insert { path: path.to_owned(), source })?;
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
            Some(w) => {
                entry.methods[w.index()].or(if w == Method::Head { entry.methods[Method::Get.index()] } else { None })
            }
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
