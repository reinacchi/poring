//! Route / policy manifest types.

use serde::{Deserialize, Serialize};

/// The complete, serialisable description of a Poring application.
///
/// A manifest is produced by the runtime from compile-time route descriptors plus the
/// startup-time merge of app, group/plugin and route policies. It contains no secrets:
/// only declarations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest format version, see [`crate::contract::MANIFEST_FORMAT_VERSION`].
    pub format_version: u32,
    /// Application name as declared in `poring_app!`.
    pub app: String,
    /// Version of the `poring` crate that produced the manifest.
    pub poring_version: String,
    /// The declared authenticator type, if any.
    pub authenticator: Option<String>,
    /// Application-wide CORS configuration, if any.
    pub cors: Option<CorsView>,
    /// Global hooks (names only), in execution order.
    pub global_hooks: HookSet,
    /// All routes, statically registered ones first (declaration order), then dynamic ones.
    pub routes: Vec<RouteEntry>,
}

impl Manifest {
    /// Finds a route by `"METHOD /path"`, by route ID, or by handler name.
    pub fn find(&self, query: &str) -> Option<&RouteEntry> {
        let q = query.trim();
        if let Some((m, p)) = q.split_once(' ') {
            let m = m.trim();
            let p = p.trim();
            return self
                .routes
                .iter()
                .find(|r| r.method.eq_ignore_ascii_case(m) && r.path == p);
        }
        self.routes.iter().find(|r| r.id == q || r.handler == q)
    }
}

/// CORS configuration (declarations only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsView {
    /// Allowed origins (exact match). `*` only allowed without credentials.
    pub origins: Vec<String>,
    /// Whether credentials (cookies, auth headers) are allowed cross-origin.
    pub credentials: bool,
    /// Allowed request headers for preflight.
    pub headers: Vec<String>,
    /// Preflight cache max-age in seconds.
    pub max_age_secs: u64,
}

/// Hook names grouped by phase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSet {
    /// Hooks that run before extraction (guards).
    pub before: Vec<HookEntry>,
    /// Hooks that run after the handler produced a response.
    pub after: Vec<HookEntry>,
}

/// A named hook and the scope it was declared at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookEntry {
    /// Rust path of the hook.
    pub name: String,
    /// `global`, `group` or `local`.
    pub scope: String,
}

/// Source location of a declaration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLoc {
    /// File path relative to the crate root, as reported by `file!()`.
    pub file: String,
    /// 1-based line.
    pub line: u32,
}

/// Kind of route registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    /// Declared through route attribute macros and verified by `poring_app!`.
    Static,
    /// Registered at startup (e.g. a Wasm guest). Validated at startup/reload only.
    Dynamic,
    /// A typed native handler registered through the fluent API. Handler, extractor and
    /// state types are checked by the compiler; paths and policies are validated at startup.
    Native,
}

/// One route of the application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEntry {
    /// Stable route ID (see [`crate::contract::route_id`]).
    pub id: String,
    /// Static or dynamic.
    pub kind: RouteKind,
    /// Upper-case HTTP method.
    pub method: String,
    /// Full canonical path including group prefixes, e.g. `/admin/users/{id}`.
    pub path: String,
    /// Handler function name (or guest name for dynamic routes).
    pub handler: String,
    /// Declaration source.
    pub source: SourceLoc,
    /// Group prefix or plugin name this route was registered under.
    pub group: Option<String>,
    /// Typed extractors in argument order.
    pub extractors: Vec<ExtractorEntry>,
    /// Effective hook chain (global, group, local merged in execution order).
    pub hooks: HookSet,
    /// Effective security policy.
    pub policy: PolicyView,
    /// Explicit user-declared flow annotations (e.g. `"db: load user"`). Poring never
    /// infers operations inside handler bodies.
    pub annotations: Vec<String>,
    /// Route upgrades to a WebSocket.
    pub websocket: bool,
    /// Free-form metadata (e.g. Wasm guest version/hash).
    pub meta: Vec<(String, String)>,
}

/// An extractor used by a handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractorEntry {
    /// Extractor kind, e.g. `path`, `query`, `json`, `state`, `principal`.
    pub kind: String,
    /// Rust type as written in the handler signature.
    pub ty: String,
    /// Whether it reads the request body.
    pub consumes_body: bool,
    /// Whether it runs declarative validation.
    pub validates: bool,
}

/// Effective (merged) security policy of a route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyView {
    /// `required` or `public`.
    pub auth: String,
    /// Why the route is public, if it is an explicit exception.
    pub public_reason: Option<String>,
    /// True if the route is public only because the app declares no authenticator.
    pub implicit_public: bool,
    /// Required scopes (all must be present).
    pub scopes: Vec<String>,
    /// Required roles (all must be present).
    pub roles: Vec<String>,
    /// Maximum request body size in bytes.
    pub body_limit: u64,
    /// Allowed request content types (empty = not restricted).
    pub content_types: Vec<String>,
    /// CSRF mode: `enforced` (cookie-authenticated unsafe methods), `exempt` or `not_applicable`.
    pub csrf: String,
    /// Reason for a CSRF exemption.
    pub csrf_exempt_reason: Option<String>,
    /// Request timeout in milliseconds.
    pub timeout_ms: Option<u64>,
    /// Rate limit.
    pub rate_limit: Option<RateLimitView>,
    /// App-wide ceiling enforced in addition to `rate_limit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_ceiling: Option<RateLimitView>,
    /// WebSocket origins declared for this route (`["*"]` = any); absent when the app
    /// default applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_origins: Option<Vec<String>>,
    /// Provenance of each effective setting, e.g. `auth=required <- app defaults`.
    pub provenance: Vec<String>,
    /// Runtime checks executed for this route, in order.
    pub checks: Vec<String>,
}

/// Rate limit declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitView {
    /// Requests allowed per window.
    pub requests: u32,
    /// Window length in milliseconds.
    pub per_ms: u64,
    /// Bucket key: `ip` or `principal`. Client identities are never exported.
    pub key: String,
    /// Always `token_bucket`: a burst of `requests`, refilled continuously over `per_ms`.
    #[serde(default = "token_bucket")]
    pub algorithm: String,
    /// Bucket sharing: `route`, `group` or `app`.
    #[serde(default = "route_scope")]
    pub scope: String,
    /// For shared buckets, the declaration that owns the bucket (e.g. ``group `/api` ``).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_by: Option<String>,
    /// Whether responses carry `RateLimit`/`RateLimit-Policy` headers.
    #[serde(default)]
    pub headers: bool,
}

fn token_bucket() -> String {
    "token_bucket".to_owned()
}

fn route_scope() -> String {
    "route".to_owned()
}
