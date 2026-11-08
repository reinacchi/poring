//! Compile-time route descriptors emitted by Poring's attribute macros.
//!
//! Every `#[poring::get(..)]`-style attribute produces a `const` [`RouteDescriptor`].
//! `poring_app!` collects them into a `const` [`AppDescriptor`] which is then checked by
//! [`crate::policy::check::check_app`] *during constant evaluation* (that is, at compile
//! time), and turned into the runtime routing table at startup.

use crate::policy::PolicySpec;

/// HTTP methods supported by static route declarations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
    /// `HEAD`
    Head,
    /// `OPTIONS`
    Options,
}

impl Method {
    /// All methods, in table order.
    pub const ALL: [Method; 7] = [
        Method::Get,
        Method::Post,
        Method::Put,
        Method::Patch,
        Method::Delete,
        Method::Head,
        Method::Options,
    ];

    /// Upper-case method name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
        }
    }

    /// Index into a per-path method table.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Whether the method is "unsafe" in the RFC 9110 sense (state-changing).
    pub const fn is_unsafe(self) -> bool {
        matches!(
            self,
            Method::Post | Method::Put | Method::Patch | Method::Delete
        )
    }

    /// Converts from an `http::Method`.
    pub fn from_http(m: &http::Method) -> Option<Method> {
        Some(match *m {
            http::Method::GET => Method::Get,
            http::Method::POST => Method::Post,
            http::Method::PUT => Method::Put,
            http::Method::PATCH => Method::Patch,
            http::Method::DELETE => Method::Delete,
            http::Method::HEAD => Method::Head,
            http::Method::OPTIONS => Method::Options,
            _ => return None,
        })
    }

    /// Parses an upper-case method name.
    pub fn parse(s: &str) -> Option<Method> {
        Method::ALL
            .into_iter()
            .find(|m| m.as_str().eq_ignore_ascii_case(s))
    }
}

/// What kind of extractor an argument is (for manifests, graphs and OpenAPI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtractorKind {
    /// `Path<T>`
    Path,
    /// `Query<T>`
    Query,
    /// `Json<T>`
    Json,
    /// `Form<T>`
    Form,
    /// `Header<T>`
    Header,
    /// `Cookie<T>` / `CookieJar`
    Cookie,
    /// `State<T>`
    State,
    /// `Principal<T>`
    Principal,
    /// `Extension<T>`
    Extension,
    /// Raw body (`Bytes`, `String`)
    Body,
    /// Request metadata (`Method`, `Uri`, `HeaderMap`, `RequestId`...)
    Request,
    /// WebSocket upgrade
    WebSocket,
    /// Multipart form data
    Multipart,
    /// User-defined extractor
    Custom,
}

impl ExtractorKind {
    /// Lower-case name used in manifests.
    pub const fn as_str(self) -> &'static str {
        match self {
            ExtractorKind::Path => "path",
            ExtractorKind::Query => "query",
            ExtractorKind::Json => "json",
            ExtractorKind::Form => "form",
            ExtractorKind::Header => "header",
            ExtractorKind::Cookie => "cookie",
            ExtractorKind::State => "state",
            ExtractorKind::Principal => "principal",
            ExtractorKind::Extension => "extension",
            ExtractorKind::Body => "body",
            ExtractorKind::Request => "request",
            ExtractorKind::WebSocket => "websocket",
            ExtractorKind::Multipart => "multipart",
            ExtractorKind::Custom => "custom",
        }
    }
}

/// Function producing a JSON schema for an extractor or response (OpenAPI generation).
pub type SchemaFn = fn(&mut crate::schema::SchemaRegistry) -> serde_json::Value;

/// Describes one handler argument.
#[derive(Clone, Copy, Debug)]
pub struct ExtractorDesc {
    /// Extractor kind.
    pub kind: ExtractorKind,
    /// The Rust type as written in the signature.
    pub ty: &'static str,
    /// Whether this extractor reads the request body.
    pub consumes_body: bool,
    /// Whether declarative validation rules apply.
    pub validates: bool,
    /// Whether this extractor needs an authenticated principal.
    pub uses_principal: bool,
    /// Schema of the extracted data, if describable.
    pub schema: Option<SchemaFn>,
}

/// One documented response of a route (derived from the handler's return type).
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseDoc {
    /// Status code. `0` means "varies / default".
    pub status: u16,
    /// Content type, if known.
    pub content_type: Option<&'static str>,
    /// Body schema, if describable.
    pub schema: Option<serde_json::Value>,
}

/// Produces the documented responses of a route.
pub type ResponseFn = fn(&mut crate::schema::SchemaRegistry) -> Vec<ResponseDoc>;

/// Compile-time description of one statically declared route.
#[derive(Clone, Copy, Debug)]
pub struct RouteDescriptor {
    /// Handler function name.
    pub name: &'static str,
    /// HTTP method.
    pub method: Method,
    /// Canonical path (`{name}` / `{*rest}` parameter syntax).
    pub path: &'static str,
    /// Path parameter names in order.
    pub params: &'static [&'static str],
    /// Extractors in argument order.
    pub extractors: &'static [ExtractorDesc],
    /// Route-local before hooks.
    pub before: &'static [&'static str],
    /// Route-local after hooks.
    pub after: &'static [&'static str],
    /// Route-level policy declaration (merged with group/app defaults).
    pub policy: PolicySpec,
    /// User-declared flow annotations.
    pub annotations: &'static [&'static str],
    /// Doc comment summary of the handler.
    pub doc: &'static str,
    /// Declaring file.
    pub file: &'static str,
    /// Declaring line.
    pub line: u32,
    /// Whether the route upgrades to a WebSocket.
    pub websocket: bool,
    /// Documented responses (from the return type).
    pub response: ResponseFn,
}

/// A route group (or plugin) inside an app.
#[derive(Clone, Copy, Debug)]
pub struct GroupDescriptor {
    /// Group name (prefix or plugin name).
    pub name: &'static str,
    /// Static path prefix, e.g. `/admin` (may be empty for plugins without prefix).
    pub prefix: &'static str,
    /// Group-level policy.
    pub policy: PolicySpec,
    /// Group before hooks.
    pub before: &'static [&'static str],
    /// Group after hooks.
    pub after: &'static [&'static str],
    /// Whether this group is a plugin (`poring_plugin!`).
    pub plugin: bool,
}

/// A route registered in an app, with its group membership.
#[derive(Clone, Copy, Debug)]
pub struct RouteRef {
    /// The route descriptor.
    pub desc: &'static RouteDescriptor,
    /// Index into [`AppDescriptor::groups`].
    pub group: Option<u16>,
}

/// CORS declaration.
#[derive(Clone, Copy, Debug)]
pub struct CorsSpec {
    /// Allowed origins (exact). `"*"` is only valid without credentials.
    pub origins: &'static [&'static str],
    /// Allow credentials.
    pub credentials: bool,
    /// Allowed request headers in preflight.
    pub headers: &'static [&'static str],
    /// Preflight max age in seconds.
    pub max_age_secs: u64,
}

/// Compile-time description of a whole app, produced by `poring_app!`.
#[derive(Clone, Copy, Debug)]
pub struct AppDescriptor {
    /// App type name.
    pub name: &'static str,
    /// App-level default policy.
    pub defaults: PolicySpec,
    /// Whether an authenticator type was declared.
    pub has_authenticator: bool,
    /// Authenticator type name (for manifests).
    pub auth_type: &'static str,
    /// Whether the authenticator may authenticate from cookies (enables CSRF checks).
    pub auth_uses_cookies: bool,
    /// CORS configuration.
    pub cors: Option<CorsSpec>,
    /// Global before hooks.
    pub before: &'static [&'static str],
    /// Global after hooks.
    pub after: &'static [&'static str],
    /// Groups and plugins.
    pub groups: &'static [GroupDescriptor],
    /// All routes in dispatch-index order.
    pub routes: &'static [RouteRef],
}

impl AppDescriptor {
    /// Full path of route `i` (group prefix + route path).
    pub fn full_path(&self, i: usize) -> String {
        let r = &self.routes[i];
        let prefix = r
            .group
            .map(|g| self.groups[g as usize].prefix)
            .unwrap_or("");
        join_path(prefix, r.desc.path)
    }
}

/// Joins a static group prefix and a route path. `"/admin"` + `"/"` is `"/admin"`.
pub fn join_path(prefix: &str, path: &str) -> String {
    if prefix.is_empty() || prefix == "/" {
        return path.to_owned();
    }
    let prefix = prefix.trim_end_matches('/');
    if path == "/" {
        prefix.to_owned()
    } else {
        format!("{prefix}{path}")
    }
}
