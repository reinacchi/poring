//! # Poring
//!
//! Poring is an ergonomic Rust web framework built on Tokio and Hyper.
//!
//! Routes are declared in one of two ways, served by the same router, extractors and
//! security pipeline:
//!
//! * **Fluent API.** [`Poring`] chains routes, groups, policies and hooks without
//!   attributes. Handler and extractor types are checked by the compiler. Route conflicts,
//!   path syntax and policy rules are checked by [`Poring::build`] before the server binds.
//! * **Attribute macros.** `#[poring::get("/users/{id}")]` and `poring_app!` declare the
//!   same things, and `poring_app!` checks the whole app during compilation.
//!
//! ```no_run
//! use poring::prelude::*;
//!
//! fn main() -> Result<(), poring::StartupError> {
//!     Poring::new()
//!         .get("/", || async { "Hello, Poring!" })
//!         .get("/hello/{name}", |Path(name): Path<String>| async move { format!("Hello, {name}!") })
//!         .run("127.0.0.1:3000")
//! }
//! ```
//!
//! ```no_run
//! use poring::prelude::*;
//!
//! #[poring::get("/hello/{name}")]
//! async fn hello(Path(name): Path<String>) -> String {
//!     format!("Hello, {name}!")
//! }
//!
//! poring_app! {
//!     pub Api {
//!         routes: [hello],
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), poring::StartupError> {
//!     Api::builder().listen("127.0.0.1:3000").await
//! }
//! ```
//!
//! Every request is enforced at runtime (authentication, authorisation, CSRF, CORS, rate
//! limits, body limits and timeouts), whichever API declared the route. Static flow
//! graphs (Mermaid, DOT, JSON) and runtime traces share node IDs. With the `wasm` and
//! `hot-reload` features, sandboxed WebAssembly guests can be served behind the same
//! pipeline and swapped while the host keeps running.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[path = "app/mod.rs"]
pub mod app;
pub mod body;
pub mod contract;
pub mod ctx;
pub mod descriptor;
pub mod dynamic;
pub mod error;
pub mod extract;
pub mod flow;
pub mod fluent;
pub mod handler;
#[cfg(feature = "openapi")]
pub mod openapi;
pub mod policy;
pub mod response;
pub mod router;
pub mod schema;
pub mod testing;
#[cfg(feature = "tls-rustls")]
pub mod tls;
#[cfg(feature = "wasm")]
pub mod wasm;
#[cfg(feature = "websocket")]
pub mod ws;

pub use app::{
    App, AppSpec, Builder, Limits, ResponseInfo, SecurityHeaders, Server, StartupError,
    dump_manifest_if_requested,
};
pub use body::{Body, ReqBody};
pub use ctx::{Ctx, RequestId};
pub use error::{ApiError, FrameworkError, ValidationIssue};
pub use fluent::{FluentApp, Poring};
pub use handler::{Group, Handler, HookOutcome};
#[cfg(feature = "json")]
pub use response::Json;
pub use response::{Html, IntoResponse, Redirect, Response};
pub use schema::PoringSchema;

pub use poring_macros::{
    PoringSchema, PoringState, delete, get, head, hook, options, patch, poring_app, poring_plugin,
    post, put, route, ws,
};

pub use bytes::Bytes;
pub use http::{self, HeaderMap, HeaderValue, Method, StatusCode, Uri};

/// Everyday imports.
pub mod prelude {
    pub use crate::descriptor::Method as RouteMethod;
    pub use crate::extract::{
        Authenticated, Cookie, Cookies, Extension, Form, FromIdentity, FromRef, FromRequest,
        Header, Path, Principal, Query, State,
    };
    pub use crate::fluent::Poring;
    pub use crate::policy::{
        AuthError, AuthRequest, Authenticator, Cors, Credential, Identity, Policy, RateKey,
        RateLimit, RateLimitStatus, RateScope,
    };
    #[cfg(feature = "json")]
    pub use crate::response::Json;
    pub use crate::response::{Html, IntoResponse, Redirect, Response};
    pub use crate::{
        ApiError, Body, Bytes, Ctx, HeaderMap, HeaderValue, PoringSchema, RequestId, StatusCode,
    };
    pub use poring_macros::{PoringState, poring_app, poring_plugin};
}

/// Re-exports used by macro-generated code. Not part of the public API.
#[doc(hidden)]
pub mod __private {
    pub use crate::app::{AppSpec, Builder, Missing, Provided};
    pub use crate::ctx::Ctx;
    pub use crate::descriptor::{
        AppDescriptor, CorsSpec, ExtractorDesc, ExtractorKind, GroupDescriptor, Method,
        ResponseDoc, RouteDescriptor, RouteRef,
    };
    pub use crate::extract::{ExtractorMeta, FromRef, FromRequest};
    pub use crate::flow::Stage;
    pub use crate::policy::check::check_app;
    pub use crate::policy::{
        AuthSpec, Authenticator, CsrfSpec, NoAuth, PolicySpec, RateKey, RateLimitSpec, RateScope,
        TimeoutSpec, WsOriginsSpec,
    };
    pub use crate::response::describe::{
        DescribeFallback, DescribeResponse, DescribeViaTrait, Probe,
    };
    pub use crate::response::respond::{RespondPlain, RespondResult, Wrap};
    pub use crate::response::{IntoResponse, Response};
    pub use crate::schema::{PoringSchema, SchemaRegistry, ValidationCx, rules};
    pub use serde_json;

    /// Implemented by `#[poring::get]`-style macros: the route's compile-time descriptor.
    pub trait RouteInfo {
        /// The descriptor.
        const DESCRIPTOR: RouteDescriptor;
    }

    /// Implemented by route attribute macros: statically dispatched route glue.
    #[diagnostic::on_unimplemented(
        message = "route `{Self}` cannot run in an app with state `{S}`",
        label = "one of this route's extractors or hooks is unavailable for this app state",
        note = "`State<T>` requires the app state to provide `T` (add a field and `#[derive(PoringState)]`, or implement `FromRef`); hooks must be declared for the same state type"
    )]
    pub trait RouteHandler<S>: RouteInfo {
        /// Route-local before hooks.
        fn before<'a, 'c>(
            cx: &'c mut Ctx<'a, S>,
        ) -> impl Future<Output = Result<(), Response>> + Send + 'c;
        /// Extraction, handler call and response mapping.
        fn handle<'a, 'c>(cx: &'c mut Ctx<'a, S>) -> impl Future<Output = Response> + Send + 'c;
        /// Route-local after hooks.
        fn after<'a, 'c>(
            cx: &'c mut Ctx<'a, S>,
            res: &'c mut Response,
        ) -> impl Future<Output = ()> + Send + 'c;
    }

    /// Implemented by `poring_plugin!`: plugin descriptors.
    pub trait PluginSpec {
        /// The plugin as a group (name, prefix, policy, hooks).
        const GROUP: GroupDescriptor;
        /// The plugin's routes.
        const ROUTES: &'static [&'static RouteDescriptor];
    }

    /// Implemented by `poring_plugin!`: statically dispatched plugin routes, generic over
    /// any app state that satisfies all of the plugin's requirements.
    #[diagnostic::on_unimplemented(
        message = "plugin `{Self}` cannot be used in an app with state `{S}`",
        note = "a route or hook of the plugin needs state the app does not provide (see `FromRef`)"
    )]
    pub trait PluginDispatch<S>: PluginSpec {
        /// Plugin before hooks, route before hooks and the handler of plugin-local route
        /// `index` (short-circuits on the first hook error).
        fn run<'a, 'c>(
            index: u16,
            cx: &'c mut Ctx<'a, S>,
        ) -> impl Future<Output = Response> + Send + 'c;
        /// Route after hooks, then plugin after hooks (always run).
        fn after<'a, 'c>(
            index: u16,
            cx: &'c mut Ctx<'a, S>,
            res: &'c mut Response,
        ) -> impl Future<Output = ()> + Send + 'c;
    }

    /// Placeholder used to initialise const route arrays before filling them.
    pub const PLACEHOLDER_ROUTE: RouteDescriptor = RouteDescriptor {
        name: "",
        method: Method::Get,
        path: "/",
        params: &[],
        extractors: &[],
        before: &[],
        after: &[],
        policy: PolicySpec::INHERIT,
        annotations: &[],
        doc: "",
        file: "",
        line: 0,
        websocket: false,
        response: no_response_doc,
    };

    fn no_response_doc(_: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        Vec::new()
    }

    /// Copies `src` routes into `dst` starting at `at`, tagging them with `group`.
    pub const fn fill_routes<const N: usize>(
        mut dst: [RouteRef; N],
        at: usize,
        src: &'static [&'static RouteDescriptor],
        group: Option<u16>,
    ) -> [RouteRef; N] {
        let mut i = 0;
        while i < src.len() {
            dst[at + i] = RouteRef {
                desc: src[i],
                group,
            };
            i += 1;
        }
        dst
    }

    /// Builds the `Provided` typestate (macro use).
    pub fn provided<T>(t: T) -> Provided<T> {
        crate::app::provided(t)
    }

    /// Before hook (`#[poring::hook]` on `async fn(&mut Ctx<'_, S>) -> R`).
    #[diagnostic::on_unimplemented(
        message = "`{Self}` is not a before-hook for app state `{S}`",
        note = "declare hooks with `#[poring::hook]` on `async fn name(cx: &mut Ctx<'_, {S}>) -> Result<(), E>`"
    )]
    pub trait BeforeHook<S> {
        /// Hook name.
        const NAME: &'static str;
        /// Runs the hook; `Err(response)` short-circuits.
        fn before<'a, 'c>(
            cx: &'c mut Ctx<'a, S>,
        ) -> impl Future<Output = Result<(), Response>> + Send + 'c;
    }

    /// After hook (`#[poring::hook]` on `async fn(&Ctx<'_, S>, &mut Response)`).
    #[diagnostic::on_unimplemented(
        message = "`{Self}` is not an after-hook for app state `{S}`",
        note = "declare hooks with `#[poring::hook]` on `async fn name(cx: &Ctx<'_, {S}>, res: &mut Response)`"
    )]
    pub trait AfterHook<S> {
        /// Hook name.
        const NAME: &'static str;
        /// Runs the hook.
        fn after<'a, 'c>(
            cx: &'c Ctx<'a, S>,
            res: &'c mut Response,
        ) -> impl Future<Output = ()> + Send + 'c;
    }

    pub use crate::handler::HookOutcome;

    /// Builds an [`ExtractorDesc`] from an extractor type in const context.
    pub const fn extractor<T: ExtractorMeta>(ty: &'static str) -> ExtractorDesc {
        ExtractorDesc {
            kind: T::KIND,
            ty,
            consumes_body: T::CONSUMES_BODY,
            validates: T::VALIDATES,
            uses_principal: T::USES_PRINCIPAL,
            schema: T::SCHEMA,
        }
    }

    /// Fallback for an impossible dispatch index.
    pub fn unknown_route() -> Response {
        crate::error::rejection::internal("unknown_route").into_response()
    }

    /// Records the handler stage.
    #[inline]
    pub fn mark<S>(cx: &mut Ctx<'_, S>, s: Stage) {
        cx.__mark(s);
    }

    use std::future::Future;
}
