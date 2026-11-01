//! Application assembly: the [`AppSpec`] contract implemented by `poring_app!`, the
//! typestate [`Builder`], the request pipeline and the hyper server.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::contract::{ExtractorEntry, HookEntry, HookSet, Manifest, RouteEntry, RouteKind, SourceLoc};
use http::header::{HeaderName, HeaderValue};
use http::{Request, StatusCode};

use crate::body::{BodyEnd, ReqBody};
use crate::ctx::{Ctx, Params, RequestId};
use crate::descriptor::{AppDescriptor, Method};
use crate::dynamic::{DynRequest, DynamicRoute};
use crate::error::{FrameworkError, rejection};
use crate::flow::{FlowConfig, FlowRecorder, FlowState, Stage};
use crate::policy::enforce::{CorsRuntime, RateKeyValue, RateLimiter, csrf_ok};
use crate::policy::resolve::AppContext;
use crate::policy::{AuthError, AuthRequest, Authenticator, Credential, PolicySpec, RateKey};
use crate::response::{IntoResponse, Response};
use crate::router::{Check, Lookup, RouteRuntime, Router, RouterError, Target};

/// Implemented by `poring_app!` for the generated app type. Not intended to be
/// implemented by hand: the macro also emits the compile-time checks that make the
/// implementation trustworthy.
pub trait AppSpec: Sized + Send + Sync + 'static {
    /// App state type.
    type State: Send + Sync + 'static;
    /// Authenticator type (`NoAuth` if none declared).
    type Auth: Authenticator;
    /// The whole-app descriptor (checked by `check_app` during const evaluation).
    const APP: AppDescriptor;

    /// Runs hooks, extractors and the handler of static route `index`. Only reachable
    /// through the runtime pipeline because `Ctx` has no public constructor.
    fn dispatch<'a, 'c>(index: u16, cx: &'c mut Ctx<'a, Self::State>) -> impl Future<Output = Response> + Send + 'c;
}

/// Server and parser limits.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Maximum raw query string length (bytes).
    pub max_query_bytes: usize,
    /// Maximum urlencoded fields in a query string or form body.
    pub max_form_fields: usize,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Time allowed for a client to send request headers.
    pub header_read_timeout: Duration,
    /// Grace period for in-flight requests on shutdown.
    pub shutdown_grace: Duration,
    /// Rate-limiter bucket capacity (memory bound).
    pub rate_limit_keys: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_query_bytes: 8 * 1024,
            max_form_fields: 256,
            max_connections: 10_000,
            header_read_timeout: Duration::from_secs(30),
            shutdown_grace: Duration::from_secs(10),
            rate_limit_keys: 100_000,
        }
    }
}

/// Information passed to after-response hooks (no bodies, headers or credentials).
#[derive(Clone, Debug)]
pub struct ResponseInfo {
    /// Correlation ID.
    pub request_id: String,
    /// Matched route ID.
    pub route: Option<String>,
    /// Method.
    pub method: http::Method,
    /// Status.
    pub status: StatusCode,
    /// Time from receive until the body finished (or was dropped).
    pub elapsed: Duration,
    /// How the body ended.
    pub end: BodyEnd,
}

type OnRequest = Box<dyn Fn(&http::request::Parts) -> Option<Response> + Send + Sync>;
type OnResponse = Arc<dyn Fn(&ResponseInfo) + Send + Sync>;
type ErrorMapper = Box<dyn Fn(&FrameworkError, Response) -> Response + Send + Sync>;

/// Typestate marker: a required builder input has not been supplied.
#[derive(Debug, Clone, Copy, Default)]
pub struct Missing;

/// Typestate marker: a required builder input has been supplied.
#[derive(Debug, Clone)]
pub struct Provided<T>(pub(crate) T);

pub(crate) fn provided<T>(t: T) -> Provided<T> {
    Provided(t)
}

/// Implemented only for `Provided<T>`: the app state has been supplied.
#[diagnostic::on_unimplemented(
    message = "the app state has not been provided",
    label = "call `.state(...)` on the builder before starting the server",
    note = "this app declares `state: {T}` in `poring_app!`"
)]
pub trait StateReady<T> {
    #[doc(hidden)]
    fn into_inner(self) -> T;
}
impl<T> StateReady<T> for Provided<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

/// Implemented only for `Provided<T>`: the authenticator has been supplied.
#[diagnostic::on_unimplemented(
    message = "the authenticator has not been provided",
    label = "call `.authenticator(...)` on the builder before starting the server",
    note = "this app declares `auth: {T}` in `poring_app!`; routes requiring authentication cannot run without it"
)]
pub trait AuthReady<T> {
    #[doc(hidden)]
    fn into_inner(self) -> T;
}
impl<T> AuthReady<T> for Provided<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

/// Security response headers added to every response (unless the handler set them).
#[derive(Clone, Debug)]
pub struct SecurityHeaders(pub Vec<(HeaderName, HeaderValue)>);

impl Default for SecurityHeaders {
    /// `X-Content-Type-Options: nosniff` only.
    fn default() -> Self {
        SecurityHeaders(vec![(http::header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"))])
    }
}

impl SecurityHeaders {
    /// API-oriented strict set: nosniff, `X-Frame-Options: DENY`,
    /// `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`.
    /// HSTS is not included because it is only correct behind TLS; add it explicitly.
    pub fn strict_api() -> Self {
        use http::header::*;
        SecurityHeaders(vec![
            (X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")),
            (X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
            (REFERRER_POLICY, HeaderValue::from_static("no-referrer")),
            (CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'")),
        ])
    }

    /// Adds a header.
    pub fn with(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.0.push((name, value));
        self
    }
}

struct BuilderConfig {
    limits: Limits,
    flow: FlowConfig,
    security_headers: SecurityHeaders,
    on_request: Vec<OnRequest>,
    on_response: Vec<OnResponse>,
    error_mapper: Option<ErrorMapper>,
    dynamic: Vec<DynamicRoute>,
    request_ids: bool,
    trust_forwarded_for: bool,
}

/// Typestate builder generated per app by `poring_app!` (`Api::builder()`).
///
/// `St`/`Au` track whether the declared state and authenticator were supplied; the
/// server can only be built when both are `Provided` (compile-time check).
pub struct Builder<A: AppSpec, St, Au> {
    state: St,
    auth: Au,
    cfg: BuilderConfig,
    _app: std::marker::PhantomData<fn() -> A>,
}

impl<A: AppSpec, St, Au> std::fmt::Debug for Builder<A, St, Au> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder").field("app", &A::APP.name).finish_non_exhaustive()
    }
}

impl<A: AppSpec, St, Au> Builder<A, St, Au> {
    #[doc(hidden)]
    pub fn __new(state: St, auth: Au) -> Self {
        Builder {
            state,
            auth,
            cfg: BuilderConfig {
                limits: Limits::default(),
                flow: FlowConfig::default(),
                security_headers: SecurityHeaders::default(),
                on_request: Vec::new(),
                on_response: Vec::new(),
                error_mapper: None,
                dynamic: Vec::new(),
                request_ids: true,
                trust_forwarded_for: false,
            },
            _app: std::marker::PhantomData,
        }
    }

    /// Overrides parser/server limits.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.cfg.limits = limits;
        self
    }

    /// Enables runtime flow recording (sampling 1 in `sample_every`).
    pub fn flow_recording(mut self, cfg: FlowConfig) -> Self {
        self.cfg.flow = cfg;
        self
    }

    /// Sets the security headers added to responses.
    pub fn security_headers(mut self, h: SecurityHeaders) -> Self {
        self.cfg.security_headers = h;
        self
    }

    /// Adds a pre-route request hook. Returning `Some` short-circuits
    /// before routing and before any policy check (maintenance mode, blocklists).
    pub fn on_request(mut self, f: impl Fn(&http::request::Parts) -> Option<Response> + Send + Sync + 'static) -> Self {
        self.cfg.on_request.push(Box::new(f));
        self
    }

    /// Adds an after-response hook, run once the response body
    /// has been fully handed to hyper or dropped.
    pub fn on_response(mut self, f: impl Fn(&ResponseInfo) + Send + Sync + 'static) -> Self {
        self.cfg.on_response.push(Arc::new(f));
        self
    }

    /// Rewrites framework-generated error responses (404, 405, 401, 403, 413, 415, 422,
    /// 429, 503 and extractor rejections). Application `ApiError`s are not affected.
    pub fn map_errors(mut self, f: impl Fn(&FrameworkError, Response) -> Response + Send + Sync + 'static) -> Self {
        self.cfg.error_mapper = Some(Box::new(f));
        self
    }

    /// Emits/propagates `x-request-id` (default: on).
    pub fn request_ids(mut self, on: bool) -> Self {
        self.cfg.request_ids = on;
        self
    }

    /// Uses the left-most `X-Forwarded-For` address as the client IP for rate limiting.
    /// Only enable behind a trusted reverse proxy that overwrites the header.
    pub fn trust_forwarded_for(mut self, on: bool) -> Self {
        self.cfg.trust_forwarded_for = on;
        self
    }

    /// Registers a dynamic (runtime-validated, not compile-time-verified) route.
    pub fn mount_dynamic(mut self, route: DynamicRoute) -> Self {
        self.cfg.dynamic.push(route);
        self
    }
}

impl<A: AppSpec, Au> Builder<A, Missing, Au> {
    /// Supplies the app state declared in `poring_app!`.
    pub fn state(self, state: A::State) -> Builder<A, Provided<A::State>, Au> {
        Builder { state: Provided(state), auth: self.auth, cfg: self.cfg, _app: std::marker::PhantomData }
    }
}

impl<A: AppSpec, St> Builder<A, St, Missing> {
    /// Supplies the authenticator declared in `poring_app!`.
    pub fn authenticator(self, auth: A::Auth) -> Builder<A, St, Provided<A::Auth>> {
        Builder { state: self.state, auth: Provided(auth), cfg: self.cfg, _app: std::marker::PhantomData }
    }
}

/// Error starting an app.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// Routing table could not be built.
    #[error(transparent)]
    Router(#[from] RouterError),
    /// A dynamic route violates policy or path rules.
    #[error("dynamic route `{method} {path}`: {reason}")]
    DynamicRoute {
        /// Method.
        method: &'static str,
        /// Path.
        path: String,
        /// Reason.
        reason: String,
    },
    /// A static route failed runtime policy resolution (should be prevented at compile time).
    #[error("route `{0}`: {1}")]
    Policy(String, String),
    /// I/O error binding the listener.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl<A: AppSpec, St, Au> Builder<A, St, Au> {
    /// Builds the immutable app: resolves effective policies, builds the router and the
    /// manifest. Fails on dynamic-route violations or router conflicts.
    ///
    /// Only callable once the declared state and authenticator have been supplied
    /// (compile-time check).
    pub fn build(self) -> Result<App<A>, StartupError>
    where
        St: StateReady<A::State>,
        Au: AuthReady<A::Auth>,
    {
        App::from_parts(self.state.into_inner(), self.auth.into_inner(), self.cfg)
    }

    /// Builds and serves on `addr` until Ctrl-C, then drains gracefully.
    pub async fn listen(self, addr: impl tokio::net::ToSocketAddrs) -> Result<(), StartupError>
    where
        St: StateReady<A::State>,
        Au: AuthReady<A::Auth>,
    {
        let app = self.build()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(app = A::APP.name, addr = ?listener.local_addr().ok(), "poring listening");
        app.serve(listener, async {
            // If signal registration fails we keep serving; shutdown can still happen
            // through process termination.
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
        })
        .await?;
        Ok(())
    }
}

/// A built, immutable Poring application.
pub struct App<A: AppSpec> {
    inner: Arc<AppInner<A>>,
}

impl<A: AppSpec> Clone for App<A> {
    fn clone(&self) -> Self {
        App { inner: self.inner.clone() }
    }
}

impl<A: AppSpec> std::fmt::Debug for App<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App").field("name", &A::APP.name).field("routes", &self.inner.routes.len()).finish()
    }
}

struct AppInner<A: AppSpec> {
    state: A::State,
    auth: A::Auth,
    router: Router,
    routes: Vec<RouteRuntime>,
    cors: Option<CorsRuntime>,
    limiter: RateLimiter,
    recorder: FlowRecorder,
    limits: Limits,
    security_headers: SecurityHeaders,
    on_request: Vec<OnRequest>,
    on_response: Vec<OnResponse>,
    error_mapper: Option<ErrorMapper>,
    request_ids: bool,
    trust_forwarded_for: bool,
    manifest_base: Manifest,
}

fn hook_entries(names: &[&str], scope: &str) -> Vec<HookEntry> {
    names.iter().map(|n| HookEntry { name: (*n).to_owned(), scope: scope.to_owned() }).collect()
}

fn plan<A: AppSpec>(dynamic: Vec<DynamicRoute>) -> Result<(Vec<RouteRuntime>, Manifest), StartupError> {
    let app = &A::APP;
    let ctx = AppContext {
        has_authenticator: app.has_authenticator,
        auth_uses_cookies: app.auth_uses_cookies,
        cors: app.cors.is_some(),
    };
    let mut routes = Vec::new();
    let mut entries = Vec::new();
    for (i, r) in app.routes.iter().enumerate() {
        let d = r.desc;
        let group = r.group.map(|g| &app.groups[g as usize]);
        let path = app.full_path(i);
        let mut levels: Vec<(&str, &PolicySpec)> = vec![("app defaults", &app.defaults)];
        let gname;
        if let Some(g) = group {
            gname = format!("{} `{}`", if g.plugin { "plugin" } else { "group" }, g.name);
            levels.push((&gname, &g.policy));
        }
        levels.push(("route", &d.policy));
        let reads_body = d.extractors.iter().any(|e| e.consumes_body);
        let uses_principal = d.extractors.iter().any(|e| e.uses_principal);
        let policy = crate::policy::resolve(ctx, &levels, d.method, reads_body, uses_principal)
            .map_err(|e| StartupError::Policy(format!("{} {path}", d.method.as_str()), e))?;
        let id = crate::contract::route_id(d.method.as_str(), &path);
        let checks = policy.checks().iter().filter_map(|c| Check::parse(c)).collect();
        let mut hooks = HookSet::default();
        hooks.before.extend(hook_entries(app.before, "global"));
        if let Some(g) = group {
            hooks.before.extend(hook_entries(g.before, if g.plugin { "plugin" } else { "group" }));
        }
        hooks.before.extend(hook_entries(d.before, "local"));
        hooks.after.extend(hook_entries(d.after, "local"));
        if let Some(g) = group {
            hooks.after.extend(hook_entries(g.after, if g.plugin { "plugin" } else { "group" }));
        }
        hooks.after.extend(hook_entries(app.after, "global"));
        entries.push(RouteEntry {
            id: id.clone(),
            kind: RouteKind::Static,
            method: d.method.as_str().to_owned(),
            path: path.clone(),
            handler: d.name.to_owned(),
            source: SourceLoc { file: d.file.to_owned(), line: d.line },
            group: group.map(|g| g.name.to_owned()),
            extractors: d
                .extractors
                .iter()
                .map(|e| ExtractorEntry {
                    kind: e.kind.as_str().to_owned(),
                    ty: e.ty.to_owned(),
                    consumes_body: e.consumes_body,
                    validates: e.validates,
                })
                .collect(),
            hooks,
            policy: policy.view(),
            annotations: d.annotations.iter().map(|s| (*s).to_owned()).collect(),
            websocket: d.websocket,
            meta: Vec::new(),
        });
        routes.push(RouteRuntime {
            id,
            index: i as u32,
            method: d.method,
            path,
            policy,
            checks,
            target: Target::Static(i as u16),
        });
    }
    for dr in dynamic {
        crate::dynamic::validate_path(&dr.path).map_err(|reason| StartupError::DynamicRoute {
            method: dr.method.as_str(),
            path: dr.path.clone(),
            reason,
        })?;
        let spec = dr.policy.to_spec();
        let levels: Vec<(&str, &PolicySpec)> = vec![("app defaults", &app.defaults), ("dynamic route", &spec)];
        let policy = crate::policy::resolve(ctx, &levels, dr.method, true, false).map_err(|reason| {
            StartupError::DynamicRoute { method: dr.method.as_str(), path: dr.path.clone(), reason }
        })?;
        let id = crate::contract::route_id(dr.method.as_str(), &dr.path);
        let checks = policy.checks().iter().filter_map(|c| Check::parse(c)).collect();
        // Dynamic routes skip static hooks (they are not part of the generated dispatch).
        let hooks = HookSet::default();
        entries.push(RouteEntry {
            id: id.clone(),
            kind: RouteKind::Dynamic,
            method: dr.method.as_str().to_owned(),
            path: dr.path.clone(),
            handler: dr.name.clone(),
            source: SourceLoc::default(),
            group: None,
            extractors: vec![ExtractorEntry {
                kind: "body".into(),
                ty: "Bytes".into(),
                consumes_body: true,
                validates: false,
            }],
            hooks,
            policy: policy.view(),
            annotations: Vec::new(),
            websocket: false,
            meta: Vec::new(),
        });
        let index = routes.len() as u32;
        routes.push(RouteRuntime {
            id,
            index,
            method: dr.method,
            path: dr.path,
            policy,
            checks,
            target: Target::Dynamic(dr.endpoint),
        });
    }
    let manifest = Manifest {
        format_version: crate::contract::MANIFEST_FORMAT_VERSION,
        app: app.name.to_owned(),
        poring_version: env!("CARGO_PKG_VERSION").to_owned(),
        authenticator: app.has_authenticator.then(|| app.auth_type.to_owned()),
        cors: app.cors.map(|c| crate::contract::CorsView {
            origins: c.origins.iter().map(|s| (*s).to_owned()).collect(),
            credentials: c.credentials,
            headers: c.headers.iter().map(|s| (*s).to_owned()).collect(),
            max_age_secs: c.max_age_secs,
        }),
        global_hooks: HookSet { before: hook_entries(app.before, "global"), after: hook_entries(app.after, "global") },
        routes: entries,
    };
    Ok((routes, manifest))
}

/// Environment variable read by [`dump_manifest_if_requested`].
pub const DUMP_MANIFEST_ENV: &str = "PORING_DUMP_MANIFEST";

/// Development hook used by `cargo poring`: if `PORING_DUMP_MANIFEST=<path>` is set, writes
/// the app's static manifest (JSON) to `<path>` and exits the process with status 0
/// (status 2 on error). Otherwise returns immediately.
///
/// Call it as the first statement of `main`, before constructing state or opening
/// connections, so that inspecting an app never runs its production side effects and never
/// starts a server.
pub fn dump_manifest_if_requested<A: AppSpec>() {
    let Some(path) = std::env::var_os(DUMP_MANIFEST_ENV) else { return };
    let result = static_manifest::<A>()
        .map_err(|e| e.to_string())
        .and_then(|m| serde_json::to_vec_pretty(&m).map_err(|e| e.to_string()))
        .and_then(|bytes| std::fs::write(&path, bytes).map_err(|e| e.to_string()));
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("poring: failed to dump manifest: {e}");
            std::process::exit(2);
        }
    }
}

/// Resolves an app's manifest without state, authenticator or network (used by
/// `Api::manifest()` and `cargo poring`). Dynamic routes are not included.
pub fn static_manifest<A: AppSpec>() -> Result<Manifest, StartupError> {
    plan::<A>(Vec::new()).map(|(_, m)| m)
}

impl<A: AppSpec> App<A> {
    fn from_parts(state: A::State, auth: A::Auth, cfg: BuilderConfig) -> Result<Self, StartupError> {
        let (routes, manifest_base) = plan::<A>(cfg.dynamic)?;
        let router = Router::build(&routes)?;
        let app = &A::APP;
        Ok(App {
            inner: Arc::new(AppInner {
                state,
                auth,
                router,
                limiter: RateLimiter::new(cfg.limits.rate_limit_keys),
                recorder: FlowRecorder::new(cfg.flow),
                cors: app.cors.as_ref().map(CorsRuntime::from_spec),
                routes,
                limits: cfg.limits,
                security_headers: cfg.security_headers,
                on_request: cfg.on_request,
                on_response: cfg.on_response,
                error_mapper: cfg.error_mapper,
                request_ids: cfg.request_ids,
                trust_forwarded_for: cfg.trust_forwarded_for,
                manifest_base,
            }),
        })
    }

    /// The application manifest (effective policies, hooks, extractors; dynamic routes
    /// include their current endpoint metadata such as the live guest version).
    pub fn manifest(&self) -> Manifest {
        let mut m = self.inner.manifest_base.clone();
        for (entry, rt) in m.routes.iter_mut().zip(&self.inner.routes) {
            if let Target::Dynamic(ep) = &rt.target {
                entry.meta = ep.metadata();
            }
        }
        m
    }

    /// The static flow graph (optionally for one route: `"GET /users/{id}"`, ID or handler).
    pub fn graph(&self, route: Option<&str>) -> Option<crate::contract::FlowGraph> {
        crate::contract::build_graph(&self.manifest(), route)
    }

    /// The runtime flow recorder (traces are only recorded if enabled on the builder).
    pub fn flow(&self) -> &FlowRecorder {
        &self.inner.recorder
    }

    /// The rate limiter (exposed for metrics).
    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.inner.limiter
    }

    /// Handles one request in-process (used by the server and by tests).
    pub async fn handle(&self, req: Request<ReqBody>, peer: Option<SocketAddr>) -> Response {
        self.inner.handle(req, peer).await
    }

    /// Binds `addr` and serves in a background task; returns a handle for shutdown.
    pub async fn bind(self, addr: impl tokio::net::ToSocketAddrs) -> std::io::Result<Server> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(self.serve(listener, async move {
            let _ = rx.await;
        }));
        Ok(Server { addr: local, shutdown: Some(tx), join })
    }

    /// Serves connections from `listener` until `shutdown` completes, then stops
    /// accepting, asks every connection to finish its in-flight request, and waits up to
    /// `Limits::shutdown_grace` for them to drain.
    pub async fn serve(
        self,
        listener: tokio::net::TcpListener,
        shutdown: impl Future<Output = ()> + Send,
    ) -> std::io::Result<()> {
        let max = self.inner.limits.max_connections.max(1);
        let permits = Arc::new(tokio::sync::Semaphore::new(max));
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        tokio::pin!(shutdown);
        loop {
            let permit = tokio::select! {
                _ = &mut shutdown => break,
                p = permits.clone().acquire_owned() => match p {
                    Ok(p) => p,
                    Err(_) => break,
                },
            };
            let (stream, peer) = tokio::select! {
                _ = &mut shutdown => break,
                r = listener.accept() => match r {
                    Ok(v) => v,
                    Err(e) => {
                        // Transient accept errors (EMFILE etc.): back off briefly.
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            let _ = stream.set_nodelay(true);
            let app = self.clone();
            let mut stop = stop_rx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                serve_conn(app, stream, peer, &mut stop).await;
            });
        }
        drop(listener);
        let _ = stop_tx.send(true);
        let drained = tokio::time::timeout(self.inner.limits.shutdown_grace, permits.acquire_many(max as u32)).await;
        if drained.is_err() {
            tracing::warn!("graceful shutdown grace period elapsed with connections still open");
        }
        Ok(())
    }
}

async fn serve_conn<A: AppSpec>(
    app: App<A>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) {
    let io = hyper_util::rt::TokioIo::new(stream);
    let header_timeout = app.inner.limits.header_read_timeout;
    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let app = app.clone();
        // One span per request (OpenTelemetry-compatible via a `tracing` layer). Only the
        // method and path are recorded: never query strings, headers, cookies or bodies.
        let span = tracing::info_span!(
            "poring.request",
            method = %req.method(),
            path = %req.uri().path(),
            route = tracing::field::Empty,
            status = tracing::field::Empty,
            request_id = tracing::field::Empty,
        );
        tracing::Instrument::instrument(
            async move { Ok::<_, Infallible>(app.inner.handle(req.map(ReqBody::Incoming), Some(peer)).await) },
            span,
        )
    });
    #[cfg(not(feature = "http2"))]
    let conn = {
        let mut b = hyper::server::conn::http1::Builder::new();
        b.timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(header_timeout);
        b.serve_connection(io, svc).with_upgrades()
    };
    #[cfg(feature = "http2")]
    let builder = {
        let mut b = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        b.http1().timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(header_timeout);
        b
    };
    #[cfg(feature = "http2")]
    let conn = builder.serve_connection_with_upgrades(io, svc);
    tokio::pin!(conn);
    tokio::select! {
        r = conn.as_mut() => {
            if let Err(e) = r {
                tracing::debug!(error = %e, "connection ended with error");
            }
            return;
        }
        _ = stop.wait_for(|s| *s) => {
            conn.as_mut().graceful_shutdown();
        }
    }
    if let Err(e) = conn.await {
        tracing::debug!(error = %e, "connection ended with error during shutdown");
    }
}

/// Handle to a server started with [`App::bind`].
#[derive(Debug)]
pub struct Server {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Server {
    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Triggers graceful shutdown and waits for it to finish.
    pub async fn shutdown(mut self) -> std::io::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        match (&mut self.join).await {
            Ok(r) => r,
            Err(e) => Err(std::io::Error::other(e)),
        }
    }
}

fn peer_ip(parts: &http::request::Parts, peer: Option<SocketAddr>, trust_xff: bool) -> RateKeyValue {
    if trust_xff
        && let Some(ip) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
    {
        return RateKeyValue::Ip(ip);
    }
    peer.map(|p| RateKeyValue::Ip(p.ip())).unwrap_or(RateKeyValue::Unknown)
}

impl<A: AppSpec> AppInner<A> {
    async fn handle(&self, req: Request<ReqBody>, peer: Option<SocketAddr>) -> Response {
        let start = Instant::now();
        let (parts, body) = req.into_parts();
        let request_id = RequestId::from_headers(&parts.headers);
        let mut flow = if self.recorder.sample() { Some(Box::new(FlowState::new(start))) } else { None };
        let is_head = parts.method == http::Method::HEAD;
        let origin = parts.headers.get(http::header::ORIGIN).cloned();
        let method = parts.method.clone();
        if let Some(f) = flow.as_deref_mut() {
            f.mark(Stage::Receive);
        }

        for hook in &self.on_request {
            if let Some(r) = hook(&parts) {
                return self
                    .finish(r, Finish { request_id, route: None, flow, start, is_head, origin, method, extra: None });
            }
        }

        if let Some(f) = flow.as_deref_mut() {
            f.mark(Stage::Match);
        }
        let lookup = self.router.lookup(parts.uri.path(), &parts.method);
        match lookup {
            Lookup::NotFound => {
                if let Some(f) = flow.as_deref_mut() {
                    f.mark(Stage::NotFound);
                }
                let r = rejection::not_found().into_response();
                self.finish(r, Finish { request_id, route: None, flow, start, is_head, origin, method, extra: None })
            }
            Lookup::MethodNotAllowed(entry) => {
                if let Some(f) = flow.as_deref_mut() {
                    f.mark(Stage::MethodNotAllowed);
                }
                let r = rejection::method_not_allowed(entry.allow.clone()).into_response();
                self.finish(r, Finish { request_id, route: None, flow, start, is_head, origin, method, extra: None })
            }
            Lookup::AutoOptions(entry) => {
                let preflight = parts.headers.contains_key(http::header::ACCESS_CONTROL_REQUEST_METHOD);
                let r = match (&self.cors, &origin, preflight) {
                    (Some(cors), Some(o), true) => {
                        if let Some(f) = flow.as_deref_mut() {
                            f.mark(Stage::CorsPreflight);
                        }
                        if o.to_str().map(|s| cors.allows(s)).unwrap_or(false) {
                            let mut r = StatusCode::NO_CONTENT.into_response();
                            cors.apply_preflight(o, &entry.allow, r.headers_mut());
                            r
                        } else {
                            rejection::forbidden("cors_origin_denied", "origin not allowed").into_response()
                        }
                    }
                    _ => {
                        let mut r = StatusCode::NO_CONTENT.into_response();
                        r.headers_mut().insert(http::header::ALLOW, entry.allow.clone());
                        r
                    }
                };
                // Preflight responses already carry CORS headers; don't re-apply.
                self.finish(
                    r,
                    Finish { request_id, route: None, flow, start, is_head, origin: None, method, extra: None },
                )
            }
            Lookup::Found(idx, params) => {
                let route = &self.routes[idx as usize];
                self.run_route(route, parts, body, params, peer, request_id, flow, start, is_head, origin, method).await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_route<'a>(
        &'a self,
        route: &'a RouteRuntime,
        parts: http::request::Parts,
        body: ReqBody,
        params: Params<'a>,
        peer: Option<SocketAddr>,
        request_id: RequestId,
        flow: Option<Box<FlowState>>,
        start: Instant,
        is_head: bool,
        origin: Option<HeaderValue>,
        method: http::Method,
    ) -> Response {
        let mut cx: Ctx<'a, A::State> = Ctx {
            parts,
            body: Some(body),
            params,
            state: &self.state,
            route,
            identity: None,
            flow,
            peer,
            request_id,
            response_headers: None,
            limits: &self.limits,
        };
        let res = match self.enforce(&mut cx).await {
            Err(r) => r,
            Ok(()) => {
                let timeout = route.policy.timeout;
                let res = match &route.target {
                    Target::Static(i) => {
                        let fut = A::dispatch(*i, &mut cx);
                        match timeout {
                            Some(d) => tokio::time::timeout(d, fut).await.ok(),
                            None => Some(fut.await),
                        }
                    }
                    Target::Dynamic(ep) => {
                        let fut = call_dynamic(ep.as_ref(), &mut cx);
                        match timeout {
                            Some(d) => tokio::time::timeout(d, fut).await.ok(),
                            None => Some(fut.await),
                        }
                    }
                };
                match res {
                    Some(r) => {
                        cx.mark(Stage::Respond);
                        r
                    }
                    None => {
                        cx.mark(Stage::Deny(503));
                        rejection::timeout().into_response()
                    }
                }
            }
        };
        let Ctx { flow, request_id, response_headers, .. } = cx;
        self.finish(
            res,
            Finish { request_id, route: Some(route), flow, start, is_head, origin, method, extra: response_headers },
        )
    }

    /// Runs the route's precomputed security checks in order.
    async fn enforce(&self, cx: &mut Ctx<'_, A::State>) -> Result<(), Response> {
        let route = cx.route;
        for check in &route.checks {
            match check {
                Check::Cors => {
                    cx.mark(Stage::Cors);
                    if let (Some(cors), Some(o)) = (&self.cors, cx.parts.headers.get(http::header::ORIGIN)) {
                        let allowed = o.to_str().map(|s| cors.allows(s)).unwrap_or(false);
                        let unsafe_method = Method::from_http(&cx.parts.method).map(Method::is_unsafe).unwrap_or(true);
                        if !allowed && unsafe_method {
                            cx.mark(Stage::Deny(403));
                            return Err(
                                rejection::forbidden("cors_origin_denied", "origin not allowed").into_response()
                            );
                        }
                    }
                }
                Check::RateLimit => {
                    cx.mark(Stage::RateLimit);
                    if let Some(spec) = route.policy.rate_limit {
                        let key = match (spec.key, &cx.identity) {
                            (RateKey::Principal, Some(id)) => RateKeyValue::Subject(id.subject.clone()),
                            _ => peer_ip(&cx.parts, cx.peer, self.trust_forwarded_for),
                        };
                        if let Err(wait) = self.limiter.check(route.index, key, &spec, Instant::now()) {
                            cx.mark(Stage::Deny(429));
                            return Err(rejection::too_many_requests(wait).into_response());
                        }
                    }
                }
                Check::Auth => {
                    cx.mark(Stage::Auth);
                    let req = AuthRequest {
                        method: &cx.parts.method,
                        uri: &cx.parts.uri,
                        headers: &cx.parts.headers,
                        peer: cx.peer,
                    };
                    match self.auth.authenticate(&req).await {
                        Ok(Some(id)) => cx.identity = Some(id),
                        Ok(None) | Err(AuthError::Invalid) => {
                            cx.mark(Stage::Deny(401));
                            return Err(rejection::unauthenticated().into_response());
                        }
                        Err(AuthError::Unavailable(msg)) => {
                            tracing::error!(error = %msg, "authenticator unavailable");
                            cx.mark(Stage::Deny(503));
                            return Err(rejection::unavailable("authentication unavailable").into_response());
                        }
                    }
                }
                Check::Authz => {
                    cx.mark(Stage::Authz);
                    let ok = match &cx.identity {
                        Some(id) => {
                            route.policy.scopes.iter().all(|s| id.has_scope(s))
                                && route.policy.roles.iter().all(|r| id.has_role(r))
                        }
                        None => false,
                    };
                    if !ok {
                        cx.mark(Stage::Deny(403));
                        return Err(rejection::forbidden("insufficient_scope", "missing required scope or role")
                            .into_response());
                    }
                }
                Check::Csrf => {
                    cx.mark(Stage::Csrf);
                    let cookie_auth = cx.identity.as_ref().map(|i| i.credential == Credential::Cookie).unwrap_or(false);
                    if cookie_auth && !csrf_ok(&cx.parts.headers) {
                        cx.mark(Stage::Deny(403));
                        return Err(rejection::forbidden("csrf", "missing or invalid CSRF token").into_response());
                    }
                }
                Check::BodyGate => {
                    cx.mark(Stage::BodyGate);
                    let limit = route.policy.body_limit;
                    if let Some(len) = cx
                        .parts
                        .headers
                        .get(http::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        && len > limit
                    {
                        cx.mark(Stage::Deny(413));
                        return Err(rejection::payload_too_large(limit).into_response());
                    }
                    if !route.policy.content_types.is_empty() {
                        let has_body = cx
                            .parts
                            .headers
                            .get(http::header::CONTENT_LENGTH)
                            .map(|v| v != "0")
                            .unwrap_or_else(|| cx.parts.headers.contains_key(http::header::TRANSFER_ENCODING));
                        let ct =
                            cx.content_type().map(|c| c.split(';').next().unwrap_or("").trim().to_ascii_lowercase());
                        let ok = match ct {
                            Some(ct) => route.policy.content_types.iter().any(|a| a.eq_ignore_ascii_case(&ct)),
                            None => !has_body,
                        };
                        if !ok {
                            cx.mark(Stage::Deny(415));
                            return Err(rejection::unsupported_media_type(&route.policy.content_types.join(", "))
                                .into_response());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(&self, mut res: Response, f: Finish<'_>) -> Response {
        if let Some(fe) = res.extensions().get::<FrameworkError>().cloned()
            && let Some(m) = &self.error_mapper
        {
            res = m(&fe, res);
        }
        let headers = res.headers_mut();
        if let Some(extra) = f.extra {
            for (k, v) in extra {
                if let Some(k) = k {
                    headers.insert(k, v);
                }
            }
        }
        for (k, v) in &self.security_headers.0 {
            if !headers.contains_key(k) {
                headers.insert(k.clone(), v.clone());
            }
        }
        if self.request_ids {
            headers.insert(HeaderName::from_static("x-request-id"), f.request_id.to_header());
        }
        if let (Some(cors), Some(o)) = (&self.cors, &f.origin)
            && o.to_str().map(|s| cors.allows(s)).unwrap_or(false)
        {
            cors.apply(o, headers);
        }
        if f.is_head {
            // RFC 9110: HEAD carries the GET headers (including Content-Length) without a body.
            if let Some(len) = res.body().exact_len() {
                res.headers_mut().insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
            }
            *res.body_mut() = crate::body::Body::empty();
        }
        let status = res.status();
        let route_id = f.route.map(|r| r.id.clone());
        if f.flow.is_some() || !self.on_response.is_empty() {
            let mut flow = f.flow;
            if let Some(fl) = flow.as_deref_mut() {
                fl.mark(Stage::Send);
            }
            let hooks = self.on_response.clone();
            let rid = f.request_id.to_string();
            let method = f.method;
            let start = f.start;
            let traces = flow.map(|fl| fl.finish(&rid, route_id.as_deref(), status.as_u16()));
            if let Some(t) = traces {
                self.recorder.push(t);
            }
            if !hooks.is_empty() {
                let info_route = route_id.clone();
                res.body_mut().on_done(move |end| {
                    let info = ResponseInfo {
                        request_id: rid,
                        route: info_route,
                        method,
                        status,
                        elapsed: start.elapsed(),
                        end,
                    };
                    for h in &hooks {
                        h(&info);
                    }
                });
            }
        }
        let span = tracing::Span::current();
        if !span.is_disabled() {
            span.record("route", route_id.as_deref().unwrap_or("-"));
            span.record("status", status.as_u16());
            span.record("request_id", tracing::field::display(&f.request_id));
        }
        tracing::debug!(
            target: "poring::request",
            request_id = %f.request_id,
            route = route_id.as_deref().unwrap_or("-"),
            status = status.as_u16(),
            elapsed_us = f.start.elapsed().as_micros() as u64,
        );
        res
    }
}

struct Finish<'a> {
    request_id: RequestId,
    route: Option<&'a RouteRuntime>,
    flow: Option<Box<FlowState>>,
    start: Instant,
    is_head: bool,
    origin: Option<HeaderValue>,
    method: http::Method,
    extra: Option<http::HeaderMap>,
}

async fn call_dynamic<S>(ep: &dyn crate::dynamic::DynEndpoint, cx: &mut Ctx<'_, S>) -> Response {
    cx.__mark_extract();
    let body = match crate::extract::read_body(cx).await {
        Ok(b) => b,
        Err(e) => {
            cx.mark(Stage::Reject);
            return e.into_response();
        }
    };
    let path = cx.parts.uri.path();
    let ranges: Vec<(&str, usize, usize)> = cx.params.iter().collect();
    let mut params = Vec::with_capacity(ranges.len());
    for (name, s, e) in ranges {
        match crate::extract::path::decode(path.get(s..e).unwrap_or("")) {
            Ok(v) => params.push((name.to_owned(), v.into_owned())),
            Err(_) => {
                cx.mark(Stage::Reject);
                return rejection::bad_request(
                    "invalid_path_param",
                    format!("path parameter `{name}` is not valid percent-encoded UTF-8"),
                )
                .into_response();
            }
        }
    }
    let mut headers = cx.parts.headers.clone();
    headers.remove(http::header::AUTHORIZATION);
    headers.remove(http::header::COOKIE);
    headers.remove(http::header::PROXY_AUTHORIZATION);
    let req = DynRequest {
        method: cx.parts.method.clone(),
        uri: cx.parts.uri.clone(),
        headers,
        body,
        params,
        identity: cx.identity.clone(),
        request_id: cx.request_id.to_string(),
    };
    cx.mark(Stage::Wasm);
    ep.call(req).await
}
