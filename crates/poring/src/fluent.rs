//! The fluent, attribute-free application builder.
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
//! # What is checked, and when
//!
//! Handler signatures are checked by the compiler: every argument must be an extractor
//! for the app state, the output must implement [`IntoResponse`](crate::IntoResponse),
//! only the last argument may read the body, and `GET`/`HEAD` handlers cannot read it.
//! `State<T>` only compiles when the app state provides `T`.
//!
//! Whole-app rules that `poring_app!` checks during compilation (duplicate or ambiguous
//! routes, path syntax, group prefixes, authentication wiring, `deny_anonymous`
//! exceptions, body-limit narrowing, CORS and CSRF declarations) are checked by
//! [`Poring::build`] instead, before any socket is bound. Every request then passes
//! through the same runtime policy pipeline as macro routes.

use crate::app::{App, AppLevel, AppSpec, BuilderConfig, StartupError, config_methods};
use crate::contract::SourceLoc;
use crate::ctx::Ctx;
use crate::descriptor::AppDescriptor;
use crate::handler::{Group, HookOutcome, NativeRoute, route_methods};
use crate::policy::{Authenticator, Cors, LevelKind, NoAuth, Policy, RateLimit};
use crate::response::Response;

/// An application assembled with method chaining.
///
/// `S` is the shared state type and `Au` the [`Authenticator`]. Both default to "none"
/// (`()` and [`NoAuth`]). [`Poring::build`] produces an [`App`], the same runtime type
/// that `poring_app!` apps use.
pub struct Poring<S = (), Au = NoAuth> {
    state: S,
    auth: Au,
    has_auth: bool,
    defaults: Policy,
    rate_limit: Option<RateLimit>,
    cors: Option<Cors>,
    name: String,
    state_after_routes: bool,
    cfg: BuilderConfig<S>,
}

/// A built fluent application.
pub type FluentApp<S = (), Au = NoAuth> = App<Poring<S, Au>>;

impl<S, Au> std::fmt::Debug for Poring<S, Au> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Poring")
            .field("name", &self.name)
            .field("routes", &self.cfg.native.routes.len())
            .field("authenticator", &self.has_auth)
            .finish_non_exhaustive()
    }
}

impl Poring<(), NoAuth> {
    /// An empty app without state or authenticator.
    pub fn new() -> Self {
        Poring::with_state(())
    }
}

impl Default for Poring<(), NoAuth> {
    fn default() -> Self {
        Poring::new()
    }
}

impl<S: Send + Sync + 'static> Poring<S, NoAuth> {
    /// An empty app with shared state `S`, available to handlers through `State<T>`
    /// (`T` = `S` itself, or a part of it via `FromRef`).
    pub fn with_state(state: S) -> Self {
        Poring {
            state,
            auth: NoAuth,
            has_auth: false,
            defaults: Policy::new(),
            rate_limit: None,
            cors: None,
            name: "Poring".to_owned(),
            state_after_routes: false,
            cfg: BuilderConfig::default(),
        }
    }
}

impl<Au: Authenticator> Poring<(), Au> {
    /// Supplies the shared state. Handlers are type-checked against the state type, so
    /// this must be called before any route, group or hook is registered; otherwise
    /// [`build`](Poring::build) fails.
    pub fn state<S: Send + Sync + 'static>(self, state: S) -> Poring<S, Au> {
        Poring {
            state,
            auth: self.auth,
            has_auth: self.has_auth,
            defaults: self.defaults,
            rate_limit: self.rate_limit,
            cors: self.cors,
            name: self.name,
            state_after_routes: self.state_after_routes || !self.cfg.native.is_empty(),
            cfg: BuilderConfig {
                limits: self.cfg.limits,
                flow: self.cfg.flow,
                security_headers: self.cfg.security_headers,
                on_request: self.cfg.on_request,
                on_response: self.cfg.on_response,
                error_mapper: self.cfg.error_mapper,
                dynamic: self.cfg.dynamic,
                native: Default::default(),
                request_ids: self.cfg.request_ids,
                trusted_proxies: self.cfg.trusted_proxies,
                legacy_forwarded_for: self.cfg.legacy_forwarded_for,
                rate_limit_ceiling: self.cfg.rate_limit_ceiling,
                ws_origins: self.cfg.ws_origins,
            },
        }
    }
}

impl<S: Send + Sync + 'static> Poring<S, NoAuth> {
    /// Supplies the authenticator. Routes then require an authenticated principal unless
    /// a policy makes them public, exactly as with `auth:` in `poring_app!`.
    pub fn authenticator<Au: Authenticator>(self, auth: Au) -> Poring<S, Au> {
        Poring {
            state: self.state,
            auth,
            has_auth: true,
            defaults: self.defaults,
            rate_limit: self.rate_limit,
            cors: self.cors,
            name: self.name,
            state_after_routes: self.state_after_routes,
            cfg: self.cfg,
        }
    }
}

impl<S: Send + Sync + 'static, Au: Authenticator> Poring<S, Au> {
    config_methods!();

    /// Sets the app name used in manifests, graphs and logs (default `Poring`).
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the app-level default policy, merged before group and route policies.
    pub fn policy(mut self, policy: Policy) -> Self {
        self.defaults = policy;
        self
    }

    /// The app's default rate limit, inherited by every route that does not declare its
    /// own (the most specific declaration wins). With [`RateScope::App`] all those routes
    /// share one bucket per client; otherwise each route has its own. For a limit that
    /// routes cannot override, use [`rate_limit_ceiling`](Poring::rate_limit_ceiling).
    ///
    /// [`RateScope::App`]: crate::policy::RateScope::App
    pub fn rate_limit(mut self, limit: RateLimit) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    /// Enables CORS for the whole app.
    pub fn cors(mut self, cors: Cors) -> Self {
        self.cors = Some(cors);
        self
    }

    /// Adds an app-level before hook, run for every fluent route before group hooks.
    /// Returning an early response (`Err(e)` or `Some(response)`) skips the handler;
    /// after hooks still run.
    pub fn before<F, O>(mut self, hook: F) -> Self
    where
        F: for<'a, 'b> Fn(&'b mut Ctx<'a, S>) -> O + Send + Sync + 'static,
        O: HookOutcome,
    {
        self.cfg.native.hooks.add_before(hook);
        self
    }

    /// Adds an app-level after hook, run after group hooks.
    pub fn after<F>(mut self, hook: F) -> Self
    where
        F: for<'a, 'b> Fn(&'b Ctx<'a, S>, &'b mut Response) + Send + Sync + 'static,
    {
        self.cfg.native.hooks.add_after(hook);
        self
    }

    /// Registers routes under a static `prefix` with their own policy and hooks:
    /// `.group("/api", |api| api.get("/ping", || async { "pong" }))`.
    #[track_caller]
    pub fn group(mut self, prefix: &str, f: impl FnOnce(Group<S>) -> Group<S>) -> Self {
        let loc = std::panic::Location::caller();
        let g = f(Group::new(
            prefix,
            SourceLoc {
                file: loc.file().replace('\\', "/"),
                line: loc.line(),
            },
        ));
        self.cfg.native.add_group(g);
        self
    }

    fn push_route(mut self, route: NativeRoute<S>) -> Self {
        self.cfg.native.routes.push((None, route));
        self
    }

    route_methods!(S);

    /// Validates every route, group and policy, resolves effective policies and builds
    /// the router. Fails, without binding a socket, on duplicate or ambiguous routes,
    /// invalid paths or prefixes, and policy violations.
    pub fn build(self) -> Result<App<Self>, StartupError> {
        if self.state_after_routes {
            return Err(StartupError::Config(
                "`.state(..)` was called after routes or hooks were registered; call it first (or use `Poring::with_state`)"
                    .into(),
            ));
        }
        let mut defaults = self.defaults;
        if let Some(limit) = self.rate_limit {
            if defaults.has_rate_limit() {
                return Err(StartupError::Config(
                    "the app rate limit is declared by both `.rate_limit(..)` and `.policy(..)`"
                        .into(),
                ));
            }
            defaults = defaults.with_rate_limit(limit);
        }
        defaults
            .validate(LevelKind::App)
            .map_err(|e| StartupError::Config(format!("app defaults: {e}")))?;
        let level = AppLevel {
            name: self.name,
            defaults,
            has_authenticator: self.has_auth,
            auth_type: if self.has_auth {
                crate::handler::pretty_type_name(std::any::type_name::<Au>())
            } else {
                String::new()
            },
            auth_uses_cookies: self.has_auth && Au::USES_COOKIES,
            cors: self.cors,
            ceiling: None,
        };
        App::from_parts(self.state, self.auth, self.cfg, level)
    }

    /// Builds the app and serves it on `addr` until Ctrl-C, then drains in-flight
    /// requests. Use from async code (for example under `#[tokio::main]`).
    pub async fn listen(self, addr: impl tokio::net::ToSocketAddrs) -> Result<(), StartupError> {
        self.build()?.listen(addr).await
    }

    /// Builds the app, starts a multi-threaded Tokio runtime and serves on `addr` until
    /// Ctrl-C. For a synchronous `main`.
    ///
    /// Returns [`StartupError::NestedRuntime`] instead of panicking when called from
    /// inside a Tokio runtime; use [`listen`](Poring::listen) there.
    pub fn run(self, addr: impl tokio::net::ToSocketAddrs) -> Result<(), StartupError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(StartupError::NestedRuntime);
        }
        // Validate before starting threads so configuration errors surface immediately.
        let app = self.build()?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        rt.block_on(app.listen(addr))
    }
}

/// The fluent builder doubles as the type-level marker of the apps it builds, so a built
/// fluent app is an `App<Poring<S, Au>>` (see [`FluentApp`]). It declares no
/// macro routes; all of its routes are native.
impl<S: Send + Sync + 'static, Au: Authenticator> AppSpec for Poring<S, Au> {
    type State = S;
    type Auth = Au;
    const APP: AppDescriptor = AppDescriptor {
        name: "Poring",
        defaults: crate::policy::PolicySpec::INHERIT,
        has_authenticator: false,
        auth_type: "",
        auth_uses_cookies: false,
        cors: None,
        before: &[],
        after: &[],
        groups: &[],
        routes: &[],
    };

    fn dispatch<'a, 'c>(
        index: u16,
        cx: &'c mut Ctx<'a, S>,
    ) -> impl std::future::Future<Output = Response> + Send + 'c {
        let _ = (index, cx);
        std::future::ready(crate::__private::unknown_route())
    }
}
