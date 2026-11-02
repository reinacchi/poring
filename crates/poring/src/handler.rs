//! Native handlers for routes registered at runtime through the fluent API.
//!
//! A [`Handler`] is an `async` function or closure taking up to eight extractors. Each
//! argument is extracted with the same [`FromRequest`] implementation the attribute macros
//! use, so extraction order, body limits, validation and rejections are identical. Handlers
//! are type-erased once at startup; each request costs one boxed future.

use std::future::Future;
use std::marker::PhantomData;

use crate::contract::SourceLoc;
use crate::ctx::Ctx;
use crate::descriptor::{ExtractorDesc, Method, ResponseDoc};
use crate::dynamic::BoxFuture;
use crate::extract::{ExtractorMeta, FromRequest};
use crate::flow::Stage;
use crate::policy::Policy;
use crate::response::{IntoResponse, Response};
use crate::schema::SchemaRegistry;

/// Generates the route registration methods shared by `Poring`, `Group` and the macro
/// app `Builder`. `$S` is the app state type; the implementing type provides
/// `fn push_route(self, NativeRoute<$S>) -> Self`.
macro_rules! route_methods {
    ($S:ty) => {
        /// Registers a `GET` route. Handlers for `GET` cannot read the request body.
        #[track_caller]
        pub fn get<H, Args>(self, path: &str, handler: H) -> Self
        where
            H: $crate::handler::Handler<Args, $S>,
            Args: 'static,
        {
            const {
                assert!(
                    !<H as $crate::handler::Handler<Args, $S>>::READS_BODY,
                    "poring: GET handlers cannot read the request body"
                )
            };
            self.push_route($crate::handler::NativeRoute::new(
                $crate::descriptor::Method::Get,
                path,
                None,
                handler,
            ))
        }

        /// Registers a `POST` route.
        #[track_caller]
        pub fn post<H, Args>(self, path: &str, handler: H) -> Self
        where
            H: $crate::handler::Handler<Args, $S>,
            Args: 'static,
        {
            self.push_route($crate::handler::NativeRoute::new(
                $crate::descriptor::Method::Post,
                path,
                None,
                handler,
            ))
        }

        /// Registers a `PUT` route.
        #[track_caller]
        pub fn put<H, Args>(self, path: &str, handler: H) -> Self
        where
            H: $crate::handler::Handler<Args, $S>,
            Args: 'static,
        {
            self.push_route($crate::handler::NativeRoute::new(
                $crate::descriptor::Method::Put,
                path,
                None,
                handler,
            ))
        }

        /// Registers a `PATCH` route.
        #[track_caller]
        pub fn patch<H, Args>(self, path: &str, handler: H) -> Self
        where
            H: $crate::handler::Handler<Args, $S>,
            Args: 'static,
        {
            self.push_route($crate::handler::NativeRoute::new(
                $crate::descriptor::Method::Patch,
                path,
                None,
                handler,
            ))
        }

        /// Registers a `DELETE` route.
        #[track_caller]
        pub fn delete<H, Args>(self, path: &str, handler: H) -> Self
        where
            H: $crate::handler::Handler<Args, $S>,
            Args: 'static,
        {
            self.push_route($crate::handler::NativeRoute::new(
                $crate::descriptor::Method::Delete,
                path,
                None,
                handler,
            ))
        }

        /// Registers an explicit `HEAD` route (otherwise `HEAD` is served by the `GET` route).
        #[track_caller]
        pub fn head<H, Args>(self, path: &str, handler: H) -> Self
        where
            H: $crate::handler::Handler<Args, $S>,
            Args: 'static,
        {
            const {
                assert!(
                    !<H as $crate::handler::Handler<Args, $S>>::READS_BODY,
                    "poring: HEAD handlers cannot read the request body"
                )
            };
            self.push_route($crate::handler::NativeRoute::new(
                $crate::descriptor::Method::Head,
                path,
                None,
                handler,
            ))
        }

        /// Registers an explicit `OPTIONS` route (otherwise `OPTIONS` is answered automatically).
        #[track_caller]
        pub fn options<H, Args>(self, path: &str, handler: H) -> Self
        where
            H: $crate::handler::Handler<Args, $S>,
            Args: 'static,
        {
            self.push_route($crate::handler::NativeRoute::new(
                $crate::descriptor::Method::Options,
                path,
                None,
                handler,
            ))
        }

        /// Registers a route for `method`. Body-reading handlers on `GET`/`HEAD` are
        /// rejected when the app is built.
        #[track_caller]
        pub fn route<H, Args>(
            self,
            method: $crate::descriptor::Method,
            path: &str,
            handler: H,
        ) -> Self
        where
            H: $crate::handler::Handler<Args, $S>,
            Args: 'static,
        {
            self.push_route($crate::handler::NativeRoute::new(
                method, path, None, handler,
            ))
        }

        /// Registers a route with its own [`Policy`](crate::policy::Policy), merged after
        /// the app and group policies.
        #[track_caller]
        pub fn route_with<H, Args>(
            self,
            method: $crate::descriptor::Method,
            path: &str,
            policy: $crate::policy::Policy,
            handler: H,
        ) -> Self
        where
            H: $crate::handler::Handler<Args, $S>,
            Args: 'static,
        {
            self.push_route($crate::handler::NativeRoute::new(
                method,
                path,
                Some(policy),
                handler,
            ))
        }
    };
}
pub(crate) use route_methods;

/// An `async` function or closure usable as a fluent route handler.
///
/// Implemented for every `Fn(T1, .., Tn) -> Fut` with `n <= 8` where each `Ti` is an
/// extractor for the app state `S` and `Fut` is a `Send` future whose output implements
/// [`IntoResponse`]. Only the last argument may read the request body, and `GET`/`HEAD`
/// handlers may not read it at all. These two rules are evaluated when the registration
/// is compiled to code (`cargo build`/`cargo test`, not `cargo check`), and checked again
/// by `build()`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a Poring handler for app state `{S}`",
    label = "not a valid handler",
    note = "a handler is an `async fn` or a closure returning a `Send` future; it takes up to 8 extractors (each implementing `FromRequest<{S}>`) and its output implements `IntoResponse`",
    note = "`State<T>` needs the app state to provide `T`: call `.state(..)` (or `Poring::with_state`) before registering routes"
)]
pub trait Handler<Args, S>: Send + Sync + 'static {
    /// Whether any argument reads the request body.
    #[doc(hidden)]
    const READS_BODY: bool;
    /// Compile-time check that only the last argument reads the body.
    #[doc(hidden)]
    const BODY_ORDER: ();

    /// Extractor metadata in argument order.
    #[doc(hidden)]
    fn __extractors() -> Vec<ExtractorDesc>;

    /// Documented responses of the handler's output type.
    #[doc(hidden)]
    fn __responses(reg: &mut SchemaRegistry) -> Vec<ResponseDoc>;

    /// Extracts the arguments, calls the handler and converts its output.
    #[doc(hidden)]
    fn __call<'a, 'c>(
        &'c self,
        cx: &'c mut Ctx<'a, S>,
    ) -> impl Future<Output = Response> + Send + 'c;
}

fn desc<T: ExtractorMeta>() -> ExtractorDesc {
    ExtractorDesc {
        kind: T::KIND,
        ty: std::any::type_name::<T>(),
        consumes_body: T::CONSUMES_BODY,
        validates: T::VALIDATES,
        uses_principal: T::USES_PRINCIPAL,
        schema: T::SCHEMA,
    }
}

macro_rules! impl_handler {
    ($($t:ident $v:ident),*) => {
        impl_handler!(@impl [$($t $v),*] [] $($t)*);
    };
    // Splits the argument list into "all but last" (which must not read the body).
    (@impl [$($t:ident $v:ident),*] [$($init:ident)*] $last:ident) => {
        impl<F, Fut, R, S, $($t,)*> Handler<($($t,)*), S> for F
        where
            F: Fn($($t),*) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = R> + Send,
            R: IntoResponse,
            S: Send + Sync + 'static,
            $($t: FromRequest<S> + Send,)*
        {
            const READS_BODY: bool = false $(|| <$t as ExtractorMeta>::CONSUMES_BODY)*;
            const BODY_ORDER: () = {
                $(assert!(
                    !<$init as ExtractorMeta>::CONSUMES_BODY,
                    "poring: only the last handler argument may read the request body"
                );)*
            };

            fn __extractors() -> Vec<ExtractorDesc> {
                vec![$(desc::<$t>()),*]
            }

            fn __responses(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
                R::__poring_describe(reg)
            }

            #[allow(unused_variables)]
            fn __call<'a, 'c>(&'c self, cx: &'c mut Ctx<'a, S>) -> impl Future<Output = Response> + Send + 'c {
                let () = Self::BODY_ORDER;
                async move {
                    $(
                        cx.__mark_extract();
                        let $v = match <$t as FromRequest<S>>::from_request(cx).await {
                            Ok(v) => v,
                            Err(e) => {
                                cx.mark(Stage::Reject);
                                return e.into_response();
                            }
                        };
                    )*
                    cx.mark(Stage::Handler);
                    (self)($($v),*).await.into_response()
                }
            }
        }
    };
    (@impl [$($all:tt)*] [$($init:ident)*] $head:ident $($rest:ident)+) => {
        impl_handler!(@impl [$($all)*] [$($init)* $head] $($rest)+);
    };
}

impl<F, Fut, R, S> Handler<(), S> for F
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = R> + Send,
    R: IntoResponse,
    S: Send + Sync + 'static,
{
    const READS_BODY: bool = false;
    const BODY_ORDER: () = ();

    fn __extractors() -> Vec<ExtractorDesc> {
        Vec::new()
    }

    fn __responses(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        R::__poring_describe(reg)
    }

    #[allow(clippy::manual_async_fn)] // Keeps the `Send + 'c` contract of the trait explicit.
    fn __call<'a, 'c>(
        &'c self,
        cx: &'c mut Ctx<'a, S>,
    ) -> impl Future<Output = Response> + Send + 'c {
        async move {
            cx.mark(Stage::Handler);
            (self)().await.into_response()
        }
    }
}

impl_handler!(T1 a1);
impl_handler!(T1 a1, T2 a2);
impl_handler!(T1 a1, T2 a2, T3 a3);
impl_handler!(T1 a1, T2 a2, T3 a3, T4 a4);
impl_handler!(T1 a1, T2 a2, T3 a3, T4 a4, T5 a5);
impl_handler!(T1 a1, T2 a2, T3 a3, T4 a4, T5 a5, T6 a6);
impl_handler!(T1 a1, T2 a2, T3 a3, T4 a4, T5 a5, T6 a6, T7 a7);
impl_handler!(T1 a1, T2 a2, T3 a3, T4 a4, T5 a5, T6 a6, T7 a7, T8 a8);

/// Type-erased handler stored in the app.
pub(crate) trait ErasedHandler<S>: Send + Sync {
    fn call<'a, 'c>(&'c self, cx: &'c mut Ctx<'a, S>) -> BoxFuture<'c, Response>;
}

struct Erased<H, A>(H, PhantomData<fn() -> A>);

impl<S, A: 'static, H: Handler<A, S>> ErasedHandler<S> for Erased<H, A> {
    fn call<'a, 'c>(&'c self, cx: &'c mut Ctx<'a, S>) -> BoxFuture<'c, Response> {
        Box::pin(self.0.__call(cx))
    }
}

/// Converts a hook's return value into "continue" or an early response.
///
/// Implemented for `()`, `Option<Response>` and `Result<(), E>` where `E: IntoResponse`.
pub trait HookOutcome {
    /// `Ok(())` continues; `Err(response)` short-circuits the request.
    #[allow(clippy::result_large_err)]
    fn into_outcome(self) -> Result<(), Response>;
}

impl HookOutcome for () {
    fn into_outcome(self) -> Result<(), Response> {
        Ok(())
    }
}

impl<E: IntoResponse> HookOutcome for Result<(), E> {
    fn into_outcome(self) -> Result<(), Response> {
        self.map_err(IntoResponse::into_response)
    }
}

impl HookOutcome for Option<Response> {
    fn into_outcome(self) -> Result<(), Response> {
        match self {
            Some(r) => Err(r),
            None => Ok(()),
        }
    }
}

pub(crate) type BeforeFn<S> =
    Box<dyn for<'a, 'b> Fn(&'b mut Ctx<'a, S>) -> Result<(), Response> + Send + Sync>;
pub(crate) type AfterFn<S> =
    Box<dyn for<'a, 'b> Fn(&'b Ctx<'a, S>, &'b mut Response) + Send + Sync>;

/// Named hooks of one level.
pub(crate) struct Hooks<S> {
    pub(crate) before: Vec<(String, BeforeFn<S>)>,
    pub(crate) after: Vec<(String, AfterFn<S>)>,
}

impl<S> Default for Hooks<S> {
    fn default() -> Self {
        Hooks {
            before: Vec::new(),
            after: Vec::new(),
        }
    }
}

// The early `Response` is returned by value, as in `HookOutcome`: boxing it would add an
// allocation to every short-circuit.
#[allow(clippy::result_large_err)]
impl<S> Hooks<S> {
    pub(crate) fn add_before<F, O>(&mut self, f: F)
    where
        F: for<'a, 'b> Fn(&'b mut Ctx<'a, S>) -> O + Send + Sync + 'static,
        O: HookOutcome,
    {
        let name = hook_name::<F>("before");
        self.before
            .push((name, Box::new(move |cx| f(cx).into_outcome())));
    }

    pub(crate) fn add_after<F>(&mut self, f: F)
    where
        F: for<'a, 'b> Fn(&'b Ctx<'a, S>, &'b mut Response) + Send + Sync + 'static,
    {
        let name = hook_name::<F>("after");
        self.after.push((name, Box::new(f)));
    }

    pub(crate) fn before_names(&self) -> impl Iterator<Item = &str> {
        self.before.iter().map(|(n, _)| n.as_str())
    }

    pub(crate) fn after_names(&self) -> impl Iterator<Item = &str> {
        self.after.iter().map(|(n, _)| n.as_str())
    }

    /// Runs the before hooks in order; the first early response wins.
    pub(crate) fn run_before(&self, cx: &mut Ctx<'_, S>) -> Result<(), Response> {
        for (_, h) in &self.before {
            cx.__mark_before();
            if let Err(r) = h(cx) {
                cx.mark(Stage::ShortCircuit);
                return Err(r);
            }
        }
        Ok(())
    }

    pub(crate) fn run_after(&self, cx: &mut Ctx<'_, S>, res: &mut Response) {
        for (_, h) in &self.after {
            cx.__mark_after();
            h(cx, res);
        }
    }
}

/// A route registered through the fluent API, before the app is built.
pub(crate) struct NativeRoute<S> {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) policy: Option<Policy>,
    pub(crate) name: String,
    pub(crate) extractors: Vec<ExtractorDesc>,
    pub(crate) reads_body: bool,
    pub(crate) responses: fn(&mut SchemaRegistry) -> Vec<ResponseDoc>,
    pub(crate) source: SourceLoc,
    pub(crate) handler: Box<dyn ErasedHandler<S>>,
}

impl<S: 'static> NativeRoute<S> {
    #[track_caller]
    pub(crate) fn new<H: Handler<A, S>, A: 'static>(
        method: Method,
        path: &str,
        policy: Option<Policy>,
        handler: H,
    ) -> Self {
        let () = H::BODY_ORDER;
        let loc = std::panic::Location::caller();
        let pretty = pretty_type_name(std::any::type_name::<H>());
        let name = if pretty.contains("closure") || pretty.is_empty() {
            crate::contract::route_id(method.as_str(), path)
        } else {
            pretty
        };
        NativeRoute {
            method,
            path: path.to_owned(),
            policy,
            name,
            extractors: H::__extractors(),
            reads_body: H::READS_BODY,
            responses: H::__responses,
            source: SourceLoc {
                file: loc.file().replace('\\', "/"),
                line: loc.line(),
            },
            handler: Box::new(Erased(handler, PhantomData)),
        }
    }
}

/// A group of fluent routes under a static prefix, with its own policy and hooks.
///
/// Created by `.group(prefix, |group| ..)`. Groups do not nest, matching `poring_app!`.
pub struct Group<S> {
    pub(crate) prefix: String,
    pub(crate) policy: Policy,
    pub(crate) rate_limit: Option<crate::policy::RateLimit>,
    pub(crate) hooks: Hooks<S>,
    pub(crate) routes: Vec<NativeRoute<S>>,
    pub(crate) source: SourceLoc,
}

impl<S> std::fmt::Debug for Group<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("prefix", &self.prefix)
            .field("routes", &self.routes.len())
            .finish()
    }
}

impl<S: Send + Sync + 'static> Group<S> {
    pub(crate) fn new(prefix: &str, source: SourceLoc) -> Self {
        Group {
            prefix: prefix.to_owned(),
            policy: Policy::new(),
            rate_limit: None,
            hooks: Hooks::default(),
            routes: Vec::new(),
            source,
        }
    }

    /// Sets the group policy (merged between the app defaults and each route).
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// The group's rate limit, inherited by routes that do not declare their own. With
    /// [`RateScope::Group`](crate::policy::RateScope::Group) every such route shares one
    /// bucket per client; otherwise each route has its own.
    pub fn rate_limit(mut self, limit: crate::policy::RateLimit) -> Self {
        self.rate_limit = Some(limit);
        self
    }

    /// Adds a before hook, run after the app-level hooks for every route in the group.
    /// Returning an early response skips the handler; after hooks still run.
    pub fn before<F, O>(mut self, hook: F) -> Self
    where
        F: for<'a, 'b> Fn(&'b mut Ctx<'a, S>) -> O + Send + Sync + 'static,
        O: HookOutcome,
    {
        self.hooks.add_before(hook);
        self
    }

    /// Adds an after hook, run before the app-level after hooks.
    pub fn after<F>(mut self, hook: F) -> Self
    where
        F: for<'a, 'b> Fn(&'b Ctx<'a, S>, &'b mut Response) + Send + Sync + 'static,
    {
        self.hooks.add_after(hook);
        self
    }

    fn push_route(mut self, route: NativeRoute<S>) -> Self {
        self.routes.push(route);
        self
    }

    route_methods!(S);
}

/// Fluent routes, groups and hooks collected by a builder.
pub(crate) struct NativeSet<S> {
    /// `(group index, route)` in registration order.
    pub(crate) routes: Vec<(Option<usize>, NativeRoute<S>)>,
    pub(crate) groups: Vec<NativeGroup<S>>,
    pub(crate) hooks: Hooks<S>,
    /// Configuration errors reported by `build()`.
    pub(crate) errors: Vec<String>,
}

pub(crate) struct NativeGroup<S> {
    pub(crate) prefix: String,
    pub(crate) policy: Policy,
    pub(crate) hooks: Hooks<S>,
    pub(crate) source: SourceLoc,
}

impl<S> Default for NativeSet<S> {
    fn default() -> Self {
        NativeSet {
            routes: Vec::new(),
            groups: Vec::new(),
            hooks: Hooks::default(),
            errors: Vec::new(),
        }
    }
}

impl<S> NativeSet<S> {
    pub(crate) fn is_empty(&self) -> bool {
        self.routes.is_empty()
            && self.groups.is_empty()
            && self.hooks.before.is_empty()
            && self.hooks.after.is_empty()
    }

    pub(crate) fn add_group(&mut self, g: Group<S>) {
        let idx = self.groups.len();
        let policy = match g.rate_limit {
            Some(_) if g.policy.has_rate_limit() => {
                self.errors.push(format!(
                    "group `{}`: the rate limit is declared by both `.rate_limit(..)` and `.policy(..)`",
                    g.prefix
                ));
                g.policy
            }
            Some(limit) => g.policy.with_rate_limit(limit),
            None => g.policy,
        };
        self.groups.push(NativeGroup {
            prefix: g.prefix,
            policy,
            hooks: g.hooks,
            source: g.source,
        });
        self.routes
            .extend(g.routes.into_iter().map(|r| (Some(idx), r)));
    }
}

/// Shortens `std::any::type_name` output: `poring::extract::path::Path<alloc::string::String>`
/// becomes `Path<String>`.
pub(crate) fn pretty_type_name(full: &str) -> String {
    let mut out = String::with_capacity(full.len());
    let mut seg_start = 0;
    let mut chars = full.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ':' && chars.peek() == Some(&':') {
            chars.next();
            out.truncate(seg_start);
            continue;
        }
        out.push(c);
        if !(c.is_alphanumeric() || c == '_' || c == '{' || c == '}') {
            seg_start = out.len();
        }
    }
    out
}

fn hook_name<F>(kind: &str) -> String {
    let pretty = pretty_type_name(std::any::type_name::<F>());
    if pretty.contains("closure") {
        format!("{kind} closure")
    } else {
        pretty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_names() {
        assert_eq!(
            pretty_type_name("poring::extract::path::Path<alloc::string::String>"),
            "Path<String>"
        );
        assert_eq!(
            pretty_type_name("(u64, core::option::Option<a::B>)"),
            "(u64, Option<B>)"
        );
        assert_eq!(pretty_type_name("app::main::{{closure}}"), "{{closure}}");
    }
}
