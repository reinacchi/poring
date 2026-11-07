//! The per-request pipeline: routing, security checks, dispatch and response finishing.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use http::header::{HeaderName, HeaderValue};
use http::{Request, StatusCode};

use crate::body::ReqBody;
use crate::contract::Manifest;
use crate::ctx::{Ctx, Params, RequestId};
use crate::descriptor::Method;
use crate::dynamic::DynRequest;
use crate::error::{FrameworkError, rejection};
use crate::flow::{FlowRecorder, FlowState, Stage};
use crate::handler::Hooks;
use crate::policy::enforce::{CorsRuntime, csrf_ok};
use crate::policy::rate_limit::{
    RateKeyValue, RateLimitDecision, RateLimiter, RateOutcome, RateProbe,
};
use crate::policy::{AuthError, AuthRequest, Authenticator, Credential, RateKey, TrustedProxies};
use crate::response::{IntoResponse, Response};
use crate::router::{Check, Lookup, RouteRuntime, Router, Target};

use super::plan::{NativeRuntime, RouteDoc};
use super::{AppSpec, ErrorMapper, Limits, OnRequest, OnResponse, ResponseInfo, SecurityHeaders};

pub(super) struct AppInner<A: AppSpec> {
    pub(super) state: A::State,
    pub(super) auth: A::Auth,
    pub(super) name: String,
    pub(super) router: Router,
    pub(super) routes: Vec<RouteRuntime>,
    pub(super) native: Vec<NativeRuntime<A::State>>,
    pub(super) native_groups: Vec<Hooks<A::State>>,
    pub(super) native_hooks: Hooks<A::State>,
    #[cfg_attr(not(feature = "openapi"), allow(dead_code))]
    pub(super) docs: Vec<RouteDoc>,
    pub(super) cors: Option<CorsRuntime>,
    pub(super) limiter: RateLimiter,
    pub(super) recorder: FlowRecorder,
    pub(super) limits: Limits,
    pub(super) security_headers: SecurityHeaders,
    pub(super) on_request: Vec<OnRequest>,
    pub(super) on_response: Arc<[OnResponse]>,
    pub(super) error_mapper: Option<ErrorMapper>,
    pub(super) request_ids: bool,
    pub(super) proxies: TrustedProxies,
    pub(super) ws_origins: crate::policy::ws_origin::WsOriginPolicy,
    /// Route-level overrides of `ws_origins`, indexed by `RouteRuntime::index`.
    pub(super) route_ws_origins: Box<[Option<crate::policy::ws_origin::WsOriginPolicy>]>,
    /// App-wide WebSocket counters (shared by every listener serving this app).
    #[cfg(feature = "websocket")]
    pub(crate) ws_counters: std::sync::Arc<crate::ws::WsCounters>,
    pub(super) manifest_base: Manifest,
}

const RATELIMIT: HeaderName = HeaderName::from_static("ratelimit");
const RATELIMIT_POLICY: HeaderName = HeaderName::from_static("ratelimit-policy");

impl<A: AppSpec> AppInner<A> {
    pub(super) async fn handle(&self, req: Request<ReqBody>, peer: Option<SocketAddr>) -> Response {
        let start = Instant::now();
        let (parts, body) = req.into_parts();
        let request_id = RequestId::from_headers(&parts.headers);
        let mut flow = if self.recorder.sample() {
            Some(Box::new(FlowState::new(start)))
        } else {
            None
        };
        let is_head = parts.method == http::Method::HEAD;
        // The origin is only consulted when CORS is configured.
        let origin = match self.cors {
            Some(_) => parts.headers.get(http::header::ORIGIN).cloned(),
            None => None,
        };
        let method = parts.method.clone();
        if let Some(f) = flow.as_deref_mut() {
            f.mark(Stage::Receive);
        }

        for hook in &self.on_request {
            if let Some(r) = hook(&parts) {
                return self.finish(
                    r,
                    Finish {
                        request_id,
                        route: None,
                        flow,
                        start,
                        is_head,
                        origin,
                        method,
                        extra: None,
                        rate: None,
                    },
                );
            }
        }

        if let Some(f) = flow.as_deref_mut() {
            f.mark(Stage::Match);
        }
        let lookup = if crate::policy::ws_origin::is_h2_websocket_handshake(&parts) {
            self.router.lookup_websocket(parts.uri.path(), |i| {
                self.routes[i as usize].policy.websocket
            })
        } else {
            self.router.lookup(parts.uri.path(), &parts.method)
        };
        match lookup {
            Lookup::NotFound => {
                if let Some(f) = flow.as_deref_mut() {
                    f.mark(Stage::NotFound);
                }
                let r = rejection::not_found().into_response();
                self.finish(
                    r,
                    Finish {
                        request_id,
                        route: None,
                        flow,
                        start,
                        is_head,
                        origin,
                        method,
                        extra: None,
                        rate: None,
                    },
                )
            }
            Lookup::MethodNotAllowed(entry) => {
                if let Some(f) = flow.as_deref_mut() {
                    f.mark(Stage::MethodNotAllowed);
                }
                let r = rejection::method_not_allowed(entry.allow.clone()).into_response();
                self.finish(
                    r,
                    Finish {
                        request_id,
                        route: None,
                        flow,
                        start,
                        is_head,
                        origin,
                        method,
                        extra: None,
                        rate: None,
                    },
                )
            }
            Lookup::AutoOptions(entry) => {
                let preflight = parts
                    .headers
                    .contains_key(http::header::ACCESS_CONTROL_REQUEST_METHOD);
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
                            rejection::forbidden("cors_origin_denied", "origin not allowed")
                                .into_response()
                        }
                    }
                    _ => {
                        let mut r = StatusCode::NO_CONTENT.into_response();
                        r.headers_mut()
                            .insert(http::header::ALLOW, entry.allow.clone());
                        r
                    }
                };
                // Preflight responses already carry CORS headers; don't re-apply.
                self.finish(
                    r,
                    Finish {
                        request_id,
                        route: None,
                        flow,
                        start,
                        is_head,
                        origin: None,
                        method,
                        extra: None,
                        rate: None,
                    },
                )
            }
            Lookup::Found(idx, params) => {
                let route = &self.routes[idx as usize];
                self.run_route(
                    route, parts, body, params, peer, request_id, flow, start, is_head, origin,
                    method,
                )
                .await
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
            rate_limit: None,
        };
        let res = match self.enforce(&mut cx).await {
            Err(r) => r,
            Ok(()) => {
                let timeout = route.policy.timeout;
                let res = match &route.target {
                    Target::Static(i) => within(timeout, A::dispatch(*i, &mut cx)).await,
                    Target::Dynamic(ep) => {
                        within(timeout, call_dynamic(ep.as_ref(), &mut cx)).await
                    }
                    Target::Native(i) => within(timeout, self.call_native(*i, &mut cx)).await,
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
        let Ctx {
            flow,
            request_id,
            response_headers,
            rate_limit,
            ..
        } = cx;
        let finish = Finish {
            request_id,
            route: Some(route),
            flow,
            start,
            is_head,
            origin,
            method,
            extra: response_headers,
            rate: rate_limit,
        };
        self.finish(res, finish)
    }

    /// Runs a fluent route: global, app-level and group before hooks, the handler, then
    /// group, app-level and global after hooks (the same order as macro routes). After hooks
    /// also run when a before hook short-circuits.
    async fn call_native(&self, i: u32, cx: &mut Ctx<'_, A::State>) -> Response {
        let Some(entry) = self.native.get(i as usize) else {
            return crate::__private::unknown_route();
        };
        let group = entry.group.and_then(|g| self.native_groups.get(g));
        let mut res = 'run: {
            if let Err(r) = A::__global_before(cx).await {
                break 'run r;
            }
            if let Err(r) = self.native_hooks.run_before(cx) {
                break 'run r;
            }
            if let Some(g) = group
                && let Err(r) = g.run_before(cx)
            {
                break 'run r;
            }
            entry.handler.call(cx).await
        };
        if let Some(g) = group {
            g.run_after(cx, &mut res);
        }
        self.native_hooks.run_after(cx, &mut res);
        A::__global_after(cx, &mut res).await;
        res
    }

    /// Takes one token from every bucket that applies to the route (all or none) and records
    /// the outcome for response headers and `Ctx::rate_limit`.
    #[allow(clippy::result_large_err)] // Same shape as the other pipeline checks.
    fn rate_limit(&self, cx: &mut Ctx<'_, A::State>) -> Result<(), Response> {
        let Some(rate) = &cx.route.rate else {
            return Ok(());
        };
        let ip = match cx.peer {
            Some(peer) => RateKeyValue::ip(self.proxies.client_ip(peer.ip(), &cx.parts.headers)),
            None => RateKeyValue::Unknown,
        };
        let needs_subject = rate.rules.iter().any(|r| r.key == RateKey::Principal);
        let subject = match (&cx.identity, needs_subject) {
            (Some(id), true) => Some(RateKeyValue::Subject(id.subject.clone())),
            (None, true) => {
                // Unreachable: principal-keyed limits are only resolved on authenticated
                // routes, and they run after authentication.
                return Err(rejection::internal("rate_limit_without_principal").into_response());
            }
            (_, false) => None,
        };
        let probes: smallvec::SmallVec<[RateProbe<'_>; 4]> = rate
            .rules
            .iter()
            .map(|r| RateProbe {
                rule: r.rule,
                key: match (r.key, &subject) {
                    (RateKey::Principal, Some(s)) => s,
                    _ => &ip,
                },
            })
            .collect();
        let (decision, index) = self.limiter.check_indexed(&probes, Instant::now());
        let policy = rate.rules.get(index).map_or("route", |r| r.name);
        match decision {
            RateLimitDecision::Allowed(status) => {
                cx.rate_limit = Some(RateOutcome::Checked { status, policy });
                Ok(())
            }
            RateLimitDecision::Denied(status) => {
                cx.rate_limit = Some(RateOutcome::Checked { status, policy });
                cx.mark(Stage::Deny(429));
                let wait = status.retry_after.unwrap_or_default();
                Err(rejection::too_many_requests(wait).into_response())
            }
            RateLimitDecision::Saturated { retry_after } => {
                tracing::warn!(route = %cx.route.id, "rate limiter is full of active buckets");
                cx.rate_limit = Some(RateOutcome::Saturated(retry_after));
                cx.mark(Stage::Deny(503));
                Err(rejection::rate_limiter_saturated(retry_after).into_response())
            }
        }
    }

    fn note_ws_origin_denied(&self) {
        #[cfg(feature = "websocket")]
        self.ws_counters.note(crate::ws::WsEvent::OriginDenied);
        tracing::debug!("websocket handshake rejected by origin policy");
    }

    /// Whether a WebSocket handshake's `Origin` is acceptable for the route (`true` for
    /// requests that are not WebSocket handshakes).
    fn ws_origin_ok(&self, cx: &Ctx<'_, A::State>) -> bool {
        crate::policy::ws_origin::websocket_handshake(
            &cx.parts.method,
            cx.parts.version,
            &cx.parts.headers,
            &cx.parts.extensions,
        )
        .is_none()
            || crate::policy::ws_origin::origin_allowed(
                &cx.parts.headers,
                &cx.parts.uri,
                self.cors.as_ref(),
                self.route_ws_origins
                    .get(cx.route.index as usize)
                    .and_then(Option::as_ref)
                    .unwrap_or(&self.ws_origins),
                &self.proxies,
                cx.peer.map(|p| p.ip()),
            )
    }

    /// Runs the route's precomputed security checks in order.
    #[allow(clippy::result_large_err)] // Same shape as `rate_limit`; boxing would allocate per denial.
    async fn enforce(&self, cx: &mut Ctx<'_, A::State>) -> Result<(), Response> {
        let route = cx.route;
        // WebSocket handshakes are GETs, so neither the CORS check (unsafe methods only)
        // nor CSRF stops a cross-site handshake. WebSocket routes run `Check::WsOrigin`
        // first (listed in their contract); any other route that receives an upgrade
        // request is checked here as a backstop (not a graph stage: only `deny.403`).
        if !route.policy.websocket && !self.ws_origin_ok(cx) {
            cx.mark(Stage::Deny(403));
            self.note_ws_origin_denied();
            return Err(ws_origin_denied());
        }
        for check in &route.checks {
            match check {
                Check::WsOrigin => {
                    cx.mark(Stage::WsOrigin);
                    if !self.ws_origin_ok(cx) {
                        cx.mark(Stage::Deny(403));
                        self.note_ws_origin_denied();
                        return Err(ws_origin_denied());
                    }
                }
                Check::Cors => {
                    cx.mark(Stage::Cors);
                    if let (Some(cors), Some(o)) =
                        (&self.cors, cx.parts.headers.get(http::header::ORIGIN))
                    {
                        let allowed = o.to_str().map(|s| cors.allows(s)).unwrap_or(false);
                        // An HTTP/2 WebSocket handshake is judged like the HTTP/1.1 GET.
                        let unsafe_method =
                            !crate::policy::ws_origin::is_h2_websocket_handshake(&cx.parts)
                                && Method::from_http(&cx.parts.method)
                                    .map(Method::is_unsafe)
                                    .unwrap_or(true);
                        if !allowed && unsafe_method {
                            cx.mark(Stage::Deny(403));
                            return Err(rejection::forbidden(
                                "cors_origin_denied",
                                "origin not allowed",
                            )
                            .into_response());
                        }
                    }
                }
                Check::RateLimit => {
                    cx.mark(Stage::RateLimit);
                    self.rate_limit(cx)?;
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
                            #[cfg(feature = "websocket")]
                            if route.policy.websocket {
                                self.ws_counters.note(crate::ws::WsEvent::AuthDenied);
                            }
                            return Err(rejection::unauthenticated().into_response());
                        }
                        Err(AuthError::Unavailable(msg)) => {
                            tracing::error!(error = %msg, "authenticator unavailable");
                            cx.mark(Stage::Deny(503));
                            return Err(rejection::unavailable("authentication unavailable")
                                .into_response());
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
                        return Err(rejection::forbidden(
                            "insufficient_scope",
                            "missing required scope or role",
                        )
                        .into_response());
                    }
                }
                Check::Csrf => {
                    cx.mark(Stage::Csrf);
                    let cookie_auth = cx
                        .identity
                        .as_ref()
                        .map(|i| i.credential == Credential::Cookie)
                        .unwrap_or(false);
                    if cookie_auth && !csrf_ok(&cx.parts.headers) {
                        cx.mark(Stage::Deny(403));
                        return Err(
                            rejection::forbidden("csrf", "missing or invalid CSRF token")
                                .into_response(),
                        );
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
                            .unwrap_or_else(|| {
                                cx.parts
                                    .headers
                                    .contains_key(http::header::TRANSFER_ENCODING)
                            });
                        let ct = cx.content_type().map(|c| {
                            c.split(';')
                                .next()
                                .unwrap_or("")
                                .trim()
                                .to_ascii_lowercase()
                        });
                        let ok = match ct {
                            Some(ct) => route
                                .policy
                                .content_types
                                .iter()
                                .any(|a| a.eq_ignore_ascii_case(&ct)),
                            None => !has_body,
                        };
                        if !ok {
                            cx.mark(Stage::Deny(415));
                            return Err(rejection::unsupported_media_type(
                                &route.policy.content_types.join(", "),
                            )
                            .into_response());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(&self, mut res: Response, f: Finish<'_>) -> Response {
        if let Some(m) = &self.error_mapper
            && let Some(fe) = res.extensions().get::<FrameworkError>().cloned()
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
            headers.insert(
                HeaderName::from_static("x-request-id"),
                f.request_id.to_header(),
            );
        }
        let rate_headers = match (f.route.and_then(|r| r.rate.as_ref()), &f.rate) {
            (Some(rate), Some(outcome)) => apply_rate_headers(rate, outcome, headers),
            _ => &[][..],
        };
        if let (Some(cors), Some(o)) = (&self.cors, &f.origin)
            && o.to_str().map(|s| cors.allows(s)).unwrap_or(false)
        {
            cors.apply(o, headers);
            if !rate_headers.is_empty() {
                let exposed = rate_headers.join(", ");
                if let Ok(v) = HeaderValue::from_str(&exposed) {
                    headers.append(http::header::ACCESS_CONTROL_EXPOSE_HEADERS, v);
                }
            }
        }
        if f.is_head {
            // RFC 9110: HEAD carries the GET headers (including Content-Length) without a body.
            if let Some(len) = res.body().exact_len() {
                res.headers_mut()
                    .insert(http::header::CONTENT_LENGTH, HeaderValue::from(len));
            }
            *res.body_mut() = crate::body::Body::empty();
        }
        let status = res.status();
        let route_id = f.route.map(|r| r.id.as_str());
        if f.flow.is_some() || !self.on_response.is_empty() {
            let mut flow = f.flow;
            if let Some(fl) = flow.as_deref_mut() {
                fl.mark(Stage::Send);
            }
            let hooks = self.on_response.clone();
            let rid = f.request_id.to_string();
            let method = f.method;
            let start = f.start;
            let traces = flow.map(|fl| fl.finish(&rid, route_id, status.as_u16()));
            if let Some(t) = traces {
                self.recorder.push(t);
            }
            if !hooks.is_empty() {
                let info_route = route_id.map(str::to_owned);
                res.body_mut().on_done(move |end| {
                    let info = ResponseInfo {
                        request_id: rid,
                        route: info_route,
                        method,
                        status,
                        elapsed: start.elapsed(),
                        end,
                    };
                    for h in hooks.iter() {
                        h(&info);
                    }
                });
            }
        }
        let span = tracing::Span::current();
        if !span.is_disabled() {
            span.record("route", route_id.unwrap_or("-"));
            span.record("status", status.as_u16());
            span.record("request_id", tracing::field::display(&f.request_id));
        }
        tracing::debug!(
            target: "poring::request",
            request_id = %f.request_id,
            route = route_id.unwrap_or("-"),
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
    rate: Option<RateOutcome>,
}

/// Sets the rate-limit response headers authoritatively (replacing any set by hooks or
/// error mappers) and returns the names a CORS response should expose.
fn apply_rate_headers(
    rate: &crate::policy::rate_limit::RouteRate,
    outcome: &RateOutcome,
    headers: &mut http::HeaderMap,
) -> &'static [&'static str] {
    let retry = match outcome {
        RateOutcome::Checked { status, .. } => status.retry_after_secs(),
        RateOutcome::Saturated(d) => Some(crate::policy::rate_limit::ceil_secs(*d)),
    };
    match retry {
        Some(secs) => {
            headers.insert(http::header::RETRY_AFTER, HeaderValue::from(secs.max(1)));
        }
        None => {
            headers.remove(http::header::RETRY_AFTER);
        }
    }
    headers.remove(RATELIMIT);
    headers.remove(RATELIMIT_POLICY);
    let quota = rate.headers && matches!(outcome, RateOutcome::Checked { .. });
    if quota {
        if let Some(p) = &rate.policy_header {
            headers.insert(RATELIMIT_POLICY, p.clone());
        }
        if let Some(v) = outcome.header() {
            headers.insert(RATELIMIT, v);
        }
        // Quota values describe one client: keep shared caches from storing them.
        if !headers.contains_key(http::header::CACHE_CONTROL) {
            headers.insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
        }
    }
    match (retry.is_some(), quota) {
        (true, true) => &["Retry-After", "RateLimit", "RateLimit-Policy"],
        (true, false) => &["Retry-After"],
        (false, true) => &["RateLimit", "RateLimit-Policy"],
        (false, false) => &[],
    }
}

/// Awaits `fut`, giving up after `limit` with the same semantics as `tokio::time::timeout`:
/// the deadline is fixed before the first poll, the future is polled before the timer, and
/// the timer is polled without a budget when the future used up the task's budget. The timer
/// is only created once the future returns `Pending`, so handlers that complete on their
/// first poll never touch the timer wheel.
async fn within<F: Future>(limit: Option<Duration>, fut: F) -> Option<F::Output> {
    let Some(deadline) = limit.and_then(|d| tokio::time::Instant::now().checked_add(d)) else {
        return Some(fut.await);
    };
    let mut fut = std::pin::pin!(fut);
    let mut timer = std::pin::pin!(None::<tokio::time::Sleep>);
    std::future::poll_fn(|cx| {
        let had_budget = tokio::task::coop::has_budget_remaining();
        if let Poll::Ready(v) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(v));
        }
        if timer.is_none() {
            timer.set(Some(tokio::time::sleep_until(deadline)));
        }
        let Some(delay) = timer.as_mut().as_pin_mut() else {
            return Poll::Pending;
        };
        let elapsed = if had_budget && !tokio::task::coop::has_budget_remaining() {
            Pin::new(&mut tokio::task::coop::unconstrained(delay)).poll(cx)
        } else {
            delay.poll(cx)
        };
        elapsed.map(|()| None)
    })
    .await
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

fn ws_origin_denied() -> Response {
    rejection::forbidden("ws_origin_denied", "WebSocket handshake origin not allowed")
        .into_response()
}
