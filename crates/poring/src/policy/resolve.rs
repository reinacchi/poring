//! Startup-time effective policy resolution (mirrors [`super::check`]).

use std::time::Duration;

use crate::contract::{PolicyView, RateLimitView};

use crate::descriptor::Method;
use crate::policy::{
    DEFAULT_BODY_LIMIT, DEFAULT_TIMEOUT_MS, Level, LevelAuth, LevelCsrf, PolicySpec, RateLimitSpec,
    TimeoutSpec,
};

/// Effective CSRF mode of a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsrfMode {
    /// Cookie-authenticated unsafe requests must present a valid double-submit token.
    Enforced,
    /// Explicitly exempt (documented reason).
    Exempt(String),
    /// Not applicable (safe method, public route, or authenticator never uses cookies).
    NotApplicable,
}

/// The merged, runtime-enforced policy of one route.
#[derive(Clone, Debug)]
pub struct EffectivePolicy {
    /// Authentication required.
    pub auth_required: bool,
    /// Explicit public exception reason.
    pub public_reason: Option<String>,
    /// Public only because the app declares no authenticator.
    pub implicit_public: bool,
    /// Required scopes.
    pub scopes: Vec<String>,
    /// Required roles.
    pub roles: Vec<String>,
    /// Max body bytes.
    pub body_limit: u64,
    /// Allowed content types (empty = unrestricted).
    pub content_types: Vec<String>,
    /// CSRF mode.
    pub csrf: CsrfMode,
    /// Timeout.
    pub timeout: Option<Duration>,
    /// Rate limit.
    pub rate_limit: Option<RateLimitSpec>,
    /// The level that declared `rate_limit` (determines the shared bucket for group and
    /// app scopes).
    pub rate_limit_source: Option<String>,
    /// App-wide ceiling enforced in addition to `rate_limit` (see
    /// [`AppContext::ceiling`]).
    pub rate_limit_ceiling: Option<RateLimitSpec>,
    /// CORS checks apply (app has CORS configured).
    pub cors: bool,
    /// Route reads the request body (enables the body gate).
    pub reads_body: bool,
    /// Route serves WebSocket handshakes (enables the `ws_origin` check). Set by the
    /// planner from the route declaration; [`resolve()`] leaves it `false`.
    pub websocket: bool,
    /// WebSocket origins declared by the most specific level (`None`: the app's
    /// `.ws_origins(..)` configuration applies).
    pub ws_origins: Option<crate::policy::WsOrigins>,
    /// Provenance lines for `explain`.
    pub provenance: Vec<String>,
}

impl EffectivePolicy {
    /// The ordered list of runtime checks, using graph stage names.
    pub fn checks(&self) -> Vec<String> {
        let mut c = Vec::new();
        let principal = |r: Option<RateLimitSpec>| {
            r.is_some_and(|r| r.key == crate::policy::RateKey::Principal)
        };
        // All applicable limits are checked together, after authentication when any of
        // them is keyed by principal.
        let by_principal = principal(self.rate_limit) || principal(self.rate_limit_ceiling);
        let limited = self.rate_limit.is_some() || self.rate_limit_ceiling.is_some();
        if self.websocket {
            c.push("ws_origin".to_owned());
        }
        if self.cors {
            c.push("cors".to_owned());
        }
        if limited && !by_principal {
            c.push("rate_limit".to_owned());
        }
        if self.auth_required {
            c.push("auth".to_owned());
            if !self.scopes.is_empty() || !self.roles.is_empty() {
                c.push("authz".to_owned());
            }
        }
        // Principal-keyed limits need the authenticated subject, so they run after auth.
        if limited && by_principal {
            c.push("rate_limit".to_owned());
        }
        if self.auth_required && self.csrf == CsrfMode::Enforced {
            c.push("csrf".to_owned());
        }
        if self.reads_body {
            c.push("body_gate".to_owned());
        }
        c
    }

    /// Serialisable view for manifests.
    pub fn view(&self) -> PolicyView {
        PolicyView {
            auth: if self.auth_required {
                "required"
            } else {
                "public"
            }
            .to_owned(),
            public_reason: self.public_reason.clone(),
            implicit_public: self.implicit_public,
            scopes: self.scopes.clone(),
            roles: self.roles.clone(),
            body_limit: self.body_limit,
            content_types: self.content_types.clone(),
            csrf: match &self.csrf {
                CsrfMode::Enforced => "enforced",
                CsrfMode::Exempt(_) => "exempt",
                CsrfMode::NotApplicable => "not_applicable",
            }
            .to_owned(),
            csrf_exempt_reason: match &self.csrf {
                CsrfMode::Exempt(r) => Some(r.clone()),
                _ => None,
            },
            timeout_ms: self.timeout.map(|d| d.as_millis() as u64),
            rate_limit: self
                .rate_limit
                .map(|r| rate_limit_view(&r, self.rate_limit_source.as_deref().unwrap_or("route"))),
            rate_limit_ceiling: self
                .rate_limit_ceiling
                .map(|r| rate_limit_view(&r, "app ceiling")),
            ws_origins: self.ws_origins.as_ref().map(crate::policy::WsOrigins::view),
            provenance: self.provenance.clone(),
            checks: self.checks(),
        }
    }
}

fn rate_limit_view(r: &RateLimitSpec, source: &str) -> RateLimitView {
    use crate::policy::RateScope;
    RateLimitView {
        requests: r.requests,
        per_ms: r.per_ms,
        key: r.key.as_str().to_owned(),
        algorithm: "token_bucket".to_owned(),
        scope: if source == "app ceiling" {
            "app".to_owned()
        } else {
            r.scope.as_str().to_owned()
        },
        shared_by: match r.scope {
            RateScope::Route if source != "app ceiling" => None,
            _ => Some(source.to_owned()),
        },
        headers: r.headers,
    }
}

/// Inputs describing the app-level context for resolution.
#[derive(Clone, Copy, Debug)]
pub struct AppContext {
    /// An authenticator is declared.
    pub has_authenticator: bool,
    /// The authenticator may use cookies.
    pub auth_uses_cookies: bool,
    /// CORS is configured.
    pub cors: bool,
    /// App-wide rate limit enforced in addition to every route's own limit. A
    /// principal-keyed ceiling covers authenticated routes only (public routes have no
    /// principal); use an IP-keyed ceiling to cover every route.
    pub ceiling: Option<RateLimitSpec>,
}

/// Merges `levels` (app first, then group/plugin, then route) into an effective policy.
///
/// Each element is `(level name, spec)`. Returns an error string if a rule enforced by
/// [`super::check::check_app`] is violated (only reachable for dynamic routes, which are
/// not compile-time checked).
pub fn resolve(
    app: AppContext,
    levels: &[(&str, &PolicySpec)],
    method: Method,
    reads_body: bool,
    uses_principal: bool,
) -> Result<EffectivePolicy, String> {
    let levels: Vec<(&str, Level<'static>)> = levels.iter().map(|(n, p)| (*n, p.level())).collect();
    resolve_levels(app, &levels, method, reads_body, uses_principal)
}

/// [`resolve()`] over borrowed levels (`const` macro declarations or owned fluent policies).
pub(crate) fn resolve_levels(
    app: AppContext,
    levels: &[(&str, Level<'_>)],
    method: Method,
    reads_body: bool,
    uses_principal: bool,
) -> Result<EffectivePolicy, String> {
    let mut prov = Vec::new();
    let mut auth = LevelAuth::Inherit;
    let mut auth_src = "default";
    let mut strict = false;
    let mut scopes: Vec<String> = Vec::new();
    let mut roles: Vec<String> = Vec::new();
    let mut body_limit: Option<(u64, &str)> = None;
    let mut content_types: Option<(&[&str], &str)> = None;
    let mut csrf = LevelCsrf::Inherit;
    let mut csrf_src = "default";
    let mut timeout = TimeoutSpec::Inherit;
    let mut timeout_src = "default";
    let mut rate: Option<(RateLimitSpec, &str)> = None;
    let mut ws_origins: Option<(&crate::policy::WsOrigins, &str)> = None;
    let last = levels.len().saturating_sub(1);
    let mut inherited_reqs = false;

    for (idx, (name, p)) in levels.iter().enumerate() {
        let is_route = idx == last;
        if is_route {
            inherited_reqs = !scopes.is_empty() || !roles.is_empty();
        }
        if p.auth != LevelAuth::Inherit {
            auth = p.auth;
            auth_src = name;
        }
        if p.strict && !is_route {
            strict = true;
            prov.push(format!("deny_anonymous (strict) <- {name}"));
        }
        for s in &p.scopes {
            if !scopes.iter().any(|x| x == s) {
                scopes.push((*s).to_owned());
                prov.push(format!("scope `{s}` <- {name}"));
            }
        }
        for r in &p.roles {
            if !roles.iter().any(|x| x == r) {
                roles.push((*r).to_owned());
                prov.push(format!("role `{r}` <- {name}"));
            }
        }
        if let Some(l) = p.body_limit {
            if let Some((cur, src)) = body_limit
                && l > cur
            {
                return Err(format!(
                    "{name} declares body_limit {l} above the limit {cur} inherited from {src}; limits may only be narrowed"
                ));
            }
            body_limit = Some((l, name));
        }
        if !p.content_types.is_empty() {
            content_types = Some((p.content_types.as_slice(), name));
        }
        if p.csrf != LevelCsrf::Inherit {
            csrf = p.csrf;
            csrf_src = name;
        }
        if p.timeout != TimeoutSpec::Inherit {
            timeout = p.timeout;
            timeout_src = name;
        }
        if let Some(r) = p.rate_limit {
            rate = Some((r, name));
        }
        if let Some(o) = &p.ws_origins {
            ws_origins = Some((o, name));
        }
    }
    let ws_origins = match ws_origins {
        Some((o, src)) => {
            crate::policy::ws_origin::WsOriginPolicy::from_config(o, app.auth_uses_cookies)
                .map_err(|e| format!("{src}: {e}"))?;
            prov.push(format!("ws_origins={:?} <- {src}", o.view()));
            Some(o.clone())
        }
        None => None,
    };

    let (auth_required, public_reason, implicit_public) = match auth {
        LevelAuth::Inherit => {
            if app.has_authenticator {
                prov.push("auth=required <- default (app declares an authenticator)".to_owned());
                (true, None, false)
            } else {
                prov.push("auth=public <- implicit (app declares no authenticator)".to_owned());
                (false, None, true)
            }
        }
        LevelAuth::Required => {
            prov.push(format!("auth=required <- {auth_src}"));
            (true, None, false)
        }
        LevelAuth::Public(reason) => {
            if reason.is_empty() {
                prov.push(format!("auth=public <- {auth_src}"));
                (false, None, false)
            } else {
                prov.push(format!("auth=public (exception: {reason}) <- {auth_src}"));
                (false, Some(reason.to_owned()), false)
            }
        }
    };

    if auth_required && !app.has_authenticator {
        return Err("requires authentication but the app declares no authenticator".into());
    }
    if uses_principal && !auth_required {
        return Err("extracts a Principal but is not authenticated".into());
    }
    if !auth_required && strict && public_reason.is_none() {
        return Err("is public under a strict deny_anonymous policy without a reason".into());
    }
    let route_public = matches!(levels.last().map(|l| l.1.auth), Some(LevelAuth::Public(_)));
    if route_public && inherited_reqs && public_reason.is_none() {
        return Err("is public and would drop inherited scope/role requirements".into());
    }
    if !auth_required && (!scopes.is_empty() || !roles.is_empty()) {
        prov.push(
            "inherited scopes/roles dropped: route is an explicit public exception".to_owned(),
        );
        scopes.clear();
        roles.clear();
    }

    let body_limit = match body_limit {
        Some((l, src)) => {
            prov.push(format!("body_limit={l} <- {src}"));
            l
        }
        None => {
            prov.push(format!("body_limit={DEFAULT_BODY_LIMIT} <- default"));
            DEFAULT_BODY_LIMIT
        }
    };
    let content_types = match content_types {
        Some((c, src)) => {
            prov.push(format!("content_types={c:?} <- {src}"));
            c.iter().map(|s| (*s).to_owned()).collect()
        }
        None => Vec::new(),
    };
    let csrf_mode = match csrf {
        LevelCsrf::Exempt(reason) => {
            prov.push(format!("csrf=exempt ({reason}) <- {csrf_src}"));
            CsrfMode::Exempt(reason.to_owned())
        }
        _ if auth_required && app.auth_uses_cookies && method.is_unsafe() => {
            prov.push(format!(
                "csrf=enforced <- {csrf_src} (cookie-capable authenticator, unsafe method)"
            ));
            CsrfMode::Enforced
        }
        _ => CsrfMode::NotApplicable,
    };
    let timeout = match timeout {
        TimeoutSpec::Inherit => {
            prov.push(format!("timeout={DEFAULT_TIMEOUT_MS}ms <- default"));
            Some(Duration::from_millis(DEFAULT_TIMEOUT_MS))
        }
        TimeoutSpec::Disabled => {
            prov.push(format!("timeout=none <- {timeout_src}"));
            None
        }
        TimeoutSpec::Ms(ms) => {
            prov.push(format!("timeout={ms}ms <- {timeout_src}"));
            Some(Duration::from_millis(ms))
        }
    };
    if let Some((r, src)) = rate
        && r.key == crate::policy::RateKey::Principal
        && !auth_required
    {
        return Err(format!(
            "has a principal-keyed rate limit (from {src}) but is not authenticated; key it by IP or require authentication"
        ));
    }
    let rate_limit_source = rate.map(|(_, src)| src.to_owned());
    let rate_limit = rate.map(|(r, src)| {
        prov.push(format!(
            "rate_limit={}/{}ms by {} <- {src}",
            r.requests,
            r.per_ms,
            r.key.as_str()
        ));
        if r.scope != crate::policy::RateScope::Route {
            prov.push(format!(
                "rate_limit bucket shared by every route inheriting it ({} scope)",
                r.scope.as_str()
            ));
        }
        r
    });
    let rate_limit_ceiling = app
        .ceiling
        .filter(|c| c.key == crate::policy::RateKey::Ip || auth_required);
    if let Some(c) = rate_limit_ceiling {
        prov.push(format!(
            "rate_limit ceiling={}/{}ms by {} <- app (enforced in addition)",
            c.requests,
            c.per_ms,
            c.key.as_str()
        ));
    }

    Ok(EffectivePolicy {
        auth_required,
        public_reason,
        implicit_public,
        scopes,
        roles,
        body_limit,
        content_types,
        csrf: csrf_mode,
        timeout,
        rate_limit,
        rate_limit_source,
        rate_limit_ceiling,
        cors: app.cors,
        reads_body,
        websocket: false,
        ws_origins,
        provenance: prov,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::AuthSpec;

    const APP_AUTH: AppContext = AppContext {
        has_authenticator: true,
        auth_uses_cookies: true,
        cors: false,
        ceiling: None,
    };

    #[test]
    fn scopes_union_and_body_narrowing() {
        let app = PolicySpec {
            body_limit: Some(1 << 20),
            scopes: &["a"],
            ..PolicySpec::INHERIT
        };
        let route = PolicySpec {
            body_limit: Some(1024),
            scopes: &["b"],
            ..PolicySpec::INHERIT
        };
        let e = resolve(
            APP_AUTH,
            &[("app", &app), ("route", &route)],
            Method::Post,
            true,
            false,
        )
        .unwrap();
        assert!(e.auth_required);
        assert_eq!(e.scopes, vec!["a", "b"]);
        assert_eq!(e.body_limit, 1024);
        assert_eq!(e.csrf, CsrfMode::Enforced);
        assert_eq!(e.checks(), vec!["auth", "authz", "csrf", "body_gate"]);
    }

    #[test]
    fn raising_limit_is_rejected() {
        let app = PolicySpec {
            body_limit: Some(1024),
            ..PolicySpec::INHERIT
        };
        let route = PolicySpec {
            body_limit: Some(4096),
            ..PolicySpec::INHERIT
        };
        assert!(
            resolve(
                APP_AUTH,
                &[("app", &app), ("route", &route)],
                Method::Post,
                true,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn strict_requires_reason() {
        let app = PolicySpec {
            auth: AuthSpec::Required,
            strict: true,
            ..PolicySpec::INHERIT
        };
        let bare = PolicySpec {
            auth: AuthSpec::Public { reason: "" },
            ..PolicySpec::INHERIT
        };
        let why = PolicySpec {
            auth: AuthSpec::Public {
                reason: "health probe",
            },
            ..PolicySpec::INHERIT
        };
        assert!(
            resolve(
                APP_AUTH,
                &[("app", &app), ("route", &bare)],
                Method::Get,
                false,
                false
            )
            .is_err()
        );
        let ok = resolve(
            APP_AUTH,
            &[("app", &app), ("route", &why)],
            Method::Get,
            false,
            false,
        )
        .unwrap();
        assert!(!ok.auth_required);
        assert_eq!(ok.public_reason.as_deref(), Some("health probe"));
    }

    #[test]
    fn implicit_public_without_authenticator() {
        let ctx = AppContext {
            has_authenticator: false,
            auth_uses_cookies: false,
            cors: false,
            ceiling: None,
        };
        let e = resolve(
            ctx,
            &[
                ("app", &PolicySpec::INHERIT),
                ("route", &PolicySpec::INHERIT),
            ],
            Method::Get,
            false,
            false,
        )
        .unwrap();
        assert!(!e.auth_required);
        assert!(e.implicit_public);
        assert!(e.checks().is_empty());
    }
}
