//! Startup planning: validation, policy resolution, rate-limit buckets, manifests and
//! contract metadata. Everything here runs once in `build()`, before a socket is bound.

use std::collections::HashMap;

use crate::contract::{
    ExtractorEntry, HookEntry, HookSet, Manifest, RouteEntry, RouteKind, SourceLoc,
};
use crate::descriptor::{AppDescriptor, ExtractorDesc, ExtractorKind, Method, ResponseFn};
use crate::dynamic::DynamicRoute;
use crate::handler::{ErasedHandler, Hooks, NativeSet};
use crate::policy::rate_limit::{RateRule, RouteRate, RouteRule};
use crate::policy::resolve::{AppContext, EffectivePolicy, resolve_levels};
use crate::policy::{Cors, Level, LevelKind, Policy, RateLimitSpec, RateScope};
use crate::router::{Check, RouteRuntime, Target};
use crate::schema::SchemaRegistry;

use super::{AppSpec, StartupError};

pub(super) struct NativeRuntime<S> {
    pub(super) handler: Box<dyn ErasedHandler<S>>,
    pub(super) group: Option<usize>,
}

/// App-level declarations: from `poring_app!`'s descriptor or from a fluent builder.
pub(crate) struct AppLevel {
    pub(crate) name: String,
    pub(crate) defaults: Policy,
    pub(crate) has_authenticator: bool,
    pub(crate) auth_type: String,
    pub(crate) auth_uses_cookies: bool,
    pub(crate) cors: Option<Cors>,
    pub(crate) ceiling: Option<RateLimitSpec>,
}

impl AppLevel {
    pub(crate) fn from_descriptor(app: &AppDescriptor) -> Self {
        AppLevel {
            name: app.name.to_owned(),
            defaults: Policy::from_spec(&app.defaults),
            has_authenticator: app.has_authenticator,
            auth_type: app.auth_type.to_owned(),
            auth_uses_cookies: app.auth_uses_cookies,
            cors: app.cors.as_ref().map(Cors::from_spec),
            ceiling: None,
        }
    }

    fn context(&self) -> AppContext {
        AppContext {
            has_authenticator: self.has_authenticator,
            auth_uses_cookies: self.auth_uses_cookies,
            cors: self.cors.is_some(),
            ceiling: self.ceiling,
        }
    }
}

/// Contract metadata of one route (OpenAPI), aligned with the manifest's routes.
#[cfg_attr(not(feature = "openapi"), allow(dead_code))]
pub(crate) struct RouteDoc {
    pub(crate) name: String,
    pub(crate) doc: String,
    pub(crate) params: Vec<String>,
    pub(crate) extractors: Vec<ExtractorDesc>,
    pub(crate) responses: Option<ResponseFn>,
}

fn hook_entries<'n>(names: impl IntoIterator<Item = &'n str>, scope: &str) -> Vec<HookEntry> {
    names
        .into_iter()
        .map(|n| HookEntry {
            name: n.to_owned(),
            scope: scope.to_owned(),
        })
        .collect()
}

fn extractor_entries(ex: &[ExtractorDesc], pretty: bool) -> Vec<ExtractorEntry> {
    ex.iter()
        .map(|e| ExtractorEntry {
            kind: e.kind.as_str().to_owned(),
            ty: if pretty {
                crate::handler::pretty_type_name(e.ty)
            } else {
                e.ty.to_owned()
            },
            consumes_body: e.consumes_body,
            validates: e.validates,
        })
        .collect()
}

/// Mirrors the route macros' `Path<T>` arity check for fluent routes, using the
/// extractor's schema: tuples must match the parameter count and scalars need exactly one.
fn check_path_extractor(e: &ExtractorDesc, params: &[String]) -> Result<(), String> {
    if e.kind != ExtractorKind::Path {
        return Ok(());
    }
    let ty = crate::handler::pretty_type_name(e.ty);
    if params.is_empty() {
        return Err(format!(
            "`{ty}` is extracted, but the route declares no path parameters"
        ));
    }
    let Some(schema_fn) = e.schema else {
        return Ok(());
    };
    let mut reg = SchemaRegistry::new();
    let raw = schema_fn(&mut reg);
    let schema = reg.resolve(&raw);
    if let Some(items) = schema
        .get("prefixItems")
        .and_then(serde_json::Value::as_array)
    {
        if items.len() != params.len() {
            return Err(format!(
                "`{ty}` extracts {} values, but the route declares {} parameter(s): {}",
                items.len(),
                params.len(),
                params.join(", ")
            ));
        }
    } else if schema.get("properties").is_none()
        && schema.get("additionalProperties").is_none()
        && params.len() != 1
    {
        return Err(format!(
            "`{ty}` extracts one value, but the route declares {} parameters ({}); use a tuple or a struct",
            params.len(),
            params.join(", ")
        ));
    }
    Ok(())
}

/// Assigns bucket scope IDs. A scope is the unit of bucket sharing: one per route for
/// route-scoped limits, one per declaring group or app for shared limits, and one for the
/// app ceiling. IDs are dense, assigned in registration order and never derived from
/// route indices, so routes of different kinds can never share a bucket by accident.
#[derive(Default)]
struct BucketScopes(HashMap<String, u32>);

impl BucketScopes {
    fn id(&mut self, label: String) -> u32 {
        let next = self.0.len() as u32;
        *self.0.entry(label).or_insert(next)
    }

    /// The rate limits of a route. `route_label` identifies the route and `group_label`
    /// the group it inherits from (if any).
    fn route_rate(
        &mut self,
        policy: &EffectivePolicy,
        route_label: &str,
        group_label: Option<&str>,
    ) -> Option<RouteRate> {
        let mut rules = Vec::new();
        let mut headers = false;
        if let Some(spec) = policy.rate_limit {
            let from_app = policy.rate_limit_source.as_deref() == Some("app defaults");
            let (label, name) = match spec.scope {
                RateScope::App if from_app => ("app".to_owned(), "app"),
                RateScope::Group | RateScope::App => match group_label {
                    Some(g) if !from_app => (format!("group:{g}"), "group"),
                    _ => ("app".to_owned(), "app"),
                },
                RateScope::Route => (format!("route:{route_label}"), "route"),
            };
            rules.push(RouteRule {
                rule: RateRule::new(self.id(label), &spec),
                key: spec.key,
                name,
            });
            headers |= spec.headers;
        }
        if let Some(spec) = policy.rate_limit_ceiling {
            let rule = RateRule::new(self.id("ceiling".to_owned()), &spec);
            rules.push(RouteRule {
                rule,
                key: spec.key,
                name: "ceiling",
            });
            headers |= spec.headers;
        }
        (!rules.is_empty()).then(|| RouteRate::new(rules, headers))
    }
}

fn runtime(
    id: String,
    index: u32,
    method: Method,
    path: String,
    policy: EffectivePolicy,
    target: Target,
    rate: Option<RouteRate>,
) -> RouteRuntime {
    let checks = policy
        .checks()
        .iter()
        .filter_map(|c| Check::parse(c))
        .collect();
    RouteRuntime {
        id,
        index,
        method,
        path,
        policy,
        checks,
        target,
        rate,
    }
}

/// Everything resolved at startup.
pub(super) struct Planned<S> {
    pub(super) routes: Vec<RouteRuntime>,
    pub(super) manifest: Manifest,
    pub(super) docs: Vec<RouteDoc>,
    pub(super) native: Vec<NativeRuntime<S>>,
    pub(super) native_groups: Vec<Hooks<S>>,
    pub(super) native_hooks: Hooks<S>,
}

pub(super) fn plan<A: AppSpec>(
    level: &AppLevel,
    native: NativeSet<A::State>,
    dynamic: Vec<DynamicRoute>,
) -> Result<Planned<A::State>, StartupError> {
    let app = &A::APP;
    let ctx = level.context();
    let defaults = level
        .defaults
        .level()
        .map_err(|e| StartupError::Config(format!("app `{}` defaults: {e}", level.name)))?;
    let mut scopes = BucketScopes::default();
    let mut routes = Vec::new();
    let mut entries = Vec::new();
    let mut docs = Vec::new();
    let native_before: Vec<&str> = native.hooks.before_names().collect();
    let native_after: Vec<&str> = native.hooks.after_names().collect();

    for (i, r) in app.routes.iter().enumerate() {
        let d = r.desc;
        let group = r.group.map(|g| &app.groups[g as usize]);
        let path = app.full_path(i);
        let mut levels: Vec<(&str, Level<'_>)> = vec![("app defaults", defaults.clone())];
        let gname;
        if let Some(g) = group {
            gname = format!("{} `{}`", if g.plugin { "plugin" } else { "group" }, g.name);
            levels.push((&gname, g.policy.level()));
        }
        levels.push(("route", d.policy.level()));
        let reads_body = d.extractors.iter().any(|e| e.consumes_body);
        let uses_principal = d.extractors.iter().any(|e| e.uses_principal);
        let mut policy = resolve_levels(ctx, &levels, d.method, reads_body, uses_principal)
            .map_err(|e| StartupError::Policy(format!("{} {path}", d.method.as_str()), e))?;
        policy.websocket = d.websocket;
        let id = crate::contract::route_id(d.method.as_str(), &path);
        let group_label = r.group.map(|g| format!("macro#{g}"));
        let rate = scopes.route_rate(&policy, &id, group_label.as_deref());
        let group_scope = |g: &crate::descriptor::GroupDescriptor| {
            if g.plugin { "plugin" } else { "group" }
        };
        let mut hooks = HookSet::default();
        hooks
            .before
            .extend(hook_entries(app.before.iter().copied(), "global"));
        if let Some(g) = group {
            hooks
                .before
                .extend(hook_entries(g.before.iter().copied(), group_scope(g)));
        }
        hooks
            .before
            .extend(hook_entries(d.before.iter().copied(), "local"));
        hooks
            .after
            .extend(hook_entries(d.after.iter().copied(), "local"));
        if let Some(g) = group {
            hooks
                .after
                .extend(hook_entries(g.after.iter().copied(), group_scope(g)));
        }
        hooks
            .after
            .extend(hook_entries(app.after.iter().copied(), "global"));
        entries.push(RouteEntry {
            id: id.clone(),
            kind: RouteKind::Static,
            method: d.method.as_str().to_owned(),
            path: path.clone(),
            handler: d.name.to_owned(),
            source: SourceLoc {
                file: d.file.replace('\\', "/"),
                line: d.line,
            },
            group: group.map(|g| g.name.to_owned()),
            extractors: extractor_entries(d.extractors, false),
            hooks,
            policy: policy.view(),
            annotations: d.annotations.iter().map(|s| (*s).to_owned()).collect(),
            websocket: d.websocket,
            meta: Vec::new(),
        });
        docs.push(RouteDoc {
            name: d.name.to_owned(),
            doc: d.doc.to_owned(),
            params: d.params.iter().map(|p| (*p).to_owned()).collect(),
            extractors: d.extractors.to_vec(),
            responses: Some(d.response),
        });
        let target = Target::Static(i as u16);
        routes.push(runtime(id, i as u32, d.method, path, policy, target, rate));
    }

    let mut groups = Vec::with_capacity(native.groups.len());
    for g in &native.groups {
        let at = format!("{}:{}", g.source.file, g.source.line);
        let prefix = crate::router::validate_prefix(&g.prefix)
            .map_err(|e| StartupError::Config(format!("{e} (group declared at {at})")))?;
        let group_err = |e: String| StartupError::Config(format!("group `{prefix}` ({at}): {e}"));
        g.policy.validate(LevelKind::Group).map_err(group_err)?;
        let group_level = g.policy.level().map_err(group_err)?;
        if let (Some(gl), Some(al)) = (group_level.body_limit, defaults.body_limit)
            && gl > al
        {
            return Err(group_err(format!(
                "raises the app body limit ({gl} > {al} bytes); limits may only be narrowed"
            )));
        }
        groups.push((prefix, format!("group `{}`", g.prefix), group_level));
    }
    let mut native_rt = Vec::with_capacity(native.routes.len());
    for (gi, r) in native.routes {
        let raw = match gi {
            Some(g) => crate::descriptor::join_path(&groups[g].0, &r.path),
            None => r.path.clone(),
        };
        let at = format!("{}:{}", r.source.file, r.source.line);
        let (path, params) = crate::router::canonicalise(&raw)
            .map_err(|e| StartupError::Config(format!("{e} (registered at {at})")))?;
        let label = format!("{} {path}", r.method.as_str());
        let route_err =
            |e: String| StartupError::Policy(label.clone(), format!("{e} (registered at {at})"));
        let route_policy = r.policy.clone().unwrap_or_default();
        route_policy.validate(LevelKind::Route).map_err(route_err)?;
        if r.reads_body && matches!(r.method, Method::Get | Method::Head) {
            return Err(route_err(format!(
                "{m} handler `{}` reads the request body; {m} requests have no defined body semantics",
                r.name,
                m = r.method.as_str(),
            )));
        }
        if let Some(pos) = r.extractors.iter().position(|e| e.consumes_body)
            && pos + 1 != r.extractors.len()
        {
            return Err(route_err(format!(
                "argument {} reads the request body; only the last argument may",
                pos + 1
            )));
        }
        for e in &r.extractors {
            check_path_extractor(e, &params).map_err(route_err)?;
        }
        let mut levels: Vec<(&str, Level<'_>)> = vec![("app defaults", defaults.clone())];
        if let Some(g) = gi {
            levels.push((&groups[g].1, groups[g].2.clone()));
        }
        levels.push(("route", route_policy.level().map_err(route_err)?));
        let uses_principal = r.extractors.iter().any(|e| e.uses_principal);
        let mut policy = resolve_levels(ctx, &levels, r.method, r.reads_body, uses_principal)
            .map_err(route_err)?;
        policy.websocket = r
            .extractors
            .iter()
            .any(|e| e.kind == ExtractorKind::WebSocket);
        let id = crate::contract::route_id(r.method.as_str(), &path);
        let group_label = gi.map(|g| format!("fluent#{g}"));
        let rate = scopes.route_rate(&policy, &id, group_label.as_deref());
        let group_hooks = gi.map(|g| &native.groups[g].hooks);
        let mut hooks = HookSet::default();
        hooks
            .before
            .extend(hook_entries(app.before.iter().copied(), "global"));
        hooks
            .before
            .extend(hook_entries(native_before.iter().copied(), "global"));
        hooks.before.extend(hook_entries(
            group_hooks.into_iter().flat_map(Hooks::before_names),
            "group",
        ));
        hooks.after.extend(hook_entries(
            group_hooks.into_iter().flat_map(Hooks::after_names),
            "group",
        ));
        hooks
            .after
            .extend(hook_entries(native_after.iter().copied(), "global"));
        hooks
            .after
            .extend(hook_entries(app.after.iter().copied(), "global"));
        entries.push(RouteEntry {
            id: id.clone(),
            kind: RouteKind::Native,
            method: r.method.as_str().to_owned(),
            path: path.clone(),
            handler: r.name.clone(),
            source: r.source.clone(),
            group: gi.map(|g| groups[g].0.clone()),
            extractors: extractor_entries(&r.extractors, true),
            hooks,
            policy: policy.view(),
            annotations: Vec::new(),
            websocket: r
                .extractors
                .iter()
                .any(|e| e.kind == ExtractorKind::WebSocket),
            meta: Vec::new(),
        });
        docs.push(RouteDoc {
            name: r.name.clone(),
            doc: String::new(),
            params,
            extractors: r.extractors,
            responses: Some(r.responses),
        });
        let target = Target::Native(native_rt.len() as u32);
        let index = routes.len() as u32;
        routes.push(runtime(id, index, r.method, path, policy, target, rate));
        native_rt.push(NativeRuntime {
            handler: r.handler,
            group: gi,
        });
    }
    let native_groups: Vec<Hooks<A::State>> = native.groups.into_iter().map(|g| g.hooks).collect();

    for dr in dynamic {
        let dyn_err = |reason: String| StartupError::DynamicRoute {
            method: dr.method.as_str(),
            path: dr.path.clone(),
            reason,
        };
        crate::dynamic::validate_path(&dr.path).map_err(dyn_err)?;
        let declared = dr.policy.to_policy();
        declared.validate(LevelKind::Route).map_err(dyn_err)?;
        let levels: Vec<(&str, Level<'_>)> = vec![
            ("app defaults", defaults.clone()),
            ("dynamic route", declared.level().map_err(dyn_err)?),
        ];
        let policy = resolve_levels(ctx, &levels, dr.method, true, false).map_err(dyn_err)?;
        let id = crate::contract::route_id(dr.method.as_str(), &dr.path);
        let rate = scopes.route_rate(&policy, &id, None);
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
            // Dynamic routes have no hooks: hooks are part of the generated dispatch.
            hooks: HookSet::default(),
            policy: policy.view(),
            annotations: Vec::new(),
            websocket: false,
            meta: Vec::new(),
        });
        docs.push(RouteDoc {
            name: dr.name.clone(),
            doc: String::new(),
            params: crate::router::canonicalise(&dr.path)
                .map(|(_, p)| p)
                .unwrap_or_default(),
            extractors: Vec::new(),
            responses: None,
        });
        let index = routes.len() as u32;
        let target = Target::Dynamic(dr.endpoint);
        routes.push(runtime(id, index, dr.method, dr.path, policy, target, rate));
    }

    let mut global_hooks = HookSet {
        before: hook_entries(app.before.iter().copied(), "global"),
        after: hook_entries(native_after.iter().copied(), "global"),
    };
    global_hooks
        .before
        .extend(hook_entries(native_before.iter().copied(), "global"));
    global_hooks
        .after
        .extend(hook_entries(app.after.iter().copied(), "global"));
    let manifest = Manifest {
        format_version: crate::contract::MANIFEST_FORMAT_VERSION,
        app: level.name.clone(),
        poring_version: env!("CARGO_PKG_VERSION").to_owned(),
        authenticator: level.has_authenticator.then(|| level.auth_type.clone()),
        cors: level.cors.as_ref().map(|c| crate::contract::CorsView {
            origins: c.origins.clone(),
            credentials: c.credentials,
            headers: c.headers.clone(),
            max_age_secs: c.max_age_secs,
        }),
        global_hooks,
        routes: entries,
    };
    Ok(Planned {
        routes,
        manifest,
        docs,
        native: native_rt,
        native_groups,
        native_hooks: native.hooks,
    })
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
    let Some(path) = std::env::var_os(DUMP_MANIFEST_ENV) else {
        return;
    };
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

#[cfg(feature = "openapi")]
pub(crate) fn static_contract<A: AppSpec>() -> Result<(Manifest, Vec<RouteDoc>), StartupError> {
    plan::<A>(
        &AppLevel::from_descriptor(&A::APP),
        NativeSet::default(),
        Vec::new(),
    )
    .map(|p| (p.manifest, p.docs))
}

/// Resolves an app's manifest without state, authenticator or network (used by
/// `Api::manifest()` and `cargo poring`). Dynamic routes are not included.
pub fn static_manifest<A: AppSpec>() -> Result<Manifest, StartupError> {
    plan::<A>(
        &AppLevel::from_descriptor(&A::APP),
        NativeSet::default(),
        Vec::new(),
    )
    .map(|p| p.manifest)
}
