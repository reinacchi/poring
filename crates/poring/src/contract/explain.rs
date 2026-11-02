//! Policy explanation and audit export.

use std::fmt::Write as _;

use crate::contract::graph::build_graph;
use crate::contract::manifest::{Manifest, RouteKind};

/// Explains the effective policy, checks, exceptions and graph nodes of one route.
///
/// `query` is `"METHOD /path"`, a route ID or a handler name.
pub fn explain(manifest: &Manifest, query: &str) -> Option<String> {
    let r = manifest.find(query)?;
    let p = &r.policy;
    let mut o = String::new();
    let _ = writeln!(o, "# {} {}", r.method, r.path);
    let _ = writeln!(o);
    let _ = writeln!(o, "- route id: `{}`", r.id);
    let _ = writeln!(
        o,
        "- kind: {}",
        match r.kind {
            RouteKind::Static => "static (declaration verified at compile time by poring_app!)",
            RouteKind::Dynamic =>
                "dynamic (validated at startup/reload only; NOT compile-time verified)",
            RouteKind::Native =>
                "native (types checked at compile time; path and policy validated at startup)",
        }
    );
    let _ = writeln!(
        o,
        "- handler: `{}` ({}:{})",
        r.handler, r.source.file, r.source.line
    );
    if let Some(g) = &r.group {
        let _ = writeln!(o, "- group/plugin: `{g}`");
    }
    for (k, v) in &r.meta {
        let _ = writeln!(o, "- {k}: {v}");
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "## Effective policy");
    let _ = writeln!(o);
    let auth = if p.auth == "public" {
        match (&p.public_reason, p.implicit_public) {
            (Some(reason), _) => format!("public (explicit exception: {reason})"),
            (None, true) => "public (implicit: the app declares no authenticator)".to_owned(),
            (None, false) => "public".to_owned(),
        }
    } else {
        "required".to_owned()
    };
    let _ = writeln!(o, "| setting | value |\n|---|---|");
    let _ = writeln!(o, "| auth | {auth} |");
    let _ = writeln!(o, "| scopes (all required) | {} |", list(&p.scopes));
    let _ = writeln!(o, "| roles (all required) | {} |", list(&p.roles));
    let _ = writeln!(o, "| body limit | {} bytes |", p.body_limit);
    let _ = writeln!(o, "| content types | {} |", list(&p.content_types));
    let csrf = match &p.csrf_exempt_reason {
        Some(r) => format!("{} ({r})", p.csrf),
        None => p.csrf.clone(),
    };
    let _ = writeln!(o, "| csrf | {csrf} |");
    let _ = writeln!(
        o,
        "| timeout | {} |",
        p.timeout_ms
            .map(|t| format!("{t} ms"))
            .unwrap_or_else(|| "none".into())
    );
    let _ = writeln!(
        o,
        "| rate limit | {} |",
        p.rate_limit
            .as_ref()
            .map(|r| {
                let shared = r
                    .shared_by
                    .as_deref()
                    .map(|o| format!(", shared by {o}"))
                    .unwrap_or_default();
                format!(
                    "{} per {} ms by {} ({} bucket{shared})",
                    r.requests, r.per_ms, r.key, r.scope
                )
            })
            .unwrap_or_else(|| "none".into())
    );
    if let Some(c) = &p.rate_limit_ceiling {
        let _ = writeln!(
            o,
            "| rate limit ceiling | {} per {} ms by {} (app bucket, enforced in addition) |",
            c.requests, c.per_ms, c.key
        );
    }
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "## Provenance (merge order: app -> group/plugin -> route)"
    );
    let _ = writeln!(o);
    for line in &p.provenance {
        let _ = writeln!(o, "- {line}");
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "## Runtime checks (in order)");
    let _ = writeln!(o);
    if p.checks.is_empty() {
        let _ = writeln!(o, "- (none)");
    }
    for (i, c) in p.checks.iter().enumerate() {
        let _ = writeln!(o, "{}. `{}.{c}`", i + 1, r.id);
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "## Hooks and extractors");
    let _ = writeln!(o);
    for h in &r.hooks.before {
        let _ = writeln!(o, "- before ({}): `{}`", h.scope, h.name);
    }
    for e in &r.extractors {
        let _ = writeln!(
            o,
            "- extract `{}` ({}{}{})",
            e.ty,
            e.kind,
            if e.consumes_body { ", reads body" } else { "" },
            if e.validates { ", validates" } else { "" }
        );
    }
    for h in &r.hooks.after {
        let _ = writeln!(o, "- after ({}): `{}`", h.scope, h.name);
    }
    if let Some(g) = build_graph(manifest, Some(query)) {
        let _ = writeln!(o);
        let _ = writeln!(o, "## Graph nodes");
        let _ = writeln!(o);
        for n in g
            .nodes
            .iter()
            .filter(|n| n.route.as_deref() == Some(r.id.as_str()))
        {
            let _ = writeln!(o, "- `{}`: {}", n.id, n.label);
        }
    }
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "> Compile-time checks verify that these declarations are consistent and wired to the \
         runtime enforcement path. They do not prove the handler body itself is secure."
    );
    Some(o)
}

fn list(v: &[String]) -> String {
    if v.is_empty() {
        "-".to_owned()
    } else {
        v.iter()
            .map(|s| format!("`{s}`"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Produces a Markdown audit table of every route and its effective policy.
pub fn audit_markdown(manifest: &Manifest) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "# Security audit: {}", manifest.app);
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "authenticator: {}  ",
        manifest.authenticator.as_deref().unwrap_or("(none)")
    );
    if let Some(c) = &manifest.cors {
        let _ = writeln!(
            o,
            "cors: origins={:?} credentials={}  ",
            c.origins, c.credentials
        );
    }
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "| route | kind | auth | scopes | roles | body limit | csrf | rate limit | timeout | exception |"
    );
    let _ = writeln!(o, "|---|---|---|---|---|---|---|---|---|---|");
    for r in &manifest.routes {
        let p = &r.policy;
        let _ = writeln!(
            o,
            "| `{} {}` | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            r.method,
            r.path,
            match r.kind {
                RouteKind::Static => "static",
                RouteKind::Dynamic => "dynamic",
                RouteKind::Native => "native",
            },
            p.auth,
            list(&p.scopes),
            list(&p.roles),
            p.body_limit,
            p.csrf,
            p.rate_limit
                .as_ref()
                .map(|r| format!("{}/{}ms {}", r.requests, r.per_ms, r.key))
                .unwrap_or_else(|| "-".into()),
            p.timeout_ms
                .map(|t| format!("{t}ms"))
                .unwrap_or_else(|| "-".into()),
            p.public_reason
                .as_deref()
                .or(p.csrf_exempt_reason.as_deref())
                .unwrap_or(if p.implicit_public {
                    "implicit public (no authenticator)"
                } else {
                    "-"
                })
        );
    }
    o
}
