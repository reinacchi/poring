//! Deterministic static flow graph derived from a [`Manifest`], plus the runtime trace
//! type used to overlay actually-traversed edges.
//!
//! Node IDs are `"<route-id>.<stage>"` for per-route nodes (for example
//! `get_users_id.auth`) and bare stage names for the shared nodes (`receive`, `match`,
//! `not_found`, `method_not_allowed`, `cors_preflight`, `send`). The runtime records
//! exactly the same IDs, so a runtime trace can be laid over the static graph.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::contract::manifest::{Manifest, RouteEntry, RouteKind};

/// Stage names shared by the static graph and the runtime flow recorder.
pub mod stage {
    /// Connection accepted / request parsed by hyper.
    pub const RECEIVE: &str = "receive";
    /// Router lookup.
    pub const MATCH: &str = "match";
    /// No route matched (404).
    pub const NOT_FOUND: &str = "not_found";
    /// Path matched but method did not (405).
    pub const METHOD_NOT_ALLOWED: &str = "method_not_allowed";
    /// CORS preflight answered by the framework.
    pub const CORS_PREFLIGHT: &str = "cors_preflight";
    /// Response handed to hyper.
    pub const SEND: &str = "send";
    /// Per-route CORS origin check.
    pub const CORS: &str = "cors";
    /// Rate-limit bucket check.
    pub const RATE_LIMIT: &str = "rate_limit";
    /// Authentication (trusted authenticator).
    pub const AUTH: &str = "auth";
    /// Scope/role authorisation.
    pub const AUTHZ: &str = "authz";
    /// CSRF protection for cookie-authenticated unsafe methods.
    pub const CSRF: &str = "csrf";
    /// Content-Length / Content-Type gate before the body is read.
    pub const BODY_GATE: &str = "body_gate";
    /// Before hook `before.<i>`.
    pub const BEFORE: &str = "before";
    /// Extractor `extract.<i>`.
    pub const EXTRACT: &str = "extract";
    /// Declarative validation of extractor `validate.<i>`.
    pub const VALIDATE: &str = "validate";
    /// User-declared annotation `annotation.<i>`.
    pub const ANNOTATION: &str = "annotation";
    /// The handler.
    pub const HANDLER: &str = "handler";
    /// Wasm guest dispatch (dynamic routes).
    pub const WASM: &str = "wasm";
    /// After hook `after.<i>`.
    pub const AFTER: &str = "after";
    /// Response mapping / serialisation.
    pub const RESPOND: &str = "respond";
    /// Before hook returned an early response.
    pub const SHORT_CIRCUIT: &str = "short_circuit";
    /// Extractor rejected the request (400/415/422...).
    pub const REJECT: &str = "reject";
    /// Handler returned `Err`.
    pub const ERROR: &str = "error";
    /// Security denial `deny.<status>`.
    pub const DENY: &str = "deny";
}

/// Kind of a graph node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// Shared entry/exit node.
    Edge,
    /// Router decision.
    Router,
    /// Security check.
    Security,
    /// Lifecycle hook.
    Hook,
    /// Typed extractor.
    Extract,
    /// Declarative validation.
    Validate,
    /// User-declared annotation.
    Annotation,
    /// Handler (native) or guest dispatch (Wasm).
    Handler,
    /// Response mapping.
    Respond,
    /// Denial / error / short-circuit terminal.
    Branch,
}

/// A node of the flow graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowNode {
    /// Stable node ID.
    pub id: String,
    /// Owning route ID, if per-route.
    pub route: Option<String>,
    /// Node kind.
    pub kind: NodeKind,
    /// Human-readable label (never contains secrets: built from declarations only).
    pub label: String,
}

/// Kind of a graph edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Normal forward progress.
    Next,
    /// Security denial branch.
    Deny,
    /// Error / rejection branch.
    Error,
    /// Early-response branch.
    ShortCircuit,
    /// A user-declared annotation attached to a node. Never observed at runtime: Poring
    /// does not infer operations inside handler bodies.
    Declared,
}

/// A directed edge (a *possible* transition).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowEdge {
    /// Source node ID.
    pub from: String,
    /// Target node ID.
    pub to: String,
    /// Edge kind.
    pub kind: EdgeKind,
    /// Optional label (e.g. a status code).
    pub label: Option<String>,
}

/// A deterministic static flow graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowGraph {
    /// Application name.
    pub app: String,
    /// Graph-level metadata (sorted key/value pairs).
    pub meta: Vec<(String, String)>,
    /// Nodes in deterministic order.
    pub nodes: Vec<FlowNode>,
    /// Edges in deterministic order.
    pub edges: Vec<FlowEdge>,
}

/// One recorded runtime step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    /// Node ID (same scheme as the static graph).
    pub node: String,
    /// Start offset from request start, microseconds.
    pub start_us: u64,
    /// Duration in microseconds (0 for instantaneous decisions).
    pub dur_us: u64,
}

/// The path one request actually took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeTrace {
    /// Correlation ID (from a validated `x-request-id` header or generated).
    pub request_id: String,
    /// Matched route ID, if any.
    pub route: Option<String>,
    /// Final HTTP status.
    pub status: u16,
    /// Total duration until the response was handed to hyper, microseconds.
    pub total_us: u64,
    /// Steps in execution order.
    pub steps: Vec<TraceStep>,
}

impl RuntimeTrace {
    /// The ordered list of node IDs visited.
    pub fn path(&self) -> Vec<&str> {
        self.steps.iter().map(|s| s.node.as_str()).collect()
    }
}

struct Builder {
    nodes: Vec<FlowNode>,
    edges: Vec<FlowEdge>,
    seen: BTreeSet<String>,
}

impl Builder {
    fn node(&mut self, id: String, route: Option<&str>, kind: NodeKind, label: String) -> String {
        if self.seen.insert(id.clone()) {
            self.nodes.push(FlowNode {
                id: id.clone(),
                route: route.map(str::to_owned),
                kind,
                label,
            });
        }
        id
    }

    fn edge(&mut self, from: &str, to: &str, kind: EdgeKind, label: Option<&str>) {
        let e = FlowEdge {
            from: from.to_owned(),
            to: to.to_owned(),
            kind,
            label: label.map(str::to_owned),
        };
        if !self.edges.contains(&e) {
            self.edges.push(e);
        }
    }
}

/// Builds the static flow graph for all routes, or for the single route matching
/// `route_filter` (`"METHOD /path"`, route ID or handler name).
///
/// Returns `None` if a filter is given and no route matches.
pub fn build_graph(manifest: &Manifest, route_filter: Option<&str>) -> Option<FlowGraph> {
    let routes: Vec<&RouteEntry> = match route_filter {
        Some(q) => vec![manifest.find(q)?],
        None => manifest.routes.iter().collect(),
    };
    let mut b = Builder {
        nodes: Vec::new(),
        edges: Vec::new(),
        seen: BTreeSet::new(),
    };
    let receive = b.node(
        stage::RECEIVE.into(),
        None,
        NodeKind::Edge,
        "receive".into(),
    );
    let matcher = b.node(
        stage::MATCH.into(),
        None,
        NodeKind::Router,
        "route match".into(),
    );
    let send = b.node(
        stage::SEND.into(),
        None,
        NodeKind::Edge,
        "send response".into(),
    );
    b.edge(&receive, &matcher, EdgeKind::Next, None);
    if route_filter.is_none() {
        let nf = b.node(
            stage::NOT_FOUND.into(),
            None,
            NodeKind::Branch,
            "404 Not Found".into(),
        );
        let mna = b.node(
            stage::METHOD_NOT_ALLOWED.into(),
            None,
            NodeKind::Branch,
            "405 Method Not Allowed (+Allow)".into(),
        );
        b.edge(&matcher, &nf, EdgeKind::Error, Some("404"));
        b.edge(&matcher, &mna, EdgeKind::Error, Some("405"));
        b.edge(&nf, &send, EdgeKind::Next, None);
        b.edge(&mna, &send, EdgeKind::Next, None);
        if manifest.cors.is_some() {
            let pf = b.node(
                stage::CORS_PREFLIGHT.into(),
                None,
                NodeKind::Branch,
                "CORS preflight (204)".into(),
            );
            b.edge(
                &matcher,
                &pf,
                EdgeKind::ShortCircuit,
                Some("OPTIONS preflight"),
            );
            b.edge(&pf, &send, EdgeKind::Next, None);
        }
    }

    for r in routes {
        add_route(&mut b, r, &matcher, &send);
    }

    let mut meta = vec![
        (
            "format_version".to_owned(),
            crate::contract::MANIFEST_FORMAT_VERSION.to_string(),
        ),
        ("poring_version".to_owned(), manifest.poring_version.clone()),
    ];
    if let Some(a) = &manifest.authenticator {
        meta.push(("authenticator".to_owned(), a.clone()));
    }
    meta.sort();
    Some(FlowGraph {
        app: manifest.app.clone(),
        meta,
        nodes: b.nodes,
        edges: b.edges,
    })
}

fn add_route(b: &mut Builder, r: &RouteEntry, matcher: &str, send: &str) {
    let rid = r.id.as_str();
    let id = |s: &str| format!("{rid}.{s}");
    let respond = b.node(
        id(stage::RESPOND),
        Some(rid),
        NodeKind::Respond,
        format!("{} {}: map response", r.method, r.path),
    );

    let deny = |b: &mut Builder, from: &str, status: &str, why: &str| {
        let d = b.node(
            format!("{rid}.{}.{status}", stage::DENY),
            Some(rid),
            NodeKind::Branch,
            format!("deny {status}"),
        );
        b.edge(from, &d, EdgeKind::Deny, Some(&format!("{status} {why}")));
        b.edge(&d, send, EdgeKind::Next, None);
    };

    let mut prev = matcher.to_owned();
    let mut first = true;
    let step = |b: &mut Builder, prev: &mut String, node: String, first: &mut bool| {
        let label = if *first {
            Some(format!("{} {}", r.method, r.path))
        } else {
            None
        };
        b.edge(prev, &node, EdgeKind::Next, label.as_deref());
        *first = false;
        *prev = node;
    };

    for check in &r.policy.checks {
        let (label, denials): (String, &[(&str, &str)]) = match check.as_str() {
            "cors" => ("CORS origin check".into(), &[("403", "origin not allowed")]),
            "rate_limit" => {
                let mut rl = match &r.policy.rate_limit {
                    Some(l) => {
                        let mut s =
                            format!("rate limit {}/{}ms by {}", l.requests, l.per_ms, l.key);
                        if let Some(owner) = &l.shared_by {
                            s.push_str(&format!(" (bucket shared by {owner})"));
                        }
                        s
                    }
                    None => "rate limit".into(),
                };
                if let Some(c) = &r.policy.rate_limit_ceiling {
                    rl.push_str(&format!(
                        " + app ceiling {}/{}ms by {}",
                        c.requests, c.per_ms, c.key
                    ));
                }
                (
                    rl,
                    &[("429", "too many requests"), ("503", "rate limiter full")],
                )
            }
            "auth" => (
                "authenticate (trusted authenticator)".into(),
                &[("401", "unauthenticated")],
            ),
            "authz" => {
                let mut l = String::from("authorise");
                if !r.policy.scopes.is_empty() {
                    l.push_str(&format!(" scopes={:?}", r.policy.scopes));
                }
                if !r.policy.roles.is_empty() {
                    l.push_str(&format!(" roles={:?}", r.policy.roles));
                }
                (l, &[("403", "forbidden")])
            }
            "csrf" => (
                "CSRF check (cookie auth, unsafe method)".into(),
                &[("403", "csrf")],
            ),
            "body_gate" => (
                format!(
                    "body gate <= {} bytes{}",
                    r.policy.body_limit,
                    if r.policy.content_types.is_empty() {
                        String::new()
                    } else {
                        format!(", types={:?}", r.policy.content_types)
                    }
                ),
                &[
                    ("413", "payload too large"),
                    ("415", "unsupported media type"),
                ],
            ),
            _ => continue,
        };
        let n = b.node(id(check), Some(rid), NodeKind::Security, label);
        step(b, &mut prev, n.clone(), &mut first);
        for (status, why) in denials {
            deny(b, &n, status, why);
        }
    }

    let after_entry = if r.hooks.after.is_empty() {
        respond.clone()
    } else {
        id(&format!("{}.0", stage::AFTER))
    };

    if !r.hooks.before.is_empty() {
        let sc = b.node(
            id(stage::SHORT_CIRCUIT),
            Some(rid),
            NodeKind::Branch,
            "early response from hook".into(),
        );
        for (i, h) in r.hooks.before.iter().enumerate() {
            let n = b.node(
                id(&format!("{}.{i}", stage::BEFORE)),
                Some(rid),
                NodeKind::Hook,
                format!("before[{}] {}", h.scope, h.name),
            );
            step(b, &mut prev, n.clone(), &mut first);
            b.edge(&n, &sc, EdgeKind::ShortCircuit, Some("Err/early return"));
        }
        // An early response still flows through after hooks.
        b.edge(&sc, &after_entry, EdgeKind::Next, None);
    }

    let has_reject = !r.extractors.is_empty();
    let reject = if has_reject {
        let n = b.node(
            id(stage::REJECT),
            Some(rid),
            NodeKind::Branch,
            "extractor rejection (4xx)".into(),
        );
        b.edge(&n, &after_entry, EdgeKind::Next, None);
        Some(n)
    } else {
        None
    };
    for (i, ex) in r.extractors.iter().enumerate() {
        let n = b.node(
            id(&format!("{}.{i}", stage::EXTRACT)),
            Some(rid),
            NodeKind::Extract,
            format!("extract {} ({})", ex.ty, ex.kind),
        );
        step(b, &mut prev, n.clone(), &mut first);
        if let Some(rej) = &reject {
            b.edge(&n, rej, EdgeKind::Error, Some("reject"));
        }
        if ex.validates {
            let v = b.node(
                id(&format!("{}.{i}", stage::VALIDATE)),
                Some(rid),
                NodeKind::Validate,
                format!("validate {}", ex.ty),
            );
            step(b, &mut prev, v.clone(), &mut first);
            if let Some(rej) = &reject {
                b.edge(&v, rej, EdgeKind::Error, Some("422 invalid"));
            }
        }
    }

    let handler = if r.kind == RouteKind::Dynamic {
        let ver = r
            .meta
            .iter()
            .find(|(k, _)| k == "guest_version")
            .map(|(_, v)| v.as_str())
            .unwrap_or("?");
        b.node(
            id(stage::WASM),
            Some(rid),
            NodeKind::Handler,
            format!("wasm guest {} (version {ver})", r.handler),
        )
    } else {
        b.node(
            id(stage::HANDLER),
            Some(rid),
            NodeKind::Handler,
            format!("handler {}", r.handler),
        )
    };
    step(b, &mut prev, handler.clone(), &mut first);
    for (i, a) in r.annotations.iter().enumerate() {
        let n = b.node(
            id(&format!("{}.{i}", stage::ANNOTATION)),
            Some(rid),
            NodeKind::Annotation,
            format!("declared: {a}"),
        );
        b.edge(&handler, &n, EdgeKind::Declared, Some("declares"));
    }
    if r.policy.timeout_ms.is_some() {
        deny(b, &handler, "503", "timeout");
    }
    let err = b.node(
        id(stage::ERROR),
        Some(rid),
        NodeKind::Branch,
        "handler error -> IntoResponse".into(),
    );
    b.edge(&handler, &err, EdgeKind::Error, Some("Err"));
    b.edge(&err, &after_entry, EdgeKind::Next, None);

    for (i, h) in r.hooks.after.iter().enumerate() {
        let n = b.node(
            id(&format!("{}.{i}", stage::AFTER)),
            Some(rid),
            NodeKind::Hook,
            format!("after[{}] {}", h.scope, h.name),
        );
        step(b, &mut prev, n, &mut first);
    }
    step(b, &mut prev, respond.clone(), &mut first);
    b.edge(&respond, send, EdgeKind::Next, None);
}
