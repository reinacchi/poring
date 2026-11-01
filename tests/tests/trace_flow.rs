//! Static graph determinism, runtime traces aligned with static node IDs,
//! redaction, bounded recording, and the tracing span.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use poring::contract::{RuntimeTrace, build_graph, render_dot, render_json, render_mermaid, render_mermaid_with_trace};
use poring::flow::FlowConfig;
use poring_tests::secure::{NewNote, SecureApp, SecureState, TableAuth};

use poring_tests::snapshot;

fn recording_app(capacity: usize) -> poring::App<SecureApp> {
    SecureApp::builder()
        .state(SecureState::default())
        .authenticator(TableAuth::fixture())
        .flow_recording(FlowConfig { sample_every: 1, capacity })
        .build()
        .unwrap()
}

/// Every consecutive pair of runtime steps must be an edge of the static graph.
fn assert_trace_follows_graph(t: &RuntimeTrace) {
    let m = SecureApp::manifest().unwrap();
    let g = build_graph(&m, None).unwrap();
    let edges: BTreeSet<(String, String)> = g.edges.iter().map(|e| (e.from.clone(), e.to.clone())).collect();
    let nodes: BTreeSet<&str> = g.nodes.iter().map(|n| n.id.as_str()).collect();
    for s in &t.steps {
        assert!(nodes.contains(s.node.as_str()), "runtime node {} not in static graph", s.node);
    }
    for w in t.path().windows(2) {
        assert!(
            edges.contains(&(w[0].to_owned(), w[1].to_owned())),
            "runtime transition {} -> {} not in static graph",
            w[0],
            w[1]
        );
    }
}

#[test]
fn static_graphs_are_deterministic_snapshots() {
    let m = SecureApp::manifest().unwrap();
    let a = build_graph(&m, Some("POST /notes")).unwrap();
    let b = build_graph(&SecureApp::manifest().unwrap(), Some("post_notes")).unwrap();
    assert_eq!(a, b, "lookup by route and by id yields the same deterministic graph");
    snapshot("post_notes.mmd", &render_mermaid(&a));
    snapshot("post_notes.dot", &render_dot(&a));
    snapshot("post_notes.json", &render_json(&a));
    snapshot("secure.manifest.json", &(serde_json::to_string_pretty(&m).unwrap() + "\n"));
    let full = build_graph(&m, None).unwrap();
    // Security denials and error branches are graph-visible.
    for id in [
        "post_notes.deny.401",
        "post_notes.deny.403",
        "post_notes.deny.413",
        "post_notes.deny.415",
        "post_notes.deny.429",
        "post_notes.deny.503",
        "post_notes.reject",
        "post_notes.error",
        "not_found",
        "method_not_allowed",
        "cors_preflight",
    ] {
        assert!(full.nodes.iter().any(|n| n.id == id), "missing node {id}");
    }
}

#[tokio::test]
async fn runtime_paths_match_static_graph() {
    let app = recording_app(64);
    let c = app.client();
    c.post("/notes").bearer("writer-token").json(&NewNote { text: "secret note body".into() }).send().await;
    c.get("/notes").send().await; // 401
    c.post("/notes").bearer("reader-token").json(&NewNote { text: "x".into() }).send().await; // 403
    c.post("/notes").bearer("writer-token").json(&serde_json::json!({"text": ""})).send().await; // 422
    c.get("/nope").send().await; // 404
    c.get("/slow").bearer("reader-token").send().await; // 503
    c.get("/health").send().await;
    let traces = app.flow().recent();
    assert_eq!(traces.len(), 7);
    for t in &traces {
        assert_trace_follows_graph(t);
    }
    let paths: Vec<Vec<&str>> = traces.iter().map(|t| t.path()).collect();
    assert_eq!(
        paths[0],
        [
            "receive",
            "match",
            "post_notes.cors",
            "post_notes.auth",
            "post_notes.authz",
            "post_notes.rate_limit",
            "post_notes.csrf",
            "post_notes.body_gate",
            "post_notes.before.0",
            "post_notes.extract.0",
            "post_notes.extract.1",
            "post_notes.extract.2",
            "post_notes.validate.2",
            "post_notes.handler",
            "post_notes.respond",
            "send"
        ]
    );
    assert_eq!(traces[0].status, 201);
    assert_eq!(paths[1], ["receive", "match", "get_notes.cors", "get_notes.auth", "get_notes.deny.401", "send"]);
    assert_eq!(paths[2].last_chunk::<2>().unwrap(), &["post_notes.deny.403", "send"]);
    assert!(paths[3].ends_with(&["post_notes.validate.2", "post_notes.reject", "post_notes.respond", "send"]));
    assert_eq!(traces[3].status, 422);
    assert_eq!(paths[4], ["receive", "match", "not_found", "send"]);
    assert!(paths[5].ends_with(&["get_slow.handler", "get_slow.deny.503", "send"]));
    assert!(traces.iter().all(|t| t.steps.windows(2).all(|w| w[0].start_us <= w[1].start_us)), "monotonic timings");
}

#[tokio::test]
async fn traces_never_contain_credentials_or_bodies() {
    let app = recording_app(64);
    let c = app.client();
    c.post("/notes")
        .header("cookie", "sid=session-bob; poring-csrf=0123456789abcdef0123")
        .header("x-csrf-token", "0123456789abcdef0123")
        .json(&NewNote { text: "TOP-SECRET-BODY".into() })
        .send()
        .await;
    c.get("/notes?q=private-query").bearer("writer-token").send().await;
    let dump = serde_json::to_string(&app.flow().recent()).unwrap();
    for secret in [
        "writer-token",
        "session-bob",
        "0123456789abcdef0123",
        "TOP-SECRET-BODY",
        "private-query",
        "authorization",
        "cookie",
    ] {
        assert!(!dump.contains(secret), "trace leaked `{secret}`: {dump}");
    }
}

#[tokio::test]
async fn recording_is_bounded_and_sampling_works() {
    let app = recording_app(4);
    for _ in 0..10 {
        app.client().get("/health").send().await;
    }
    assert_eq!(app.flow().recent().len(), 4);
    let s = app.flow().stats();
    assert_eq!(s.recorded, 10);
    assert_eq!(s.dropped, 6, "oldest traces are evicted and counted");

    let sampled = SecureApp::builder()
        .state(SecureState::default())
        .authenticator(TableAuth::fixture())
        .flow_recording(FlowConfig { sample_every: 5, capacity: 100 })
        .build()
        .unwrap();
    for _ in 0..20 {
        sampled.client().get("/health").send().await;
    }
    assert_eq!(sampled.flow().recent().len(), 4, "1 in 5 sampled");

    let off = SecureApp::builder().state(SecureState::default()).authenticator(TableAuth::fixture()).build().unwrap();
    off.client().get("/health").send().await;
    assert!(off.flow().recent().is_empty(), "recording is off by default");
}

#[tokio::test]
async fn overlay_highlights_traversed_edges_only() {
    let app = recording_app(8);
    app.client().get("/notes").send().await; // 401 path
    let t = app.flow().recent().pop().unwrap();
    let g = build_graph(&SecureApp::manifest().unwrap(), Some("GET /notes")).unwrap();
    let mmd = render_mermaid_with_trace(&g, &t);
    let highlighted = mmd.lines().filter(|l| l.trim_start().starts_with("linkStyle")).count();
    assert_eq!(highlighted, t.steps.len() - 1, "{mmd}");
    assert!(mmd.contains("get_notes_deny_401"));
    std::fs::write(std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("get_notes_401.mmd"), mmd).unwrap();
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);
impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().push(String::from_utf8_lossy(b).into_owned());
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn tracing_events_use_graph_node_ids_without_secrets() {
    let cap = Capture::default();
    let w = cap.clone();
    let sub = tracing_subscriber::fmt()
        .with_env_filter("poring::flow=trace")
        .with_writer(move || w.clone())
        .with_ansi(false)
        .finish();
    let _g = tracing::subscriber::set_default(sub);
    let app = recording_app(8);
    app.client().get("/notes").bearer("reader-token").send().await;
    let out = cap.0.lock().unwrap().concat();
    assert!(out.contains("node=get_notes.auth"), "{out}");
    assert!(out.contains("node=get_notes.handler"), "{out}");
    assert!(!out.contains("reader-token"));
}
