//! Runtime enforcement of compile-time-declared policies (penetration-oriented).

use std::time::Duration;

use poring_tests::secure::{Events, NewNote, Note, SecureApp, SecureState, TableAuth};

fn app_with(auth: TableAuth) -> (poring::App<SecureApp>, Events) {
    let events = Events::default();
    let app = SecureApp::builder()
        .state(SecureState { events: events.clone(), ..Default::default() })
        .authenticator(auth)
        .build()
        .unwrap();
    (app, events)
}

fn app() -> (poring::App<SecureApp>, Events) {
    app_with(TableAuth::fixture())
}

fn hook_count(e: &Events) -> usize {
    e.0.lock().unwrap().len()
}

#[tokio::test]
async fn unauthenticated_requests_are_rejected_except_on_public_routes() {
    let (app, events) = app();
    let c = app.client();
    assert_eq!(c.get("/health").send().await.text(), "ok", "documented public exception");
    let r = c.get("/notes").send().await;
    assert_eq!(r.status, 401);
    assert_eq!(r.header("www-authenticate"), Some("Bearer"));
    assert_eq!(c.get("/notes").bearer("forged").send().await.status, 401);
    assert_eq!(c.get("/notes").header("authorization", "Basic Zm9vOmJhcg==").send().await.status, 401);
    assert_eq!(c.get("/notes").bearer("reader-token").send().await.status, 200);
    // Only the two successful requests ran user hooks; denials never reach user code.
    assert_eq!(hook_count(&events), 2);
}

#[tokio::test]
async fn missing_scopes_or_roles_are_forbidden() {
    let (app, events) = app();
    let c = app.client();
    let r = c.post("/notes").bearer("reader-token").json(&NewNote { text: "hi".into() }).send().await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json::<serde_json::Value>()["error"]["code"], "insufficient_scope");
    assert_eq!(c.get("/admin/stats").bearer("writer-token").send().await.status, 403, "group role required");
    assert_eq!(c.get("/admin/stats").bearer("admin-token").send().await.text(), "0");
    assert_eq!(hook_count(&events), 1);
}

#[tokio::test]
async fn principal_reaches_handler() {
    let (app, _) = app();
    let c = app.client();
    let r = c.post("/notes").bearer("writer-token").json(&NewNote { text: "hello".into() }).send().await;
    assert_eq!(r.status, 201);
    assert_eq!(r.json::<Note>().owner, "bob");
    assert_eq!(c.get("/me").bearer("admin-token").send().await.text(), "root");
}

#[tokio::test]
async fn csrf_enforced_for_cookie_sessions_only() {
    let (app, _) = app();
    let c = app.client();
    let body = serde_json::json!({"text": "via cookie"});
    let r = c.post("/notes").header("cookie", "sid=session-bob").json(&body).send().await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json::<serde_json::Value>()["error"]["code"], "csrf");
    let r = c
        .post("/notes")
        .header("cookie", "sid=session-bob; poring-csrf=0123456789abcdef0123")
        .header("x-csrf-token", "0123456789abcdef9999")
        .json(&body)
        .send()
        .await;
    assert_eq!(r.status, 403, "mismatched token");
    // Both denied attempts consumed bob's principal-keyed budget (2/s): rate limiting runs
    // before CSRF, so failed attempts count. A third attempt now is rate limited.
    let r = c.post("/notes").header("cookie", "sid=session-bob").json(&body).send().await;
    assert_eq!(r.status, 429);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = c
        .post("/notes")
        .header("cookie", "sid=session-bob; poring-csrf=0123456789abcdef0123")
        .header("x-csrf-token", "0123456789abcdef0123")
        .json(&body)
        .send()
        .await;
    assert_eq!(r.status, 201);
    // Safe methods with cookie auth need no token; bearer auth is not CSRF-relevant.
    assert_eq!(c.get("/notes").header("cookie", "sid=session-bob").send().await.status, 200);
    assert_eq!(c.post("/notes").bearer("writer-token").json(&body).send().await.status, 201);
}

#[tokio::test]
async fn body_size_and_content_type_are_checked_before_reading() {
    let (app, events) = app();
    let c = app.client();
    let r = c
        .post("/notes")
        .bearer("writer-token")
        .header("content-type", "application/json")
        .body(format!("{{\"text\":\"{}\"}}", "a".repeat(2000)))
        .send()
        .await;
    assert_eq!(r.status, 413);
    let r = c.post("/notes").bearer("writer-token").header("content-type", "text/plain").body("hi").send().await;
    assert_eq!(r.status, 415);
    // The webhook's own 256 B limit narrows the app's 64 KiB default.
    let r = c.post("/webhook").body(vec![b'x'; 300]).send().await;
    assert_eq!(r.status, 413);
    assert_eq!(c.post("/webhook").body(vec![b'x'; 10]).send().await.text(), "got 10 bytes");
    assert_eq!(hook_count(&events), 1, "only the accepted webhook ran hooks");
}

#[tokio::test]
async fn rate_limits_apply_per_principal_and_per_ip() {
    let (app, _) = app();
    let c = app.client();
    let n = || NewNote { text: "x".into() };
    assert_eq!(c.post("/notes").bearer("writer-token").json(&n()).send().await.status, 201);
    assert_eq!(c.post("/notes").bearer("writer-token").json(&n()).send().await.status, 201);
    let r = c.post("/notes").bearer("writer-token").json(&n()).send().await;
    assert_eq!(r.status, 429);
    assert!(r.header("retry-after").is_some());
    // A different principal has its own bucket.
    assert_eq!(c.post("/notes").bearer("admin-token").json(&n()).send().await.status, 201);
    // IP-keyed limit on /me: 3/s from one address, independent per address.
    let a: std::net::SocketAddr = "10.0.0.1:1000".parse().unwrap();
    let b: std::net::SocketAddr = "10.0.0.2:1000".parse().unwrap();
    for _ in 0..3 {
        assert_eq!(c.get("/me").bearer("reader-token").peer(a).send().await.status, 200);
    }
    assert_eq!(c.get("/me").bearer("reader-token").peer(a).send().await.status, 429);
    assert_eq!(c.get("/me").bearer("reader-token").peer(b).send().await.status, 200);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(c.get("/me").bearer("reader-token").peer(a).send().await.status, 200, "bucket refills");
}

#[tokio::test]
async fn handler_is_cancelled_at_its_timeout() {
    let (app, _) = app();
    let started = std::time::Instant::now();
    let r = app.client().get("/slow").bearer("reader-token").send().await;
    assert_eq!(r.status, 503);
    assert_eq!(r.json::<serde_json::Value>()["error"]["code"], "timeout");
    assert!(started.elapsed() < Duration::from_secs(2), "handler was cancelled at the deadline");
}

#[tokio::test]
async fn authenticator_outage_is_reported_as_unavailable() {
    let (app, _) = app_with(TableAuth { fail: true, ..TableAuth::fixture() });
    assert_eq!(app.client().get("/notes").bearer("reader-token").send().await.status, 503);
}

#[tokio::test]
async fn cors_preflight_and_cross_site_writes() {
    let (app, _) = app();
    let c = app.client();
    let r = c
        .options("/notes")
        .header("origin", "https://app.example")
        .header("access-control-request-method", "POST")
        .send()
        .await;
    assert_eq!(r.status, 204);
    assert_eq!(r.header("access-control-allow-origin"), Some("https://app.example"));
    assert_eq!(r.header("access-control-allow-credentials"), Some("true"));
    assert!(r.header("access-control-allow-methods").unwrap().contains("POST"));
    let r = c
        .options("/notes")
        .header("origin", "https://evil.example")
        .header("access-control-request-method", "POST")
        .send()
        .await;
    assert_eq!(r.status, 403);
    // Cross-site unsafe request from a disallowed origin is denied before auth.
    let r = c
        .post("/notes")
        .header("origin", "https://evil.example")
        .bearer("writer-token")
        .json(&NewNote { text: "x".into() })
        .send()
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json::<serde_json::Value>()["error"]["code"], "cors_origin_denied");
    // Allowed origin gets CORS headers on the real response.
    let r = c.get("/notes").header("origin", "https://app.example").bearer("reader-token").send().await;
    assert_eq!(r.header("access-control-allow-origin"), Some("https://app.example"));
    assert_eq!(r.header("vary"), Some("origin"));
    // Disallowed origin, safe method: no CORS headers (the browser blocks reading).
    let r = c.get("/notes").header("origin", "https://evil.example").bearer("reader-token").send().await;
    assert_eq!(r.status, 200);
    assert!(r.header("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn effective_policies_in_manifest() {
    let m = SecureApp::manifest().unwrap();
    let health = m.find("GET /health").unwrap();
    assert_eq!(health.policy.auth, "public");
    assert_eq!(health.policy.public_reason.as_deref(), Some("load balancer liveness probe"));
    let create = m.find("POST /notes").unwrap();
    assert_eq!(create.policy.checks, ["cors", "auth", "authz", "rate_limit", "csrf", "body_gate"]);
    assert_eq!(create.policy.body_limit, 1024);
    assert_eq!(create.policy.csrf, "enforced");
    let stats = m.find("GET /admin/stats").unwrap();
    assert_eq!(stats.policy.roles, ["admin"]);
    assert!(stats.policy.provenance.iter().any(|p| p == "role `admin` <- group `/admin`"));
    let hook = m.find("POST /webhook").unwrap();
    assert_eq!(hook.policy.csrf, "exempt");
    assert_eq!(hook.policy.body_limit, 256);
    let md = poring::contract::audit_markdown(&m);
    assert!(md.contains("| `GET /health` | static | public |"));
}

mod dynamic_routes {
    use super::*;
    use poring::IntoResponse;
    use poring::descriptor::Method;
    use poring::dynamic::{BoxFuture, DynEndpoint, DynPolicy, DynRequest, DynamicRoute};
    use std::sync::{Arc, Mutex};

    /// Records what the (untrusted) endpoint was allowed to see.
    #[derive(Default)]
    struct Spy(Mutex<Vec<String>>);
    impl DynEndpoint for Spy {
        fn call(&self, req: DynRequest) -> BoxFuture<'static, poring::Response> {
            let saw_auth = req.headers.contains_key("authorization") || req.headers.contains_key("cookie");
            let who = req.identity.as_ref().map(|i| i.subject.clone()).unwrap_or_default();
            self.0.lock().unwrap().push(format!(
                "{who}:{saw_auth}:{}",
                req.params.iter().map(|(k, v)| format!("{k}={v}")).collect::<String>()
            ));
            Box::pin(async move { format!("dynamic for {who}").into_response() })
        }
        fn metadata(&self) -> Vec<(String, String)> {
            vec![("guest_version".into(), "7".into())]
        }
    }

    fn route(path: &str, policy: DynPolicy, ep: Arc<dyn DynEndpoint>) -> DynamicRoute {
        DynamicRoute { method: Method::Post, path: path.into(), name: "spy".into(), policy, endpoint: ep }
    }

    fn build(r: DynamicRoute) -> Result<poring::App<SecureApp>, poring::StartupError> {
        SecureApp::builder().state(SecureState::default()).authenticator(TableAuth::fixture()).mount_dynamic(r).build()
    }

    #[tokio::test]
    async fn dynamic_routes_get_the_same_enforcement() {
        let spy = Arc::new(Spy::default());
        let policy = DynPolicy { scopes: vec!["notes:write".into()], body_limit: Some(64), ..Default::default() };
        let app = build(route("/plugins/{name}", policy, spy.clone())).unwrap();
        let c = app.client();
        assert_eq!(c.post("/plugins/x").send().await.status, 401);
        assert_eq!(c.post("/plugins/x").bearer("reader-token").send().await.status, 403);
        assert_eq!(c.post("/plugins/x").bearer("writer-token").body(vec![0u8; 100]).send().await.status, 413);
        let r = c.post("/plugins/a%20b").bearer("writer-token").body("hi").send().await;
        assert_eq!(r.text(), "dynamic for bob");
        // The guest saw the identity but never the raw credential headers.
        assert_eq!(spy.0.lock().unwrap().as_slice(), ["bob:false:name=a b"]);
        let m = app.manifest();
        let e = m.find("POST /plugins/{name}").unwrap();
        assert_eq!(e.kind, poring::contract::RouteKind::Dynamic);
        assert_eq!(e.meta, [("guest_version".to_owned(), "7".to_owned())]);
        assert_eq!(e.policy.checks, ["cors", "auth", "authz", "csrf", "body_gate"]);
    }

    #[test]
    fn dynamic_policy_violations_fail_at_startup() {
        let ep: Arc<dyn DynEndpoint> = Arc::new(Spy::default());
        let public = DynPolicy { auth_required: Some(false), ..Default::default() };
        let e = build(route("/open", public, ep.clone())).unwrap_err().to_string();
        assert!(e.contains("strict deny_anonymous"), "{e}");
        let raise = DynPolicy { body_limit: Some(10 << 20), ..Default::default() };
        let e = build(route("/big", raise, ep.clone())).unwrap_err().to_string();
        assert!(e.contains("narrowed"), "{e}");
        let e = build(route("/bad/{*x}/y", DynPolicy::default(), ep.clone())).unwrap_err().to_string();
        assert!(e.contains("catch-all"), "{e}");
        let e = build(DynamicRoute { method: Method::Post, ..route("/notes", DynPolicy::default(), ep.clone()) })
            .unwrap_err()
            .to_string();
        assert!(e.contains("registered twice"), "{e}");
        let ok = DynPolicy {
            auth_required: Some(false),
            public_reason: Some("signed payloads".into()),
            ..Default::default()
        };
        assert!(build(route("/open", ok, ep)).is_ok());
    }
}
