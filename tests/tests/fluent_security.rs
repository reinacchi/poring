//! Fluent routes go through the same policy resolution and runtime enforcement as macro
//! routes, and configurations the macros reject at compile time are rejected by `build()`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use poring::policy::RateKey;
use poring::prelude::*;
use poring_tests::secure::{NewNote, TableAuth};

type SecureFluent = poring::FluentApp<Arc<AtomicUsize>, TableAuth>;

/// A strict app: everything requires authentication unless documented as public.
fn secure() -> (SecureFluent, Arc<AtomicUsize>) {
    let hooks = Arc::new(AtomicUsize::new(0));
    let app = Poring::with_state(hooks.clone())
        .authenticator(TableAuth::fixture())
        .policy(Policy::new().deny_anonymous().body_limit(1024))
        .cors(Cors::new().origins(["https://app.example"]).credentials(true))
        .before(|cx: &mut Ctx<'_, Arc<AtomicUsize>>| {
            cx.state().fetch_add(1, Ordering::SeqCst);
        })
        .route_with(RouteMethod::Get, "/health", Policy::new().public_with_reason("probe"), || async { "ok" })
        .get("/me", |Principal(who): Principal<Authenticated>| async move { who.subject.clone() })
        .group("/notes", |g| {
            g.policy(Policy::new().scopes(["notes:read"]))
                .get("/", || async { "[]" })
                .route_with(
                    RouteMethod::Post,
                    "/",
                    Policy::new().scopes(["notes:write"]).content_types(["application/json"]).rate_limit(
                        2,
                        Duration::from_secs(60),
                        RateKey::Principal,
                    ),
                    |Json(n): Json<NewNote>| async move { (StatusCode::CREATED, n.text) },
                )
                .route_with(RouteMethod::Post, "/webhook", Policy::new().csrf_exempt("HMAC-signed webhook"), || async {
                    "accepted"
                })
        })
        .group("/admin", |g| g.policy(Policy::new().roles(["admin"])).get("/stats", || async { "0" }))
        .route_with(RouteMethod::Get, "/slow", Policy::new().timeout(Duration::from_millis(50)), || async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            "too late"
        })
        .build()
        .unwrap();
    (app, hooks)
}

#[tokio::test]
async fn authentication_and_public_exceptions() {
    let (app, hooks) = secure();
    let c = app.client();
    assert_eq!(c.get("/health").send().await.text(), "ok");
    let r = c.get("/me").send().await;
    assert_eq!(r.status, 401);
    assert_eq!(r.header("www-authenticate"), Some("Bearer"));
    assert_eq!(c.get("/me").bearer("forged").send().await.status, 401);
    assert_eq!(c.get("/me").bearer("reader-token").send().await.text(), "alice");
    assert_eq!(hooks.load(Ordering::SeqCst), 2, "denied requests never reach hooks");
}

#[tokio::test]
async fn scopes_roles_and_principals_cannot_be_bypassed() {
    let (app, _) = secure();
    let c = app.client();
    assert_eq!(c.get("/notes").bearer("reader-token").send().await.text(), "[]");
    let r = c.post("/notes").bearer("reader-token").json(&NewNote { text: "x".into() }).send().await;
    assert_eq!(r.status, 403);
    assert_eq!(r.json::<serde_json::Value>()["error"]["code"], "insufficient_scope");
    assert_eq!(c.post("/notes").bearer("writer-token").json(&NewNote { text: "x".into() }).send().await.status, 201);
    assert_eq!(c.get("/admin/stats").bearer("writer-token").send().await.status, 403, "group role");
    assert_eq!(c.get("/admin/stats").bearer("admin-token").send().await.text(), "0");
    let m = app.manifest();
    let post = m.routes.iter().find(|r| r.id == "post_notes").unwrap();
    assert_eq!(post.policy.scopes, ["notes:read", "notes:write"], "scopes accumulate across levels");
    assert_eq!(post.policy.checks, ["cors", "auth", "authz", "rate_limit", "csrf", "body_gate"]);
}

#[tokio::test]
async fn csrf_cors_rate_limits_sizes_and_timeouts() {
    let (app, _) = secure();
    let c = app.client();
    let session = "sid=session-bob; poring-csrf=0123456789abcdef0123";
    let no_token = c.post("/notes").header("cookie", session).json(&NewNote { text: "x".into() }).send().await;
    assert_eq!(no_token.status, 403);
    assert_eq!(no_token.json::<serde_json::Value>()["error"]["code"], "csrf");
    let with_token = c
        .post("/notes")
        .header("cookie", session)
        .header("x-csrf-token", "0123456789abcdef0123")
        .json(&NewNote { text: "x".into() })
        .send()
        .await;
    assert_eq!(with_token.status, 201);
    assert_eq!(
        c.post("/notes/webhook").header("cookie", session).send().await.text(),
        "accepted",
        "documented exemption"
    );
    // The principal-keyed limit (2 per minute) counted both CSRF attempts.
    let other = c.post("/notes").bearer("admin-token").json(&NewNote { text: "x".into() }).send().await;
    assert_eq!(other.status, 201, "a different principal has its own bucket");
    let third = c
        .post("/notes")
        .header("cookie", session)
        .header("x-csrf-token", "0123456789abcdef0123")
        .json(&NewNote { text: "x".into() })
        .send()
        .await;
    assert_eq!(third.status, 429);
    assert!(third.header("retry-after").is_some());

    let evil = c.post("/notes").bearer("writer-token").header("origin", "https://evil.example").send().await;
    assert_eq!(evil.status, 403, "disallowed origin on an unsafe method");
    let ok = c.get("/notes").bearer("reader-token").header("origin", "https://app.example").send().await;
    assert_eq!(ok.header("access-control-allow-origin"), Some("https://app.example"));
    assert_eq!(ok.header("access-control-allow-credentials"), Some("true"));
    let preflight = c
        .request(poring::Method::OPTIONS, "/notes")
        .header("origin", "https://app.example")
        .header("access-control-request-method", "POST")
        .send()
        .await;
    assert_eq!(preflight.status, 204);

    // Fresh app: rate-limit buckets above are exhausted for these principals.
    let (app, _) = secure();
    let c = app.client();
    let big = c.post("/notes").bearer("admin-token").header("content-type", "application/json").body(vec![b' '; 2000]);
    assert_eq!(big.send().await.status, 413);
    let text = c.post("/notes").bearer("admin-token").header("content-type", "text/plain").body("x").send().await;
    assert_eq!(text.status, 415);
    let started = std::time::Instant::now();
    let slow = c.get("/slow").bearer("reader-token").send().await;
    assert_eq!(slow.status, 503);
    assert!(started.elapsed() < Duration::from_secs(2), "the handler was cancelled at its timeout");
}

fn startup_error(app: Result<poring::FluentApp<(), TableAuth>, poring::StartupError>) -> String {
    app.map(|_| ()).expect_err("configuration must be rejected").to_string()
}

fn authed() -> Poring<(), TableAuth> {
    Poring::new().authenticator(TableAuth::fixture())
}

#[test]
fn policy_violations_are_rejected_before_binding() {
    let no_auth = Poring::new()
        .route_with(RouteMethod::Get, "/x", Policy::new().authenticated(), || async { "x" })
        .build()
        .unwrap_err()
        .to_string();
    assert!(no_auth.contains("declares no authenticator"), "{no_auth}");
    let principal = Poring::new().get("/me", |Principal(a): Principal<Authenticated>| async move { a.subject.clone() });
    assert!(principal.build().unwrap_err().to_string().contains("extracts a Principal but is not authenticated"));

    let strict = authed().policy(Policy::new().deny_anonymous());
    let bare = strict.route_with(RouteMethod::Get, "/h", Policy::new().public(), || async { "h" }).build();
    assert!(startup_error(bare).contains("strict deny_anonymous policy without a reason"));

    let drops = authed().group("/g", |g| {
        g.policy(Policy::new().scopes(["s"]))
            .route_with(RouteMethod::Get, "/x", Policy::new().public(), || async { "x" })
    });
    assert!(startup_error(drops.build()).contains("drop inherited scope/role requirements"));

    let raise = authed().policy(Policy::new().body_limit(10)).group("/g", |g| g.policy(Policy::new().body_limit(20)));
    assert!(startup_error(raise.build()).contains("raises the app body limit"));

    let route_strict =
        authed().route_with(RouteMethod::Get, "/x", Policy::new().deny_anonymous(), || async { "x" }).build();
    assert!(startup_error(route_strict).contains("apps and groups"));
    let public_scoped =
        authed().route_with(RouteMethod::Get, "/x", Policy::new().public().scopes(["s"]), || async { "x" }).build();
    assert!(startup_error(public_scoped).contains("cannot require scopes or roles"));
    let empty_reason =
        authed().route_with(RouteMethod::Post, "/x", Policy::new().csrf_exempt(" "), || async { "x" }).build();
    assert!(startup_error(empty_reason).contains("documented reason"));
    let public_app = authed().policy(Policy::new().public()).build();
    assert!(startup_error(public_app).contains("app defaults cannot be public"));
    let zero_rate = authed()
        .route_with(
            RouteMethod::Get,
            "/x",
            Policy::new().rate_limit(0, Duration::from_secs(1), RateKey::Ip),
            || async { "x" },
        )
        .build();
    assert!(startup_error(zero_rate).contains("count must be > 0"));

    let wildcard = authed().cors(Cors::new().origins(["*"]).credentials(true)).build();
    assert!(startup_error(wildcard).contains("wildcard origin"));
}

#[test]
fn route_conflicts_and_invalid_paths_are_rejected_deterministically() {
    let cases: Vec<(Poring, &str)> = vec![
        (Poring::new().get("/a", || async { "1" }).get("/a", || async { "2" }), "registered twice"),
        (Poring::new().get("/u/{id}", || async { "1" }).get("/u/{name}", || async { "2" }), "cannot be inserted"),
        (Poring::new().get("/f/{*rest}", || async { "1" }).get("/f/{id}", || async { "2" }), "cannot be inserted"),
        (
            Poring::new().group("/a", |g| g.get("/b", || async { "1" })).get("/a/b", || async { "2" }),
            "registered twice",
        ),
        (Poring::new().get("no-slash", || async { "1" }), "must start with `/`"),
        (Poring::new().get("/a//b", || async { "1" }), "must not contain `//`"),
        (Poring::new().get("/img-{id}.png", || async { "1" }), "must span a whole segment"),
        (Poring::new().get("/{*rest}/x", || async { "1" }), "must be the last segment"),
        (Poring::new().get("/a/%2F", || async { "1" }), "percent-encoded"),
        (Poring::new().get("/{a}/{a}", || async { "1" }), "duplicate parameter"),
        (Poring::new().group("/api/", |g| g.get("/x", || async { "1" })), "must not end with `/`"),
        (Poring::new().group("/v/{version}", |g| g.get("/x", || async { "1" })), "must be static"),
        (Poring::new().group("api", |g| g.get("/x", || async { "1" })), "must start with `/`"),
        (Poring::new().get("/one/{a}/{b}", |Path(a): Path<u32>| async move { a.to_string() }), "extracts one value"),
        (
            Poring::new().get("/two/{a}", |Path(t): Path<(u32, u32)>| async move { t.0.to_string() }),
            "extracts 2 values",
        ),
        (Poring::new().get("/none", |Path(a): Path<u32>| async move { a.to_string() }), "declares no path parameters"),
        (Poring::new().route(RouteMethod::Get, "/body", |b: Bytes| async move { b }), "reads the request body"),
    ];
    for (i, (builder, expected)) in cases.into_iter().enumerate() {
        let err = builder.build().map(|_| ()).expect_err("must be rejected").to_string();
        assert!(err.contains(expected), "case {i}: `{err}` should mention `{expected}`");
    }
    // Same input, same error (registration order decides which route is reported).
    let msg = |_: ()| {
        Poring::new()
            .get("/a", || async { "1" })
            .get("/a", || async { "2" })
            .build()
            .map(|_| ())
            .unwrap_err()
            .to_string()
    };
    assert_eq!(msg(()), msg(()));
    assert_eq!(msg(()), "route `GET /a` is registered twice");
}

#[test]
fn startup_errors_name_the_registration_site() {
    let err = Poring::new().get("/a//b", || async { "1" }).build().map(|_| ()).unwrap_err().to_string();
    assert!(err.contains("tests/tests/fluent_security.rs:"), "{err}");
}
