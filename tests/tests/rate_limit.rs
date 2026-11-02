//! Rate limiting through the full request pipeline: statuses and headers, identity and
//! proxy trust, bucket scopes, ceilings, memory bounds, ordering, and every route kind.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use poring::dynamic::{BoxFuture, DynEndpoint, DynPolicy, DynRequest, DynamicRoute};
use poring::prelude::*;
use poring_tests::secure::TableAuth;

fn peer(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), 40_000)
}

fn per_minute(n: u32) -> RateLimit {
    RateLimit::new(n, Duration::from_secs(60))
}

/// The example from the specification, verbatim apart from `run` (which would block).
fn shared_group_app() -> poring::FluentApp {
    Poring::new()
        .group("/api", |api| {
            api.rate_limit(
                RateLimit::new(10, Duration::from_secs(60))
                    .by_ip()
                    .scope(RateScope::Group)
                    .expose_headers(true),
            )
            .get("/one", || async { "one" })
            .get("/two", || async { "two" })
        })
        .get("/free", || async { "free" })
        .build()
        .unwrap()
}

#[tokio::test]
async fn burst_remaining_and_retry_after_headers() {
    let app = Poring::new().get_rate_limited_demo().build().unwrap();
    let c = app.client();
    let mut remaining = Vec::new();
    for _ in 0..3 {
        let r = c.get("/limited").send().await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("ratelimit-policy"), Some("\"route\";q=3;w=30"));
        assert!(
            r.header("retry-after").is_none(),
            "no retry delay on success"
        );
        assert_eq!(r.header("cache-control"), Some("private, no-store"));
        remaining.push(r.header("ratelimit").unwrap().to_owned());
    }
    // 3 per 30 s: a token every 10 s; the bucket still has tokens until the third request.
    assert_eq!(
        remaining,
        [
            "\"route\";r=2;t=0",
            "\"route\";r=1;t=0",
            "\"route\";r=0;t=10"
        ]
    );
    let denied = c.get("/limited").send().await;
    assert_eq!(denied.status, 429);
    assert_eq!(
        denied.header("retry-after"),
        Some("10"),
        "time until one request is admitted"
    );
    assert_eq!(denied.header("ratelimit"), Some("\"route\";r=0;t=10"));
    assert_eq!(
        denied.json::<serde_json::Value>()["error"]["code"],
        "rate_limited"
    );
}

trait Demo {
    fn get_rate_limited_demo(self) -> Self;
}

impl Demo for Poring {
    fn get_rate_limited_demo(self) -> Self {
        self.route_with(
            RouteMethod::Get,
            "/limited",
            Policy::new()
                .with_rate_limit(RateLimit::new(3, Duration::from_secs(30)).expose_headers(true)),
            || async { "ok" },
        )
        .get("/open", || async { "open" })
    }
}

#[tokio::test]
async fn unlimited_routes_get_no_headers_and_no_buckets() {
    let app = Poring::new().get_rate_limited_demo().build().unwrap();
    let c = app.client();
    for _ in 0..50 {
        let r = c.get("/open").send().await;
        assert_eq!(r.status, 200);
        for h in [
            "ratelimit",
            "ratelimit-policy",
            "retry-after",
            "cache-control",
        ] {
            assert!(r.header(h).is_none(), "{h} on an unlimited route");
        }
    }
    assert!(
        app.rate_limiter().is_empty(),
        "unlimited routes never allocate limiter state"
    );
    assert_eq!(app.rate_limiter().stats(), Default::default());
    let m = app.manifest();
    let open = m.routes.iter().find(|r| r.path == "/open").unwrap();
    assert!(
        open.policy.rate_limit.is_none() && !open.policy.checks.iter().any(|c| c == "rate_limit")
    );
}

#[tokio::test]
async fn hooks_and_error_mappers_cannot_leave_stale_headers() {
    let app = Poring::new()
        .after(|_cx, res| {
            res.headers_mut()
                .insert("ratelimit", HeaderValue::from_static("\"route\";r=999;t=0"));
            res.headers_mut()
                .insert("retry-after", HeaderValue::from_static("9999"));
        })
        .map_errors(|_e, mut res| {
            res.headers_mut().remove("retry-after");
            res
        })
        .get_rate_limited_demo()
        .build()
        .unwrap();
    let c = app.client();
    let ok = c.get("/limited").send().await;
    assert_eq!(ok.header("ratelimit"), Some("\"route\";r=2;t=0"));
    assert!(ok.header("retry-after").is_none());
    assert_eq!(ok.headers.get_all("ratelimit").iter().count(), 1);
    c.get("/limited").send().await;
    c.get("/limited").send().await;
    let denied = c.get("/limited").send().await;
    assert_eq!(denied.status, 429);
    assert_eq!(
        denied.header("retry-after"),
        Some("10"),
        "restored after the error mapper"
    );
}

#[tokio::test]
async fn head_requests_and_cors_exposure() {
    let app = Poring::new()
        .cors(Cors::new().origins(["https://app.example"]))
        .get_rate_limited_demo()
        .build()
        .unwrap();
    let c = app.client();
    let head = c.request(poring::Method::HEAD, "/limited").send().await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(
        head.header("ratelimit"),
        Some("\"route\";r=2;t=0"),
        "HEAD consumes a token"
    );

    let allowed = c
        .get("/limited")
        .header("origin", "https://app.example")
        .send()
        .await;
    assert_eq!(
        allowed.header("access-control-expose-headers"),
        Some("RateLimit, RateLimit-Policy")
    );
    let other = c
        .get("/limited")
        .header("origin", "https://evil.example")
        .send()
        .await;
    assert!(
        other.header("access-control-expose-headers").is_none(),
        "not exposed to unauthorised origins"
    );
    let denied = c
        .get("/limited")
        .header("origin", "https://app.example")
        .send()
        .await;
    assert_eq!(denied.status, 429);
    assert_eq!(
        denied.header("access-control-expose-headers"),
        Some("Retry-After, RateLimit, RateLimit-Policy")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_requests_never_exceed_the_allowance() {
    let app = Poring::new()
        .route_with(
            RouteMethod::Get,
            "/x",
            Policy::new().with_rate_limit(per_minute(25)),
            || async { "x" },
        )
        .build()
        .unwrap();
    let mut tasks = Vec::new();
    for _ in 0..200 {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            app.client().get("/x").send().await.status.as_u16()
        }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap() == 200 {
            ok += 1;
        }
    }
    assert_eq!(ok, 25, "exactly the burst allowance is admitted");
    assert_eq!(app.rate_limiter().stats().denied, 175);
}

#[tokio::test]
async fn ips_are_canonical_and_independent_and_headers_cannot_spoof_them() {
    let app = Poring::new()
        .route_with(
            RouteMethod::Get,
            "/x",
            Policy::new().with_rate_limit(per_minute(1)),
            || async { "x" },
        )
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(c.get("/x").peer(peer("192.0.2.1")).send().await.status, 200);
    assert_eq!(
        c.get("/x")
            .peer(peer("::ffff:192.0.2.1"))
            .send()
            .await
            .status,
        429,
        "same client"
    );
    assert_eq!(
        c.get("/x").peer(peer("192.0.2.2")).send().await.status,
        200,
        "other clients are independent"
    );
    let spoofed = c
        .get("/x")
        .peer(peer("192.0.2.1"))
        .header("x-forwarded-for", "203.0.113.50")
        .send()
        .await;
    assert_eq!(
        spoofed.status, 429,
        "X-Forwarded-For from an untrusted peer is ignored"
    );
}

#[tokio::test]
async fn trusted_proxy_chains_identify_the_client() {
    let app = Poring::new()
        .trusted_proxies(["10.0.0.0/8"])
        .route_with(
            RouteMethod::Get,
            "/x",
            Policy::new().with_rate_limit(per_minute(1)),
            || async { "x" },
        )
        .build()
        .unwrap();
    let c = app.client();
    let via = |client: &str| {
        c.get("/x")
            .peer(peer("10.0.0.5"))
            .header("x-forwarded-for", client)
    };
    assert_eq!(via("198.51.100.1").send().await.status, 200);
    assert_eq!(
        via("198.51.100.2").send().await.status,
        200,
        "clients behind the proxy are separate"
    );
    assert_eq!(via("198.51.100.1").send().await.status, 429);
    // A client cannot escape its quota by prepending addresses.
    assert_eq!(via("1.2.3.4, 198.51.100.1").send().await.status, 429);
    // A direct, untrusted client cannot claim another client's identity either.
    let direct = c
        .get("/x")
        .peer(peer("203.0.113.9"))
        .header("x-forwarded-for", "198.51.100.3");
    assert_eq!(direct.send().await.status, 200);
    let real = c
        .get("/x")
        .peer(peer("10.0.0.5"))
        .header("x-forwarded-for", "198.51.100.3");
    assert_eq!(
        real.send().await.status,
        200,
        "198.51.100.3 was never charged"
    );

    #[allow(deprecated)]
    let legacy = Poring::new().trust_forwarded_for(true).build();
    assert!(legacy.unwrap_err().to_string().contains("trusted_proxies"));
    let invalid = Poring::new().trusted_proxies(["0.0.0.0/0"]).build();
    assert!(
        invalid
            .unwrap_err()
            .to_string()
            .contains("would trust every address")
    );
}

#[tokio::test]
async fn group_buckets_are_shared_within_and_isolated_between_groups() {
    let app = shared_group_app();
    let c = app.client();
    let mut seen = Vec::new();
    for path in ["/api/one", "/api/two", "/api/one"] {
        seen.push(
            c.get(path)
                .send()
                .await
                .header("ratelimit")
                .unwrap()
                .to_owned(),
        );
    }
    assert_eq!(
        seen,
        [
            "\"group\";r=9;t=0",
            "\"group\";r=8;t=0",
            "\"group\";r=7;t=0"
        ]
    );
    assert!(c.get("/free").send().await.header("ratelimit").is_none());

    let two_groups = Poring::new()
        .group("/a", |g| {
            g.rate_limit(per_minute(1).scope(RateScope::Group))
                .get("/x", || async { "a" })
        })
        .group("/b", |g| {
            g.rate_limit(per_minute(1).scope(RateScope::Group))
                .get("/x", || async { "b" })
        })
        .build()
        .unwrap();
    let c = two_groups.client();
    assert_eq!(c.get("/a/x").send().await.status, 200);
    assert_eq!(c.get("/a/x").send().await.status, 429);
    assert_eq!(
        c.get("/b/x").send().await.status,
        200,
        "another group has its own bucket"
    );

    let per_route = Poring::new()
        .group("/r", |g| {
            g.rate_limit(per_minute(1))
                .get("/x", || async { "x" })
                .get("/y", || async { "y" })
        })
        .build()
        .unwrap();
    let c = per_route.client();
    assert_eq!(c.get("/r/x").send().await.status, 200);
    assert_eq!(
        c.get("/r/y").send().await.status,
        200,
        "route scope keeps separate buckets"
    );
}

#[tokio::test]
async fn route_overrides_app_scope_and_the_ceiling_cannot_be_bypassed() {
    let app = Poring::new()
        .rate_limit(per_minute(2).scope(RateScope::App))
        .rate_limit_ceiling(per_minute(4).expose_headers(true))
        .get("/a", || async { "a" })
        .get("/b", || async { "b" })
        .route_with(
            RouteMethod::Get,
            "/own",
            Policy::new().with_rate_limit(per_minute(100)),
            || async { "own" },
        )
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(c.get("/a").send().await.status, 200);
    assert_eq!(c.get("/b").send().await.status, 200);
    assert_eq!(
        c.get("/a").send().await.status,
        429,
        "/a and /b share the app bucket"
    );
    // `/own` has its own generous limit, but the ceiling (4) still applies: 2 used above.
    let first = c.get("/own").send().await;
    assert_eq!(
        first.header("ratelimit-policy"),
        Some("\"route\";q=100;w=60, \"ceiling\";q=4;w=60")
    );
    assert_eq!(
        first.header("ratelimit"),
        Some("\"ceiling\";r=1;t=0"),
        "reports the tighter policy"
    );
    assert_eq!(c.get("/own").send().await.status, 200);
    let capped = c.get("/own").send().await;
    assert_eq!(capped.status, 429);
    assert!(
        capped
            .header("ratelimit")
            .unwrap()
            .starts_with("\"ceiling\";r=0")
    );
    assert_eq!(
        app.manifest().routes[2]
            .policy
            .rate_limit_ceiling
            .as_ref()
            .unwrap()
            .scope,
        "app"
    );
}

#[tokio::test]
async fn denied_requests_do_not_consume_other_buckets() {
    let app = Poring::new()
        .rate_limit_ceiling(per_minute(1))
        .route_with(
            RouteMethod::Get,
            "/x",
            Policy::new().with_rate_limit(per_minute(2).expose_headers(true)),
            || async { "x" },
        )
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(c.get("/x").send().await.status, 200);
    for _ in 0..5 {
        assert_eq!(c.get("/x").send().await.status, 429, "ceiling exhausted");
    }
    // Had the denials consumed route tokens, the route bucket would be empty by now.
    assert_eq!(app.rate_limiter().stats().allowed, 1);
}

#[tokio::test]
async fn principal_keys_follow_authentication_and_never_fall_back_to_ip() {
    let app = Poring::new()
        .authenticator(TableAuth::fixture())
        .route_with(
            RouteMethod::Get,
            "/me",
            Policy::new().rate_limit(1, Duration::from_secs(60), RateKey::Principal),
            |q: RateLimitStatus| async move { format!("{} left", q.remaining) },
        )
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(
        c.get("/me").send().await.status,
        401,
        "authentication runs before the limit"
    );
    assert!(
        app.rate_limiter().is_empty(),
        "unauthenticated requests consume nothing"
    );
    assert_eq!(
        c.get("/me").bearer("reader-token").send().await.text(),
        "0 left"
    );
    assert_eq!(c.get("/me").bearer("reader-token").send().await.status, 429);
    assert_eq!(
        c.get("/me").bearer("writer-token").send().await.status,
        200,
        "per principal"
    );

    let public = Poring::new()
        .authenticator(TableAuth::fixture())
        .route_with(
            RouteMethod::Get,
            "/p",
            Policy::new()
                .public()
                .rate_limit(1, Duration::from_secs(60), RateKey::Principal),
            || async { "p" },
        )
        .build();
    let err = public.map(|_| ()).unwrap_err().to_string();
    assert!(
        err.contains("principal-keyed rate limit") && err.contains("not authenticated"),
        "{err}"
    );
}

#[tokio::test]
async fn a_full_table_fails_closed_without_resetting_active_clients() {
    let app = Poring::new()
        .limits(poring::Limits {
            rate_limit_keys: 2,
            ..Default::default()
        })
        .route_with(
            RouteMethod::Get,
            "/x",
            Policy::new().with_rate_limit(per_minute(1)),
            || async { "x" },
        )
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(c.get("/x").peer(peer("192.0.2.1")).send().await.status, 200);
    assert_eq!(c.get("/x").peer(peer("192.0.2.2")).send().await.status, 200);
    let flood = c.get("/x").peer(peer("192.0.2.3")).send().await;
    assert_eq!(flood.status, 503);
    assert_eq!(
        flood.json::<serde_json::Value>()["error"]["code"],
        "rate_limiter_saturated"
    );
    assert!(flood.header("retry-after").is_some());
    assert_eq!(
        c.get("/x").peer(peer("192.0.2.1")).send().await.status,
        429,
        "still throttled"
    );
    let s = app.rate_limiter().stats();
    assert_eq!((s.allowed, s.denied, s.saturated), (2, 1, 1));
    assert_eq!(app.rate_limiter().len(), 2);
}

#[test]
fn invalid_configuration_is_rejected_before_binding() {
    let cases: Vec<(Poring, &str)> = vec![
        (
            Poring::new().limits(poring::Limits {
                rate_limit_keys: 0,
                ..Default::default()
            }),
            "rate_limit_keys",
        ),
        (
            Poring::new().route_with(
                RouteMethod::Get,
                "/x",
                Policy::new().with_rate_limit(per_minute(0)),
                || async { "x" },
            ),
            "count must be > 0",
        ),
        (
            Poring::new().route_with(
                RouteMethod::Get,
                "/x",
                Policy::new().with_rate_limit(RateLimit::new(1, Duration::from_micros(10))),
                || async { "x" },
            ),
            "window must be between",
        ),
        (
            Poring::new().route_with(
                RouteMethod::Get,
                "/x",
                Policy::new().with_rate_limit(RateLimit::new(1, Duration::from_micros(1500))),
                || async { "x" },
            ),
            "whole number of milliseconds",
        ),
        (
            Poring::new().route_with(
                RouteMethod::Get,
                "/x",
                Policy::new().with_rate_limit(per_minute(1).scope(RateScope::Group)),
                || async { "x" },
            ),
            "must be declared on a group",
        ),
        (
            Poring::new().rate_limit(per_minute(1).scope(RateScope::Group)),
            "must be declared on a group",
        ),
        (
            Poring::new().group("/g", |g| g.rate_limit(per_minute(1).scope(RateScope::App))),
            "must be declared on the app",
        ),
        (
            Poring::new().group("/g", |g| {
                g.rate_limit(per_minute(1)).policy(Policy::new().rate_limit(
                    1,
                    Duration::from_secs(1),
                    RateKey::Ip,
                ))
            }),
            "declared by both",
        ),
        (
            Poring::new().rate_limit_ceiling(per_minute(1).scope(RateScope::Group)),
            "cannot be group-scoped",
        ),
    ];
    for (i, (builder, expected)) in cases.into_iter().enumerate() {
        let err = builder
            .build()
            .map(|_| ())
            .expect_err("must be rejected")
            .to_string();
        assert!(
            err.contains(expected),
            "case {i}: `{err}` should mention `{expected}`"
        );
    }
}

mod macros {
    use poring::prelude::*;
    use poring_tests::secure::TableAuth;

    #[poring::get("/one")]
    pub async fn one() -> &'static str {
        "one"
    }

    #[poring::get("/two")]
    pub async fn two() -> &'static str {
        "two"
    }

    #[poring::get("/mine", policy(rate_limit(requests = 5, per = "1m", headers = true)))]
    pub async fn mine() -> &'static str {
        "mine"
    }

    poring_app! {
        pub Limited {
            auth: TableAuth,
            defaults: policy(auth = required),
            groups: [
                group("/g", policy(rate_limit(requests = 2, per = "1m", key = principal, scope = group, headers = true))) {
                    routes: [one, two, mine]
                },
            ],
        }
    }
}

#[tokio::test]
async fn macro_routes_share_the_same_engine_and_semantics() {
    let app = macros::Limited::builder()
        .authenticator(TableAuth::fixture())
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(
        c.get("/g/one").send().await.status,
        401,
        "auth runs first and consumes nothing"
    );
    let r = c.get("/g/one").bearer("reader-token").send().await;
    assert_eq!(r.header("ratelimit"), Some("\"group\";r=1;t=0"));
    assert_eq!(
        c.get("/g/two")
            .bearer("reader-token")
            .send()
            .await
            .header("ratelimit"),
        Some("\"group\";r=0;t=30")
    );
    assert_eq!(
        c.get("/g/one").bearer("reader-token").send().await.status,
        429,
        "shared group bucket"
    );
    assert_eq!(
        c.get("/g/mine").bearer("reader-token").send().await.status,
        200,
        "route override"
    );
    assert_eq!(
        c.get("/g/one").bearer("writer-token").send().await.status,
        200,
        "per principal"
    );
    let view = macros::Limited::manifest().unwrap();
    let one = view.routes.iter().find(|r| r.path == "/g/one").unwrap();
    let rl = one.policy.rate_limit.as_ref().unwrap();
    assert_eq!(
        (rl.scope.as_str(), rl.shared_by.as_deref(), rl.headers),
        ("group", Some("group `/g`"), true)
    );
    assert_eq!(one.policy.checks, ["auth", "rate_limit"]);
}

#[derive(Default)]
struct Echo(AtomicUsize);

impl DynEndpoint for Echo {
    fn call(&self, _req: DynRequest) -> BoxFuture<'static, Response> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { "guest".into_response() })
    }
}

#[tokio::test]
async fn dynamic_routes_use_the_same_limiter() {
    let echo = Arc::new(Echo::default());
    let policy = DynPolicy {
        rate_limit: Some(
            poring::policy::RateLimitSpec::new(1, 60_000, RateKey::Ip).with_headers(true),
        ),
        ..Default::default()
    };
    let route = DynamicRoute {
        method: RouteMethod::Post,
        path: "/guest".into(),
        name: "echo".into(),
        policy,
        endpoint: echo.clone(),
    };
    let app = Poring::new().mount_dynamic(route).build().unwrap();
    let c = app.client();
    let ok = c.post("/guest").send().await;
    assert_eq!(ok.header("ratelimit"), Some("\"route\";r=0;t=60"));
    assert_eq!(c.post("/guest").send().await.status, 429);
    assert_eq!(
        echo.0.load(Ordering::SeqCst),
        1,
        "denied requests never reach the endpoint"
    );
}

#[tokio::test]
async fn manifests_graphs_and_explanations_never_contain_identities() {
    let app = Poring::new()
        .authenticator(TableAuth::fixture())
        .rate_limit_ceiling(per_minute(100))
        .group("/g", |g| {
            g.rate_limit(per_minute(3).by_principal().scope(RateScope::Group))
                .get("/x", || async { "x" })
        })
        .build()
        .unwrap();
    app.client().get("/g/x").bearer("reader-token").send().await;
    let m = app.manifest();
    let json = serde_json::to_string(&m).unwrap();
    for secret in ["alice", "reader-token", "127.0.0.1"] {
        assert!(!json.contains(secret), "manifest leaks {secret}");
    }
    let p = &m.routes[0].policy;
    assert_eq!(
        p.checks,
        ["auth", "rate_limit"],
        "principal-keyed limits run after authentication"
    );
    let graph = poring::contract::render_mermaid(&app.graph(None).unwrap());
    assert!(graph.contains("rate limit 3/60000ms by principal (bucket shared by group `/g`) + app ceiling 100/60000ms by ip"));
    assert!(graph.contains("503 rate limiter full"));
    let explained = poring::contract::explain(&m, "GET /g/x").unwrap();
    assert!(explained.contains(
        "| rate limit ceiling | 100 per 60000 ms by ip (app bucket, enforced in addition) |"
    ));
}

#[tokio::test]
async fn hooks_and_handlers_read_the_admitted_status_without_a_second_token() {
    let seen = Arc::new(AtomicUsize::new(usize::MAX));
    let seen_hook = seen.clone();
    let app = Poring::new()
        .before(move |cx: &mut Ctx<'_, ()>| {
            if let Some(s) = cx.rate_limit() {
                seen_hook.store(s.remaining as usize, Ordering::SeqCst);
            }
        })
        .route_with(
            RouteMethod::Get,
            "/q",
            Policy::new().with_rate_limit(RateLimit::new(4, Duration::from_secs(2))),
            |s: Option<RateLimitStatus>| async move {
                let s = s.unwrap();
                assert!(s.full_refill_after <= Duration::from_millis(500) * (4 - s.remaining));
                format!("{} {:?}", s.remaining, s.next_token_after)
            },
        )
        .get("/none", |s: Option<RateLimitStatus>| async move {
            format!("{}", s.is_some())
        })
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(c.get("/q").send().await.text(), "3 0ns");
    assert_eq!(seen.load(Ordering::SeqCst), 3);
    assert_eq!(c.get("/q").send().await.text(), "2 0ns");
    assert_eq!(
        app.rate_limiter().stats().allowed,
        2,
        "reading the status takes no token"
    );
    assert_eq!(c.get("/none").send().await.text(), "false");
}
