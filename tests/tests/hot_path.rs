//! Regression tests for the request hot path: router API and macro parity, socket and
//! in-process parity, timeouts, request IDs, hooks, CORS and error mapping. Tracing parity
//! lives in `tracing_parity.rs`, which needs a test binary of its own.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use poring::prelude::*;
use poring_tests::raw_http;

async fn plain() -> &'static str {
    "ok"
}

async fn path(Path(id): Path<u64>) -> String {
    id.to_string()
}

async fn json() -> Json<Vec<u64>> {
    Json((0..128).collect())
}

async fn post(Json(values): Json<Vec<u64>>) -> String {
    values.iter().sum::<u64>().to_string()
}

mod attributes {
    use poring::prelude::*;

    #[poring::get("/bench/plain")]
    pub async fn plain() -> &'static str {
        super::plain().await
    }

    #[poring::get("/bench/path/{id}")]
    pub async fn path(id: Path<u64>) -> String {
        super::path(id).await
    }

    #[poring::get("/bench/json")]
    pub async fn json() -> Json<Vec<u64>> {
        super::json().await
    }

    #[poring::post("/bench/post")]
    pub async fn post(body: Json<Vec<u64>>) -> String {
        super::post(body).await
    }

    poring_app! {
        pub Bench {
            routes: [plain, path, json, post],
        }
    }
}

fn fluent() -> Poring {
    Poring::new()
        .get("/bench/plain", plain)
        .get("/bench/path/{id}", path)
        .get("/bench/json", json)
        .post("/bench/post", post)
}

/// The response as a comparable value: status, headers (minus the per-request ID) and body.
fn shape(r: &poring::testing::TestResponse) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut headers: Vec<(String, String)> = r
        .headers
        .iter()
        .filter(|(k, _)| k.as_str() != "x-request-id")
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("?").to_owned()))
        .collect();
    headers.sort();
    (r.status.as_u16(), headers, r.body.to_vec())
}

#[tokio::test]
async fn router_api_and_macros_respond_identically() {
    let routed = fluent().build().unwrap();
    let macros = attributes::Bench::builder().build().unwrap();
    let body: Vec<u64> = (0..256).collect();
    for (method, uri) in [
        ("GET", "/bench/plain"),
        ("HEAD", "/bench/plain"),
        ("GET", "/bench/path/12345"),
        ("GET", "/bench/path/not-a-number"),
        ("GET", "/bench/json"),
        ("POST", "/bench/post"),
        ("POST", "/bench/plain"),
        ("GET", "/missing"),
        ("OPTIONS", "/bench/plain"),
    ] {
        let m: http::Method = method.parse().unwrap();
        let a = routed
            .client()
            .request(m.clone(), uri)
            .json(&body)
            .send()
            .await;
        let b = macros.client().request(m, uri).json(&body).send().await;
        assert_eq!(shape(&a), shape(&b), "{method} {uri}");
    }
    let r = routed.client().get("/bench/plain").send().await;
    assert_eq!(r.text(), "ok");
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert!(r.header("x-request-id").is_some());
    let r = routed.client().post("/bench/post").json(&body).send().await;
    assert_eq!(r.text(), (0..256u64).sum::<u64>().to_string());
}

/// Splits a raw HTTP/1.1 response into status, the headers named in `keep`, and the body.
fn parse_raw(raw: &str, keep: &[&str]) -> (u16, Vec<(String, String)>, String) {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .filter(|(k, _)| keep.contains(&k.as_str()))
        .collect();
    headers.sort();
    (status, headers, body.to_owned())
}

#[tokio::test]
async fn socket_and_in_process_responses_match() {
    let app = fluent().build().unwrap();
    let in_process = fluent().build().unwrap();
    let server = app.bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr();
    let keep = [
        "content-type",
        "content-length",
        "x-content-type-options",
        "allow",
    ];
    for (method, uri) in [
        ("GET", "/bench/plain"),
        ("GET", "/bench/path/7"),
        ("GET", "/bench/json"),
        ("DELETE", "/bench/plain"),
        ("GET", "/nope"),
    ] {
        let req = format!("{method} {uri} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let raw = raw_http(addr, req.as_bytes()).await;
        let (status, headers, body) = parse_raw(&raw, &keep);
        assert!(
            raw.to_ascii_lowercase().contains("\r\nx-request-id: "),
            "request IDs over the wire: {raw}"
        );
        let local = in_process
            .client()
            .request(method.parse().unwrap(), uri)
            .send()
            .await;
        let mut local_headers: Vec<(String, String)> = local
            .headers
            .iter()
            .filter(|(k, _)| keep.contains(&k.as_str()))
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
            .collect();
        if !local_headers.iter().any(|(k, _)| k == "content-length") {
            local_headers.push(("content-length".into(), local.body.len().to_string()));
        }
        local_headers.sort();
        assert_eq!(status, local.status.as_u16(), "{method} {uri}");
        assert_eq!(headers, local_headers, "{method} {uri}");
        assert_eq!(body.as_bytes(), &local.body[..], "{method} {uri}");
    }
    server.shutdown().await.unwrap();
}

fn timeouts() -> poring::FluentApp {
    let timeout = |ms| Policy::new().timeout(Duration::from_millis(ms));
    Poring::new()
        .route_with(RouteMethod::Get, "/ready", timeout(50), || async {
            "ready"
        })
        .route_with(RouteMethod::Get, "/pending", timeout(2_000), || async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            "pending"
        })
        .route_with(RouteMethod::Get, "/late", timeout(50), || async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            "late"
        })
        .route_with(RouteMethod::Get, "/hog", timeout(50), || async {
            // Spends the task's whole cooperative budget on every poll and never finishes.
            let mut polls = 0u64;
            while polls < u64::MAX {
                tokio::task::coop::consume_budget().await;
                polls += 1;
            }
            "never"
        })
        .route_with(
            RouteMethod::Get,
            "/unbounded",
            Policy::new().no_timeout(),
            || async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                "unbounded"
            },
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn timeouts_apply_whether_or_not_the_handler_is_ready_at_once() {
    let app = timeouts();
    let c = app.client();
    assert_eq!(c.get("/ready").send().await.text(), "ready");
    assert_eq!(c.get("/pending").send().await.text(), "pending");
    assert_eq!(c.get("/unbounded").send().await.text(), "unbounded");
    for uri in ["/late", "/hog"] {
        let started = Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(5), c.get(uri).send())
            .await
            .unwrap_or_else(|_| panic!("{uri}: the route timeout never fired"));
        assert_eq!(r.status, 503, "{uri}");
        assert_eq!(
            r.json::<serde_json::Value>()["error"]["code"],
            "timeout",
            "{uri}"
        );
        assert!(started.elapsed() < Duration::from_secs(2), "{uri}");
    }
}

#[tokio::test]
async fn request_ids_are_generated_propagated_or_disabled() {
    let app = fluent().build().unwrap();
    let c = app.client();
    let a = c.get("/bench/plain").send().await;
    let b = c.get("/missing").send().await;
    let (a, b) = (
        a.header("x-request-id").unwrap(),
        b.header("x-request-id").unwrap(),
    );
    assert_ne!(a, b);
    for id in [a, b] {
        let (prefix, n) = id.split_once('-').unwrap();
        assert_eq!(prefix.len(), 8);
        assert!(
            prefix
                .chars()
                .chain(n.chars())
                .all(|c| c.is_ascii_hexdigit())
        );
    }
    let echoed = c
        .get("/bench/plain")
        .header("x-request-id", "client-supplied-1")
        .send()
        .await;
    assert_eq!(echoed.header("x-request-id"), Some("client-supplied-1"));

    let off = fluent().request_ids(false).build().unwrap();
    let r = off.client().get("/bench/plain").send().await;
    assert_eq!(r.text(), "ok");
    assert_eq!(r.header("x-request-id"), None);
}

#[tokio::test]
async fn response_hooks_see_routes_in_registration_order() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (first, second) = (seen.clone(), seen.clone());
    let app = fluent()
        .on_response(move |info| {
            first.lock().unwrap().push((
                "first",
                info.route.clone(),
                info.status.as_u16(),
                info.request_id.clone(),
            ));
        })
        .on_response(move |info| {
            second.lock().unwrap().push((
                "second",
                info.route.clone(),
                info.status.as_u16(),
                info.request_id.clone(),
            ));
        })
        .build()
        .unwrap();
    let route = app
        .manifest()
        .routes
        .iter()
        .find(|r| r.path == "/bench/plain")
        .map(|r| r.id.clone())
        .unwrap();
    let r = app
        .client()
        .get("/bench/plain")
        .header("x-request-id", "hook-1")
        .send()
        .await;
    assert_eq!(r.status, 200);
    app.client().get("/missing").send().await;
    let seen = seen.lock().unwrap();
    let names: Vec<_> = seen.iter().map(|s| s.0).collect();
    assert_eq!(names, ["first", "second", "first", "second"]);
    assert_eq!(seen[0].1.as_deref(), Some(route.as_str()));
    assert_eq!((seen[0].2, seen[0].3.as_str()), (200, "hook-1"));
    assert_eq!(seen[1], seen[0].clone().with_name("second"));
    assert_eq!((seen[2].1.as_deref(), seen[2].2), (None, 404));
}

trait WithName {
    fn with_name(self, name: &'static str) -> Self;
}

impl WithName for (&'static str, Option<String>, u16, String) {
    fn with_name(mut self, name: &'static str) -> Self {
        self.0 = name;
        self
    }
}

#[tokio::test]
async fn origins_are_only_honoured_when_cors_is_configured() {
    let without = fluent().build().unwrap();
    let r = without
        .client()
        .get("/bench/plain")
        .header("origin", "https://app.example")
        .send()
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("access-control-allow-origin"), None);
    let r = without
        .client()
        .request(http::Method::OPTIONS, "/bench/plain")
        .header("origin", "https://app.example")
        .header("access-control-request-method", "GET")
        .send()
        .await;
    assert_eq!(r.status, 204);
    assert_eq!(r.header("access-control-allow-origin"), None);
    assert!(r.header("allow").is_some());

    let with = fluent()
        .cors(Cors::new().origins(["https://app.example"]))
        .build()
        .unwrap();
    let c = with.client();
    let r = c
        .get("/bench/plain")
        .header("origin", "https://app.example")
        .send()
        .await;
    assert_eq!(
        r.header("access-control-allow-origin"),
        Some("https://app.example")
    );
    let r = c
        .get("/bench/plain")
        .header("origin", "https://evil.example")
        .send()
        .await;
    assert_eq!(
        r.status, 200,
        "safe methods are served without CORS headers"
    );
    assert_eq!(r.header("access-control-allow-origin"), None);
    let r = c
        .post("/bench/post")
        .header("origin", "https://evil.example")
        .json(&[1u64])
        .send()
        .await;
    assert_eq!(r.status, 403);
    let r = c
        .request(http::Method::OPTIONS, "/bench/plain")
        .header("origin", "https://app.example")
        .header("access-control-request-method", "GET")
        .send()
        .await;
    assert_eq!(r.status, 204);
    assert_eq!(
        r.header("access-control-allow-origin"),
        Some("https://app.example")
    );
}

#[tokio::test]
async fn error_mapping_runs_only_for_framework_errors() {
    let app = fluent()
        .map_errors(|e, mut res| {
            res.headers_mut()
                .insert("x-mapped", http::HeaderValue::from_static(e.code));
            res
        })
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(
        c.get("/missing").send().await.header("x-mapped"),
        Some("not_found")
    );
    assert_eq!(c.get("/bench/plain").send().await.header("x-mapped"), None);
}
