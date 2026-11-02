//! Routing, HTTP semantics, extractors, responses, hooks, state, errors.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use poring::prelude::*;
use poring_tests::{raw_http, status_of};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default)]
struct Counter(Arc<AtomicUsize>);

#[derive(Clone, PoringState)]
struct AppState {
    counter: Counter,
    greeting: Greeting,
}

#[derive(Clone)]
struct Greeting(&'static str);

#[derive(Debug, Deserialize, Serialize, PoringSchema, PartialEq)]
struct NewItem {
    #[poring(min_length = 1, max_length = 16)]
    name: String,
    #[poring(minimum = 1, maximum = 100)]
    qty: u32,
}

#[derive(Debug, Deserialize, PoringSchema)]
struct Paging {
    page: Option<u32>,
    tag: Option<Vec<String>>,
}

#[poring::get("/")]
async fn root() -> &'static str {
    "root"
}

#[poring::get("/users/new")]
async fn users_new() -> &'static str {
    "static wins"
}

#[poring::get("/users/{id}")]
async fn user(Path(id): Path<u64>) -> String {
    format!("user {id}")
}

#[poring::get("/files/{*rest}")]
async fn files(Path(rest): Path<String>) -> String {
    format!("file {rest}")
}

#[poring::get("/pair/{a}/{b}")]
async fn pair(Path((a, b)): Path<(u8, String)>) -> String {
    format!("{a}:{b}")
}

#[poring::get("/search")]
async fn search(Query(q): Query<Paging>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "page": q.page, "tags": q.tag }))
}

#[poring::post("/items", policy(body_limit = "128B"))]
async fn create(
    State(c): State<Counter>,
    Json(item): Json<NewItem>,
) -> (StatusCode, Json<NewItem>) {
    c.0.fetch_add(1, Ordering::SeqCst);
    (StatusCode::CREATED, Json(item))
}

#[poring::get("/greet")]
async fn greet(State(g): State<Greeting>) -> &'static str {
    g.0
}

#[poring::get("/fail")]
async fn fail() -> Result<&'static str, ApiError> {
    Err(ApiError::conflict("already exists"))
}

#[poring::get("/sync")]
fn sync_handler() -> &'static str {
    "sync ok"
}

#[poring::put("/echo")]
async fn echo(body: String) -> String {
    body
}

#[poring::hook]
async fn require_header(cx: &mut Ctx<'_, AppState>) -> Result<(), ApiError> {
    if cx.headers().contains_key("x-allow") {
        cx.extensions_mut().insert(Marker("from-hook"));
        Ok(())
    } else {
        Err(ApiError::forbidden("missing x-allow"))
    }
}

#[derive(Clone)]
struct Marker(&'static str);

#[poring::hook]
async fn stamp(_cx: &Ctx<'_, AppState>, res: &mut Response) {
    res.headers_mut()
        .insert("x-stamped", HeaderValue::from_static("yes"));
}

#[poring::get("/guarded", before = [require_header], after = [stamp])]
async fn guarded(Extension(m): Extension<Marker>) -> &'static str {
    m.0
}

#[poring::route(PATCH, "/patch/:id")]
async fn patch_sugar(Path(id): Path<u32>) -> String {
    format!("patched {id}")
}

poring_app! {
    Core {
        state: AppState,
        routes: [root, users_new, user, files, pair, search, create, greet, fail, sync_handler, echo, guarded, patch_sugar],
    }
}

fn app() -> (poring::App<Core>, Counter) {
    let counter = Counter::default();
    let app = Core::builder()
        .state(AppState {
            counter: counter.clone(),
            greeting: Greeting("hi from state"),
        })
        .build()
        .expect("app builds");
    (app, counter)
}

#[tokio::test]
async fn static_routes_and_params() {
    let (app, _) = app();
    let c = app.client();
    assert_eq!(c.get("/").send().await.text(), "root");
    assert_eq!(c.get("/users/42").send().await.text(), "user 42");
    assert_eq!(
        c.get("/users/new").send().await.text(),
        "static wins",
        "static segment beats parameter"
    );
    assert_eq!(
        c.get("/files/a/b%20c.txt").send().await.text(),
        "file a/b c.txt"
    );
    assert_eq!(c.get("/pair/7/x%2Fy").send().await.text(), "7:x/y");
    assert_eq!(
        c.patch("/patch/9").send().await.text(),
        "patched 9",
        "`:id` sugar is canonicalised"
    );
    assert_eq!(c.get("/sync").send().await.text(), "sync ok");
}

#[tokio::test]
async fn unknown_paths_methods_head_and_options_follow_http_semantics() {
    let (app, _) = app();
    let c = app.client();
    let r = c.get("/nope").send().await;
    assert_eq!(r.status, 404);
    let r = c.delete("/users/1").send().await;
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), Some("GET, HEAD, OPTIONS"));
    let r = c.head("/users/1").send().await;
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty(), "HEAD has no body");
    assert_eq!(
        r.header("content-length"),
        Some("6"),
        "HEAD keeps GET's Content-Length"
    );
    let r = c.options("/items").send().await;
    assert_eq!(r.status, 204);
    assert_eq!(r.header("allow"), Some("POST, OPTIONS"));
    // Trailing slash is a distinct path (strict matching).
    assert_eq!(c.get("/users/1/").send().await.status, 404);
    // Encoded static segment does not match.
    assert_eq!(c.get("/us%65rs/1").send().await.status, 404);
    // Security header + request id.
    let r = c.get("/").header("x-request-id", "abc-123").send().await;
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(r.header("x-request-id"), Some("abc-123"));
    let r = c
        .get("/")
        .header("x-request-id", "bad id\twith stuff")
        .send()
        .await;
    assert_ne!(
        r.header("x-request-id"),
        Some("bad id\twith stuff"),
        "unsafe ids are replaced"
    );
}

#[tokio::test]
async fn malformed_input_is_rejected() {
    let (app, _) = app();
    let c = app.client();
    let r = c.get("/users/abc").send().await;
    assert_eq!(r.status, 400);
    assert!(r.text().contains("must be u64"), "{}", r.text());
    assert_eq!(c.get("/users/%ZZ").send().await.status, 400);
    assert_eq!(c.get("/pair/300/x").send().await.status, 400, "u8 overflow");
    let r = c
        .post("/items")
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await;
    assert_eq!(r.status, 400);
    let r = c
        .post("/items")
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await;
    assert_eq!(r.status, 415);
    let r = c
        .post("/items")
        .json(&serde_json::json!({"name": "x"}))
        .send()
        .await;
    assert_eq!(
        r.status,
        400,
        "missing field is a shape error: {}",
        r.text()
    );
}

#[tokio::test]
async fn json_validation_and_limits() {
    let (app, counter) = app();
    let c = app.client();
    let ok = c
        .post("/items")
        .json(&NewItem {
            name: "pen".into(),
            qty: 3,
        })
        .send()
        .await;
    assert_eq!(ok.status, 201);
    assert_eq!(
        ok.json::<NewItem>(),
        NewItem {
            name: "pen".into(),
            qty: 3
        }
    );
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);

    let bad = c
        .post("/items")
        .json(&NewItem {
            name: "".into(),
            qty: 1000,
        })
        .send()
        .await;
    assert_eq!(bad.status, 422);
    let v: serde_json::Value = bad.json();
    let issues = v["error"]["issues"].as_array().unwrap();
    assert_eq!(issues.len(), 2, "{v}");
    assert_eq!(issues[0]["path"], "/name");
    assert_eq!(issues[0]["rule"], "min_length");
    assert_eq!(issues[1]["path"], "/qty");
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        1,
        "handler not called on invalid input"
    );

    let big = format!("{{\"name\":\"{}\",\"qty\":1}}", "x".repeat(200));
    let r = c
        .post("/items")
        .header("content-type", "application/json")
        .body(big)
        .send()
        .await;
    assert_eq!(r.status, 413);
}

#[tokio::test]
async fn query_repeated_keys_and_state() {
    let (app, _) = app();
    let c = app.client();
    let r = c.get("/search?page=2&tag=a&tag=b").send().await;
    assert_eq!(
        r.json::<serde_json::Value>(),
        serde_json::json!({"page": 2, "tags": ["a", "b"]})
    );
    let r = c.get("/search?page=x").send().await;
    assert_eq!(r.status, 400);
    let many = (0..300)
        .map(|i| format!("k{i}=v"))
        .collect::<Vec<_>>()
        .join("&");
    assert_eq!(
        c.get(&format!("/search?{many}")).send().await.status,
        400,
        "field-count ceiling"
    );
    assert_eq!(c.get("/greet").send().await.text(), "hi from state");
}

#[tokio::test]
async fn errors_hooks_and_raw_body() {
    let (app, _) = app();
    let c = app.client();
    let r = c.get("/fail").send().await;
    assert_eq!(r.status, 409);
    assert_eq!(r.json::<serde_json::Value>()["error"]["code"], "conflict");

    let r = c.get("/guarded").send().await;
    assert_eq!(r.status, 403);
    assert_eq!(
        r.header("x-stamped"),
        Some("yes"),
        "after hooks run on short-circuit responses"
    );
    let r = c.get("/guarded").header("x-allow", "1").send().await;
    assert_eq!(r.text(), "from-hook");
    assert_eq!(r.header("x-stamped"), Some("yes"));

    assert_eq!(
        c.put("/echo").body("raw body").send().await.text(),
        "raw body"
    );
}

#[tokio::test]
async fn error_mapper_rewrites_framework_errors_only() {
    let app = Core::builder()
        .state(AppState {
            counter: Counter::default(),
            greeting: Greeting("x"),
        })
        .map_errors(|e, _| (e.status, format!("mapped {}", e.code)).into_response())
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(c.get("/nope").send().await.text(), "mapped not_found");
    assert_eq!(
        c.get("/users/x").send().await.text(),
        "mapped invalid_path_param"
    );
    // Application errors are untouched.
    assert!(
        c.get("/fail")
            .send()
            .await
            .text()
            .contains("already exists")
    );
}

#[tokio::test]
async fn real_socket_semantics_and_graceful_shutdown() {
    let (app, _) = app();
    let server = app.bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr();

    let r = raw_http(
        addr,
        b"GET /users/5 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status_of(&r), 200);
    assert!(r.ends_with("user 5"), "{r}");

    // Malformed request line: hyper rejects it before routing.
    let r = raw_http(addr, b"GARBAGE\r\n\r\n").await;
    assert!(r.is_empty() || status_of(&r) == 400, "{r}");

    // Lying/oversized body without Content-Length (chunked) is cut off during collection.
    let chunk = "x".repeat(300);
    let req = format!(
        "POST /items HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{chunk}\r\n0\r\n\r\n",
        chunk.len()
    );
    assert_eq!(status_of(&raw_http(addr, req.as_bytes()).await), 413);

    // Declared Content-Length above the limit is rejected before reading.
    let req = "POST /items HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n";
    assert_eq!(status_of(&raw_http(addr, req.as_bytes()).await), 413);

    // HEAD over the wire.
    let r = raw_http(
        addr,
        b"HEAD /users/5 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status_of(&r), 200);
    assert!(r.to_ascii_lowercase().contains("content-length: 6"));
    assert!(!r.contains("user 5"));

    server.shutdown().await.unwrap();
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err(),
        "listener closed after shutdown"
    );
}

#[tokio::test]
async fn graceful_shutdown_waits_for_in_flight_requests() {
    #[poring::get("/slow")]
    async fn slow() -> &'static str {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        "done"
    }
    poring_app! { Slow { routes: [slow] } }
    let server = Slow::builder()
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let inflight = tokio::spawn(async move {
        raw_http(
            addr,
            b"GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    server.shutdown().await.unwrap();
    let r = inflight.await.unwrap();
    assert_eq!(status_of(&r), 200);
    assert!(r.ends_with("done"));
}

#[tokio::test]
async fn manifest_describes_routes() {
    let m = Core::manifest().unwrap();
    assert_eq!(m.app, "Core");
    let r = m.find("POST /items").unwrap();
    assert_eq!(r.id, "post_items");
    assert_eq!(r.policy.body_limit, 128);
    assert_eq!(r.policy.auth, "public");
    assert!(r.policy.implicit_public);
    assert_eq!(r.extractors.len(), 2);
    assert_eq!(r.extractors[1].ty, "Json<NewItem>");
    assert!(r.extractors[1].validates);
    let g = m.find("GET /guarded").unwrap();
    assert_eq!(g.hooks.before[0].name, "require_header");
    assert_eq!(g.hooks.after[0].name, "stamp");
}

#[tokio::test]
async fn repeated_scalar_query_key_policy() {
    let (app, _) = app();
    let r = app.client().get("/search?page=1&page=2").send().await;
    // A repeated key for a scalar field is rejected.
    assert_eq!(r.status, 400, "{}", r.text());
}
