//! The attribute-free fluent API: handlers, extractors, state, groups, hooks, mixed
//! registration, contracts, real sockets and `run()`.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use poring::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PoringSchema, PartialEq)]
struct Message {
    #[poring(min_length = 1, max_length = 20)]
    text: String,
}

#[derive(Deserialize, PoringSchema)]
struct Page {
    page: u32,
    #[poring(maximum = 50)]
    per_page: Option<u32>,
}

async fn named(Path(name): Path<String>) -> String {
    format!("Hello, {name}!")
}

fn quickstart() -> poring::FluentApp {
    // The same routes as examples/quickstart.rs (the README quickstart).
    Poring::new()
        .get("/", || async { "Hello, Poring!" })
        .get("/hello/{name}", |Path(name): Path<String>| async move {
            format!("Hello, {name}!")
        })
        .build()
        .unwrap()
}

#[tokio::test]
async fn readme_quickstart_routes_respond_as_documented() {
    let app = quickstart();
    let c = app.client();
    let r = c.get("/").send().await;
    assert_eq!(r.status, 200);
    assert_eq!(r.text(), "Hello, Poring!");
    assert_eq!(r.header("content-type"), Some("text/plain; charset=utf-8"));
    assert_eq!(c.get("/hello/Reina").send().await.text(), "Hello, Reina!");
    assert_eq!(
        c.get("/hello/R%C3%A9ina%20C").send().await.text(),
        "Hello, Réina C!",
        "percent-decoded"
    );
    let bad = c.get("/hello/%FF").send().await;
    assert_eq!(bad.status, 400, "malformed percent-encoding is rejected");
    assert_eq!(c.get("/hello").send().await.status, 404);
}

#[tokio::test]
async fn async_json_echo_and_validation() {
    let app = Poring::new()
        .get("/ping", || async { "pong" })
        .post("/echo", |Json(message): Json<Message>| async move {
            Json(message)
        })
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(c.get("/ping").send().await.text(), "pong");
    let r = c
        .post("/echo")
        .json(&Message { text: "hi".into() })
        .send()
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.json::<Message>(), Message { text: "hi".into() });
    let invalid = c
        .post("/echo")
        .json(&Message {
            text: String::new(),
        })
        .send()
        .await;
    assert_eq!(invalid.status, 422);
    assert_eq!(
        invalid.json::<serde_json::Value>()["error"]["issues"][0]["rule"],
        "min_length"
    );
    let wrong_type = c
        .post("/echo")
        .header("content-type", "text/plain")
        .body("hi")
        .send()
        .await;
    assert_eq!(wrong_type.status, 415);
    let malformed = c
        .post("/echo")
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await;
    assert_eq!(malformed.status, 400);
}

#[tokio::test]
async fn every_method_and_response_conversion() {
    let app = Poring::new()
        .get("/r", || async { "get" })
        .post("/r", || async { (StatusCode::CREATED, "post") })
        .put("/r", || async { String::from("put") })
        .patch("/r", || async { Html("<b>patch</b>") })
        .delete("/r", || async { StatusCode::NO_CONTENT })
        .options("/r", || async {
            (
                StatusCode::OK,
                [(poring::http::header::ALLOW, HeaderValue::from_static("GET"))],
                "",
            )
        })
        .get("/fallible/{n}", |Path(n): Path<u32>| async move {
            if n == 0 {
                Err(ApiError::not_found("zero"))
            } else {
                Ok(format!("n={n}"))
            }
        })
        .get("/redirect", || async { Redirect::to("/r") })
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(c.get("/r").send().await.text(), "get");
    let p = c.post("/r").send().await;
    assert_eq!(p.status, 201);
    assert_eq!(p.text(), "post");
    assert_eq!(
        c.request(poring::Method::PUT, "/r").send().await.text(),
        "put"
    );
    let h = c.request(poring::Method::PATCH, "/r").send().await;
    assert_eq!(h.header("content-type"), Some("text/html; charset=utf-8"));
    assert_eq!(
        c.request(poring::Method::DELETE, "/r").send().await.status,
        204
    );
    assert_eq!(
        c.request(poring::Method::OPTIONS, "/r")
            .send()
            .await
            .header("allow"),
        Some("GET")
    );
    assert_eq!(c.get("/fallible/2").send().await.text(), "n=2");
    assert_eq!(c.get("/fallible/0").send().await.status, 404);
    assert_eq!(
        c.get("/fallible/x").send().await.status,
        400,
        "typed path parameter"
    );
    assert_eq!(
        c.get("/redirect").send().await.header("location"),
        Some("/r")
    );
}

#[tokio::test]
async fn head_options_404_and_405_follow_http_semantics() {
    let app = quickstart();
    let c = app.client();
    let head = c.request(poring::Method::HEAD, "/").send().await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(head.header("content-length"), Some("14"));
    let opts = c.request(poring::Method::OPTIONS, "/").send().await;
    assert_eq!(opts.status, 204);
    assert_eq!(opts.header("allow"), Some("GET, HEAD, OPTIONS"));
    let not_allowed = c.post("/").send().await;
    assert_eq!(not_allowed.status, 405);
    assert_eq!(not_allowed.header("allow"), Some("GET, HEAD, OPTIONS"));
    assert_eq!(c.get("/missing").send().await.status, 404);
}

#[derive(Clone, Default)]
struct Counter(Arc<AtomicUsize>);

#[derive(Clone, Default, PoringState)]
struct AppState {
    counter: Counter,
    greeting: Greeting,
}

#[derive(Clone)]
struct Greeting(&'static str);

impl Default for Greeting {
    fn default() -> Self {
        Greeting("Hi")
    }
}

async fn bump(State(c): State<Counter>) -> String {
    (c.0.fetch_add(1, Ordering::SeqCst) + 1).to_string()
}

#[tokio::test]
async fn multiple_extractors_state_and_captured_values() {
    let suffix = Arc::new(String::from("!"));
    let app = Poring::with_state(AppState::default())
        .post("/bump", bump)
        .get("/greet/{name}", {
            let suffix = suffix.clone();
            move |State(g): State<Greeting>,
                  Path(name): Path<String>,
                  Query(q): Query<Page>,
                  h: HeaderMap| {
                let suffix = suffix.clone();
                async move {
                    let agent = h
                        .get("x-agent")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-")
                        .to_owned();
                    format!(
                        "{} {name}{suffix} page={} per={:?} agent={agent}",
                        g.0, q.page, q.per_page
                    )
                }
            }
        })
        .post(
            "/files/{dir}/{name}",
            |Path((dir, name)): Path<(String, String)>,
             State(c): State<Counter>,
             method: poring::Method,
             body: Bytes| async move {
                format!(
                    "{method} {dir}/{name} {} bytes, count={}",
                    body.len(),
                    c.0.load(Ordering::SeqCst)
                )
            },
        )
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(c.post("/bump").send().await.text(), "1");
    assert_eq!(c.post("/bump").send().await.text(), "2");
    let r = c
        .get("/greet/Reina?page=2&per_page=10")
        .header("x-agent", "t")
        .send()
        .await;
    assert_eq!(r.text(), "Hi Reina! page=2 per=Some(10) agent=t");
    assert_eq!(
        c.get("/greet/Reina?page=x").send().await.status,
        400,
        "query type mismatch"
    );
    assert_eq!(
        c.get("/greet/Reina?page=1&per_page=99").send().await.status,
        422,
        "query validation"
    );
    let f = c.post("/files/a/b.txt").body("hello").send().await;
    assert_eq!(f.text(), "POST a/b.txt 5 bytes, count=2");
}

#[tokio::test]
async fn body_limits_apply_to_fluent_body_extractors() {
    let app = Poring::new()
        .policy(Policy::new().body_limit(64))
        .post("/small", |b: Bytes| async move { b.len().to_string() })
        .route_with(
            RouteMethod::Post,
            "/tiny",
            Policy::new().body_limit(4),
            |b: String| async move { b },
        )
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(
        c.post("/small").body(vec![b'a'; 64]).send().await.text(),
        "64"
    );
    assert_eq!(
        c.post("/small").body(vec![b'a'; 65]).send().await.status,
        413
    );
    assert_eq!(c.post("/tiny").body("abcd").send().await.text(), "abcd");
    assert_eq!(c.post("/tiny").body("abcde").send().await.status, 413);
    let raise = Poring::new()
        .policy(Policy::new().body_limit(64))
        .route_with(
            RouteMethod::Post,
            "/big",
            Policy::new().body_limit(65),
            |b: Bytes| async move { b.len().to_string() },
        )
        .build();
    assert!(
        raise
            .unwrap_err()
            .to_string()
            .contains("limits may only be narrowed")
    );
}

#[tokio::test]
async fn groups_compose_prefixes_policies_and_hook_order() {
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let (l1, l2, l3, l4, l5) = (
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
    );
    let app = Poring::new()
        .before(move |cx: &mut Ctx<'_, ()>| {
            l1.lock()
                .unwrap()
                .push(format!("app-before {}", cx.route_id()))
        })
        .after(move |_cx, _res| l2.lock().unwrap().push("app-after".into()))
        .get("/", || async { "root" })
        .group("/api", move |api| {
            api.before(move |_cx| l3.lock().unwrap().push("group-before".into()))
                .after(move |_cx, res| {
                    l4.lock().unwrap().push("group-after".into());
                    res.headers_mut()
                        .insert("x-group", HeaderValue::from_static("api"));
                })
                .get("/", move || {
                    let l5 = l5.clone();
                    async move {
                        l5.lock().unwrap().push("handler".into());
                        "api root"
                    }
                })
                .get("/v1/ping", || async { "pong" })
        })
        .build()
        .unwrap();
    let c = app.client();
    let r = c.get("/api").send().await;
    assert_eq!(r.text(), "api root");
    assert_eq!(r.header("x-group"), Some("api"));
    assert_eq!(
        *log.lock().unwrap(),
        [
            "app-before get_api",
            "group-before",
            "handler",
            "group-after",
            "app-after"
        ],
        "global, group, handler, group, global"
    );
    log.lock().unwrap().clear();
    assert_eq!(c.get("/").send().await.text(), "root");
    assert_eq!(
        *log.lock().unwrap(),
        ["app-before get_root", "app-after"],
        "ungrouped routes skip group hooks"
    );
    assert_eq!(c.get("/api/v1/ping").send().await.text(), "pong");
    assert_eq!(
        c.get("/api/").send().await.status,
        404,
        "no trailing-slash folding"
    );
    let ids: Vec<String> = app.manifest().routes.iter().map(|r| r.id.clone()).collect();
    assert_eq!(
        ids,
        ["get_root", "get_api", "get_api_v1_ping"],
        "registration order is preserved"
    );
}

#[tokio::test]
async fn before_hook_short_circuits_but_after_hooks_run() {
    let ran = Arc::new(AtomicUsize::new(0));
    let (r1, r2) = (ran.clone(), ran.clone());
    let app = Poring::new()
        .before(|cx: &mut Ctx<'_, ()>| {
            if cx.headers().contains_key("x-block") {
                Err(ApiError::forbidden("blocked"))
            } else {
                Ok(())
            }
        })
        .after(move |_cx, res| {
            r1.fetch_add(1, Ordering::SeqCst);
            res.headers_mut()
                .insert("x-after", HeaderValue::from_static("1"));
        })
        .get("/", move || {
            let r2 = r2.clone();
            async move {
                r2.fetch_add(100, Ordering::SeqCst);
                "handled"
            }
        })
        .build()
        .unwrap();
    let c = app.client();
    let blocked = c.get("/").header("x-block", "1").send().await;
    assert_eq!(blocked.status, 403);
    assert_eq!(blocked.header("x-after"), Some("1"));
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "handler skipped, after hook ran"
    );
    assert_eq!(c.get("/").send().await.text(), "handled");
    assert_eq!(ran.load(Ordering::SeqCst), 102);
}

mod mixed {
    use poring::prelude::*;

    #[poring::get("/macro")]
    pub async fn from_macro(State(n): State<u32>) -> String {
        format!("macro {n}")
    }

    #[poring::hook]
    pub async fn tag(_cx: &Ctx<'_, u32>, res: &mut Response) {
        res.headers_mut()
            .insert("x-global", HeaderValue::from_static("after"));
    }

    poring_app! {
        pub Mixed {
            state: u32,
            after: [tag],
            routes: [from_macro],
        }
    }
}

#[tokio::test]
async fn macro_apps_can_mount_fluent_routes_with_global_hooks() {
    let app = mixed::Mixed::builder()
        .state(7)
        .get("/fluent", |State(n): State<u32>| async move {
            format!("fluent {n}")
        })
        .group("/g", |g| g.get("/x", || async { "grouped" }))
        .build()
        .unwrap();
    let c = app.client();
    assert_eq!(c.get("/macro").send().await.text(), "macro 7");
    let f = c.get("/fluent").send().await;
    assert_eq!(f.text(), "fluent 7");
    assert_eq!(
        f.header("x-global"),
        Some("after"),
        "global macro hook runs"
    );
    assert_eq!(c.get("/g/x").send().await.text(), "grouped");
    let m = app.manifest();
    let kinds: Vec<_> = m.routes.iter().map(|r| (r.path.as_str(), r.kind)).collect();
    use poring::contract::RouteKind::{Native, Static};
    assert_eq!(
        kinds,
        [("/macro", Static), ("/fluent", Native), ("/g/x", Native)]
    );
    assert_eq!(m.routes[1].hooks.after[0].name, "tag");
    let dup = mixed::Mixed::builder()
        .state(1)
        .get("/macro", || async { "again" })
        .build();
    assert!(
        dup.unwrap_err().to_string().contains("registered twice"),
        "fluent routes cannot shadow macro routes"
    );
}

#[tokio::test]
async fn manifests_ids_graphs_and_traces_cover_fluent_routes() {
    let app = Poring::new()
        .name("demo")
        .flow_recording(poring::flow::FlowConfig {
            sample_every: 1,
            capacity: 16,
        })
        .get("/hello/{name}", named)
        .post("/echo", |Json(m): Json<Message>| async move { Json(m) })
        .build()
        .unwrap();
    let m = app.manifest();
    assert_eq!(m.app, "demo");
    let hello = &m.routes[0];
    assert_eq!(hello.id, "get_hello_name");
    assert_eq!(hello.handler, "named");
    assert_eq!(hello.kind, poring::contract::RouteKind::Native);
    assert!(
        hello.source.file.ends_with("tests/tests/fluent.rs"),
        "{}",
        hello.source.file
    );
    assert_eq!(hello.extractors[0].ty, "Path<String>");
    let echo = &m.routes[1];
    assert_eq!(
        echo.handler, "post_echo",
        "closures are named after their route"
    );
    assert!(echo.extractors[0].validates && echo.extractors[0].consumes_body);
    assert_eq!(echo.policy.checks, ["body_gate"]);

    let graph = app.graph(None).expect("graph");
    let mermaid = poring::contract::render_mermaid(&graph);
    assert!(mermaid.contains("handler post_echo"), "{mermaid}");
    let nodes: BTreeSet<&str> = graph.nodes.iter().map(|n| n.id.as_str()).collect();
    let edges: BTreeSet<(&str, &str)> = graph
        .edges
        .iter()
        .map(|e| (e.from.as_str(), e.to.as_str()))
        .collect();
    let c = app.client();
    c.post("/echo")
        .json(&Message {
            text: String::new(),
        })
        .send()
        .await;
    c.post("/echo")
        .json(&Message { text: "ok".into() })
        .send()
        .await;
    c.get("/hello/x").send().await;
    let traces = app.flow().recent();
    assert_eq!(traces.len(), 3);
    assert_eq!(traces[0].route.as_deref(), Some("post_echo"));
    assert_eq!(traces[0].status, 422);
    assert_eq!(
        traces[1].path(),
        [
            "receive",
            "match",
            "post_echo.body_gate",
            "post_echo.extract.0",
            "post_echo.validate.0",
            "post_echo.handler",
            "post_echo.respond",
            "send"
        ]
    );
    for t in &traces {
        for n in t.path() {
            assert!(
                nodes.contains(n),
                "runtime node `{n}` is in the static graph"
            );
        }
        for w in t.path().windows(2) {
            assert!(
                edges.contains(&(w[0], w[1])),
                "runtime transition {} -> {} is in the static graph",
                w[0],
                w[1]
            );
        }
    }
}

#[tokio::test]
async fn openapi_and_typescript_client_from_fluent_routes() {
    let app = Poring::new()
        .get("/hello/{name}", named)
        .get("/items", |Query(p): Query<Page>| async move {
            format!("{}", p.page)
        })
        .post("/echo", |Json(m): Json<Message>| async move {
            (StatusCode::CREATED, Json(m))
        })
        .build()
        .unwrap();
    let doc = app.openapi(&poring::openapi::Info::new("Fluent", "1.0.0"));
    let hello = &doc["paths"]["/hello/{name}"]["get"];
    assert_eq!(hello["operationId"], "named");
    assert_eq!(hello["parameters"][0]["name"], "name");
    assert_eq!(
        hello["responses"]["200"]["content"]["text/plain"]["schema"]["type"],
        "string"
    );
    let items = &doc["paths"]["/items"]["get"]["parameters"];
    assert!(
        items
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "per_page" && p["in"] == "query")
    );
    let echo = &doc["paths"]["/echo"]["post"];
    assert_eq!(
        echo["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/Message"
    );
    assert!(echo["responses"]["default"]["content"]["application/json"].is_object());
    assert!(echo["responses"]["422"].is_object());
    assert_eq!(
        doc,
        app.openapi(&poring::openapi::Info::new("Fluent", "1.0.0")),
        "deterministic"
    );
    let ts = poring::openapi::typescript_client(&doc);
    assert!(
        ts.contains("export type Message = { text: string }"),
        "{ts}"
    );
    assert!(
        ts.contains("named: (args: { path: { name: string }"),
        "{ts}"
    );
}

#[tokio::test]
async fn real_sockets_concurrency_and_graceful_shutdown() {
    let started = Arc::new(tokio::sync::Notify::new());
    let signal = started.clone();
    let app = Poring::new()
        .get("/slow", move || {
            let signal = signal.clone();
            async move {
                signal.notify_one();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                "done"
            }
        })
        .get("/fast/{n}", |Path(n): Path<u32>| async move {
            (n * 2).to_string()
        })
        .build()
        .unwrap();
    let server = app.bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr();
    let mut tasks = Vec::new();
    for n in 0..32u32 {
        tasks.push(tokio::spawn(async move {
            let raw = poring_tests::raw_http(
                addr,
                format!("GET /fast/{n} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await;
            (
                poring_tests::status_of(&raw),
                raw.ends_with(&(n * 2).to_string()),
            )
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), (200, true));
    }
    let raw = poring_tests::raw_http(
        addr,
        b"DELETE /fast/1 HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(poring_tests::status_of(&raw), 405);
    let raw = poring_tests::raw_http(
        addr,
        b"GET /nope HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(poring_tests::status_of(&raw), 404);
    let in_flight = tokio::spawn(async move {
        poring_tests::raw_http(
            addr,
            b"GET /slow HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
        )
        .await
    });
    // Shut down once the slow request is inside its handler.
    started.notified().await;
    server.shutdown().await.unwrap();
    let raw = in_flight.await.unwrap();
    assert!(
        raw.starts_with("HTTP/1.1 200") && raw.ends_with("done"),
        "in-flight request completed: {raw}"
    );
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err(),
        "listener closed after shutdown"
    );
}

#[test]
fn run_reports_bind_errors() {
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = blocker.local_addr().unwrap();
    let err = Poring::new()
        .get("/", || async { "x" })
        .run(addr)
        .unwrap_err();
    assert!(matches!(err, poring::StartupError::Io(_)), "{err:?}");
}

#[test]
fn run_reports_configuration_errors_before_starting() {
    let err = Poring::new()
        .get("/a", || async { "1" })
        .get("/a", || async { "2" })
        .run("127.0.0.1:0")
        .unwrap_err();
    assert!(err.to_string().contains("registered twice"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_inside_a_runtime_is_an_error_not_a_panic() {
    let err = Poring::new()
        .get("/", || async { "x" })
        .run("127.0.0.1:0")
        .unwrap_err();
    assert!(matches!(err, poring::StartupError::NestedRuntime));
    assert!(err.to_string().contains(".listen(addr).await"));
}

#[tokio::test(flavor = "current_thread")]
async fn run_inside_a_current_thread_runtime_is_an_error_too() {
    let err = Poring::new().run("127.0.0.1:0").unwrap_err();
    assert!(matches!(err, poring::StartupError::NestedRuntime));
}

#[test]
fn state_must_be_supplied_before_routes() {
    let err = Poring::new()
        .get("/", || async { "x" })
        .state(5u8)
        .build()
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("`.state(..)` was called after routes"),
        "{err}"
    );
    assert!(
        Poring::new()
            .state(5u8)
            .get("/", |State(n): State<u8>| async move { n.to_string() })
            .build()
            .is_ok()
    );
}
