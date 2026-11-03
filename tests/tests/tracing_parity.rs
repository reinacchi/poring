//! Tracing must not change responses, and the request span and event must record the route
//! and status without the query string.
//!
//! This test has a binary of its own on purpose. `tracing` caches, per call site and for the
//! whole process, whether any subscriber is interested. Tests running in parallel threads
//! of the same binary hit Poring's call sites with no subscriber installed, so a subscriber
//! installed by one test can miss them. With a single test per process, the subscriber is
//! installed before anything else can register those call sites with no subscriber present.

use std::sync::{Arc, Mutex};

use poring::prelude::*;
use poring_tests::raw_http;

async fn path(Path(id): Path<u64>) -> String {
    id.to_string()
}

fn app() -> poring::FluentApp {
    Poring::new().get("/bench/path/{id}", path).build().unwrap()
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Status, headers (minus the per-request ID) and body.
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

#[tokio::test(flavor = "current_thread")]
async fn tracing_does_not_change_responses_and_records_the_route() {
    let out = Captured::default();
    let writer = out.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let traced_app = app();
    let server = app().bind("127.0.0.1:0").await.unwrap();
    let raw = raw_http(
        server.local_addr(),
        b"GET /bench/path/5?secret=1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    let traced = traced_app.client().get("/bench/path/5").send().await;
    server.shutdown().await.unwrap();
    drop(_guard);

    let untraced = app().client().get("/bench/path/5").send().await;
    assert_eq!(shape(&untraced), shape(&traced));
    assert!(raw.ends_with("\r\n\r\n5"), "{raw}");

    let log = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
    let route = traced_app.manifest().routes[0].id.clone();
    assert!(
        log.contains("poring.request"),
        "request span missing:\n{log}"
    );
    assert!(
        log.contains(&format!("route=\"{route}\"")) || log.contains(&format!("route={route}")),
        "route missing:\n{log}"
    );
    assert!(log.contains("status=200"), "status missing:\n{log}");
    assert!(
        !log.contains("secret"),
        "query strings are never recorded:\n{log}"
    );
}
