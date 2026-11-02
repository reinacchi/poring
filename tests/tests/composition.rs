//! Groups, global/group/local hook ordering, plugins with scoped state.

use std::sync::{Arc, Mutex};

use poring::prelude::*;
use serde::{Deserialize, Serialize};

/// Shared event log for asserting hook order.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);
impl Log {
    fn push(&self, s: &str) {
        self.0.lock().unwrap().push(s.to_owned());
    }
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

#[derive(Clone, Default)]
struct Metrics(Arc<Mutex<u64>>);

#[derive(Clone, PoringState)]
struct AppState {
    log: Log,
    metrics: Metrics,
}

mod hooks {
    use super::*;

    #[poring::hook]
    pub async fn global_before(cx: &mut Ctx<'_, AppState>) {
        cx.state().log.push("global.before");
    }
    #[poring::hook]
    pub async fn global_after(cx: &Ctx<'_, AppState>, _res: &mut Response) {
        cx.state().log.push("global.after");
    }
    #[poring::hook]
    pub async fn group_before(cx: &mut Ctx<'_, AppState>) -> Result<(), ApiError> {
        cx.state().log.push("group.before");
        if cx.headers().contains_key("x-deny") {
            Err(ApiError::forbidden("denied by group hook"))
        } else {
            Ok(())
        }
    }
    #[poring::hook]
    pub async fn group_after(cx: &Ctx<'_, AppState>, res: &mut Response) {
        cx.state().log.push("group.after");
        res.headers_mut()
            .insert("x-group", HeaderValue::from_static("v1"));
    }
    #[poring::hook]
    pub async fn local_before(cx: &mut Ctx<'_, AppState>) {
        cx.state().log.push("local.before");
    }
    #[poring::hook]
    pub async fn local_after(cx: &Ctx<'_, AppState>, _res: &mut Response) {
        cx.state().log.push("local.after");
    }
}

/// A reusable plugin: generic over any app state that provides `Metrics`.
mod metrics_plugin {
    use super::*;

    #[poring::hook]
    pub async fn count<S: Send + Sync>(cx: &mut Ctx<'_, S>)
    where
        Metrics: FromRef<S>,
    {
        let m = Metrics::from_ref(cx.state());
        *m.0.lock().unwrap() += 1;
    }

    #[poring::get("/count")]
    pub async fn read(State(m): State<Metrics>) -> String {
        m.0.lock().unwrap().to_string()
    }

    #[poring::get("/")]
    pub async fn root() -> &'static str {
        "metrics root"
    }

    poring_plugin! {
        pub MetricsPlugin {
            prefix: "/metrics",
            policy: policy(rate_limit = "100/s"),
            before: [count],
            routes: [read, root],
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PoringSchema)]
struct Article {
    #[poring(min_length = 3)]
    title: String,
    tags: Vec<String>,
}

#[poring::get("/plain")]
async fn plain(State(log): State<Log>) -> &'static str {
    log.push("handler");
    "plain"
}

#[poring::post("/articles", before = [hooks::local_before], after = [hooks::local_after])]
async fn create_article(
    State(log): State<Log>,
    Json(a): Json<Article>,
) -> (StatusCode, Json<Article>) {
    log.push("handler");
    (StatusCode::CREATED, Json(a))
}

#[poring::get("/")]
async fn v1_root(State(log): State<Log>) -> &'static str {
    log.push("handler");
    "v1 root"
}

poring_app! {
    Composed {
        state: AppState,
        before: [hooks::global_before],
        after: [hooks::global_after],
        routes: [plain],
        groups: [
            group("/v1", before = [hooks::group_before], after = [hooks::group_after]) {
                routes: [create_article, v1_root],
            },
        ],
        plugins: [metrics_plugin::MetricsPlugin],
    }
}

fn app() -> (poring::App<Composed>, Log) {
    let log = Log::default();
    let app = Composed::builder()
        .state(AppState {
            log: log.clone(),
            metrics: Metrics::default(),
        })
        .build()
        .unwrap();
    (app, log)
}

#[tokio::test]
async fn hook_order_global_group_local() {
    let (app, log) = app();
    let c = app.client();
    let r = c
        .post("/v1/articles")
        .json(&serde_json::json!({"title": "Hello", "tags": ["a"]}))
        .send()
        .await;
    assert_eq!(r.status, 201, "{}", r.text());
    assert_eq!(r.header("x-group"), Some("v1"));
    assert_eq!(
        log.take(),
        [
            "global.before",
            "group.before",
            "local.before",
            "handler",
            "local.after",
            "group.after",
            "global.after"
        ]
    );
}

#[tokio::test]
async fn short_circuit_skips_handler_but_runs_after_hooks() {
    let (app, log) = app();
    let r = app.client().get("/v1").header("x-deny", "1").send().await;
    assert_eq!(r.status, 403);
    assert_eq!(r.header("x-group"), Some("v1"));
    assert_eq!(
        log.take(),
        [
            "global.before",
            "group.before",
            "group.after",
            "global.after"
        ]
    );
}

#[tokio::test]
async fn validation_rejection_runs_after_hooks_not_handler() {
    let (app, log) = app();
    let r = app
        .client()
        .post("/v1/articles")
        .json(&serde_json::json!({"title": "x", "tags": []}))
        .send()
        .await;
    assert_eq!(r.status, 422);
    assert_eq!(
        log.take(),
        [
            "global.before",
            "group.before",
            "local.before",
            "local.after",
            "group.after",
            "global.after"
        ]
    );
}

#[tokio::test]
async fn group_prefix_root_and_ungrouped_routes() {
    let (app, log) = app();
    let c = app.client();
    assert_eq!(
        c.get("/v1").send().await.text(),
        "v1 root",
        "`/v1` + `/` = `/v1`"
    );
    assert_eq!(c.get("/v1/").send().await.status, 404);
    assert_eq!(c.get("/plain").send().await.text(), "plain");
    assert_eq!(
        log.take(),
        [
            "global.before",
            "group.before",
            "handler",
            "group.after",
            "global.after",
            "global.before",
            "handler",
            "global.after"
        ]
    );
}

#[tokio::test]
async fn plugin_routes_hooks_state_and_policy() {
    let (app, log) = app();
    let c = app.client();
    assert_eq!(c.get("/metrics").send().await.text(), "metrics root");
    // The plugin's `count` hook ran for both requests (including this one, before the handler).
    assert_eq!(c.get("/metrics/count").send().await.text(), "2");
    // Global hooks wrap plugin routes too.
    assert_eq!(
        log.take(),
        [
            "global.before",
            "global.after",
            "global.before",
            "global.after"
        ]
    );
    let m = Composed::manifest().unwrap();
    let r = m.find("GET /metrics/count").unwrap();
    assert_eq!(r.group.as_deref(), Some("MetricsPlugin"));
    assert_eq!(r.policy.rate_limit.as_ref().unwrap().requests, 100);
    assert_eq!(
        r.hooks
            .before
            .iter()
            .map(|h| h.scope.as_str())
            .collect::<Vec<_>>(),
        ["global", "plugin"]
    );
}
