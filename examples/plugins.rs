//! Composition: groups, global/group hooks, typed state, a reusable plugin, validation,
//! typed responses, and contract export.
//!
//! ```text
//! cargo run -p poring-examples --example plugins              # serve on :3000
//! cargo run -p poring-examples --example plugins -- --openapi # print OpenAPI 3.1
//! cargo run -p poring-examples --example plugins -- --ts      # print TypeScript client
//! ```
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use poring::prelude::*;
use serde::{Deserialize, Serialize};

/// A reusable plugin. It works in any app whose state provides `Hits`.
mod hits {
    use super::*;

    /// Shared counter.
    #[derive(Clone, Default)]
    pub struct Hits(pub Arc<AtomicU64>);

    /// Counts requests routed to the plugin.
    #[poring::hook]
    pub async fn count<S: Send + Sync>(cx: &mut Ctx<'_, S>)
    where
        Hits: FromRef<S>,
    {
        Hits::from_ref(cx.state()).0.fetch_add(1, Ordering::Relaxed);
    }

    /// Current hit count.
    #[poring::get("/")]
    pub async fn read(State(h): State<Hits>) -> Json<u64> {
        Json(h.0.load(Ordering::Relaxed))
    }

    poring_plugin! {
        /// `/stats` plugin.
        pub HitsPlugin {
            prefix: "/stats",
            policy: policy(rate_limit = "20/s"),
            before: [count],
            routes: [read],
        }
    }
}

#[derive(Clone)]
struct Config {
    greeting: &'static str,
}

#[derive(Clone, PoringState)]
struct AppState {
    config: Config,
    hits: hits::Hits,
}

/// A greeting request.
#[derive(Deserialize, PoringSchema)]
struct GreetReq {
    /// Who to greet (1-32 printable ASCII chars).
    #[poring(min_length = 1, max_length = 32, ascii)]
    name: String,
    /// Repeat count (1-5).
    #[poring(minimum = 1, maximum = 5)]
    times: Option<u8>,
}

/// A greeting.
#[derive(Serialize, PoringSchema)]
struct Greeting {
    message: String,
}

/// Logs every request.
#[poring::hook]
async fn log_request(cx: &mut Ctx<'_, AppState>) {
    tracing::info!(route = cx.route_id(), request_id = %cx.request_id(), "request");
}

/// Adds the API version to v1 responses.
#[poring::hook]
async fn v1_header(_cx: &Ctx<'_, AppState>, res: &mut Response) {
    res.headers_mut()
        .insert("x-api-version", HeaderValue::from_static("1"));
}

/// Greets someone.
#[poring::post("/greet", policy(body_limit = "1KiB"))]
async fn greet(State(cfg): State<Config>, Json(req): Json<GreetReq>) -> Json<Greeting> {
    let one = format!("{}, {}!", cfg.greeting, req.name);
    Json(Greeting {
        message: vec![one; usize::from(req.times.unwrap_or(1))].join(" "),
    })
}

/// Health check.
#[poring::get("/health")]
async fn health() -> &'static str {
    "ok"
}

poring_app! {
    Composed {
        state: AppState,
        before: [log_request],
        routes: [health],
        groups: [
            group("/v1", after = [v1_header]) { routes: [greet] },
        ],
        plugins: [hits::HitsPlugin],
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let info = poring::openapi::Info::new("Composed example", "1.0.0");
    match std::env::args().nth(1).as_deref() {
        Some("--openapi") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&poring::openapi::openapi::<Composed>(&info)?)?
            );
            return Ok(());
        }
        Some("--ts") => {
            print!(
                "{}",
                poring::openapi::typescript_client(&poring::openapi::openapi::<Composed>(&info)?)
            );
            return Ok(());
        }
        _ => {}
    }
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    Composed::builder()
        .state(AppState {
            config: Config { greeting: "Hello" },
            hits: hits::Hits::default(),
        })
        .listen(addr)
        .await?;
    Ok(())
}
