//! Everything in one server: a native typed-JSON route behind enforced security, a static
//! trace graph, and a live (hot-reloadable) Wasm guest route behind the same policy pipeline.
//!
//! ```text
//! cargo run -p poring-examples --example wasm_live -- --watch target/demo-guest.wat
//! curl -H 'authorization: Bearer demo' -X POST localhost:3000/orders \
//!      -H 'content-type: application/json' -d '{"sku":"plush","qty":2}'
//! curl -H 'authorization: Bearer demo' localhost:3000/guest/anything
//! # edit target/demo-guest.wat (or: cargo poring wasm new-echo --name orders-guest --version 2 -o target/demo-guest.wat)
//! curl localhost:3000/__graph            # Mermaid: static graph (rendered at startup)
//! ```
//! Without `--watch`, the guest only changes through the manual rollout API (production mode).
use std::path::PathBuf;

use poring::descriptor::Method;
use poring::dynamic::DynPolicy;
use poring::flow::FlowConfig;
use poring::prelude::*;
use poring::wasm::guest_kit::GuestSpec;
use poring::wasm::{GuestConfig, GuestRoute, GuestSlot, WasmHost};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct Tokens;
impl Authenticator for Tokens {
    async fn authenticate(&self, r: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        match r.bearer_token() {
            Some("demo") => Ok(Some(
                Identity::new("demo", Credential::Bearer)
                    .with_scopes(["orders:write", "guest:call"]),
            )),
            Some(_) => Err(AuthError::Invalid),
            None => Ok(None),
        }
    }
}

#[derive(Deserialize, PoringSchema)]
struct NewOrder {
    #[poring(min_length = 1, max_length = 40)]
    sku: String,
    #[poring(minimum = 1, maximum = 10)]
    qty: u8,
}

#[derive(Serialize, PoringSchema)]
struct OrderAccepted {
    sku: String,
    qty: u8,
    by: String,
}

/// Native, compile-time-verified route.
#[poring::post("/orders", policy(scopes = ["orders:write"], body_limit = "1KiB", rate_limit = "20/s"))]
async fn create_order(
    Principal(who): Principal<Authenticated>,
    Json(o): Json<NewOrder>,
) -> (StatusCode, Json<OrderAccepted>) {
    (
        StatusCode::CREATED,
        Json(OrderAccepted {
            sku: o.sku,
            qty: o.qty,
            by: who.subject.clone(),
        }),
    )
}

#[derive(Clone)]
struct Graph(std::sync::Arc<std::sync::OnceLock<String>>);

#[derive(Clone, PoringState)]
struct AppState {
    graph: Graph,
}

/// Static flow graph of the app as rendered at startup (Mermaid). The live guest version is
/// always available from `App::manifest()` / the `x-poring-guest` header.
#[poring::get(
    "/__graph",
    public(reason = "development introspection; contains declarations only")
)]
async fn graph(State(g): State<Graph>) -> String {
    g.0.get().cloned().unwrap_or_default()
}

poring_app! {
    LiveApp {
        state: AppState,
        auth: Tokens,
        defaults: policy(deny_anonymous),
        routes: [create_order, graph],
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    poring::dump_manifest_if_requested::<LiveApp>();
    tracing_subscriber::fmt().with_env_filter("info").init();
    let args: Vec<String> = std::env::args().collect();
    let watch_path = args
        .iter()
        .position(|a| a == "--watch")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    let guest_path = watch_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("target/demo-guest.wat"));
    if !guest_path.exists() {
        if let Some(dir) = guest_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&guest_path, GuestSpec::echo("orders-guest", "1").core_wat())?;
    }
    let host = WasmHost::new()?;
    let bytes = poring::wasm::watch::read_artefact(&guest_path)?;
    let slot = GuestSlot::new(host, GuestConfig::new("orders-guest"), &bytes)?;
    let policy = DynPolicy {
        scopes: vec!["guest:call".into()],
        body_limit: Some(4096),
        ..Default::default()
    };
    let graph = Graph(Default::default());
    let app = LiveApp::builder()
        .state(AppState {
            graph: graph.clone(),
        })
        .authenticator(Tokens)
        .flow_recording(FlowConfig {
            sample_every: 1,
            capacity: 64,
        })
        .mount_dynamic(GuestRoute::mount(
            slot.clone(),
            Method::Get,
            "/guest/{*rest}",
            policy,
        ))
        .build()?;
    let _ = graph.0.set(poring::contract::render_mermaid(
        &app.graph(None).ok_or("graph")?,
    ));
    // The development watcher is opt-in: `--watch <path>`.
    let _watch = match &watch_path {
        Some(p) => Some(poring::wasm::watch::watch(
            slot.clone(),
            p,
            Default::default(),
        )?),
        None => None,
    };
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, pid = std::process::id(), guest = %slot.current().version, watching = watch_path.is_some(), "wasm_live listening");
    app.serve(listener, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
