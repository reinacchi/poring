//! Static flow graph + runtime traces keyed by the same node IDs.
//!
//! ```text
//! cargo run -p poring-examples --example tracing_graph            # writes target/poring-graphs/*.mmd
//! RUST_LOG=poring::flow=trace cargo run -p poring-examples --example tracing_graph
//! cargo poring graph --example tracing_graph -p poring-examples --format dot
//! ```
use poring::contract::{build_graph, render_mermaid, render_mermaid_with_trace};
use poring::flow::FlowConfig;
use poring::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct Tokens;
impl Authenticator for Tokens {
    async fn authenticate(&self, r: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(match r.bearer_token() {
            Some("demo") => {
                Some(Identity::new("demo", Credential::Bearer).with_scopes(["orders:write"]))
            }
            Some(_) => return Err(AuthError::Invalid),
            None => None,
        })
    }
}

#[derive(Deserialize, Serialize, PoringSchema)]
struct Order {
    #[poring(min_length = 1)]
    sku: String,
    #[poring(minimum = 1, maximum = 10)]
    qty: u8,
}

/// Places an order.
#[poring::post("/orders", policy(scopes = ["orders:write"], body_limit = "2KiB"), annotate = ["db: insert order", "queue: publish OrderPlaced"])]
async fn place(
    Principal(who): Principal<Authenticated>,
    Json(o): Json<Order>,
) -> (StatusCode, String) {
    (
        StatusCode::CREATED,
        format!("{} ordered {} x {}", who.subject, o.qty, o.sku),
    )
}

poring_app! {
    Shop {
        auth: Tokens,
        routes: [place],
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    poring::dump_manifest_if_requested::<Shop>();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()))
        .init();
    let app = Shop::builder()
        .authenticator(Tokens)
        .flow_recording(FlowConfig {
            sample_every: 1,
            capacity: 16,
        })
        .build()?;
    let c = app.client();
    c.post("/orders")
        .bearer("demo")
        .json(&serde_json::json!({"sku": "poring-plush", "qty": 2}))
        .send()
        .await;
    c.post("/orders")
        .json(&serde_json::json!({"sku": "x", "qty": 1}))
        .send()
        .await;
    c.post("/orders")
        .bearer("demo")
        .json(&serde_json::json!({"sku": "", "qty": 99}))
        .send()
        .await;

    let out = std::path::Path::new("target/poring-graphs");
    std::fs::create_dir_all(out)?;
    let g = build_graph(&app.manifest(), Some("POST /orders")).ok_or("route missing")?;
    std::fs::write(out.join("orders.static.mmd"), render_mermaid(&g))?;
    for (i, t) in app.flow().recent().iter().enumerate() {
        let name = format!("orders.trace{i}.{}.mmd", t.status);
        std::fs::write(out.join(&name), render_mermaid_with_trace(&g, t))?;
        println!(
            "trace {i} (status {}, {} us): {}",
            t.status,
            t.total_us,
            t.path().join(" -> ")
        );
    }
    println!("wrote Mermaid files to {}", out.display());
    Ok(())
}
