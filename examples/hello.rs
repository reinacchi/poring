//! Minimal Poring app: `cargo run -p poring-examples --example hello`, then
//! `curl localhost:3000/` and `curl localhost:3000/hello/world`.
use poring::prelude::*;

/// Plain-text root.
#[poring::get("/")]
async fn index() -> &'static str {
    "Hello from Poring"
}

/// Greets by name (percent-decoded path parameter).
#[poring::get("/hello/{name}")]
async fn hello(Path(name): Path<String>) -> String {
    format!("hello, {name}")
}

poring_app! {
    pub Hello {
        routes: [index, hello],
    }
}

#[tokio::main]
async fn main() -> Result<(), poring::StartupError> {
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    Hello::builder().listen(addr).await
}
