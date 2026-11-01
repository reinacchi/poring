//! The README attribute-macro example (kept identical by `tests/tests/readme.rs`).
use poring::prelude::*;

#[poring::get("/")]
async fn index() -> &'static str {
    "Hello, Poring!"
}

#[poring::get("/hello/{name}")]
async fn hello(Path(name): Path<String>) -> String {
    format!("Hello, {name}!")
}

poring_app! {
    pub Api {
        routes: [index, hello],
    }
}

#[tokio::main]
async fn main() -> Result<(), poring::StartupError> {
    Api::builder().listen("127.0.0.1:3000").await
}
