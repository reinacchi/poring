//! The README quickstart (kept identical by `tests/tests/readme.rs`).
use poring::prelude::*;

fn main() -> Result<(), poring::StartupError> {
    Poring::new()
        .get("/", || async { "Hello, Poring!" })
        .get("/hello/{name}", |Path(name): Path<String>| async move { format!("Hello, {name}!") })
        .run("127.0.0.1:3000")
}
