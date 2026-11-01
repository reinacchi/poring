use poring::prelude::*;

#[derive(Clone)]
struct Db;

async fn list(State(_db): State<Db>) -> &'static str {
    "[]"
}

fn main() {
    // No `.state(..)`: the app state is `()`, which does not provide `Db`.
    let _ = Poring::new().get("/items", list).build();
}
