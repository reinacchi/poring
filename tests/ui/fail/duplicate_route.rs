use poring::prelude::*;

#[poring::get("/users")]
async fn list_a() -> &'static str {
    "a"
}

#[poring::get("/users")]
async fn list_b() -> &'static str {
    "b"
}

poring_app! {
    Api {
        routes: [list_a, list_b],
    }
}

fn main() {}
