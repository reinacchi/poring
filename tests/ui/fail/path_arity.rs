use poring::prelude::*;

#[poring::get("/users/{id}")]
async fn user(Path((_a, _b)): Path<(u64, u64)>) -> &'static str {
    "user"
}

fn main() {}
