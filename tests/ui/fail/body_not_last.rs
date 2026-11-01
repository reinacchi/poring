use poring::prelude::*;
use serde::Deserialize;

#[derive(Deserialize, PoringSchema)]
struct Input {
    name: String,
}

#[poring::post("/users/{id}")]
async fn create(Json(_i): Json<Input>, Path(_id): Path<u64>) -> &'static str {
    "ok"
}

fn main() {}
