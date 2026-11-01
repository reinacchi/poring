use poring::prelude::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Input {
    name: String,
}

#[poring::post("/users")]
async fn create(Json(i): Json<Input>) -> String {
    i.name
}

poring_app! {
    Api {
        routes: [create],
    }
}

fn main() {}
