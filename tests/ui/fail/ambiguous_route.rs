use poring::prelude::*;

#[poring::get("/users/{id}")]
async fn by_id(Path(_id): Path<u64>) -> &'static str {
    "id"
}

#[poring::delete("/users/{name}")]
async fn by_name(Path(_n): Path<String>) -> &'static str {
    "name"
}

poring_app! {
    Api {
        routes: [by_id, by_name],
    }
}

fn main() {}
