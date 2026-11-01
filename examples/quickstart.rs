//! The README quickstart, verbatim (kept in sync by `tests/tests/readme.rs`).
use poring::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, PoringSchema)]
struct NewTodo {
    #[poring(min_length = 1, max_length = 200)]
    title: String,
}

#[derive(Serialize, PoringSchema)]
struct Todo {
    id: u64,
    title: String,
}

#[poring::get("/hello/{name}")]
async fn hello(Path(name): Path<String>) -> String {
    format!("hello, {name}")
}

#[poring::post("/todos", policy(body_limit = "4KiB"))]
async fn create(Json(t): Json<NewTodo>) -> (StatusCode, Json<Todo>) {
    (StatusCode::CREATED, Json(Todo { id: 1, title: t.title }))
}

poring_app! {
    pub Api {
        routes: [hello, create],
    }
}

#[tokio::main]
async fn main() -> Result<(), poring::StartupError> {
    Api::builder().listen("127.0.0.1:3000").await
}
