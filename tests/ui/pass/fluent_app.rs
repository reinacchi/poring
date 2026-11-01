use poring::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, PoringSchema)]
struct Item {
    name: String,
}

#[derive(Clone, Default, PoringState)]
struct AppState {
    prefix: Prefix,
}

#[derive(Clone, Default)]
struct Prefix(String);

async fn create(State(p): State<Prefix>, Path(id): Path<u64>, Json(item): Json<Item>) -> Result<Json<Item>, ApiError> {
    Ok(Json(Item { name: format!("{}{id}:{}", p.0, item.name) }))
}

fn main() {
    let app: Result<poring::FluentApp<AppState>, _> = Poring::with_state(AppState::default())
        .get("/", || async { "root" })
        .post("/items/{id}", create)
        .group("/v1", |g| g.get("/ping", || async { StatusCode::NO_CONTENT }))
        .build();
    let _ = app;
}
