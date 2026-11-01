use poring::prelude::*;

#[derive(Clone)]
struct Db;

#[derive(Clone, PoringState)]
struct AppState {
    db: Db,
}

#[poring::get("/items/{id}")]
async fn item(Path(id): Path<u32>, State(_db): State<Db>) -> String {
    id.to_string()
}

poring_app! {
    Api {
        state: AppState,
        routes: [item],
    }
}

fn main() {
    let _ = Api::builder().state(AppState { db: Db }).build();
}
