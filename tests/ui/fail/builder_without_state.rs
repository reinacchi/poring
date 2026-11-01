use poring::prelude::*;

#[derive(Clone)]
struct AppState;

#[poring::get("/")]
async fn index() -> &'static str {
    "hi"
}

poring_app! {
    Api {
        state: AppState,
        routes: [index],
    }
}

fn main() {
    let _ = Api::builder().build();
}
