use poring::prelude::*;

#[derive(Clone)]
struct UserStore;

#[derive(Clone)]
struct AppState;

#[poring::get("/users")]
async fn users(State(_s): State<UserStore>) -> &'static str {
    "users"
}

poring_app! {
    Api {
        state: AppState,
        routes: [users],
    }
}

fn main() {}
