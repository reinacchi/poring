use poring::prelude::*;

#[poring::get("/admin", policy(auth = required))]
async fn admin() -> &'static str {
    "secret"
}

poring_app! {
    Api {
        routes: [admin],
    }
}

fn main() {}
