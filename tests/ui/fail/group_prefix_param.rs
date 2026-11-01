use poring::prelude::*;

#[poring::get("/")]
async fn index() -> &'static str {
    "hi"
}

poring_app! {
    Api {
        groups: [group("/tenants/{id}") { routes: [index] }],
    }
}

fn main() {}
