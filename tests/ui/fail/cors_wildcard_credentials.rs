use poring::prelude::*;

#[poring::get("/")]
async fn index() -> &'static str {
    "hi"
}

poring_app! {
    Api {
        cors: cors(origins = ["*"], credentials = true),
        routes: [index],
    }
}

fn main() {}
