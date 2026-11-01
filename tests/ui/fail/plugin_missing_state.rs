use poring::prelude::*;

#[derive(Clone)]
struct Metrics;

#[poring::get("/hits")]
async fn hits(State(_m): State<Metrics>) -> &'static str {
    "0"
}

poring_plugin! {
    MetricsPlugin {
        prefix: "/metrics",
        routes: [hits],
    }
}

#[derive(Clone)]
struct AppState;

poring_app! {
    Api {
        state: AppState,
        plugins: [MetricsPlugin],
    }
}

fn main() {}
