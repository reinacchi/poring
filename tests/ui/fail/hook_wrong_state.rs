use poring::prelude::*;

#[derive(Clone)]
struct OtherState;

#[derive(Clone)]
struct AppState;

#[poring::hook]
async fn audit(_cx: &mut Ctx<'_, OtherState>) {}

#[poring::get("/", before = [audit])]
async fn index() -> &'static str {
    "hi"
}

poring_app! {
    Api {
        state: AppState,
        routes: [index],
    }
}

fn main() {}
