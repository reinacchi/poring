#[poring::get("/x", policy(public, scopes = ["x:read"]))]
async fn x() -> &'static str {
    "x"
}

fn main() {}
