#[poring::get("/x", policy(authz = admin))]
async fn x() -> &'static str {
    "x"
}

fn main() {}
