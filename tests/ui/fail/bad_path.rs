#[poring::get("/users/x{id}")]
async fn users() -> &'static str {
    "users"
}

fn main() {}
