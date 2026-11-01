#[poring::post("/transfer", policy(csrf = off))]
async fn transfer() -> &'static str {
    "ok"
}

fn main() {}
