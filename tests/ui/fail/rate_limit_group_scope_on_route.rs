#[poring::get("/x", policy(rate_limit(requests = 5, per = "1m", scope = group)))]
async fn x() -> &'static str {
    "x"
}

fn main() {}
