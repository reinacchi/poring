use poring::prelude::*;

#[poring::get("/upload")]
async fn upload(body: Bytes) -> String {
    body.len().to_string()
}

fn main() {}
