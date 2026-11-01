use poring::prelude::*;

fn main() {
    let _ = Poring::new().get("/", |body: String| async move { body }).build();
}
