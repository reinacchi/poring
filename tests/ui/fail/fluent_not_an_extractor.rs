use poring::prelude::*;

fn main() {
    let _ = Poring::new().get("/", |n: u32| async move { n.to_string() }).build();
}
