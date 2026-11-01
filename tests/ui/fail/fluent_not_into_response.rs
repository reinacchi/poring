use poring::prelude::*;

struct Plain;

fn main() {
    let _ = Poring::new().get("/", || async { Plain }).build();
}
