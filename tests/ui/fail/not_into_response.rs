struct Plain;

#[poring::get("/")]
async fn index() -> Plain {
    Plain
}

poring::poring_app! {
    Api {
        routes: [index],
    }
}

fn main() {}
