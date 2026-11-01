use poring::prelude::*;

#[derive(Clone)]
struct Tokens;
impl Authenticator for Tokens {
    async fn authenticate(&self, r: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(r.bearer_token().map(|t| Identity::new(t, Credential::Bearer)))
    }
}

#[poring::post("/upload", policy(body_limit = "10MiB"))]
async fn upload(body: Bytes) -> String {
    body.len().to_string()
}

poring_app! {
    Api {
        auth: Tokens,
        defaults: policy(body_limit = "1MiB"),
        routes: [upload],
    }
}

fn main() {}
