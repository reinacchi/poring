use poring::prelude::*;

#[derive(Clone)]
struct Tokens;
impl Authenticator for Tokens {
    async fn authenticate(&self, r: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(r.bearer_token().map(|t| Identity::new(t, Credential::Bearer)))
    }
}

#[poring::get("/debug/vars", public)]
async fn debug_vars() -> &'static str {
    "internal state"
}

poring_app! {
    Api {
        auth: Tokens,
        defaults: policy(deny_anonymous),
        routes: [debug_vars],
    }
}

fn main() {}
