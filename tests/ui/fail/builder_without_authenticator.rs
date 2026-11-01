use poring::prelude::*;

#[derive(Clone)]
struct Tokens;
impl Authenticator for Tokens {
    async fn authenticate(&self, r: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(r.bearer_token().map(|t| Identity::new(t, Credential::Bearer)))
    }
}

#[poring::get("/me")]
async fn me(Principal(who): Principal<Identity>) -> String {
    who.subject
}

poring_app! {
    Api {
        auth: Tokens,
        routes: [me],
    }
}

fn main() {
    let _ = Api::builder().build();
}
