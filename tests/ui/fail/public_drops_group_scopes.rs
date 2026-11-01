use poring::prelude::*;

#[derive(Clone)]
struct Tokens;
impl Authenticator for Tokens {
    async fn authenticate(&self, r: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(r.bearer_token().map(|t| Identity::new(t, Credential::Bearer)))
    }
}

#[poring::get("/report", public)]
async fn report() -> &'static str {
    "report"
}

poring_app! {
    Api {
        auth: Tokens,
        groups: [group("/finance", policy(scopes = ["finance:read"])) { routes: [report] }],
    }
}

fn main() {}
