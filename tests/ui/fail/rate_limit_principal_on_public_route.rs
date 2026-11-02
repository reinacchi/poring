use poring::prelude::*;

struct Auth;
impl Authenticator for Auth {
    async fn authenticate(&self, _: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(None)
    }
}

#[poring::get("/status", policy(public(reason = "uptime probe"), rate_limit(requests = 5, key = principal)))]
async fn status() -> &'static str {
    "ok"
}

poring_app! {
    pub Api {
        auth: Auth,
        routes: [status],
    }
}

fn main() {}
