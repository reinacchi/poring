//! Intentional, documented exceptions and safe narrowing overrides compile.
use poring::prelude::*;

#[derive(Clone)]
struct Tokens;
impl Authenticator for Tokens {
    async fn authenticate(&self, r: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(r.bearer_token().map(|t| Identity::new(t, Credential::Bearer)))
    }
}

#[poring::get("/health", public(reason = "liveness probe"))]
async fn health() -> &'static str {
    "ok"
}

#[poring::post("/webhook", policy(public(reason = "HMAC-verified"), csrf = exempt("no ambient credentials"), body_limit = "4KiB"))]
async fn webhook(body: Bytes) -> String {
    body.len().to_string()
}

#[poring::get("/me", policy(scopes = ["profile"], timeout = "2s", rate_limit = "5/s"))]
async fn me(Principal(who): Principal<Authenticated>) -> String {
    who.subject.clone()
}

#[poring::get("/open-report", public(reason = "published quarterly report"))]
async fn open_report() -> &'static str {
    "report"
}

poring_app! {
    Api {
        auth: Tokens,
        defaults: policy(deny_anonymous, body_limit = "1MiB"),
        cors: cors(origins = ["https://app.example"], credentials = true),
        routes: [health, webhook, me],
        groups: [group("/finance", policy(scopes = ["finance:read"], body_limit = "64KiB")) { routes: [open_report] }],
    }
}

fn main() {
    let _ = Api::builder().authenticator(Tokens).build();
}
