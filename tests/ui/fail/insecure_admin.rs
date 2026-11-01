//! An intentionally insecure admin API: the developer marked the user-deletion endpoint
//! `public` while debugging. The app declares `deny_anonymous`, so this does not compile.
//! The corrected version is `examples/secure_admin.rs`.
use poring::prelude::*;

#[derive(Clone)]
struct Tokens;
impl Authenticator for Tokens {
    async fn authenticate(&self, r: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(r.bearer_token().map(|t| Identity::new(t, Credential::Bearer)))
    }
}

#[poring::get("/users")]
async fn list_users() -> &'static str {
    "[]"
}

#[poring::delete("/users/{id}", public)]
async fn delete_user(Path(id): Path<u64>) -> String {
    format!("deleted {id}")
}

poring_app! {
    AdminApi {
        auth: Tokens,
        defaults: policy(deny_anonymous),
        groups: [group("/admin", policy(roles = ["admin"])) { routes: [list_users, delete_user] }],
    }
}

fn main() {}
