//! A secure admin API: the corrected version of `tests/ui/fail/insecure_admin.rs`.
//!
//! * `deny_anonymous` app defaults: every route requires a principal unless it is an
//!   explicit, documented public exception (`/health`).
//! * `/admin` group requires role `admin`. Deletes additionally require scope `users:delete`.
//! * Session cookies are accepted, so unsafe methods enforce CSRF (double-submit).
//! * Body limit, rate limit and timeout are declared, merged and enforced at runtime.
//!
//! ```text
//! cargo run -p poring-examples --example secure_admin
//! curl -i localhost:3000/admin/users                                  # 401
//! curl -H 'authorization: Bearer viewer' localhost:3000/admin/users   # 403 (not admin)
//! curl -H 'authorization: Bearer root' localhost:3000/admin/users     # 200
//! curl -X DELETE -H 'authorization: Bearer root' localhost:3000/admin/users/2   # 204
//! cargo test -p poring-examples --example secure_admin                # runs the tests below
//! cargo poring explain --example secure_admin -p poring-examples "DELETE /admin/users/{id}"
//! ```
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use poring::prelude::*;
use serde::Serialize;

/// Demo authenticator: fixed bearer tokens and session cookies.
#[derive(Clone, Default)]
pub struct DemoAuth;

impl Authenticator for DemoAuth {
    const USES_COOKIES: bool = true;

    async fn authenticate(&self, req: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        let id = match (req.bearer_token(), req.cookie("sid")) {
            (Some("root"), _) => Identity::new("root", Credential::Bearer)
                .with_roles(["admin"])
                .with_scopes(["users:read", "users:delete"]),
            (Some("helpdesk"), _) => Identity::new("helpdesk", Credential::Bearer)
                .with_roles(["admin"])
                .with_scopes(["users:read"]),
            (Some("viewer"), _) => {
                Identity::new("viewer", Credential::Bearer).with_scopes(["users:read"])
            }
            (Some(_), _) => return Err(AuthError::Invalid),
            (None, Some("root-session")) => Identity::new("root", Credential::Cookie)
                .with_roles(["admin"])
                .with_scopes(["users:read", "users:delete"]),
            _ => return Ok(None),
        };
        Ok(Some(id))
    }
}

/// A user record.
#[derive(Clone, Serialize, PoringSchema)]
pub struct User {
    id: u64,
    name: String,
}

/// User directory.
#[derive(Clone)]
pub struct Directory(Arc<Mutex<BTreeMap<u64, User>>>);

impl Default for Directory {
    fn default() -> Self {
        let users = [(1, "ada"), (2, "grace"), (3, "linus")]
            .into_iter()
            .map(|(id, n)| {
                (
                    id,
                    User {
                        id,
                        name: n.to_owned(),
                    },
                )
            })
            .collect();
        Directory(Arc::new(Mutex::new(users)))
    }
}

/// Load balancer probe.
#[poring::get(
    "/health",
    public(reason = "load balancer liveness probe; returns no data")
)]
async fn health() -> &'static str {
    "ok"
}

/// List users.
#[poring::get("/users", policy(scopes = ["users:read"]), annotate = ["directory: read all users"])]
async fn list_users(State(d): State<Directory>) -> Json<Vec<User>> {
    Json(
        d.0.lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect(),
    )
}

/// Delete a user.
#[poring::delete("/users/{id}", policy(scopes = ["users:delete"], rate_limit(requests = 10, per = "1m", key = principal)), annotate = ["directory: delete user", "audit log: append"])]
async fn delete_user(
    Principal(actor): Principal<Authenticated>,
    Path(id): Path<u64>,
    State(d): State<Directory>,
) -> Result<StatusCode, ApiError> {
    let removed = d.0.lock().unwrap_or_else(|p| p.into_inner()).remove(&id);
    match removed {
        Some(u) => {
            tracing::info!(actor = %actor.subject, user = u.id, "user deleted");
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(ApiError::not_found("no such user")),
    }
}

poring_app! {
    /// Admin API.
    pub AdminApi {
        state: Directory,
        auth: DemoAuth,
        defaults: policy(deny_anonymous, body_limit = "16KiB", timeout = "5s"),
        routes: [health],
        groups: [
            group("/admin", policy(roles = ["admin"])) { routes: [list_users, delete_user] },
        ],
    }
}

/// Builds the app (shared by `main` and tests).
pub fn app() -> poring::App<AdminApi> {
    AdminApi::builder()
        .state(Directory::default())
        .authenticator(DemoAuth)
        .security_headers(poring::SecurityHeaders::strict_api())
        .build()
        .expect("app builds")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `cargo poring` inspection hook: exits here when PORING_DUMP_MANIFEST is set.
    poring::dump_manifest_if_requested::<AdminApi>();
    tracing_subscriber::fmt().with_env_filter("info").init();
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "secure_admin listening");
    app()
        .serve(listener, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn anonymous_and_unprivileged_access_is_denied() {
        let c = app().client();
        assert_eq!(c.get("/health").send().await.status, 200);
        assert_eq!(c.get("/admin/users").send().await.status, 401);
        assert_eq!(
            c.get("/admin/users").bearer("viewer").send().await.status,
            403
        );
        assert_eq!(c.delete("/admin/users/1").send().await.status, 401);
        assert_eq!(
            c.delete("/admin/users/1")
                .bearer("helpdesk")
                .send()
                .await
                .status,
            403,
            "admin without users:delete"
        );
    }

    #[tokio::test]
    async fn admin_can_list_and_delete() {
        let c = app().client();
        assert_eq!(
            c.get("/admin/users").bearer("root").send().await.status,
            200
        );
        assert_eq!(
            c.delete("/admin/users/2")
                .bearer("root")
                .send()
                .await
                .status,
            204
        );
        assert_eq!(
            c.delete("/admin/users/2")
                .bearer("root")
                .send()
                .await
                .status,
            404
        );
    }

    #[tokio::test]
    async fn cookie_session_deletes_need_csrf() {
        let c = app().client();
        let r = c
            .delete("/admin/users/1")
            .header("cookie", "sid=root-session")
            .send()
            .await;
        assert_eq!(r.status, 403);
        let r = c
            .delete("/admin/users/1")
            .header(
                "cookie",
                "sid=root-session; poring-csrf=abcdefabcdefabcdef12",
            )
            .header("x-csrf-token", "abcdefabcdefabcdef12")
            .send()
            .await;
        assert_eq!(r.status, 204);
    }

    #[tokio::test]
    async fn strict_security_headers() {
        let r = app().client().get("/health").send().await;
        assert_eq!(r.header("x-frame-options"), Some("DENY"));
        assert_eq!(
            r.header("content-security-policy"),
            Some("default-src 'none'; frame-ancestors 'none'")
        );
    }
}
