//! Rate limiting with the fluent API: IP-keyed, principal-keyed, a shared group budget, an
//! app-wide ceiling and reading the remaining quota from a handler.
//!
//! ```text
//! cargo run -p poring-examples --example rate_limits
//! curl -i localhost:3000/api/one                                  # RateLimit: "group";r=9;t=0
//! curl -i localhost:3000/api/two                                  # same bucket: r=8
//! curl -i -H 'authorization: Bearer alice' localhost:3000/me/quota
//! ```
use std::time::Duration;

use poring::prelude::*;

/// Demo bearer tokens.
struct Tokens;

impl Authenticator for Tokens {
    async fn authenticate(&self, req: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        match req.bearer_token() {
            Some(name @ ("alice" | "bob")) => Ok(Some(Identity::new(name, Credential::Bearer))),
            Some(_) => Err(AuthError::Invalid),
            None => Ok(None),
        }
    }
}

/// Reports the quota recorded when this request was admitted (no extra token is taken).
async fn quota(status: RateLimitStatus) -> String {
    format!(
        "{} of {} left; next request possible in {:?}; full again in {:?}",
        status.remaining, status.limit, status.next_token_after, status.full_refill_after
    )
}

fn app() -> Result<poring::FluentApp<(), Tokens>, poring::StartupError> {
    Poring::new()
        .authenticator(Tokens)
        // Applies in addition to every other limit; routes cannot opt out.
        .rate_limit_ceiling(RateLimit::new(1_000, Duration::from_secs(60)).by_ip())
        .group("/api", |api| {
            api.policy(Policy::new().public())
                .rate_limit(
                    RateLimit::new(10, Duration::from_secs(60))
                        .by_ip()
                        .scope(RateScope::Group)
                        .expose_headers(true),
                )
                .get("/one", || async { "one" })
                .get("/two", || async { "two" })
        })
        .group("/me", |me| {
            me.rate_limit(
                RateLimit::new(5, Duration::from_secs(10))
                    .by_principal()
                    .expose_headers(true),
            )
            .get("/quota", quota)
        })
        // The original form: one bucket per route, keyed by principal.
        .route_with(
            RouteMethod::Post,
            "/upload",
            Policy::new().rate_limit(2, Duration::from_secs(60), RateKey::Principal),
            || async { StatusCode::ACCEPTED },
        )
        .build()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    app()?.listen(addr).await?;
    Ok(())
}
