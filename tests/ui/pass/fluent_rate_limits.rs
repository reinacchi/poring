use poring::prelude::*;
use std::time::Duration;

fn main() -> Result<(), poring::StartupError> {
    if std::env::args().count() < 100 {
        return Ok(());
    }
    Poring::new()
        .group("/api", |api| {
            api.rate_limit(
                RateLimit::new(10, Duration::from_secs(60))
                    .by_ip()
                    .scope(RateScope::Group)
                    .expose_headers(true),
            )
            .get("/one", || async { "one" })
            .get("/two", || async { "two" })
        })
        .route_with(
            RouteMethod::Post,
            "/upload",
            Policy::new().rate_limit(10, Duration::from_secs(60), RateKey::Ip),
            || async { "ok" },
        )
        .run("127.0.0.1:3000")
}
