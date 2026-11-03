//! Allocation budgets for the in-process request path. A regression that adds per-request
//! heap allocations (for example cloning route IDs, boxing timers or collecting rate-limit
//! probes into vectors) fails here.
//!
//! The counts cover the whole in-process round trip, including the test client building the
//! request and collecting the response, so they are higher than the server-side cost alone.

use std::time::Duration;

use poring::prelude::*;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Average heap allocations per request after a warm-up.
async fn per_request<A: poring::app::AppSpec>(
    app: &poring::app::App<A>,
    uri: &str,
    peer: std::net::SocketAddr,
) -> f64 {
    let c = app.client();
    for _ in 0..50 {
        assert_eq!(c.get(uri).peer(peer).send().await.status, 200, "{uri}");
    }
    const N: u64 = 200;
    let before = dhat::HeapStats::get().total_blocks;
    for _ in 0..N {
        let r = c.get(uri).peer(peer).send().await;
        std::hint::black_box(&r);
    }
    (dhat::HeapStats::get().total_blocks - before) as f64 / N as f64
}

#[tokio::test(flavor = "current_thread")]
async fn per_request_allocations_stay_within_budget() {
    let _profiler = dhat::Profiler::builder().testing().build();
    let peer: std::net::SocketAddr = "192.0.2.1:4000".parse().unwrap();
    let plain = Poring::new()
        .get("/plain", || async { "ok" })
        .get(
            "/path/{id}",
            |Path(id): Path<u64>| async move { id.to_string() },
        )
        .build()
        .unwrap();
    let limited = Poring::new()
        .rate_limit(RateLimit::new(1_000_000_000, Duration::from_secs(1)))
        .rate_limit_ceiling(RateLimit::new(1_000_000_000, Duration::from_secs(1)))
        .get("/plain", || async { "ok" })
        .build()
        .unwrap();

    let measured = [
        ("plain", per_request(&plain, "/plain", peer).await, PLAIN),
        ("path", per_request(&plain, "/path/12345", peer).await, PATH),
        (
            "rate limited",
            per_request(&limited, "/plain", peer).await,
            LIMITED,
        ),
    ];
    for (name, got, budget) in measured {
        println!("{name}: {got:.2} allocations per request (budget {budget})");
        assert!(
            got <= budget,
            "{name}: {got:.2} allocations per request exceeds the budget of {budget}"
        );
    }
}

// Budgets: the counts measured for this revision (deterministic after the warm-up).
const PLAIN: f64 = 8.0;
const PATH: f64 = 10.0;
const LIMITED: f64 = 8.0;
