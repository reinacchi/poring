//! Benchmark server for external load generators (`scripts/perf.sh`). It serves the same
//! endpoints through the router API or the attribute macros, so both can be measured with
//! an independent client such as `oha`.
//!
//! ```text
//! PORING_BENCH_MODE=fluent PORING_BENCH_ADDR=127.0.0.1:3000 \
//!     cargo run --release -p poring-examples --no-default-features --example bench_server
//! oha --no-tui -z 30s -c 128 http://127.0.0.1:3000/bench/plain
//! ```
//!
//! Environment:
//! * `PORING_BENCH_MODE`: `fluent` (default), `macro`, `fluent-policy` (bearer
//!   authentication and an IP rate limit that is never exhausted) or `fluent-trace`
//!   (a `tracing` subscriber at INFO writing to a sink).
//! * `PORING_BENCH_PARITY=1`: no default security headers and no `x-request-id`, so the
//!   response headers match a minimal reference server byte for byte.
//! * `PORING_BENCH_WORKERS`: Tokio worker threads (default: number of CPUs).
use std::hint::black_box;
use std::time::Duration;

use poring::prelude::*;

static LARGE: [u8; 64 * 1024] = [b'x'; 64 * 1024];

/// Deterministic integer churn that the optimiser cannot fold away.
fn churn(iterations: u64) -> u64 {
    let mut x = black_box(0x9e37_79b9_7f4a_7c15_u64);
    for i in 0..black_box(iterations) {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(i ^ (x >> 33));
    }
    x
}

async fn plain() -> &'static str {
    "ok"
}

async fn path(Path(id): Path<u64>) -> String {
    id.to_string()
}

async fn json() -> Json<Vec<u64>> {
    Json((0..128).collect())
}

async fn post(Json(values): Json<Vec<u64>>) -> String {
    values
        .iter()
        .fold(0u64, |a, v| a.wrapping_add(*v))
        .to_string()
}

async fn cpu() -> String {
    churn(4_000).to_string()
}

async fn large() -> &'static [u8] {
    &LARGE
}

async fn heavy() -> Json<Vec<u64>> {
    let seed = churn(100_000);
    Json((0..1024u64).map(|i| seed.wrapping_add(i)).collect())
}

mod attributes {
    use poring::prelude::*;

    #[poring::get("/bench/plain")]
    pub async fn plain() -> &'static str {
        super::plain().await
    }

    #[poring::get("/bench/path/{id}")]
    pub async fn path(id: Path<u64>) -> String {
        super::path(id).await
    }

    #[poring::get("/bench/json")]
    pub async fn json() -> Json<Vec<u64>> {
        super::json().await
    }

    #[poring::post("/bench/post")]
    pub async fn post(body: Json<Vec<u64>>) -> String {
        super::post(body).await
    }

    #[poring::get("/bench/cpu")]
    pub async fn cpu() -> String {
        super::cpu().await
    }

    #[poring::get("/bench/large")]
    pub async fn large() -> &'static [u8] {
        super::large().await
    }

    #[poring::get("/bench/heavy")]
    pub async fn heavy() -> Json<Vec<u64>> {
        super::heavy().await
    }

    poring_app! {
        pub Bench {
            routes: [plain, path, json, post, cpu, large, heavy],
        }
    }
}

/// Accepts `Authorization: Bearer bench`.
struct BenchAuth;

impl Authenticator for BenchAuth {
    async fn authenticate(&self, req: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        match req.bearer_token() {
            Some("bench") => Ok(Some(Identity::new("bench", Credential::Bearer))),
            Some(_) => Err(AuthError::Invalid),
            None => Ok(None),
        }
    }
}

fn fluent() -> Poring {
    Poring::new()
        .get("/bench/plain", plain)
        .get("/bench/path/{id}", path)
        .get("/bench/json", json)
        .post("/bench/post", post)
        .get("/bench/cpu", cpu)
        .get("/bench/large", large)
        .get("/bench/heavy", heavy)
}

fn parity() -> bool {
    std::env::var("PORING_BENCH_PARITY").is_ok_and(|v| v == "1")
}

async fn serve(addr: String) -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::var("PORING_BENCH_MODE").unwrap_or_else(|_| "fluent".into());
    let headers = if parity() {
        poring::SecurityHeaders(Vec::new())
    } else {
        poring::SecurityHeaders::default()
    };
    eprintln!("bench_server: mode={mode} parity={} addr={addr}", parity());
    match mode.as_str() {
        "macro" => {
            attributes::Bench::builder()
                .security_headers(headers)
                .request_ids(!parity())
                .listen(addr)
                .await?
        }
        "fluent-policy" => {
            Poring::new()
                .authenticator(BenchAuth)
                .rate_limit(RateLimit::new(1_000_000_000, Duration::from_secs(1)))
                .get("/bench/plain", plain)
                .get("/bench/path/{id}", path)
                .post("/bench/post", post)
                .security_headers(headers)
                .request_ids(!parity())
                .listen(addr)
                .await?
        }
        "fluent" | "fluent-trace" => {
            if mode == "fluent-trace" {
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::INFO)
                    .with_writer(std::io::sink)
                    .init();
            }
            fluent()
                .security_headers(headers)
                .request_ids(!parity())
                .listen(addr)
                .await?
        }
        other => return Err(format!("unknown PORING_BENCH_MODE `{other}`").into()),
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var("PORING_BENCH_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let mut rt = tokio::runtime::Builder::new_multi_thread();
    if let Some(n) = std::env::var("PORING_BENCH_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        rt.worker_threads(n);
    }
    rt.enable_all().build()?.block_on(serve(addr))
}
