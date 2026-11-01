//! Runtime enforcement primitives: CORS, CSRF, rate limiting.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, RandomState};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use http::{HeaderMap, HeaderValue};

use crate::descriptor::CorsSpec;
use crate::policy::RateLimitSpec;

/// Name of the CSRF double-submit cookie.
pub const CSRF_COOKIE: &str = "poring-csrf";
/// Name of the CSRF request header.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Checks the double-submit CSRF token: the `x-csrf-token` header must equal the
/// `poring-csrf` cookie, and the token must be at least 16 bytes.
pub fn csrf_ok(headers: &HeaderMap) -> bool {
    let Some(cookie) = crate::extract::cookie::find_cookie(headers, CSRF_COOKIE) else {
        return false;
    };
    let Some(header) = headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    cookie.len() >= 16 && ct_eq(cookie.as_bytes(), header.as_bytes())
}

/// Generates a random 32-hex-char CSRF token and the `Set-Cookie` value carrying it.
///
/// The cookie is `SameSite=Strict; Secure; Path=/` and deliberately *not* `HttpOnly`
/// (the double-submit pattern requires client script to read it).
pub fn issue_csrf_token() -> Result<(String, HeaderValue), getrandom::Error> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw)?;
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let cookie = format!("{CSRF_COOKIE}={token}; Path=/; SameSite=Strict; Secure");
    let value = HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""));
    Ok((token, value))
}

/// Runtime CORS configuration.
#[derive(Clone, Debug)]
pub struct CorsRuntime {
    origins: Vec<String>,
    wildcard: bool,
    credentials: bool,
    allow_headers: HeaderValue,
    max_age: HeaderValue,
}

impl CorsRuntime {
    /// Builds from a compile-time spec.
    pub fn from_spec(spec: &CorsSpec) -> Self {
        let headers = if spec.headers.is_empty() {
            "content-type, authorization, x-csrf-token, x-request-id".to_owned()
        } else {
            spec.headers.join(", ")
        };
        CorsRuntime {
            origins: spec.origins.iter().map(|s| (*s).to_owned()).collect(),
            wildcard: spec.origins.contains(&"*"),
            credentials: spec.credentials,
            allow_headers: HeaderValue::from_str(&headers).unwrap_or_else(|_| HeaderValue::from_static("content-type")),
            max_age: HeaderValue::from(spec.max_age_secs),
        }
    }

    /// Whether `origin` is allowed.
    pub fn allows(&self, origin: &str) -> bool {
        (self.wildcard && !self.credentials) || self.origins.iter().any(|o| o == origin)
    }

    /// Adds CORS response headers for an allowed `origin`.
    pub fn apply(&self, origin: &HeaderValue, headers: &mut HeaderMap) {
        use http::header::*;
        if self.wildcard && !self.credentials {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        } else {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
            headers.append(VARY, HeaderValue::from_static("origin"));
        }
        if self.credentials {
            headers.insert(ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
        }
    }

    /// Adds preflight headers.
    pub fn apply_preflight(&self, origin: &HeaderValue, allow: &HeaderValue, headers: &mut HeaderMap) {
        use http::header::*;
        self.apply(origin, headers);
        headers.insert(ACCESS_CONTROL_ALLOW_METHODS, allow.clone());
        headers.insert(ACCESS_CONTROL_ALLOW_HEADERS, self.allow_headers.clone());
        headers.insert(ACCESS_CONTROL_MAX_AGE, self.max_age.clone());
    }
}

/// Rate-limit partition key value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RateKeyValue {
    /// Client IP.
    Ip(IpAddr),
    /// Principal subject.
    Subject(String),
    /// Unknown client (no peer address, e.g. in-process tests).
    Unknown,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

const SHARDS: usize = 16;

/// A bounded, sharded token-bucket rate limiter.
///
/// Memory is bounded by `max_keys` (split across shards). When a shard is full, expired
/// (fully refilled) buckets are evicted first; if none are expired, the oldest bucket is
/// evicted. This keeps memory bounded under key-flooding at the cost of letting a
/// flooded-out key start over with a full bucket (documented in SECURITY_MODEL.md).
#[derive(Debug)]
pub struct RateLimiter {
    shards: Vec<Mutex<HashMap<(u32, RateKeyValue), Bucket>>>,
    per_shard: usize,
    hasher: RandomState,
}

impl RateLimiter {
    /// Creates a limiter bounded to roughly `max_keys` buckets.
    pub fn new(max_keys: usize) -> Self {
        RateLimiter {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            per_shard: (max_keys / SHARDS).max(16),
            hasher: RandomState::new(),
        }
    }

    /// Takes one token for `(route, key)`. Returns `Err(retry_after)` when exhausted.
    pub fn check(&self, route: u32, key: RateKeyValue, spec: &RateLimitSpec, now: Instant) -> Result<(), Duration> {
        let capacity = f64::from(spec.requests.max(1));
        let per = Duration::from_millis(spec.per_ms.max(1));
        let rate = capacity / per.as_secs_f64();
        let k = (route, key);

        let shard = &self.shards[(self.hasher.hash_one(&k) as usize) % SHARDS];
        // A poisoned lock means a panic while holding it; the map is still structurally
        // valid, so continue rather than failing every request.
        let mut map = shard.lock().unwrap_or_else(|p| p.into_inner());
        if !map.contains_key(&k) && map.len() >= self.per_shard {
            Self::evict(&mut map, now, per);
        }
        let b = map.entry(k).or_insert(Bucket { tokens: capacity, last: now });
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * rate).min(capacity);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            let wait = (1.0 - b.tokens) / rate;
            Err(Duration::from_secs_f64(wait.max(0.001)))
        }
    }

    fn evict(map: &mut HashMap<(u32, RateKeyValue), Bucket>, now: Instant, per: Duration) {
        let before = map.len();
        map.retain(|_, b| now.saturating_duration_since(b.last) < per);
        if map.len() == before
            && let Some(oldest) = map.iter().min_by_key(|(_, b)| b.last).map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
    }

    /// Number of live buckets (for tests/metrics).
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().map(|m| m.len()).unwrap_or(0)).sum()
    }

    /// Whether there are no buckets.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::RateKey;

    #[test]
    fn bucket_refills_and_bounds() {
        let rl = RateLimiter::new(32);
        let spec = RateLimitSpec { requests: 2, per_ms: 1000, key: RateKey::Ip };
        let t0 = Instant::now();
        let ip = RateKeyValue::Ip("127.0.0.1".parse().unwrap());
        assert!(rl.check(0, ip.clone(), &spec, t0).is_ok());
        assert!(rl.check(0, ip.clone(), &spec, t0).is_ok());
        assert!(rl.check(0, ip.clone(), &spec, t0).is_err());
        assert!(rl.check(0, ip, &spec, t0 + Duration::from_millis(600)).is_ok());
        for i in 0..10_000u32 {
            let _ = rl.check(0, RateKeyValue::Subject(i.to_string()), &spec, t0);
        }
        assert!(rl.len() <= 16 * 16 + 16, "limiter must stay bounded, got {}", rl.len());
    }

    #[test]
    fn csrf_double_submit() {
        let mut h = HeaderMap::new();
        h.insert("cookie", HeaderValue::from_static("poring-csrf=0123456789abcdef0123"));
        assert!(!csrf_ok(&h));
        h.insert(CSRF_HEADER, HeaderValue::from_static("0123456789abcdef0123"));
        assert!(csrf_ok(&h));
        h.insert(CSRF_HEADER, HeaderValue::from_static("0123456789abcdef0124"));
        assert!(!csrf_ok(&h));
    }
}
