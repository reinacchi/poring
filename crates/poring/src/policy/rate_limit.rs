//! Single-process token-bucket rate limiting.
//!
//! # Semantics
//!
//! A limit of `requests` per `window` is a token bucket with a burst capacity of
//! `requests` tokens that refills continuously at `requests / window`. A request needs one
//! whole token. Partial tokens accumulate exactly: with 10 requests per 60 s, one token
//! becomes available every 6 s, and a bucket that has been idle for a full window is full.
//!
//! The bucket is stored as a *theoretical arrival time* (the GCRA formulation of a token
//! bucket) in integer nanoseconds scaled by the bucket's capacity, so refill and timing
//! calculations involve no floating point and no rounding until a [`Duration`] is reported.
//! Reported durations are rounded *up* to the next nanosecond, so waiting for them is
//! always enough.
//!
//! # Concurrency
//!
//! Buckets live in mutex-protected shards. All buckets that one request consumes from are
//! evaluated and updated while their shard locks are held (locks are taken in shard order),
//! so concurrent requests for the same key can never admit more requests than there are
//! tokens, and a request limited by several rules consumes from all of them or from none.
//!
//! # Memory
//!
//! The number of buckets is bounded by [`RateLimiter::capacity`]. A bucket is only removed
//! once it has completely refilled, at which point it is indistinguishable from a new one,
//! so reclaiming memory never resets a partially used quota. When the table is full of
//! active buckets the limiter fails closed: [`RateLimitDecision::Saturated`] rejects the
//! request without consuming anything (HTTP 503).
//!
//! Limits are per process. Several instances behind a load balancer each enforce their own
//! budget.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::policy::{RateKey, RateLimitSpec};

/// Smallest supported window.
pub const MIN_WINDOW: Duration = Duration::from_millis(1);
/// Largest supported window (one year).
pub const MAX_WINDOW: Duration = Duration::from_secs(366 * 24 * 60 * 60);
/// Largest supported number of buckets ([`crate::Limits::rate_limit_keys`]).
pub const MAX_KEYS: usize = 100_000_000;

const SHARDS: usize = 64;

/// Which buckets a rate limit shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum RateScope {
    /// Every route has its own bucket per client (the default).
    #[default]
    Route,
    /// Every route that inherits the limit from a group shares the group's bucket per
    /// client. Valid on group (and plugin) policies only.
    Group,
    /// Every route that inherits the limit from the app defaults shares one bucket per
    /// client. Valid on app policies only.
    App,
}

impl RateScope {
    /// Manifest name.
    pub const fn as_str(self) -> &'static str {
        match self {
            RateScope::Route => "route",
            RateScope::Group => "group",
            RateScope::App => "app",
        }
    }
}

/// A rate limit for the fluent API: `requests` per `window`, a client key, a bucket scope
/// and optional quota response headers.
///
/// ```
/// use std::time::Duration;
/// use poring::policy::{RateLimit, RateScope};
///
/// let shared = RateLimit::new(10, Duration::from_secs(60))
///     .by_ip()
///     .scope(RateScope::Group)
///     .expose_headers(true);
/// # let _ = shared;
/// ```
///
/// Values are validated when the app is built: the allowance must be at least one, and the
/// window a whole number of milliseconds between [`MIN_WINDOW`] and [`MAX_WINDOW`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    requests: u32,
    window: Duration,
    key: RateKey,
    scope: RateScope,
    headers: bool,
}

impl RateLimit {
    /// `requests` per `window`, keyed by client IP, with one bucket per route and no quota
    /// headers.
    pub const fn new(requests: u32, window: Duration) -> Self {
        RateLimit {
            requests,
            window,
            key: RateKey::Ip,
            scope: RateScope::Route,
            headers: false,
        }
    }

    /// Partitions by client IP address (see `trusted_proxies` on the app builders).
    pub const fn by_ip(mut self) -> Self {
        self.key = RateKey::Ip;
        self
    }

    /// Partitions by authenticated subject. Only valid on authenticated routes; the check
    /// then runs after authentication.
    pub const fn by_principal(mut self) -> Self {
        self.key = RateKey::Principal;
        self
    }

    /// Selects how buckets are shared.
    pub const fn scope(mut self, scope: RateScope) -> Self {
        self.scope = scope;
        self
    }

    /// Adds `RateLimit` and `RateLimit-Policy` headers to responses of the limited routes
    /// (see [`HEADER_DRAFT`]). `Retry-After` is always sent on 429.
    pub const fn expose_headers(mut self, on: bool) -> Self {
        self.headers = on;
        self
    }

    /// Validates and converts to the declaration used by the resolver.
    pub(crate) fn to_spec(self) -> Result<RateLimitSpec, String> {
        if self.requests == 0 {
            return Err("rate_limit count must be > 0".into());
        }
        if self.window < MIN_WINDOW || self.window > MAX_WINDOW {
            return Err(format!(
                "rate_limit window must be between {MIN_WINDOW:?} and {MAX_WINDOW:?}, got {:?}",
                self.window
            ));
        }
        if !self.window.subsec_nanos().is_multiple_of(1_000_000) {
            return Err(format!(
                "rate_limit window {:?} is not a whole number of milliseconds",
                self.window
            ));
        }
        let per_ms = u64::try_from(self.window.as_millis())
            .map_err(|_| "rate_limit window is too long".to_owned())?;
        Ok(RateLimitSpec::new(self.requests, per_ms, self.key)
            .with_scope(self.scope)
            .with_headers(self.headers))
    }

    pub(crate) fn from_spec(s: &RateLimitSpec) -> Self {
        RateLimit {
            requests: s.requests,
            window: Duration::from_millis(s.per_ms),
            key: s.key,
            scope: s.scope,
            headers: s.headers,
        }
    }
}

/// The revision of the IETF `RateLimit` header fields draft that Poring emits:
/// `RateLimit-Policy: "<name>";q=<requests>;w=<seconds>` and
/// `RateLimit: "<name>";r=<remaining>;t=<seconds until another request is admitted>`.
/// `w` is omitted when the window is not a whole number of seconds.
pub const HEADER_DRAFT: &str = "draft-ietf-httpapi-ratelimit-headers-10";

/// Rate-limit partition key value. Never exported in headers, logs or traces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RateKeyValue {
    /// Client IP (IPv4-mapped IPv6 addresses are stored as IPv4).
    Ip(IpAddr),
    /// Principal subject.
    Subject(String),
    /// Unknown client (no peer address, e.g. in-process tests).
    Unknown,
}

impl RateKeyValue {
    /// An IP key in canonical form.
    pub fn ip(ip: IpAddr) -> Self {
        RateKeyValue::Ip(canonical_ip(ip))
    }
}

pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// The state of the limiting bucket after a decision.
///
/// All values describe the same instant and the same bucket state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitStatus {
    /// Burst capacity (requests per window).
    pub limit: u32,
    /// Whole requests that would be admitted right now.
    pub remaining: u32,
    /// Time until another request is admitted; zero while `remaining > 0`.
    pub next_token_after: Duration,
    /// Time until the bucket is full again if no further requests arrive.
    pub full_refill_after: Duration,
    /// Present only on a denial: time until one request is admitted.
    pub retry_after: Option<Duration>,
}

impl RateLimitStatus {
    /// `Retry-After` value: whole seconds, rounded up (`None` unless denied).
    pub fn retry_after_secs(&self) -> Option<u64> {
        self.retry_after.map(ceil_secs)
    }
}

/// Outcome of a rate-limit check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Admitted; one token was taken from every applicable bucket.
    Allowed(RateLimitStatus),
    /// Throttled; nothing was consumed.
    Denied(RateLimitStatus),
    /// The bucket table is full of active buckets; nothing was consumed and the request
    /// must be rejected (fail closed). `retry_after` estimates when space frees up.
    Saturated {
        /// Time until at least one bucket can be reclaimed.
        retry_after: Duration,
    },
}

impl RateLimitDecision {
    /// Whether the request may proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitDecision::Allowed(_))
    }
}

/// A rule resolved at startup: the bucket scope and the allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateRule {
    /// Bucket scope ID (unique per bucket-sharing declaration within one app).
    pub scope: u32,
    /// Burst capacity.
    pub limit: u32,
    /// Window in nanoseconds.
    pub window_ns: u64,
}

impl RateRule {
    /// Builds a rule from a validated declaration.
    pub fn new(scope: u32, spec: &RateLimitSpec) -> Self {
        RateRule {
            scope,
            limit: spec.requests.max(1),
            window_ns: spec.per_ms.max(1).saturating_mul(1_000_000),
        }
    }
}

/// Per-request scratch storage: routes rarely carry more than a few limits, so the common
/// case stays on the stack.
type Inline<T> = smallvec::SmallVec<[T; 4]>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BucketKey {
    scope: u32,
    id: RateKeyValue,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    /// Theoretical arrival time in nanoseconds since the limiter epoch, times `limit`.
    tat: u128,
    limit: u32,
}

impl Bucket {
    /// Nanosecond (since epoch) at which the bucket is full again.
    fn idle_at_ns(&self) -> u64 {
        let l = u128::from(self.limit);
        u64::try_from(self.tat.div_ceil(l)).unwrap_or(u64::MAX)
    }
}

struct Shard {
    map: Mutex<HashMap<BucketKey, Bucket>>,
    /// Lower bound of the earliest `idle_at_ns` in this shard (`u64::MAX`: none).
    earliest_idle: AtomicU64,
}

/// Counters for metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateLimiterStats {
    /// Requests admitted.
    pub allowed: u64,
    /// Requests throttled by a client's quota (HTTP 429).
    pub denied: u64,
    /// Requests rejected because the bucket table was full (HTTP 503).
    pub saturated: u64,
    /// Fully refilled buckets reclaimed to make room.
    pub reclaimed: u64,
}

/// A bounded, sharded token-bucket rate limiter (see the module documentation).
pub struct RateLimiter {
    epoch: Instant,
    shards: Box<[Shard]>,
    hasher: RandomState,
    capacity: usize,
    len: AtomicUsize,
    allowed: AtomicU64,
    denied: AtomicU64,
    saturated: AtomicU64,
    reclaimed: AtomicU64,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .field("stats", &self.stats())
            .finish()
    }
}

/// One bucket a request consumes from.
#[derive(Clone, Copy, Debug)]
pub struct RateProbe<'k> {
    /// The rule.
    pub rule: RateRule,
    /// The client key.
    pub key: &'k RateKeyValue,
}

struct Evaluated {
    status: RateLimitStatus,
    new_tat: Option<u128>,
}

const EMPTY_STATUS: RateLimitStatus = RateLimitStatus {
    limit: 0,
    remaining: 0,
    next_token_after: Duration::ZERO,
    full_refill_after: Duration::ZERO,
    retry_after: None,
};

/// The rate limits of one route, resolved at startup.
#[derive(Clone, Debug)]
pub(crate) struct RouteRate {
    pub(crate) rules: Vec<RouteRule>,
    pub(crate) headers: bool,
    /// Precomputed `RateLimit-Policy` value (only when `headers`).
    pub(crate) policy_header: Option<http::HeaderValue>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RouteRule {
    pub(crate) rule: RateRule,
    pub(crate) key: RateKey,
    /// Policy name used in headers: `route`, `group`, `app` or `ceiling`.
    pub(crate) name: &'static str,
}

impl RouteRate {
    pub(crate) fn new(rules: Vec<RouteRule>, headers: bool) -> Self {
        let policy_header = headers
            .then(|| {
                let items: Vec<String> = rules
                    .iter()
                    .map(|r| {
                        let w = r.rule.window_ns / 1_000_000_000;
                        if r.rule.window_ns % 1_000_000_000 == 0 {
                            format!("\"{}\";q={};w={w}", r.name, r.rule.limit)
                        } else {
                            format!("\"{}\";q={}", r.name, r.rule.limit)
                        }
                    })
                    .collect();
                http::HeaderValue::from_str(&items.join(", ")).ok()
            })
            .flatten();
        RouteRate {
            rules,
            headers,
            policy_header,
        }
    }
}

/// What the rate-limit check recorded for a request.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RateOutcome {
    Checked {
        status: RateLimitStatus,
        policy: &'static str,
    },
    Saturated(Duration),
}

impl RateOutcome {
    /// The `RateLimit` header value for a checked request.
    pub(crate) fn header(&self) -> Option<http::HeaderValue> {
        match self {
            RateOutcome::Checked { status, policy } => {
                let t = ceil_secs(status.next_token_after);
                let v = format!("\"{policy}\";r={};t={t}", status.remaining);
                http::HeaderValue::from_str(&v).ok()
            }
            RateOutcome::Saturated(_) => None,
        }
    }
}

pub(crate) fn ceil_secs(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

fn scaled_to_duration(scaled: u128, limit: u32) -> Duration {
    let ns = scaled.div_ceil(u128::from(limit));
    Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
}

/// Evaluates one bucket at `now_ns` without mutating it.
fn evaluate(rule: RateRule, tat: Option<u128>, now_ns: u64) -> Evaluated {
    let l = u128::from(rule.limit);
    let t = u128::from(rule.window_ns);
    let now = u128::from(now_ns) * l;
    let tau = t * (l - 1);
    let start = tat.map_or(now, |tat| tat.max(now));
    let backlog = start - now;
    if backlog <= tau {
        let new_tat = start + t;
        let used = new_tat - now;
        let status = RateLimitStatus {
            limit: rule.limit,
            remaining: u32::try_from((l * t - used) / t).unwrap_or(u32::MAX),
            next_token_after: scaled_to_duration(used.saturating_sub(tau), rule.limit),
            full_refill_after: scaled_to_duration(used, rule.limit),
            retry_after: None,
        };
        Evaluated {
            status,
            new_tat: Some(new_tat),
        }
    } else {
        let wait = scaled_to_duration(backlog - tau, rule.limit);
        let status = RateLimitStatus {
            limit: rule.limit,
            remaining: 0,
            next_token_after: wait,
            full_refill_after: scaled_to_duration(backlog, rule.limit),
            retry_after: Some(wait),
        };
        Evaluated {
            status,
            new_tat: None,
        }
    }
}

impl RateLimiter {
    /// Creates a limiter holding at most `capacity` buckets (clamped to 1..=[`MAX_KEYS`];
    /// apps reject out-of-range values before binding).
    pub fn new(capacity: usize) -> Self {
        RateLimiter {
            epoch: Instant::now(),
            shards: (0..SHARDS)
                .map(|_| Shard {
                    map: Mutex::new(HashMap::new()),
                    earliest_idle: AtomicU64::new(u64::MAX),
                })
                .collect(),
            hasher: RandomState::new(),
            capacity: capacity.clamp(1, MAX_KEYS),
            len: AtomicUsize::new(0),
            allowed: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            saturated: AtomicU64::new(0),
            reclaimed: AtomicU64::new(0),
        }
    }

    /// Validates a configured capacity.
    pub(crate) fn validate_capacity(capacity: usize) -> Result<(), String> {
        if capacity == 0 || capacity > MAX_KEYS {
            return Err(format!(
                "Limits::rate_limit_keys must be between 1 and {MAX_KEYS}, got {capacity}"
            ));
        }
        Ok(())
    }

    /// Maximum number of buckets.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of live buckets.
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    /// Whether there are no buckets.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Decision counters.
    pub fn stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            allowed: self.allowed.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            saturated: self.saturated.load(Ordering::Relaxed),
            reclaimed: self.reclaimed.load(Ordering::Relaxed),
        }
    }

    fn now_ns(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX)
    }

    fn shard_of(&self, key: &BucketKey) -> usize {
        (self.hasher.hash_one(key) as usize) % SHARDS
    }

    fn lock(&self, i: usize) -> MutexGuard<'_, HashMap<BucketKey, Bucket>> {
        // Critical sections only run arithmetic and map operations, so a poisoned lock
        // still guards a consistent map.
        self.shards[i]
            .map
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Checks one bucket and takes a token if one is available.
    pub fn check_one(&self, rule: RateRule, key: &RateKeyValue, now: Instant) -> RateLimitDecision {
        self.check(&[RateProbe { rule, key }], now)
    }

    /// Takes one token from every probed bucket, or from none if any of them is empty.
    ///
    /// On denial the status of the bucket with the longest wait is returned; on success
    /// the status of the most constraining bucket (fewest remaining requests).
    pub fn check(&self, probes: &[RateProbe<'_>], now: Instant) -> RateLimitDecision {
        self.decide(probes, now, true).0
    }

    /// The status the next request would see, without taking a token.
    pub fn peek(&self, probes: &[RateProbe<'_>], now: Instant) -> RateLimitDecision {
        self.decide(probes, now, false).0
    }

    /// [`RateLimiter::check`], also returning the index of the probe that determined the
    /// reported status.
    pub(crate) fn check_indexed(
        &self,
        probes: &[RateProbe<'_>],
        now: Instant,
    ) -> (RateLimitDecision, usize) {
        self.decide(probes, now, true)
    }

    fn decide(
        &self,
        probes: &[RateProbe<'_>],
        now: Instant,
        commit: bool,
    ) -> (RateLimitDecision, usize) {
        let now_ns = self.now_ns(now);
        let keys: Inline<BucketKey> = probes
            .iter()
            .map(|p| BucketKey {
                scope: p.rule.scope,
                id: p.key.clone(),
            })
            .collect();
        let slots: Inline<usize> = keys.iter().map(|k| self.shard_of(k)).collect();
        let mut order: Inline<usize> = slots.clone();
        order.sort_unstable();
        order.dedup();
        let mut guards: Inline<(usize, MutexGuard<'_, HashMap<BucketKey, Bucket>>)> =
            order.iter().map(|&i| (i, self.lock(i))).collect();
        let guard_index = |shard: usize| order.binary_search(&shard).unwrap_or(0);

        let evaluated: Inline<Evaluated> = probes
            .iter()
            .zip(&keys)
            .zip(&slots)
            .map(|((p, k), &s)| {
                let tat = guards[guard_index(s)].1.get(k).map(|b| b.tat);
                evaluate(p.rule, tat, now_ns)
            })
            .collect();

        if let Some((i, denied)) = evaluated
            .iter()
            .enumerate()
            .filter(|(_, e)| e.new_tat.is_none())
            .max_by_key(|(_, e)| e.status.retry_after)
        {
            if commit {
                self.denied.fetch_add(1, Ordering::Relaxed);
            }
            return (RateLimitDecision::Denied(denied.status), i);
        }
        let Some((index, status)) = evaluated
            .iter()
            .map(|e| e.status)
            .enumerate()
            .min_by_key(|(_, s)| (s.remaining, std::cmp::Reverse(s.next_token_after)))
        else {
            return (RateLimitDecision::Allowed(EMPTY_STATUS), 0);
        };
        if !commit {
            return (RateLimitDecision::Allowed(status), index);
        }

        if !self.reserve(&keys, &slots, &order, now_ns, &mut guards) {
            self.saturated.fetch_add(1, Ordering::Relaxed);
            let earliest = self
                .shards
                .iter()
                .map(|s| s.earliest_idle.load(Ordering::Relaxed))
                .min()
                .unwrap_or(u64::MAX);
            let wait = Duration::from_nanos(earliest.saturating_sub(now_ns).max(1_000_000));
            return (RateLimitDecision::Saturated { retry_after: wait }, 0);
        }
        for ((e, k), (p, &s)) in evaluated.iter().zip(keys).zip(probes.iter().zip(&slots)) {
            let bucket = Bucket {
                tat: e.new_tat.unwrap_or(0),
                limit: p.rule.limit,
            };
            let idle = bucket.idle_at_ns();
            guards[guard_index(s)].1.insert(k, bucket);
            self.shards[s]
                .earliest_idle
                .fetch_min(idle, Ordering::Relaxed);
        }
        self.allowed.fetch_add(1, Ordering::Relaxed);
        (RateLimitDecision::Allowed(status), index)
    }

    /// Reserves room for the buckets among `keys` that do not exist yet, reclaiming fully
    /// refilled buckets if the table is full.
    fn reserve(
        &self,
        keys: &[BucketKey],
        slots: &[usize],
        order: &[usize],
        now_ns: u64,
        held: &mut [(usize, MutexGuard<'_, HashMap<BucketKey, Bucket>>)],
    ) -> bool {
        let missing = |held: &[(usize, MutexGuard<'_, HashMap<BucketKey, Bucket>>)]| {
            keys.iter()
                .zip(slots)
                .filter(|(k, s)| {
                    let g = order.binary_search(s).unwrap_or(0);
                    !held[g].1.contains_key(*k)
                })
                .count()
        };
        let mut need = missing(held);
        if need == 0 || self.try_grow(need) {
            return true;
        }
        for (i, map) in held.iter_mut() {
            self.sweep(*i, map, now_ns);
        }
        // Sweeping may have removed refilled buckets this request is about to recreate.
        need = missing(held);
        if self.try_grow(need) {
            return true;
        }
        for i in 0..SHARDS {
            if held.iter().any(|(h, _)| *h == i)
                || self.shards[i].earliest_idle.load(Ordering::Relaxed) > now_ns
            {
                continue;
            }
            // Never block on a shard another request holds: that could deadlock against
            // the locks this request already holds.
            if let Ok(mut map) = self.shards[i].map.try_lock() {
                self.sweep(i, &mut map, now_ns);
                drop(map);
                if self.try_grow(need) {
                    return true;
                }
            }
        }
        false
    }

    fn try_grow(&self, n: usize) -> bool {
        self.len
            .try_update(Ordering::AcqRel, Ordering::Acquire, |len| {
                (len + n <= self.capacity).then_some(len + n)
            })
            .is_ok()
    }

    /// Removes buckets of shard `i` that have completely refilled.
    fn sweep(&self, i: usize, map: &mut HashMap<BucketKey, Bucket>, now_ns: u64) {
        if self.shards[i].earliest_idle.load(Ordering::Relaxed) > now_ns {
            return;
        }
        let before = map.len();
        let mut earliest = u64::MAX;
        map.retain(|_, b| {
            let idle = b.idle_at_ns();
            if idle <= now_ns {
                false
            } else {
                earliest = earliest.min(idle);
                true
            }
        });
        let removed = before - map.len();
        self.shards[i]
            .earliest_idle
            .store(earliest, Ordering::Relaxed);
        if removed > 0 {
            self.len.fetch_sub(removed, Ordering::AcqRel);
            self.reclaimed.fetch_add(removed as u64, Ordering::Relaxed);
        }
    }

    /// Takes one token for `(route, key)` with a route-local rule.
    #[deprecated(
        since = "0.1.2",
        note = "use `check_one` or `check`, which return a full status"
    )]
    pub fn check_legacy(
        &self,
        route: u32,
        key: RateKeyValue,
        spec: &RateLimitSpec,
        now: Instant,
    ) -> Result<(), Duration> {
        match self.check_one(RateRule::new(route, spec), &key, now) {
            RateLimitDecision::Allowed(_) => Ok(()),
            RateLimitDecision::Denied(s) => Err(s.retry_after.unwrap_or(Duration::ZERO)),
            RateLimitDecision::Saturated { retry_after } => Err(retry_after),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(limit: u32, window_ms: u64) -> RateRule {
        RateRule {
            scope: 0,
            limit,
            window_ns: window_ms * 1_000_000,
        }
    }

    fn ip(n: u8) -> RateKeyValue {
        RateKeyValue::ip(IpAddr::from([10, 0, 0, n]))
    }

    fn status(d: RateLimitDecision) -> RateLimitStatus {
        match d {
            RateLimitDecision::Allowed(s) | RateLimitDecision::Denied(s) => s,
            RateLimitDecision::Saturated { .. } => panic!("unexpected saturation"),
        }
    }

    #[test]
    fn many_probes_are_all_or_nothing_beyond_inline_storage() {
        // More rules than the per-request scratch storage holds inline.
        let rl = RateLimiter::new(1024);
        let t0 = Instant::now();
        let rules: Vec<RateRule> = (0..6)
            .map(|scope| RateRule {
                scope,
                limit: if scope == 5 { 1 } else { 10 },
                window_ns: 10_000_000_000,
            })
            .collect();
        let k = ip(9);
        let probes: Vec<RateProbe<'_>> = rules
            .iter()
            .map(|&rule| RateProbe { rule, key: &k })
            .collect();
        let (first, index) = rl.check_indexed(&probes, t0);
        assert!(first.is_allowed());
        assert_eq!(index, 5, "the tightest rule is reported");
        let (denied, index) = rl.check_indexed(&probes, t0);
        assert!(!denied.is_allowed());
        assert_eq!(index, 5);
        for rule in &rules[..5] {
            let s = status(rl.peek(
                &[RateProbe {
                    rule: *rule,
                    key: &k,
                }],
                t0,
            ));
            // One token was taken by the allowed request; the peek accounts for the next.
            assert_eq!(
                s.remaining, 8,
                "a denied request takes no token from any bucket"
            );
        }
    }

    #[test]
    fn burst_then_exact_rejection_and_fractional_refill() {
        let rl = RateLimiter::new(1024);
        let t0 = Instant::now();
        let r = rule(3, 3_000);
        let k = ip(1);
        let remaining: Vec<u32> = (0..3)
            .map(|_| status(rl.check_one(r, &k, t0)).remaining)
            .collect();
        assert_eq!(remaining, [2, 1, 0]);
        let third = status(rl.peek(&[RateProbe { rule: r, key: &k }], t0));
        assert!(third.remaining == 0 && third.next_token_after == Duration::from_secs(1));

        let denied = rl.check_one(r, &k, t0);
        let s = status(denied);
        assert!(!denied.is_allowed());
        assert_eq!(
            s.retry_after,
            Some(Duration::from_secs(1)),
            "one token takes 1 s"
        );
        assert_eq!(s.full_refill_after, Duration::from_secs(3));
        assert_eq!(s.retry_after_secs(), Some(1));

        // 0.5 tokens accrued: still denied, and the wait shrinks exactly.
        let half = status(rl.check_one(r, &k, t0 + Duration::from_millis(500)));
        assert_eq!(half.retry_after, Some(Duration::from_millis(500)));
        assert_eq!(half.retry_after_secs(), Some(1), "Retry-After rounds up");

        let ok = rl.check_one(r, &k, t0 + Duration::from_secs(1));
        assert!(ok.is_allowed());
        let s = status(ok);
        assert_eq!(
            (s.remaining, s.next_token_after),
            (0, Duration::from_secs(1))
        );
        assert_eq!(s.full_refill_after, Duration::from_secs(3));
        assert_eq!(
            rl.stats(),
            RateLimiterStats {
                allowed: 4,
                denied: 2,
                saturated: 0,
                reclaimed: 0
            }
        );
    }

    #[test]
    fn non_integer_refill_intervals_are_exact() {
        // 3 per 1 s: one token every 333_333_333.3 ns.
        let rl = RateLimiter::new(16);
        let t0 = Instant::now();
        let r = rule(3, 1_000);
        let k = ip(2);
        for _ in 0..3 {
            assert!(rl.check_one(r, &k, t0).is_allowed());
        }
        let s = status(rl.check_one(r, &k, t0));
        assert_eq!(
            s.retry_after,
            Some(Duration::from_nanos(333_333_334)),
            "rounded up"
        );
        assert!(
            !rl.check_one(r, &k, t0 + Duration::from_nanos(333_333_333))
                .is_allowed()
        );
        assert!(
            rl.check_one(r, &k, t0 + Duration::from_nanos(333_333_334))
                .is_allowed()
        );
    }

    #[test]
    fn idle_buckets_refill_completely_and_extreme_values_do_not_overflow() {
        let rl = RateLimiter::new(16);
        let t0 = Instant::now();
        let r = rule(u32::MAX, MAX_WINDOW.as_millis() as u64);
        let k = ip(3);
        let s = status(rl.check_one(r, &k, t0));
        assert_eq!(s.remaining, u32::MAX - 1);
        let later = status(rl.check_one(r, &k, t0 + Duration::from_secs(10 * 366 * 86_400)));
        assert_eq!(later.remaining, u32::MAX - 1);
        let one = rule(1, 1);
        assert!(rl.check_one(one, &ip(4), t0).is_allowed());
        assert!(!rl.check_one(one, &ip(4), t0).is_allowed());
    }

    #[test]
    fn multiple_rules_are_all_or_nothing() {
        let rl = RateLimiter::new(16);
        let t0 = Instant::now();
        let route = RateRule {
            scope: 1,
            limit: 5,
            window_ns: 1_000_000_000,
        };
        let ceiling = RateRule {
            scope: 2,
            limit: 1,
            window_ns: 1_000_000_000,
        };
        let k = ip(5);
        let both = [
            RateProbe {
                rule: route,
                key: &k,
            },
            RateProbe {
                rule: ceiling,
                key: &k,
            },
        ];
        let first = status(rl.check(&both, t0));
        assert_eq!(first.limit, 1, "the ceiling is the tighter constraint");
        let denied = rl.check(&both, t0);
        assert!(!denied.is_allowed());
        // The denied request did not consume from the route bucket.
        let route_only = status(rl.peek(
            &[RateProbe {
                rule: route,
                key: &k,
            }],
            t0,
        ));
        assert_eq!(
            route_only.remaining, 3,
            "5 - 1 admitted - 1 for the peeked request"
        );
    }

    #[test]
    fn full_tables_reclaim_only_refilled_buckets_and_fail_closed() {
        let rl = RateLimiter::new(4);
        let t0 = Instant::now();
        let r = rule(2, 1_000);
        for n in 0..4 {
            assert!(rl.check_one(r, &ip(n), t0).is_allowed());
        }
        // Throttle client 0 so its bucket is active and denied.
        rl.check_one(r, &ip(0), t0);
        assert!(!rl.check_one(r, &ip(0), t0).is_allowed());
        // A new key cannot evict active buckets: fail closed.
        let flood = rl.check_one(r, &ip(9), t0);
        assert!(
            matches!(flood, RateLimitDecision::Saturated { .. }),
            "{flood:?}"
        );
        assert_eq!(rl.len(), 4);
        // Client 0 is still throttled: its bucket was not reset.
        assert!(!rl.check_one(r, &ip(0), t0).is_allowed());
        // After a full window every bucket has refilled and can be reclaimed.
        let later = t0 + Duration::from_secs(2);
        assert!(rl.check_one(r, &ip(9), later).is_allowed());
        assert!(rl.len() <= 4);
        assert!(rl.stats().reclaimed >= 1 && rl.stats().saturated == 1);
    }

    #[test]
    fn canonical_ips() {
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(
            RateKeyValue::ip(mapped),
            RateKeyValue::ip("192.0.2.1".parse().unwrap())
        );
    }

    #[test]
    fn specs_are_validated() {
        assert!(RateLimit::new(0, Duration::from_secs(1)).to_spec().is_err());
        assert!(RateLimit::new(1, Duration::ZERO).to_spec().is_err());
        assert!(
            RateLimit::new(1, Duration::from_micros(1500))
                .to_spec()
                .is_err()
        );
        assert!(
            RateLimit::new(1, MAX_WINDOW + Duration::from_secs(1))
                .to_spec()
                .is_err()
        );
        let s = RateLimit::new(5, Duration::from_millis(1500))
            .scope(RateScope::Group)
            .to_spec();
        assert_eq!(s.map(|s| (s.per_ms, s.scope)), Ok((1500, RateScope::Group)));
        assert!(RateLimiter::validate_capacity(0).is_err());
    }
}
