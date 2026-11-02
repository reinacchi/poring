//! Runtime flow recording, correlated with static graph node IDs.
//!
//! When a request is sampled, the pipeline records each stage it actually executes using
//! the same node IDs as the static graph (`crate::contract::graph`). Unsampled requests
//! (and builds without the `trace-flow` feature) do no recording work at all: the context
//! holds `None` and every `mark` is a single branch.
//!
//! Recording never touches request/response bodies, headers, cookies or tokens; it stores
//! stage identifiers, timings, the matched route ID, the status and the correlation ID.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::contract::graph::{RuntimeTrace, TraceStep, stage};

/// A pipeline stage. Indexed variants carry the hook/extractor position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Request received.
    Receive,
    /// Route lookup.
    Match,
    /// 404.
    NotFound,
    /// 405.
    MethodNotAllowed,
    /// CORS preflight.
    CorsPreflight,
    /// CORS check.
    Cors,
    /// Rate limit.
    RateLimit,
    /// Authentication.
    Auth,
    /// Authorisation.
    Authz,
    /// CSRF.
    Csrf,
    /// Body gate.
    BodyGate,
    /// Before hook i.
    Before(u8),
    /// Extractor i.
    Extract(u8),
    /// Validation of extractor i.
    Validate(u8),
    /// Annotation i.
    Annotation(u8),
    /// Native handler.
    Handler,
    /// Wasm guest.
    Wasm,
    /// After hook i.
    After(u8),
    /// Response mapping.
    Respond,
    /// Hook short-circuit.
    ShortCircuit,
    /// Extractor rejection.
    Reject,
    /// Handler error.
    Error,
    /// Denial with status.
    Deny(u16),
    /// Response handed to hyper.
    Send,
}

impl Stage {
    fn shared(self) -> bool {
        matches!(
            self,
            Stage::Receive
                | Stage::Match
                | Stage::NotFound
                | Stage::MethodNotAllowed
                | Stage::CorsPreflight
                | Stage::Send
        )
    }
}

/// Formats a node ID lazily (no allocation unless actually formatted).
pub struct NodeId<'a> {
    /// Route ID, if any.
    pub route: Option<&'a str>,
    /// Stage.
    pub stage: Stage,
}

impl fmt::Display for NodeId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.stage;
        if !s.shared()
            && let Some(r) = self.route
        {
            write!(f, "{r}.")?;
        }
        match s {
            Stage::Receive => f.write_str(stage::RECEIVE),
            Stage::Match => f.write_str(stage::MATCH),
            Stage::NotFound => f.write_str(stage::NOT_FOUND),
            Stage::MethodNotAllowed => f.write_str(stage::METHOD_NOT_ALLOWED),
            Stage::CorsPreflight => f.write_str(stage::CORS_PREFLIGHT),
            Stage::Cors => f.write_str(stage::CORS),
            Stage::RateLimit => f.write_str(stage::RATE_LIMIT),
            Stage::Auth => f.write_str(stage::AUTH),
            Stage::Authz => f.write_str(stage::AUTHZ),
            Stage::Csrf => f.write_str(stage::CSRF),
            Stage::BodyGate => f.write_str(stage::BODY_GATE),
            Stage::Before(i) => write!(f, "{}.{i}", stage::BEFORE),
            Stage::Extract(i) => write!(f, "{}.{i}", stage::EXTRACT),
            Stage::Validate(i) => write!(f, "{}.{i}", stage::VALIDATE),
            Stage::Annotation(i) => write!(f, "{}.{i}", stage::ANNOTATION),
            Stage::Handler => f.write_str(stage::HANDLER),
            Stage::Wasm => f.write_str(stage::WASM),
            Stage::After(i) => write!(f, "{}.{i}", stage::AFTER),
            Stage::Respond => f.write_str(stage::RESPOND),
            Stage::ShortCircuit => f.write_str(stage::SHORT_CIRCUIT),
            Stage::Reject => f.write_str(stage::REJECT),
            Stage::Error => f.write_str(stage::ERROR),
            Stage::Deny(s) => write!(f, "{}.{s}", stage::DENY),
            Stage::Send => f.write_str(stage::SEND),
        }
    }
}

/// Per-request recording state (only allocated for sampled requests).
#[derive(Debug)]
pub struct FlowState {
    start: Instant,
    steps: Vec<(Stage, u64)>,
    pub(crate) before: u8,
    pub(crate) after: u8,
    pub(crate) extract: u8,
    pub(crate) annotation: u8,
}

impl FlowState {
    pub(crate) fn new(start: Instant) -> Self {
        FlowState {
            start,
            steps: Vec::with_capacity(16),
            before: 0,
            after: 0,
            extract: 0,
            annotation: 0,
        }
    }

    pub(crate) fn mark(&mut self, s: Stage) {
        let t = self.start.elapsed().as_micros() as u64;
        self.steps.push((s, t));
    }

    pub(crate) fn finish(self, request_id: &str, route: Option<&str>, status: u16) -> RuntimeTrace {
        let total = self.start.elapsed().as_micros() as u64;
        let n = self.steps.len();
        let steps = self
            .steps
            .iter()
            .enumerate()
            .map(|(i, (s, t))| {
                let end = if i + 1 < n {
                    self.steps[i + 1].1
                } else {
                    total
                };
                TraceStep {
                    node: NodeId { route, stage: *s }.to_string(),
                    start_us: *t,
                    dur_us: end.saturating_sub(*t),
                }
            })
            .collect();
        RuntimeTrace {
            request_id: request_id.to_owned(),
            route: route.map(str::to_owned),
            status,
            total_us: total,
            steps,
        }
    }
}

/// Sampling configuration for the flow recorder.
#[derive(Clone, Copy, Debug)]
pub struct FlowConfig {
    /// Record 1 in `sample_every` requests (1 = every request). 0 disables recording.
    pub sample_every: u64,
    /// Maximum number of buffered traces (oldest are dropped first).
    pub capacity: usize,
}

impl Default for FlowConfig {
    fn default() -> Self {
        FlowConfig {
            sample_every: 0,
            capacity: 256,
        }
    }
}

/// Bounded buffer of recent runtime traces with drop accounting.
#[derive(Debug)]
pub struct FlowRecorder {
    cfg: FlowConfig,
    counter: AtomicU64,
    buf: Mutex<VecDeque<RuntimeTrace>>,
    recorded: AtomicU64,
    dropped: AtomicU64,
}

/// Recorder statistics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowStats {
    /// Traces stored.
    pub recorded: u64,
    /// Traces dropped (buffer contention or eviction of old traces).
    pub dropped: u64,
}

impl FlowRecorder {
    /// Creates a recorder.
    pub fn new(cfg: FlowConfig) -> Self {
        FlowRecorder {
            cfg,
            counter: AtomicU64::new(0),
            buf: Mutex::new(VecDeque::with_capacity(cfg.capacity.min(4096))),
            recorded: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Decides whether to sample the next request.
    pub(crate) fn sample(&self) -> bool {
        if !cfg!(feature = "trace-flow") || self.cfg.sample_every == 0 {
            return false;
        }
        self.counter
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(self.cfg.sample_every)
    }

    /// Stores a finished trace. Never blocks: on lock contention the trace is dropped and
    /// counted, so observability can't stall or fail business responses.
    pub(crate) fn push(&self, t: RuntimeTrace) {
        match self.buf.try_lock() {
            Ok(mut b) => {
                if b.len() >= self.cfg.capacity.max(1) {
                    b.pop_front();
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
                b.push_back(t);
                self.recorded.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// A copy of the buffered traces (oldest first).
    pub fn recent(&self) -> Vec<RuntimeTrace> {
        self.buf
            .lock()
            .map(|b| b.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Statistics.
    pub fn stats(&self) -> FlowStats {
        FlowStats {
            recorded: self.recorded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
}
