//! Sandboxed, hot-reloadable Wasm guest routes (`wasm` feature), using the Wasmtime
//! **Component Model** and the versioned WIT world in `wit/poring-plugin.wit`.
//!
//! * **Isolation**: every request runs in a fresh `Store` instantiated from a pre-validated
//!   `InstancePre` (no store sharing across requests), with fuel, an epoch deadline, memory,
//!   table and instance limits, and request/response size caps. Guests get no WASI: no
//!   filesystem, network, environment, clocks or randomness. The only importable capability
//!   is `log`, and only when granted.
//! * **Reload**: [`GuestSlot::try_reload`] compiles, links against the *granted* imports,
//!   validates the ABI version and declared capabilities, and runs a probe call, all off the
//!   live path. Only then does it atomically swap the active version (`ArcSwap`). In-flight
//!   requests keep their version until they finish; failures leave the last known-good
//!   version active. History is bounded and [`GuestSlot::rollback`] restores the previous
//!   version.
//! * **Policy**: a slot is mounted as a Poring *dynamic route* ([`GuestRoute`]), so the host's
//!   runtime policy pipeline (authn/authz/CSRF/rate limits/body limits/timeouts) runs before
//!   any guest code. Dynamic routes are validated at startup, **not** at compile time.
//!
//! Hot reload replaces *guest* code compiled to Wasm. It cannot replace native Rust handlers
//! in the running host process.

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::dynamic::{BoxFuture, DynEndpoint, DynRequest};
use crate::{ApiError, IntoResponse, Response};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};
use sha2::Digest;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Engine, Store};

#[cfg(feature = "guest-kit")]
pub mod guest_kit;
#[cfg(feature = "hot-reload")]
pub mod watch;

mod bindings {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "guest",
    });
}

use bindings::exports::poring::plugin::handler;

/// The guest ABI version this host supports.
pub const ABI_VERSION: u32 = 1;
/// The only capability a host can grant today.
pub const CAP_LOG: &str = "log";
/// Epoch tick used for wall-clock deadlines.
pub const EPOCH_TICK: Duration = Duration::from_millis(5);

/// Resource limits and grants for one guest slot.
#[derive(Clone, Debug)]
pub struct GuestConfig {
    /// Expected guest name (`guest-info.name` must match).
    pub name: String,
    /// Fuel per request (roughly, Wasm instructions).
    pub fuel: u64,
    /// Wall-clock limit per guest call (epoch interruption).
    pub timeout: Duration,
    /// Max linear memory per instance (bytes).
    pub max_memory_bytes: usize,
    /// Max table elements.
    pub max_table_elements: usize,
    /// Max request body passed to the guest.
    pub max_request_bytes: usize,
    /// Max response body accepted from the guest.
    pub max_response_bytes: usize,
    /// Max artefact size.
    pub max_artefact_bytes: usize,
    /// Capabilities the host grants (e.g. `log`). Everything else is denied.
    pub granted: BTreeSet<String>,
    /// Retained previous versions for rollback.
    pub retained_versions: usize,
    /// Max concurrent guest executions for this slot.
    pub max_concurrency: usize,
}

impl GuestConfig {
    /// Conservative defaults: 50M fuel, 2 s, 16 MiB memory, 1 MiB request/response, no
    /// capabilities, 3 retained versions, 64 concurrent calls.
    pub fn new(name: impl Into<String>) -> Self {
        GuestConfig {
            name: name.into(),
            fuel: 50_000_000,
            timeout: Duration::from_secs(2),
            max_memory_bytes: 16 << 20,
            max_table_elements: 10_000,
            max_request_bytes: 1 << 20,
            max_response_bytes: 1 << 20,
            max_artefact_bytes: 32 << 20,
            granted: BTreeSet::new(),
            retained_versions: 3,
            max_concurrency: 64,
        }
    }

    /// Grants a capability.
    pub fn grant(mut self, cap: &str) -> Self {
        self.granted.insert(cap.to_owned());
        self
    }
}

/// Why a candidate artefact was rejected (the active version is unaffected).
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// Larger than `max_artefact_bytes`.
    #[error("artefact is {0} bytes, above the limit")]
    TooLarge(usize),
    /// Not a valid component (or failed to compile).
    #[error("invalid component: {0}")]
    Compile(String),
    /// Imports something not granted (or not provided by the host at all).
    #[error("component imports a capability that is not granted: {0}")]
    DeniedImport(String),
    /// `guest-info.abi` mismatch.
    #[error("guest ABI version {found} is not supported (host supports {ABI_VERSION})")]
    Abi {
        /// Declared ABI.
        found: u32,
    },
    /// Declared capabilities exceed the grant.
    #[error("guest declares capabilities that are not granted: {0:?}")]
    DeniedCapability(Vec<String>),
    /// Guest name mismatch.
    #[error("guest name `{found}` does not match the slot `{expected}`")]
    Name {
        /// Expected.
        expected: String,
        /// Found.
        found: String,
    },
    /// Trap or failure while probing.
    #[error("guest failed preflight: {0}")]
    Preflight(String),
    /// I/O reading the artefact.
    #[error("cannot read artefact: {0}")]
    Io(String),
}

/// Shared Wasmtime engine with an epoch ticker.
pub struct WasmHost {
    engine: Engine,
    _ticker: std::thread::JoinHandle<()>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for WasmHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmHost").finish_non_exhaustive()
    }
}

impl Drop for WasmHost {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl WasmHost {
    /// Creates an engine with fuel metering and epoch interruption enabled.
    pub fn new() -> Result<Arc<Self>, LoadError> {
        let mut cfg = wasmtime::Config::new();
        cfg.consume_fuel(true);
        cfg.epoch_interruption(true);
        cfg.wasm_component_model(true);
        let engine = Engine::new(&cfg).map_err(|e| LoadError::Compile(e.to_string()))?;
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (e2, s2) = (engine.clone(), stop.clone());
        let ticker = std::thread::Builder::new()
            .name("poring-wasm-epoch".into())
            .spawn(move || {
                while !s2.load(Ordering::Relaxed) {
                    std::thread::sleep(EPOCH_TICK);
                    e2.increment_epoch();
                }
            })
            .map_err(|e| LoadError::Compile(format!("cannot start epoch ticker: {e}")))?;
        Ok(Arc::new(WasmHost { engine, _ticker: ticker, stop }))
    }
}

/// Per-store state: limits and the `log` capability budget.
struct StoreState {
    limits: Limiter,
    log_lines: u32,
    guest: String,
}

struct Limiter {
    max_memory: usize,
    max_table: usize,
    denied: bool,
}

impl wasmtime::ResourceLimiter for Limiter {
    fn memory_growing(&mut self, _current: usize, desired: usize, _max: Option<usize>) -> wasmtime::Result<bool> {
        let ok = desired <= self.max_memory;
        self.denied |= !ok;
        Ok(ok)
    }
    fn table_growing(&mut self, _current: usize, desired: usize, _max: Option<usize>) -> wasmtime::Result<bool> {
        let ok = desired <= self.max_table;
        self.denied |= !ok;
        Ok(ok)
    }
    fn instances(&self) -> usize {
        16
    }
    fn tables(&self) -> usize {
        16
    }
    fn memories(&self) -> usize {
        4
    }
}

const MAX_LOG_LINES: u32 = 16;
const MAX_LOG_BYTES: usize = 1024;

impl bindings::poring::plugin::log::Host for StoreState {
    fn write(&mut self, level: u8, message: String) {
        if self.log_lines >= MAX_LOG_LINES {
            return;
        }
        self.log_lines += 1;
        let msg: String = message.chars().filter(|c| !c.is_control()).take(MAX_LOG_BYTES).collect();
        match level {
            0 | 1 => tracing::error!(target: "poring::guest", guest = %self.guest, "{msg}"),
            2 => tracing::info!(target: "poring::guest", guest = %self.guest, "{msg}"),
            _ => tracing::debug!(target: "poring::guest", guest = %self.guest, "{msg}"),
        }
    }
}

/// A loaded, validated, ready-to-instantiate guest version.
pub struct GuestVersion {
    /// Monotonic sequence number within the slot (1 = first load).
    pub seq: u64,
    /// `guest-info.name`.
    pub name: String,
    /// `guest-info.version`.
    pub version: String,
    /// Declared capabilities.
    pub capabilities: Vec<String>,
    /// SHA-256 of the artefact (hex).
    pub sha256: String,
    /// When it became loadable.
    pub loaded_at: SystemTime,
    pre: bindings::GuestPre<StoreState>,
}

impl std::fmt::Debug for GuestVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestVersion")
            .field("seq", &self.seq)
            .field("name", &self.name)
            .field("version", &self.version)
            .field("sha256", &&self.sha256[..12])
            .finish_non_exhaustive()
    }
}

/// A reload attempt outcome (bounded event log).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReloadEvent {
    /// A version became active.
    Activated {
        /// Sequence.
        seq: u64,
        /// Guest version string.
        version: String,
        /// Short hash.
        sha256: String,
    },
    /// A candidate was rejected; the previous version stayed active.
    Rejected {
        /// Reason.
        reason: String,
    },
    /// Rolled back to an earlier version.
    RolledBack {
        /// Sequence now active.
        seq: u64,
    },
    /// Candidate identical to the active version; ignored.
    Unchanged,
}

/// Outcome of executing one guest call (used for status mapping and tests).
#[derive(Debug)]
enum CallError {
    Trap(String),
    OutOfFuel,
    Timeout,
    ResourceExhausted,
}

/// An atomically swappable guest with bounded history.
pub struct GuestSlot {
    host: Arc<WasmHost>,
    cfg: GuestConfig,
    linker: Linker<StoreState>,
    current: ArcSwap<GuestVersion>,
    history: Mutex<VecDeque<Arc<GuestVersion>>>,
    events: Mutex<VecDeque<ReloadEvent>>,
    seq: AtomicU64,
    permits: Arc<tokio::sync::Semaphore>,
    calls: AtomicU64,
}

impl std::fmt::Debug for GuestSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestSlot").field("name", &self.cfg.name).field("current", &*self.current.load()).finish()
    }
}

fn sha256_hex(b: &[u8]) -> String {
    sha2::Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn new_store(host: &WasmHost, cfg: &GuestConfig, fuel: u64) -> Result<Store<StoreState>, String> {
    let mut store = Store::new(
        &host.engine,
        StoreState {
            limits: Limiter { max_memory: cfg.max_memory_bytes, max_table: cfg.max_table_elements, denied: false },
            log_lines: 0,
            guest: cfg.name.clone(),
        },
    );
    store.limiter(|s| &mut s.limits);
    store.set_fuel(fuel).map_err(|e| e.to_string())?;
    let ticks = (cfg.timeout.as_millis() / EPOCH_TICK.as_millis()).max(1) as u64 + 1;
    store.set_epoch_deadline(ticks);
    store.epoch_deadline_trap();
    Ok(store)
}

fn classify(err: wasmtime::Error, store: &Store<StoreState>) -> CallError {
    if store.data().limits.denied {
        return CallError::ResourceExhausted;
    }
    match err.downcast_ref::<wasmtime::Trap>() {
        Some(wasmtime::Trap::OutOfFuel) => CallError::OutOfFuel,
        Some(wasmtime::Trap::Interrupt) => CallError::Timeout,
        Some(t) => CallError::Trap(t.to_string()),
        None => CallError::Trap(format!("{err:#}")),
    }
}

impl GuestSlot {
    /// Loads the initial version. Fails if the artefact does not pass preflight.
    pub fn new(host: Arc<WasmHost>, cfg: GuestConfig, artefact: &[u8]) -> Result<Arc<Self>, LoadError> {
        let mut linker = Linker::new(&host.engine);
        if cfg.granted.contains(CAP_LOG) {
            bindings::poring::plugin::log::add_to_linker::<StoreState, HasSelf<StoreState>>(&mut linker, |s| s)
                .map_err(|e| LoadError::Compile(e.to_string()))?;
        }
        let first = Self::preflight(&host, &cfg, &linker, artefact, 1)?;
        let slot = Arc::new(GuestSlot {
            permits: Arc::new(tokio::sync::Semaphore::new(cfg.max_concurrency.max(1))),
            host,
            linker,
            current: ArcSwap::from_pointee(first),
            history: Mutex::new(VecDeque::new()),
            events: Mutex::new(VecDeque::new()),
            seq: AtomicU64::new(1),
            calls: AtomicU64::new(0),
            cfg,
        });
        let cur = slot.current();
        slot.event(ReloadEvent::Activated {
            seq: 1,
            version: cur.version.clone(),
            sha256: cur.sha256[..12].to_owned(),
        });
        Ok(slot)
    }

    /// Loads the initial version from a file.
    pub fn from_file(host: Arc<WasmHost>, cfg: GuestConfig, path: &std::path::Path) -> Result<Arc<Self>, LoadError> {
        let bytes = std::fs::read(path).map_err(|e| LoadError::Io(e.to_string()))?;
        Self::new(host, cfg, &bytes)
    }

    fn preflight(
        host: &WasmHost,
        cfg: &GuestConfig,
        linker: &Linker<StoreState>,
        artefact: &[u8],
        seq: u64,
    ) -> Result<GuestVersion, LoadError> {
        if artefact.len() > cfg.max_artefact_bytes {
            return Err(LoadError::TooLarge(artefact.len()));
        }
        let sha256 = sha256_hex(artefact);
        let component = Component::new(&host.engine, artefact).map_err(|e| LoadError::Compile(format!("{e:#}")))?;
        let instance_pre = linker.instantiate_pre(&component).map_err(|e| LoadError::DeniedImport(format!("{e:#}")))?;
        let pre = bindings::GuestPre::new(instance_pre).map_err(|e| LoadError::Compile(format!("{e:#}")))?;
        // Probe in an isolated store with the production limits.
        let mut store = new_store(host, cfg, cfg.fuel).map_err(LoadError::Preflight)?;
        let guest = pre.instantiate(&mut store).map_err(|e| LoadError::Preflight(format!("instantiate: {e:#}")))?;
        let info = guest
            .poring_plugin_handler()
            .call_info(&mut store)
            .map_err(|e| LoadError::Preflight(format!("info(): {e:#}")))?;
        if info.abi != ABI_VERSION {
            return Err(LoadError::Abi { found: info.abi });
        }
        if info.name != cfg.name {
            return Err(LoadError::Name { expected: cfg.name.clone(), found: info.name });
        }
        let denied: Vec<String> = info.capabilities.iter().filter(|c| !cfg.granted.contains(*c)).cloned().collect();
        if !denied.is_empty() {
            return Err(LoadError::DeniedCapability(denied));
        }
        // Warm-up probe call in a fresh store (per-request semantics).
        let mut store = new_store(host, cfg, cfg.fuel).map_err(LoadError::Preflight)?;
        let guest = pre.instantiate(&mut store).map_err(|e| LoadError::Preflight(format!("instantiate: {e:#}")))?;
        let probe = handler::Request {
            method: "GET".into(),
            path: "/__poring/probe".into(),
            query: String::new(),
            headers: vec![handler::Header { name: "x-poring-probe".into(), value: "1".into() }],
            body: Vec::new(),
            params: Vec::new(),
            principal: None,
        };
        if let Err(e) = guest.poring_plugin_handler().call_handle(&mut store, &probe) {
            let why = match classify(e, &store) {
                CallError::OutOfFuel => "probe exhausted its fuel".to_owned(),
                CallError::Timeout => "probe exceeded the time limit".to_owned(),
                CallError::ResourceExhausted => "probe exceeded memory/table limits".to_owned(),
                CallError::Trap(t) => format!("probe trapped: {t}"),
            };
            return Err(LoadError::Preflight(why));
        }
        Ok(GuestVersion {
            seq,
            name: info.name,
            version: info.version,
            capabilities: info.capabilities,
            sha256,
            loaded_at: SystemTime::now(),
            pre,
        })
    }

    fn event(&self, e: ReloadEvent) {
        let mut ev = self.events.lock().unwrap_or_else(|p| p.into_inner());
        if ev.len() >= 64 {
            ev.pop_front();
        }
        ev.push_back(e);
    }

    /// Validates `artefact` off the live path and atomically activates it. On any failure
    /// the active version is unchanged and the reason is returned (and logged as an event).
    /// This is the manual production rollout API (no watcher involved).
    pub fn try_reload(&self, artefact: &[u8]) -> Result<Arc<GuestVersion>, LoadError> {
        if sha256_hex(artefact) == self.current.load().sha256 {
            self.event(ReloadEvent::Unchanged);
            return Ok(self.current());
        }
        let seq = self.seq.load(Ordering::SeqCst) + 1;
        match Self::preflight(&self.host, &self.cfg, &self.linker, artefact, seq) {
            Ok(v) => {
                self.seq.store(seq, Ordering::SeqCst);
                let new = Arc::new(v);
                let old = self.current.swap(new.clone());
                let mut h = self.history.lock().unwrap_or_else(|p| p.into_inner());
                h.push_back(old);
                while h.len() > self.cfg.retained_versions {
                    h.pop_front();
                }
                drop(h);
                tracing::info!(guest = %self.cfg.name, seq, version = %new.version, "guest version activated");
                self.event(ReloadEvent::Activated {
                    seq,
                    version: new.version.clone(),
                    sha256: new.sha256[..12].to_owned(),
                });
                Ok(new)
            }
            Err(e) => {
                tracing::warn!(guest = %self.cfg.name, error = %e, "guest reload rejected; keeping the active version");
                self.event(ReloadEvent::Rejected { reason: e.to_string() });
                Err(e)
            }
        }
    }

    /// Re-activates the most recent retained previous version.
    pub fn rollback(&self) -> Option<Arc<GuestVersion>> {
        let prev = self.history.lock().unwrap_or_else(|p| p.into_inner()).pop_back()?;
        self.current.store(prev.clone());
        tracing::warn!(guest = %self.cfg.name, seq = prev.seq, "guest rolled back");
        self.event(ReloadEvent::RolledBack { seq: prev.seq });
        Some(prev)
    }

    /// The active version.
    pub fn current(&self) -> Arc<GuestVersion> {
        self.current.load_full()
    }

    /// Retained previous versions (oldest first).
    pub fn history(&self) -> Vec<Arc<GuestVersion>> {
        self.history.lock().unwrap_or_else(|p| p.into_inner()).iter().cloned().collect()
    }

    /// Recent reload events (bounded).
    pub fn events(&self) -> Vec<ReloadEvent> {
        self.events.lock().unwrap_or_else(|p| p.into_inner()).iter().cloned().collect()
    }

    /// Total guest calls executed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }

    /// Executes one request against the version active *now*; that version stays alive
    /// until the call completes, even if a reload happens meanwhile.
    pub async fn call(self: &Arc<Self>, req: DynRequest) -> Response {
        let lease = self.current();
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "guest_busy",
                "guest concurrency limit reached",
                &lease,
            );
        };
        if req.body.len() > self.cfg.max_request_bytes {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "request too large for guest",
                &lease,
            );
        }
        let started = Instant::now();
        self.calls.fetch_add(1, Ordering::Relaxed);
        // Guest code is CPU-bound (bounded by fuel and the epoch deadline). On a multi-thread
        // runtime, `block_in_place` hands this worker's queued tasks to another thread for the
        // duration of the call, so the async scheduler keeps running without a thread hop.
        // On a current-thread runtime we fall back to `spawn_blocking`.
        let multi = tokio::runtime::Handle::try_current()
            .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            .unwrap_or(false);
        let result = if multi {
            let r = tokio::task::block_in_place(|| self.execute(&lease, req));
            drop(permit);
            r
        } else {
            let slot = self.clone();
            let lease2 = lease.clone();
            let joined = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                slot.execute(&lease2, req)
            })
            .await;
            match joined {
                Ok(r) => r,
                Err(e) => Err(CallError::Trap(format!("guest task failed: {e}"))),
            }
        };
        tracing::debug!(guest = %self.cfg.name, seq = lease.seq, elapsed_us = started.elapsed().as_micros() as u64, "guest call");
        match result {
            Ok(Ok(resp)) => self.map_response(resp, &lease),
            Ok(Err(ge)) => {
                let status = StatusCode::from_u16(ge.status.clamp(400, 599)).unwrap_or(StatusCode::BAD_GATEWAY);
                let msg: String = ge.message.chars().take(512).collect();
                error_response(status, "guest_error", &msg, &lease)
            }
            Err(CallError::OutOfFuel) => error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "guest_out_of_fuel",
                "guest exceeded its compute budget",
                &lease,
            ),
            Err(CallError::Timeout) => error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "guest_timeout",
                "guest exceeded its time limit",
                &lease,
            ),
            Err(CallError::ResourceExhausted) => error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "guest_resource_exhausted",
                "guest exceeded its memory limit",
                &lease,
            ),
            Err(CallError::Trap(t)) => {
                tracing::warn!(guest = %self.cfg.name, seq = lease.seq, trap = %t, "guest trapped");
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "guest_trap", "guest failed", &lease)
            }
        }
    }

    fn execute(
        &self,
        v: &GuestVersion,
        req: DynRequest,
    ) -> Result<Result<handler::Response, handler::GuestError>, CallError> {
        let mut store = new_store(&self.host, &self.cfg, self.cfg.fuel).map_err(CallError::Trap)?;
        let guest = match v.pre.instantiate(&mut store) {
            Ok(g) => g,
            Err(e) => return Err(classify(e, &store)),
        };
        let wreq = handler::Request {
            method: req.method.as_str().to_owned(),
            path: req.uri.path().to_owned(),
            query: req.uri.query().unwrap_or("").to_owned(),
            headers: req
                .headers
                .iter()
                .take(64)
                .filter_map(|(k, v)| {
                    v.to_str().ok().map(|v| handler::Header { name: k.as_str().to_owned(), value: v.to_owned() })
                })
                .collect(),
            body: req.body.to_vec(),
            params: req.params.into_iter().map(|(name, value)| handler::Header { name, value }).collect(),
            principal: req.identity.map(|i| i.subject),
        };
        guest.poring_plugin_handler().call_handle(&mut store, &wreq).map_err(|e| classify(e, &store))
    }

    fn map_response(&self, r: handler::Response, v: &GuestVersion) -> Response {
        if r.body.len() > self.cfg.max_response_bytes {
            return error_response(StatusCode::BAD_GATEWAY, "guest_response_too_large", "guest response too large", v);
        }
        let status =
            StatusCode::from_u16(r.status).ok().filter(|s| !s.is_informational()).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut res = (status, Bytes::from(r.body)).into_response();
        res.headers_mut().remove(http::header::CONTENT_TYPE);
        for h in r.headers.into_iter().take(32) {
            let Ok(name) = HeaderName::from_bytes(h.name.as_bytes()) else { continue };
            if FORBIDDEN_RESPONSE_HEADERS.contains(&name.as_str()) || name.as_str().starts_with("x-poring-") {
                continue;
            }
            if let Ok(val) = HeaderValue::from_str(&h.value) {
                res.headers_mut().append(name, val);
            }
        }
        tag(&mut res, v);
        res
    }
}

/// Headers a guest may not set (hop-by-hop, framing, cookies, host-owned).
pub const FORBIDDEN_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "transfer-encoding",
    "content-length",
    "upgrade",
    "te",
    "trailer",
    "proxy-authenticate",
    "set-cookie",
    "strict-transport-security",
    "access-control-allow-origin",
    "access-control-allow-credentials",
];

fn tag(res: &mut Response, v: &GuestVersion) {
    if let Ok(h) = HeaderValue::from_str(&format!("{}/{}#{}", v.name, v.version, v.seq)) {
        res.headers_mut().insert("x-poring-guest", h);
    }
}

fn error_response(status: StatusCode, code: &'static str, msg: &str, v: &GuestVersion) -> Response {
    let mut r = ApiError::new(status, code, msg.to_owned()).into_response();
    tag(&mut r, v);
    r
}

/// A guest slot mounted as a Poring dynamic route.
#[derive(Clone, Debug)]
pub struct GuestRoute(pub Arc<GuestSlot>);

impl DynEndpoint for GuestRoute {
    fn call(&self, req: DynRequest) -> BoxFuture<'static, Response> {
        let slot = self.0.clone();
        Box::pin(async move { slot.call(req).await })
    }

    fn metadata(&self) -> Vec<(String, String)> {
        let v = self.0.current();
        vec![
            ("guest_name".into(), v.name.clone()),
            ("guest_version".into(), format!("{}#{}", v.version, v.seq)),
            ("guest_sha256".into(), v.sha256[..12].to_owned()),
            ("guest_abi".into(), ABI_VERSION.to_string()),
            ("guest_capabilities".into(), v.capabilities.join(",")),
        ]
    }
}

impl GuestRoute {
    /// Builds a Poring dynamic route registration for this slot.
    pub fn mount(
        slot: Arc<GuestSlot>,
        method: crate::descriptor::Method,
        path: &str,
        policy: crate::dynamic::DynPolicy,
    ) -> crate::dynamic::DynamicRoute {
        crate::dynamic::DynamicRoute {
            method,
            path: path.to_owned(),
            name: slot.cfg.name.clone(),
            policy,
            endpoint: Arc::new(GuestRoute(slot)),
        }
    }
}
