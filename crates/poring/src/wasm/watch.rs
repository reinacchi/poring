//! Development file watcher (`hot-reload` feature). Never started implicitly: call
//! [`watch`] explicitly (as `cargo poring dev --wasm` and the `wasm_live --watch` example do).
//!
//! Pipeline per change: filesystem event (inotify/FSEvents via `notify`, plus a polling
//! safety net) → debounce → **stability check** (size and mtime unchanged across a settle
//! interval) → read → (`.wat` files are componentised with the guest kit) →
//! [`GuestSlot::try_reload`] (compile, link, validate, probe, atomic swap) on the watcher
//! thread, never on a request thread. A partially written artefact either fails the
//! stability check or fails preflight; in both cases the last known-good version keeps
//! serving.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use notify::Watcher as _;

use crate::wasm::{GuestSlot, LoadError};

/// Watcher timing.
#[derive(Clone, Copy, Debug)]
pub struct WatchConfig {
    /// Quiet period after the last event before checking.
    pub debounce: Duration,
    /// Size/mtime must stay unchanged for this long.
    pub settle: Duration,
    /// Polling interval (safety net when events are missed or unavailable).
    pub poll: Duration,
}

impl Default for WatchConfig {
    fn default() -> Self {
        WatchConfig {
            debounce: Duration::from_millis(150),
            settle: Duration::from_millis(100),
            poll: Duration::from_millis(500),
        }
    }
}

/// Stops the watcher when dropped.
#[derive(Debug)]
pub struct WatchHandle {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WatchHandle {
    /// Stops the watcher and waits for its thread.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn stat(p: &Path) -> Option<(u64, SystemTime)> {
    let m = std::fs::metadata(p).ok()?;
    Some((m.len(), m.modified().ok()?))
}

/// Reads an artefact; `.wat` core modules are componentised (guest-kit).
pub fn read_artefact(p: &Path) -> Result<Vec<u8>, LoadError> {
    let bytes = std::fs::read(p).map_err(|e| LoadError::Io(e.to_string()))?;
    #[cfg(feature = "guest-kit")]
    if p.extension().and_then(|e| e.to_str()) == Some("wat") {
        return crate::wasm::guest_kit::componentise(&bytes).map_err(|e| LoadError::Compile(e.to_string()));
    }
    Ok(bytes)
}

/// Watches `path` and hot-reloads `slot` on stable changes.
pub fn watch(slot: Arc<GuestSlot>, path: impl Into<PathBuf>, cfg: WatchConfig) -> Result<WatchHandle, LoadError> {
    let path: PathBuf = path.into();
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let file_name = path.file_name().map(|f| f.to_os_string());
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res
            && ev.paths.iter().any(|p| p.file_name().map(|f| Some(f.to_os_string()) == file_name).unwrap_or(false))
        {
            let _ = tx.send(());
        }
    })
    .ok();
    if let Some(w) = watcher.as_mut()
        && let Err(e) = w.watch(&dir, notify::RecursiveMode::NonRecursive)
    {
        tracing::warn!(error = %e, "filesystem events unavailable; falling back to polling");
        watcher = None;
    }
    let stop2 = stop.clone();
    let thread = std::thread::Builder::new()
        .name("poring-wasm-watch".into())
        .spawn(move || {
            let _keep = watcher;
            let mut last = stat(&path);
            while !stop2.load(Ordering::Relaxed) {
                let evented = rx.recv_timeout(cfg.poll).is_ok();
                if stop2.load(Ordering::Relaxed) {
                    break;
                }
                let now = stat(&path);
                if !evented && now == last {
                    continue;
                }
                // Debounce: wait until events stop arriving.
                while rx.recv_timeout(cfg.debounce).is_ok() {}
                // Stability: size and mtime unchanged across the settle interval.
                let a = stat(&path);
                std::thread::sleep(cfg.settle);
                let b = stat(&path);
                if a.is_none() || a != b || a.map(|(len, _)| len == 0).unwrap_or(true) || a == last {
                    continue;
                }
                last = b;
                match read_artefact(&path) {
                    Ok(bytes) => match slot.try_reload(&bytes) {
                        Ok(v) => tracing::info!(path = %path.display(), seq = v.seq, version = %v.version, "hot reload applied"),
                        Err(e) => tracing::warn!(path = %path.display(), error = %e, "hot reload rejected"),
                    },
                    Err(e) => tracing::warn!(path = %path.display(), error = %e, "cannot read artefact"),
                }
            }
        })
        .map_err(|e| LoadError::Io(e.to_string()))?;
    Ok(WatchHandle { stop, thread: Some(thread) })
}
