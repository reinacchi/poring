//! `cargo poring dev --wasm` and `cargo poring wasm ...` (feature `dev`).

use std::path::PathBuf;

use poring::descriptor::Method;
use poring::dynamic::DynPolicy;
use poring::prelude::*;
use poring::wasm::guest_kit::{GuestSpec, componentise};
use poring::wasm::watch::{WatchConfig, read_artefact, watch};
use poring::wasm::{GuestConfig, GuestRoute, GuestSlot, WasmHost};

/// Dev-host liveness.
#[poring::get("/__poring/health", public(reason = "dev host liveness"))]
async fn dev_health() -> String {
    format!("ok pid={}", std::process::id())
}

poring_app! {
    DevHost {
        routes: [dev_health],
    }
}

pub struct DevArgs {
    pub wasm: PathBuf,
    pub addr: String,
    pub route: String,
    pub method: String,
    pub name: Option<String>,
    pub grant: Vec<String>,
}

/// Runs a development host serving the guest at `route`, hot-reloading `wasm` on change.
/// The watcher is enabled only here (never in library defaults).
pub fn run_dev(a: DevArgs) -> Result<String, String> {
    use std::io::IsTerminal;
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    let bytes = read_artefact(&a.wasm).map_err(|e| e.to_string())?;
    let host = WasmHost::new().map_err(|e| e.to_string())?;
    // Discover the guest name from the artefact unless given.
    let name = match a.name {
        Some(n) => n,
        None => {
            let probe = GuestSlot::new(host.clone(), GuestConfig::new("__probe__"), &bytes);
            match probe {
                Err(poring::wasm::LoadError::Name { found, .. }) => found,
                Err(e) => return Err(e.to_string()),
                Ok(_) => "__probe__".to_owned(),
            }
        }
    };
    let mut cfg = GuestConfig::new(&name);
    for g in &a.grant {
        cfg = cfg.grant(g);
    }
    let slot = GuestSlot::new(host, cfg, &bytes).map_err(|e| e.to_string())?;
    let method = Method::parse(&a.method).ok_or_else(|| format!("unsupported method {}", a.method))?;
    let policy = DynPolicy {
        auth_required: Some(false),
        public_reason: Some("cargo poring dev host (development only)".into()),
        ..Default::default()
    };
    let app = DevHost::builder()
        .mount_dynamic(GuestRoute::mount(slot.clone(), method, &a.route, policy))
        .build()
        .map_err(|e| e.to_string())?;
    let _watch = watch(slot.clone(), &a.wasm, WatchConfig::default()).map_err(|e| e.to_string())?;
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&a.addr).await.map_err(|e| e.to_string())?;
        eprintln!(
            "poring dev: pid {} serving guest `{}` ({}) at {} {} on http://{}  (watching {})",
            std::process::id(),
            name,
            slot.current().version,
            a.method,
            a.route,
            a.addr,
            a.wasm.display()
        );
        app.serve(listener, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| e.to_string())
    })?;
    Ok(String::new())
}

/// `cargo poring wasm componentise <in.wat|in.wasm> -o <out.wasm>`
pub fn componentise_file(input: &PathBuf, out: &PathBuf) -> Result<String, String> {
    let bytes = std::fs::read(input).map_err(|e| e.to_string())?;
    let c = componentise(&bytes).map_err(|e| e.to_string())?;
    std::fs::write(out, &c).map_err(|e| e.to_string())?;
    Ok(format!("wrote {} ({} bytes)\n", out.display(), c.len()))
}

/// `cargo poring wasm new-echo --name N --version V -o out.wat`
pub fn new_echo(name: &str, version: &str, out: &PathBuf) -> Result<String, String> {
    let wat = GuestSpec::echo(name, version).core_wat();
    std::fs::write(out, wat).map_err(|e| e.to_string())?;
    Ok(format!("wrote {}\n", out.display()))
}
