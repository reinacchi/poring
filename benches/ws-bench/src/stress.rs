//! Sustained-load and leak checks for Poring's managed WebSocket sessions.
//!
//! ```text
//! cargo run --release -- stress                                   # 100 and 1000 connections
//! cargo run --release -- stress --conns 100,1000,5000,10000 --secs 10
//! cargo run --release -- stress --profiles slow,shutdown --conns 1000
//! ```
//!
//! Each profile starts a fresh `stress-server` process (Poring, managed sessions, release
//! build) and drives it from this process. The server prints its `WsStats` every 100 ms,
//! and answers `shutdown` on stdin with a timed graceful shutdown.
//!
//! Profiles (all sized by `--conns` and `--secs`):
//!
//! * `idle`: connections open, no traffic, held for `secs`.
//! * `small`: closed-loop echo of 64 B messages.
//! * `medium`: closed-loop echo of 4 KiB messages.
//! * `large`: closed-loop echo of 256 KiB messages (connections capped at 256).
//! * `slow`: the server floods 64 KiB messages to clients that never read. Heartbeat
//!   and write deadlines must reclaim every session with bounded memory.
//! * `churn`: connect, exchange one message, close, repeated for `secs`.
//! * `abrupt`: connections dropped without a close handshake.
//! * `shutdown`: graceful shutdown while every connection is echoing.
//!
//! Reported: handshakes ok/failed, messages/s, MiB/s, round-trip p50/p95/p99, server CPU
//! (% of one core) and RSS (before, peak, after cleanup), open descriptors (Linux),
//! failed sends/receives, heartbeat/write/idle timeouts, cleanup time (until the server
//! reports no active session) and shutdown time. Connection counts the host cannot open
//! show up as failed handshakes: report them as the environment's limit.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

use crate::pct;

// ---------------------------------------------------------------- server process

pub(crate) fn server_main(addr: &str) {
    use poring::prelude::*;
    use poring::ws::{ManagedSocket, WebSocketUpgrade};

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let server = Poring::new()
            .limits(poring::Limits {
                max_connections: 200_000,
                max_ws_sessions: 200_000,
                shutdown_grace: Duration::from_secs(5),
                ..Default::default()
            })
            .ws("/echo", |ws: WebSocketUpgrade| async move {
                ws.max_message_size(1 << 20)
                    .managed()
                    .ping_interval(Duration::from_secs(5))
                    .pong_timeout(Duration::from_secs(10))
                    .write_timeout(Duration::from_secs(5))
                    .max_queued_bytes(4 << 20)
                    .max_outbound_message(1 << 20)
                    .on_upgrade(|mut sock: ManagedSocket| async move {
                        while let Some(m) = sock.recv().await {
                            if sock.send(m).await.is_err() {
                                break;
                            }
                        }
                    })
            })
            .ws("/flood", |ws: WebSocketUpgrade| async move {
                ws.managed()
                    .ping_interval(Duration::from_secs(1))
                    .pong_timeout(Duration::from_secs(2))
                    .write_timeout(Duration::from_secs(3))
                    .queue_messages(4)
                    .max_queued_bytes(256 * 1024)
                    .on_upgrade(|mut sock: ManagedSocket| async move {
                        let chunk = vec![7u8; 64 * 1024];
                        while sock.send(Message::binary(chunk.clone())).await.is_ok() {}
                    })
            })
            .build()
            .unwrap()
            .bind(addr)
            .await
            .unwrap();
        println!("{}", server.local_addr());
        let stats = {
            let s = &server;
            move || {
                let w = s.ws_stats();
                format!(
                    "stats active={} accepted={} ended={} hb={} wt={} idle={} abnormal={} shutdown_closes={}",
                    w.active_sessions,
                    w.handshakes_accepted,
                    w.sessions_ended,
                    w.heartbeat_timeouts,
                    w.write_timeouts,
                    w.idle_timeouts,
                    w.abnormal_disconnects,
                    w.shutdown_closes
                )
            }
        };
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = tick.tick() => println!("{}", stats()),
                l = lines.next_line() => {
                    if matches!(l, Ok(Some(ref c)) if c.trim() == "shutdown") {
                        let t = Instant::now();
                        server.shutdown().await.unwrap();
                        println!("shutdown_ms={:.1}", t.elapsed().as_secs_f64() * 1000.0);
                        return;
                    }
                    if !matches!(l, Ok(Some(_))) {
                        return;
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------- harness

struct Opts {
    conns: Vec<usize>,
    secs: u64,
    profiles: Vec<String>,
}

const ALL: [&str; 8] = [
    "idle", "small", "medium", "large", "slow", "churn", "abrupt", "shutdown",
];

fn parse(args: &[String]) -> Opts {
    let mut o = Opts {
        conns: vec![100, 1000],
        secs: 5,
        profiles: ALL.iter().map(|s| (*s).to_owned()).collect(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let v = it.next().map(String::as_str).unwrap_or("");
        match a.as_str() {
            "--conns" => o.conns = crate::list(v),
            "--secs" => o.secs = v.parse().unwrap_or(5),
            "--profiles" => o.profiles = crate::list(v),
            other => panic!("unknown option {other}"),
        }
    }
    for p in &o.profiles {
        assert!(ALL.contains(&p.as_str()), "unknown profile {p}");
    }
    o
}

#[derive(Default, Clone, Copy, Debug)]
struct Stats {
    active: u64,
    accepted: u64,
    ended: u64,
    hb: u64,
    wt: u64,
    idle: u64,
    abnormal: u64,
}

fn parse_stats(line: &str) -> Option<Stats> {
    let rest = line.strip_prefix("stats ")?;
    let mut s = Stats::default();
    for kv in rest.split(' ') {
        let (k, v) = kv.split_once('=')?;
        let v: u64 = v.parse().ok()?;
        match k {
            "active" => s.active = v,
            "accepted" => s.accepted = v,
            "ended" => s.ended = v,
            "hb" => s.hb = v,
            "wt" => s.wt = v,
            "idle" => s.idle = v,
            "abnormal" => s.abnormal = v,
            _ => {}
        }
    }
    Some(s)
}

#[derive(Default)]
struct Row {
    profile: String,
    conns: usize,
    ok: usize,
    failed: usize,
    msgs_per_s: f64,
    mib_per_s: f64,
    p50: u64,
    p95: u64,
    p99: u64,
    cpu: f64,
    rss_before: f64,
    rss_peak: f64,
    rss_after: f64,
    fds_peak: Option<usize>,
    fds_after: Option<usize>,
    io_errors: u64,
    timeouts: String,
    cleanup_ms: Option<f64>,
    shutdown_ms: Option<f64>,
    note: String,
}

pub(crate) fn main(args: &[String]) {
    let opts = parse(args);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut rows = Vec::new();
    for &conns in &opts.conns {
        for p in &opts.profiles {
            let row = rt.block_on(profile(p, conns, opts.secs));
            eprintln!(
                "{:8} conns={:5}: ok {} failed {} | {:.0} msg/s p99 {} us | rss {:.1}->{:.1}->{:.1} MiB | cleanup {:?} ms | {}",
                row.profile,
                row.conns,
                row.ok,
                row.failed,
                row.msgs_per_s,
                row.p99,
                row.rss_before,
                row.rss_peak,
                row.rss_after,
                row.cleanup_ms.map(|c| c.round()),
                row.note
            );
            rows.push(row);
        }
    }
    report(&opts, &rows);
}

/// A running stress server: its pid, address, latest stats and stdin.
struct Server {
    child: tokio::process::Child,
    pid: sysinfo::Pid,
    addr: SocketAddr,
    stats: tokio::sync::watch::Receiver<Stats>,
    shutdown_ms: tokio::sync::watch::Receiver<Option<f64>>,
    stdin: tokio::process::ChildStdin,
}

async fn start() -> Server {
    let exe = std::env::current_exe().unwrap();
    let mut child = tokio::process::Command::new(exe)
        .args(["stress-server", "127.0.0.1:0"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("start stress server");
    let pid = sysinfo::Pid::from_u32(child.id().unwrap());
    let stdin = child.stdin.take().unwrap();
    let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let addr: SocketAddr = lines.next_line().await.unwrap().unwrap().parse().unwrap();
    let (tx, stats) = tokio::sync::watch::channel(Stats::default());
    let (stx, shutdown_ms) = tokio::sync::watch::channel(None);
    tokio::spawn(async move {
        while let Ok(Some(l)) = lines.next_line().await {
            if let Some(s) = parse_stats(&l) {
                let _ = tx.send(s);
            } else if let Some(ms) = l.strip_prefix("shutdown_ms=") {
                let _ = stx.send(ms.parse().ok());
            }
        }
    });
    Server {
        child,
        pid,
        addr,
        stats,
        shutdown_ms,
        stdin,
    }
}

/// Resident memory (MiB), CPU (% of one core since the previous call) and open
/// descriptors (Linux only) of `pid`.
struct Sampler {
    sys: sysinfo::System,
    pid: sysinfo::Pid,
}

impl Sampler {
    fn new(pid: sysinfo::Pid) -> Self {
        let mut s = Sampler {
            sys: sysinfo::System::new(),
            pid,
        };
        s.sample();
        s
    }

    fn sample(&mut self) -> (f64, f64) {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate};
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[self.pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        self.sys.process(self.pid).map_or((0.0, 0.0), |p| {
            (
                p.memory() as f64 / (1024.0 * 1024.0),
                f64::from(p.cpu_usage()),
            )
        })
    }

    fn fds(&self) -> Option<usize> {
        std::fs::read_dir(format!("/proc/{}/fd", self.pid.as_u32()))
            .ok()
            .map(|d| d.count())
    }
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Opens `n` connections to `path`, at most 256 handshakes in flight.
async fn connect_all(addr: SocketAddr, path: &str, n: usize) -> (Vec<Ws>, usize) {
    let sem = Arc::new(tokio::sync::Semaphore::new(256));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..n {
        let url = format!("ws://{addr}{path}");
        let sem = sem.clone();
        set.spawn(async move {
            let _p = sem.acquire_owned().await.unwrap();
            tokio::time::timeout(
                Duration::from_secs(10),
                tokio_tungstenite::connect_async(url),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .map(|(ws, _)| ws)
        });
    }
    let mut socks = Vec::with_capacity(n);
    let mut failed = 0;
    while let Some(r) = set.join_next().await {
        match r.ok().flatten() {
            Some(ws) => socks.push(ws),
            None => failed += 1,
        }
    }
    (socks, failed)
}

/// Closed-loop echo on every socket until `until`. Returns latencies (us, after
/// `measure_from`), errors and the sockets that are still usable.
async fn echo_all(
    socks: Vec<Ws>,
    size: usize,
    measure_from: Instant,
    until: Instant,
) -> (Vec<u64>, u64, Vec<Ws>) {
    let mut set = tokio::task::JoinSet::new();
    for mut ws in socks {
        set.spawn(async move {
            let payload = vec![0x5Au8; size];
            let mut lat = Vec::new();
            let mut errors = 0u64;
            let mut alive = true;
            while Instant::now() < until {
                let t = Instant::now();
                if ws.send(Message::binary(payload.clone())).await.is_err() {
                    errors += 1;
                    alive = false;
                    break;
                }
                let got = loop {
                    match ws.next().await {
                        Some(Ok(Message::Binary(b))) => break b.len() == size,
                        Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                        _ => break false,
                    }
                };
                if !got {
                    errors += 1;
                    alive = false;
                    break;
                }
                if t >= measure_from {
                    lat.push(t.elapsed().as_micros() as u64);
                }
            }
            (lat, errors, alive.then_some(ws))
        });
    }
    let (mut lat, mut errors, mut socks) = (Vec::new(), 0, Vec::new());
    while let Some(r) = set.join_next().await {
        let (l, e, ws) = r.unwrap();
        lat.extend(l);
        errors += e;
        socks.extend(ws);
    }
    (lat, errors, socks)
}

async fn close_all(socks: Vec<Ws>) {
    let mut set = tokio::task::JoinSet::new();
    for mut ws in socks {
        set.spawn(async move {
            let _ = ws.close(None).await;
            let _ = tokio::time::timeout(Duration::from_secs(5), async {
                while let Some(Ok(_)) = ws.next().await {}
            })
            .await;
        });
    }
    while set.join_next().await.is_some() {}
}

/// Waits (bounded) until the server reports no active session. Returns how long it took.
async fn until_clean(
    stats: &mut tokio::sync::watch::Receiver<Stats>,
    bound: Duration,
) -> Option<f64> {
    let t = Instant::now();
    tokio::time::timeout(bound, stats.wait_for(|s| s.active == 0))
        .await
        .ok()
        .map(|_| t.elapsed().as_secs_f64() * 1000.0)
}

async fn profile(name: &str, conns: usize, secs: u64) -> Row {
    let mut srv = start().await;
    let mut sampler = Sampler::new(srv.pid);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut row = Row {
        profile: name.to_owned(),
        conns,
        ..Default::default()
    };
    row.rss_before = sampler.sample().0;
    let peak = Arc::new(AtomicU64::new(0));
    let cpu_sum = Arc::new(AtomicU64::new(0));
    let cpu_n = Arc::new(AtomicU64::new(0));
    let fds_peak = Arc::new(AtomicU64::new(0));
    // Background sampler: peak RSS, mean CPU, peak descriptors.
    let sampling = {
        let (peak, cpu_sum, cpu_n, fds_peak) = (
            peak.clone(),
            cpu_sum.clone(),
            cpu_n.clone(),
            fds_peak.clone(),
        );
        let pid = srv.pid;
        tokio::spawn(async move {
            let mut s = Sampler::new(pid);
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let (rss, cpu) = s.sample();
                peak.fetch_max((rss * 1024.0) as u64, Ordering::Relaxed);
                cpu_sum.fetch_add((cpu * 100.0) as u64, Ordering::Relaxed);
                cpu_n.fetch_add(1, Ordering::Relaxed);
                if let Some(f) = s.fds() {
                    fds_peak.fetch_max(f as u64, Ordering::Relaxed);
                }
            }
        })
    };
    let secs_d = Duration::from_secs(secs);
    let mut lat = Vec::new();
    let mut bytes_per_msg = 0usize;
    let mut measured = secs_d;

    match name {
        "idle" => {
            let (socks, failed) = connect_all(srv.addr, "/echo", conns).await;
            (row.ok, row.failed) = (socks.len(), failed);
            // Idle connections keep answering pings (tungstenite does it while reading).
            let until = Instant::now() + secs_d;
            let (_, e, socks) = echo_idle(socks, until).await;
            row.io_errors = e;
            close_all(socks).await;
        }
        "small" | "medium" | "large" => {
            let (size, n) = match name {
                "small" => (64, conns),
                "medium" => (4096, conns),
                _ => (256 * 1024, conns.min(256)),
            };
            if n < conns {
                row.note = format!("capped at {n} connections");
            }
            bytes_per_msg = size;
            let (socks, failed) = connect_all(srv.addr, "/echo", n).await;
            (row.ok, row.failed) = (socks.len(), failed);
            let from = Instant::now() + Duration::from_secs(1);
            let (l, e, socks) = echo_all(socks, size, from, from + secs_d).await;
            lat = l;
            row.io_errors = e;
            close_all(socks).await;
        }
        "slow" => {
            // Clients complete the handshake and never read: the server's writes block.
            let (socks, failed) = connect_all(srv.addr, "/flood", conns).await;
            (row.ok, row.failed) = (socks.len(), failed);
            tokio::time::sleep(secs_d).await;
            // Still holding the sockets: every session must already be gone.
            let clean = until_clean(&mut srv.stats, Duration::from_secs(30)).await;
            row.note = format!(
                "sessions gone {} while clients still connected",
                clean.map_or("NOT".to_owned(), |_| "yes".to_owned())
            );
            drop(socks);
        }
        "churn" => {
            let until = Instant::now() + secs_d;
            let ok = Arc::new(AtomicU64::new(0));
            let failed = Arc::new(AtomicU64::new(0));
            let mut set = tokio::task::JoinSet::new();
            for _ in 0..conns.min(256) {
                let (ok, failed) = (ok.clone(), failed.clone());
                let url = format!("ws://{}/echo", srv.addr);
                set.spawn(async move {
                    let mut lat = Vec::new();
                    while Instant::now() < until {
                        let t = Instant::now();
                        let Ok(Ok((mut ws, _))) = tokio::time::timeout(
                            Duration::from_secs(10),
                            tokio_tungstenite::connect_async(&url),
                        )
                        .await
                        else {
                            failed.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        let _ = ws.send(Message::text("x")).await;
                        let _ = ws.next().await;
                        let _ = ws.close(None).await;
                        while let Some(Ok(_)) = ws.next().await {}
                        lat.push(t.elapsed().as_micros() as u64);
                        ok.fetch_add(1, Ordering::Relaxed);
                    }
                    lat
                });
            }
            while let Some(r) = set.join_next().await {
                lat.extend(r.unwrap());
            }
            row.ok = ok.load(Ordering::Relaxed) as usize;
            row.failed = failed.load(Ordering::Relaxed) as usize;
            row.note = format!(
                "{} concurrent loops; latency = connect+echo+close",
                conns.min(256)
            );
        }
        "abrupt" => {
            let (socks, failed) = connect_all(srv.addr, "/echo", conns).await;
            (row.ok, row.failed) = (socks.len(), failed);
            tokio::time::sleep(Duration::from_millis(500)).await;
            // Dropped without a close frame (TCP FIN/RST only).
            drop(socks);
            measured = Duration::ZERO;
        }
        "shutdown" => {
            let (socks, failed) = connect_all(srv.addr, "/echo", conns).await;
            (row.ok, row.failed) = (socks.len(), failed);
            let from = Instant::now();
            let load = tokio::spawn(echo_all(socks, 1024, from, from + secs_d * 10));
            tokio::time::sleep(secs_d).await;
            let _ = srv.stdin.write_all(b"shutdown\n").await;
            let _ = tokio::time::timeout(
                Duration::from_secs(30),
                srv.shutdown_ms.wait_for(Option::is_some),
            )
            .await;
            row.shutdown_ms = *srv.shutdown_ms.borrow();
            let (l, e, socks) = load.await.unwrap();
            lat = l;
            row.io_errors = e;
            drop(socks);
            bytes_per_msg = 1024;
            row.note = "errors = sessions ended by the shutdown".into();
        }
        _ => unreachable!(),
    }

    if !lat.is_empty() && !measured.is_zero() {
        row.msgs_per_s = lat.len() as f64 / measured.as_secs_f64();
        row.mib_per_s = row.msgs_per_s * bytes_per_msg as f64 / (1024.0 * 1024.0);
    }
    lat.sort_unstable();
    row.p50 = pct(&lat, 0.50);
    row.p95 = pct(&lat, 0.95);
    row.p99 = pct(&lat, 0.99);

    if name != "shutdown" {
        row.cleanup_ms = until_clean(&mut srv.stats, Duration::from_secs(30)).await;
        // Give the allocator a moment, then measure what is left.
        tokio::time::sleep(Duration::from_millis(500)).await;
        row.rss_after = sampler.sample().0;
        row.fds_after = sampler.fds();
    }
    sampling.abort();
    let s = *srv.stats.borrow();
    row.timeouts = format!("hb {} wt {} idle {} abn {}", s.hb, s.wt, s.idle, s.abnormal);
    let _ = s.accepted + s.ended;
    row.rss_peak = peak.load(Ordering::Relaxed) as f64 / 1024.0;
    let n = cpu_n.load(Ordering::Relaxed);
    row.cpu = if n == 0 {
        0.0
    } else {
        cpu_sum.load(Ordering::Relaxed) as f64 / 100.0 / n as f64
    };
    let f = fds_peak.load(Ordering::Relaxed);
    row.fds_peak = (f > 0).then_some(f as usize);
    let _ = srv.child.kill().await;
    row
}

/// Holds idle connections open, reading (so pings are answered) until `until`.
async fn echo_idle(socks: Vec<Ws>, until: Instant) -> (Vec<u64>, u64, Vec<Ws>) {
    let mut set = tokio::task::JoinSet::new();
    for mut ws in socks {
        set.spawn(async move {
            let left = until.saturating_duration_since(Instant::now());
            let ended = tokio::time::timeout(left, async {
                loop {
                    match ws.next().await {
                        Some(Ok(_)) => {}
                        _ => return true,
                    }
                }
            })
            .await
            .unwrap_or(false);
            (u64::from(ended), (!ended).then_some(ws))
        });
    }
    let (mut errors, mut socks) = (0, Vec::new());
    while let Some(r) = set.join_next().await {
        let (e, ws) = r.unwrap();
        errors += e;
        socks.extend(ws);
    }
    (Vec::new(), errors, socks)
}

fn opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or("n/a".to_owned(), |v| v.to_string())
}

fn report(opts: &Opts, rows: &[Row]) {
    println!("## Poring stress run (ws-bench stress)\n");
    println!(
        "- OS: {} {} ({}), logical CPUs: {}; client and server on the same machine",
        sysinfo::System::name().unwrap_or_default(),
        sysinfo::System::os_version().unwrap_or_default(),
        std::env::consts::ARCH,
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    println!(
        "- Managed sessions; load phase {} s per profile; fresh server process per profile\n",
        opts.secs
    );
    println!(
        "| profile | conns | ok | failed | msg/s | MiB/s | p50 (us) | p95 (us) | p99 (us) | server CPU % | RSS before / peak / after (MiB) | fds peak / after | client I/O errors | server timeouts | cleanup (ms) | shutdown (ms) | note |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---:|---|---:|---:|---|");
    for r in rows {
        println!(
            "| {} | {} | {} | {} | {:.0} | {:.1} | {} | {} | {} | {:.0} | {:.1} / {:.1} / {:.1} | {} / {} | {} | {} | {} | {} | {} |",
            r.profile,
            r.conns,
            r.ok,
            r.failed,
            r.msgs_per_s,
            r.mib_per_s,
            r.p50,
            r.p95,
            r.p99,
            r.cpu,
            r.rss_before,
            r.rss_peak,
            r.rss_after,
            opt(r.fds_peak),
            opt(r.fds_after),
            r.io_errors,
            r.timeouts,
            opt(r.cleanup_ms.map(|c| format!("{c:.0}"))),
            opt(r.shutdown_ms.map(|c| format!("{c:.0}"))),
            r.note
        );
    }
}
