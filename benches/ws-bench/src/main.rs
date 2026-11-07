//! WebSocket echo benchmark: Poring vs Axum.
//!
//! ```text
//! cd benches/ws-bench
//! cargo run --release -- run                      # full matrix, Markdown report on stdout
//! cargo run --release -- run --sizes 64,1024 --conns 1,64 --secs 3
//! cargo run --release -- run --frameworks poring --route managed   # Poring managed path
//! cargo run --release -- server poring 127.0.0.1:9001   # a server only
//! cargo run --release -- stress --conns 100,1000 --secs 10   # see src/stress.rs
//! ```
//!
//! `--route echo` (default) compares the raw echo paths of both frameworks. `--route
//! managed` runs Poring's managed session (pings, pong/idle/write deadlines, bounded
//! queues) and is only meaningful against Poring's own raw numbers: Axum has no equivalent
//! built in, and comparing it to an Axum raw echo would compare different work.
//!
//! For each framework the harness starts this binary as a **separate server process**
//! (same build, same Tokio version, release mode) and drives it from the client process:
//!
//! * **connect** — `conns` concurrent WebSocket handshakes; reports handshakes/s and
//!   handshake latency p50/p99;
//! * **echo** — each connection sends a `size`-byte binary message and waits for the echo
//!   (closed loop) for `secs` seconds after a 1 s warm-up; reports round trips/s, MiB/s
//!   (payload, one direction), round-trip latency p50/p95/p99;
//! * **server resources** — CPU (% of one core, averaged) and resident memory of the server
//!   process sampled every 250 ms during the echo phase (sysinfo);
//! * **close** — time until every connection's close handshake completed.
//!
//! Both servers echo text/binary messages unchanged with a 1 MiB message limit, plain
//! HTTP/1.1, no TLS, no JSON. Client and server share the machine: report hardware and
//! background load with the numbers. Results are measurements of this harness on one
//! machine, not general claims.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncBufReadExt;
use tokio_tungstenite::tungstenite::Message;

mod stress;

const MAX_MESSAGE: usize = 1 << 20;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("server") => {
            let fw = args.get(1).cloned().unwrap_or_else(|| "poring".into());
            let addr = args.get(2).cloned().unwrap_or_else(|| "127.0.0.1:0".into());
            server_main(&fw, &addr);
        }
        Some("run") => run_main(&args[1..]),
        Some("stress-server") => {
            let addr = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:0".into());
            stress::server_main(&addr);
        }
        Some("stress") => stress::main(&args[1..]),
        _ => {
            eprintln!(
                "usage: ws-bench run [--frameworks poring,axum] [--sizes 64,256,...] [--conns 1,64,...] [--secs N] [--route echo|managed]"
            );
            eprintln!("       ws-bench server <poring|axum> [addr]");
            eprintln!(
                "       ws-bench stress [--conns 100,1000] [--secs N] [--profiles idle,small,...]"
            );
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------- servers

fn server_main(fw: &str, addr: &str) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        // The harness reads the bound address from the first stdout line.
        println!("{}", listener.local_addr().unwrap());
        match fw {
            "poring" => poring_server(listener).await,
            "axum" => axum_server(listener).await,
            other => panic!("unknown framework {other}"),
        }
    });
}

async fn poring_server(listener: tokio::net::TcpListener) {
    use poring::prelude::*;
    use poring::ws::WebSocketUpgrade;
    let app = Poring::new()
        .limits(poring::Limits {
            max_connections: 100_000,
            max_ws_sessions: 100_000,
            ..Default::default()
        })
        .ws("/echo", |ws: WebSocketUpgrade| async move {
            ws.max_message_size(MAX_MESSAGE)
                .on_upgrade(|mut sock| async move {
                    while let Some(Ok(m)) = sock.next().await {
                        match m {
                            m @ (Message::Text(_) | Message::Binary(_)) => {
                                if sock.send(m).await.is_err() {
                                    break;
                                }
                            }
                            Message::Close(_) => break,
                            _ => {}
                        }
                    }
                })
        })
        // Same echo through a managed session (default heartbeat and deadlines).
        .ws("/managed", |ws: WebSocketUpgrade| async move {
            ws.max_message_size(MAX_MESSAGE)
                .managed()
                .on_upgrade(|mut sock| async move {
                    while let Some(m) = sock.recv().await {
                        if sock.send(m).await.is_err() {
                            break;
                        }
                    }
                })
        })
        .build()
        .unwrap();
    // Runs until the harness kills the process.
    app.serve(listener, std::future::pending::<()>())
        .await
        .unwrap();
}

async fn axum_server(listener: tokio::net::TcpListener) {
    use axum::extract::ws::{Message as AMessage, WebSocketUpgrade};
    use axum::routing::get;
    let app = axum::Router::new().route(
        "/echo",
        get(|ws: WebSocketUpgrade| async move {
            ws.max_message_size(MAX_MESSAGE)
                .on_upgrade(|mut sock| async move {
                    while let Some(Ok(m)) = sock.recv().await {
                        match m {
                            m @ (AMessage::Text(_) | AMessage::Binary(_)) => {
                                if sock.send(m).await.is_err() {
                                    break;
                                }
                            }
                            AMessage::Close(_) => break,
                            _ => {}
                        }
                    }
                })
        }),
    );
    axum::serve(listener, app).await.unwrap();
}

// ---------------------------------------------------------------- harness

pub(crate) struct Opts {
    frameworks: Vec<String>,
    sizes: Vec<usize>,
    conns: Vec<usize>,
    secs: u64,
    route: String,
}

pub(crate) fn list<T: std::str::FromStr>(s: &str) -> Vec<T> {
    s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}

fn parse_opts(args: &[String]) -> Opts {
    let mut o = Opts {
        frameworks: vec!["poring".into(), "axum".into()],
        sizes: vec![64, 256, 1024, 4096, 16384, 65536],
        conns: vec![1, 64, 256],
        secs: 3,
        route: "echo".into(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let v = it.next().map(String::as_str).unwrap_or("");
        match a.as_str() {
            "--frameworks" => o.frameworks = list(v),
            "--sizes" => o.sizes = list(v),
            "--conns" => o.conns = list(v),
            "--secs" => o.secs = v.parse().unwrap_or(3),
            "--route" => o.route = v.to_owned(),
            other => panic!("unknown option {other}"),
        }
    }
    o
}

#[derive(Default, Clone)]
struct Row {
    fw: String,
    conns: usize,
    size: usize,
    handshakes_per_s: f64,
    handshake_p50_us: u64,
    handshake_p99_us: u64,
    rtt_per_s: f64,
    mib_per_s: f64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    cpu_pct: f64,
    rss_mib: f64,
    close_ms: f64,
    errors: usize,
}

fn run_main(args: &[String]) {
    let opts = parse_opts(args);
    assert!(
        opts.route == "echo" || (opts.route == "managed" && opts.frameworks == ["poring"]),
        "--route managed is Poring-only (use --frameworks poring)"
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut rows = Vec::new();
    for fw in &opts.frameworks {
        for &conns in &opts.conns {
            for &size in &opts.sizes {
                // A fresh server process per cell, so state never carries over.
                let row = rt.block_on(cell(fw, &opts.route, conns, size, opts.secs));
                eprintln!(
                    "{fw:6} conns={conns:4} size={size:6}: {:>9.0} rt/s  p50 {:>6} us  p99 {:>6} us  cpu {:>5.0}%  rss {:>6.1} MiB  errors {}",
                    row.rtt_per_s, row.p50_us, row.p99_us, row.cpu_pct, row.rss_mib, row.errors
                );
                rows.push(row);
            }
        }
    }
    print_report(&opts, &rows);
}

async fn cell(fw: &str, route: &str, conns: usize, size: usize, secs: u64) -> Row {
    let exe = std::env::current_exe().unwrap();
    let mut child = tokio::process::Command::new(exe)
        .args(["server", fw, "127.0.0.1:0"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("start server process");
    let pid = sysinfo::Pid::from_u32(child.id().expect("server pid"));
    let mut line = String::new();
    tokio::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .await
        .unwrap();
    let addr: SocketAddr = line.trim().parse().expect("server address");
    let url = format!("ws://{addr}/{route}");
    let mut row = Row {
        fw: fw.to_owned(),
        conns,
        size,
        ..Default::default()
    };

    // Connect phase.
    let started = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..conns {
        let url = url.clone();
        set.spawn(async move {
            let t = Instant::now();
            let r = tokio_tungstenite::connect_async(url).await;
            (t.elapsed(), r.map(|(ws, _)| ws))
        });
    }
    let mut handshakes = Vec::with_capacity(conns);
    let mut sockets = Vec::with_capacity(conns);
    while let Some(r) = set.join_next().await {
        let (d, ws) = r.unwrap();
        match ws {
            Ok(ws) => {
                handshakes.push(d.as_micros() as u64);
                sockets.push(ws);
            }
            Err(_) => row.errors += 1,
        }
    }
    let connect_time = started.elapsed();
    row.handshakes_per_s = sockets.len() as f64 / connect_time.as_secs_f64();
    handshakes.sort_unstable();
    row.handshake_p50_us = pct(&handshakes, 0.50);
    row.handshake_p99_us = pct(&handshakes, 0.99);

    // Echo phase: warm-up, then measure.
    let payload = vec![0xA5u8; size];
    let warmup = Duration::from_secs(1);
    let measure = Duration::from_secs(secs);
    let begin = Instant::now();
    let measure_from = begin + warmup;
    let deadline = measure_from + measure;
    let sampler = tokio::spawn(sample_server(pid, measure_from, deadline));
    let mut set = tokio::task::JoinSet::new();
    for mut ws in sockets {
        let payload = payload.clone();
        set.spawn(async move {
            let mut lat = Vec::with_capacity(1 << 16);
            let mut errors = 0usize;
            while Instant::now() < deadline {
                let t = Instant::now();
                if ws.send(Message::binary(payload.clone())).await.is_err() {
                    errors += 1;
                    break;
                }
                match ws.next().await {
                    Some(Ok(Message::Binary(b))) if b.len() == payload.len() => {
                        if t >= measure_from {
                            lat.push(t.elapsed().as_micros() as u64);
                        }
                    }
                    _ => {
                        errors += 1;
                        break;
                    }
                }
            }
            (ws, lat, errors)
        });
    }
    let mut lat = Vec::new();
    let mut sockets = Vec::new();
    while let Some(r) = set.join_next().await {
        let (ws, l, e) = r.unwrap();
        lat.extend(l);
        row.errors += e;
        sockets.push(ws);
    }
    let (cpu, rss) = sampler.await.unwrap();
    row.cpu_pct = cpu;
    row.rss_mib = rss;
    row.rtt_per_s = lat.len() as f64 / measure.as_secs_f64();
    row.mib_per_s = row.rtt_per_s * size as f64 / (1024.0 * 1024.0);
    lat.sort_unstable();
    row.p50_us = pct(&lat, 0.50);
    row.p95_us = pct(&lat, 0.95);
    row.p99_us = pct(&lat, 0.99);

    // Close phase.
    let started = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for mut ws in sockets {
        set.spawn(async move {
            let _ = ws.close(None).await;
            while let Some(Ok(_)) = ws.next().await {}
        });
    }
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        while set.join_next().await.is_some() {}
    })
    .await;
    row.close_ms = started.elapsed().as_secs_f64() * 1000.0;
    let _ = child.kill().await;
    row
}

/// Average CPU (% of one core) and peak resident memory (MiB) of the server process.
async fn sample_server(pid: sysinfo::Pid, from: Instant, until: Instant) -> (f64, f64) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut sys = System::new();
    let refresh = |sys: &mut System| {
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
    };
    tokio::time::sleep_until(from.into()).await;
    refresh(&mut sys);
    let (mut cpu, mut n, mut rss) = (0.0f64, 0u32, 0u64);
    while Instant::now() + Duration::from_millis(250) <= until {
        tokio::time::sleep(Duration::from_millis(250)).await;
        refresh(&mut sys);
        if let Some(p) = sys.process(pid) {
            cpu += f64::from(p.cpu_usage());
            n += 1;
            rss = rss.max(p.memory());
        }
    }
    let avg = if n == 0 { 0.0 } else { cpu / f64::from(n) };
    (avg, rss as f64 / (1024.0 * 1024.0))
}

pub(crate) fn pct(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

fn print_report(opts: &Opts, rows: &[Row]) {
    println!("## WebSocket echo benchmark (ws-bench)\n");
    println!(
        "- OS: {} {} ({}), logical CPUs: {}",
        sysinfo::System::name().unwrap_or_default(),
        sysinfo::System::os_version().unwrap_or_default(),
        std::env::consts::ARCH,
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    println!(
        "- Build: release (thin LTO, 16 CGUs); measure {} s per cell after 1 s warm-up; client and server on the same machine, separate processes\n",
        opts.secs
    );
    println!(
        "| framework | conns | size (B) | handshakes/s | hs p50 (us) | hs p99 (us) | round trips/s | MiB/s | p50 (us) | p95 (us) | p99 (us) | server CPU % | server RSS (MiB) | close (ms) | errors |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for r in rows {
        println!(
            "| {} | {} | {} | {:.0} | {} | {} | {:.0} | {:.1} | {} | {} | {} | {:.0} | {:.1} | {:.0} | {} |",
            r.fw,
            r.conns,
            r.size,
            r.handshakes_per_s,
            r.handshake_p50_us,
            r.handshake_p99_us,
            r.rtt_per_s,
            r.mib_per_s,
            r.p50_us,
            r.p95_us,
            r.p99_us,
            r.cpu_pct,
            r.rss_mib,
            r.close_ms,
            r.errors
        );
    }
}
