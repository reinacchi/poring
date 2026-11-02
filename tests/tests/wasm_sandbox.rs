//! Preflight validation, sandbox limits, runtime error mapping, version leases, rollback.

use std::sync::Arc;
use std::time::{Duration, Instant};

use poring::wasm::guest_kit::{Behaviour, GuestSpec};
use poring::wasm::{GuestConfig, GuestSlot, LoadError, ReloadEvent, WasmHost};

fn req(path: &str) -> poring::dynamic::DynRequest {
    poring::dynamic::DynRequest {
        method: http::Method::GET,
        uri: path.parse().unwrap(),
        headers: http::HeaderMap::new(),
        body: bytes::Bytes::new(),
        params: Vec::new(),
        identity: None,
        request_id: "t".into(),
    }
}

async fn call(slot: &Arc<GuestSlot>, path: &str) -> (u16, String, String) {
    let r = slot.call(req(path)).await;
    let status = r.status().as_u16();
    let ver = r
        .headers()
        .get("x-poring-guest")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let body = String::from_utf8(r.into_body().collect_bytes().await.unwrap().to_vec()).unwrap();
    (status, ver, body)
}

fn slot(cfg: GuestConfig) -> Arc<GuestSlot> {
    let bytes = GuestSpec::echo(&cfg.name, "1").build().unwrap();
    GuestSlot::new(WasmHost::new().unwrap(), cfg, &bytes).unwrap()
}

#[tokio::test]
async fn preflight_rejects_bad_candidates_and_keeps_last_known_good() {
    let s = slot(GuestConfig::new("g"));
    type Case = (&'static str, Vec<u8>, fn(&LoadError) -> bool);
    let cases: Vec<Case> = vec![
        ("garbage", b"\0asm\x0d\0\x01\0garbage".to_vec(), |e| {
            matches!(e, LoadError::Compile(_))
        }),
        (
            "truncated",
            {
                let b = GuestSpec::echo("g", "2").build().unwrap();
                b[..b.len() / 2].to_vec()
            },
            |e| matches!(e, LoadError::Compile(_)),
        ),
        (
            "abi",
            {
                let mut g = GuestSpec::echo("g", "2");
                g.abi = 99;
                g.build().unwrap()
            },
            |e| matches!(e, LoadError::Abi { found: 99 }),
        ),
        (
            "name",
            GuestSpec::echo("other", "2").build().unwrap(),
            |e| matches!(e, LoadError::Name { .. }),
        ),
        (
            "declared capability",
            {
                let mut g = GuestSpec::echo("g", "2");
                g.capabilities = vec!["net".into()];
                g.build().unwrap()
            },
            |e| matches!(e, LoadError::DeniedCapability(c) if c == &["net"]),
        ),
        (
            "import not granted",
            GuestSpec::echo("g", "2")
                .behaviour(Behaviour::LogThenEcho)
                .build()
                .unwrap(),
            |e| matches!(e, LoadError::DeniedImport(_)),
        ),
        (
            "trap in probe",
            GuestSpec::echo("g", "2")
                .behaviour(Behaviour::Trap)
                .build()
                .unwrap(),
            |e| matches!(e, LoadError::Preflight(m) if m.contains("trapped")),
        ),
        (
            "fuel in probe",
            GuestSpec::echo("g", "2")
                .behaviour(Behaviour::Forever)
                .build()
                .unwrap(),
            |e| matches!(e, LoadError::Preflight(m) if m.contains("fuel")),
        ),
        (
            "memory in probe",
            GuestSpec::echo("g", "2")
                .behaviour(Behaviour::MemoryBomb)
                .build()
                .unwrap(),
            |e| matches!(e, LoadError::Preflight(m) if m.contains("memory")),
        ),
    ];
    for (what, bytes, check) in cases {
        let err = s.try_reload(&bytes).expect_err(what);
        assert!(check(&err), "{what}: unexpected error {err}");
        let (status, ver, _) = call(&s, "/still/ok").await;
        assert_eq!(
            (status, ver.as_str()),
            (200, "g/1#1"),
            "{what}: last known-good keeps serving"
        );
    }
    let rejected = s
        .events()
        .iter()
        .filter(|e| matches!(e, ReloadEvent::Rejected { .. }))
        .count();
    assert_eq!(rejected, 9);
    let mut big = GuestConfig::new("g");
    big.max_artefact_bytes = 100;
    assert!(matches!(
        GuestSlot::new(
            WasmHost::new().unwrap(),
            big,
            &GuestSpec::echo("g", "1").build().unwrap()
        ),
        Err(LoadError::TooLarge(_))
    ));
}

#[tokio::test]
async fn granted_log_capability_works() {
    let bytes = GuestSpec::echo("logger", "1")
        .behaviour(Behaviour::LogThenEcho)
        .build()
        .unwrap();
    let s = GuestSlot::new(
        WasmHost::new().unwrap(),
        GuestConfig::new("logger").grant("log"),
        &bytes,
    )
    .unwrap();
    assert_eq!(call(&s, "/x").await.0, 200);
    assert_eq!(s.current().capabilities, ["log"]);
}

#[tokio::test]
async fn runtime_failures_are_contained() {
    let s = slot(GuestConfig::new("g"));
    let host_alive = |r: &(u16, String, String)| r.1.starts_with("g/");
    s.try_reload(
        &GuestSpec::echo("g", "trap")
            .behaviour(Behaviour::Trap)
            .probe_safe()
            .build()
            .unwrap(),
    )
    .unwrap();
    let r = call(&s, "/boom").await;
    assert_eq!(r.0, 500);
    assert!(r.2.contains("guest_trap") && host_alive(&r));

    s.try_reload(
        &GuestSpec::echo("g", "spin")
            .behaviour(Behaviour::Forever)
            .probe_safe()
            .build()
            .unwrap(),
    )
    .unwrap();
    let t0 = Instant::now();
    let r = call(&s, "/loop").await;
    assert_eq!(r.0, 503);
    assert!(r.2.contains("guest_out_of_fuel"), "{}", r.2);
    assert!(t0.elapsed() < Duration::from_secs(5));

    s.try_reload(
        &GuestSpec::echo("g", "mem")
            .behaviour(Behaviour::MemoryBomb)
            .probe_safe()
            .build()
            .unwrap(),
    )
    .unwrap();
    let r = call(&s, "/mem").await;
    assert_eq!(r.0, 503);
    assert!(r.2.contains("guest_resource_exhausted"), "{}", r.2);

    s.try_reload(
        &GuestSpec::echo("g", "err")
            .behaviour(Behaviour::Error(418, "short and stout".into()))
            .probe_safe()
            .build()
            .unwrap(),
    )
    .unwrap();
    let r = call(&s, "/tea").await;
    assert_eq!(r.0, 418);
    assert!(r.2.contains("short and stout"));

    s.try_reload(
        &GuestSpec::echo("g", "bad-status")
            .status(102)
            .build()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        call(&s, "/x").await.0,
        502,
        "informational status from a guest is rejected"
    );
}

#[tokio::test]
async fn epoch_deadline_bounds_wall_clock() {
    let mut cfg = GuestConfig::new("g");
    cfg.fuel = u64::MAX / 4;
    cfg.timeout = Duration::from_millis(100);
    let s = slot(cfg);
    s.try_reload(
        &GuestSpec::echo("g", "spin")
            .behaviour(Behaviour::Forever)
            .probe_safe()
            .build()
            .unwrap(),
    )
    .unwrap();
    let t0 = Instant::now();
    let r = call(&s, "/loop").await;
    assert_eq!(r.0, 503);
    assert!(r.2.contains("guest_timeout"), "{}", r.2);
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "took {:?}",
        t0.elapsed()
    );
}

#[tokio::test]
async fn in_flight_requests_keep_their_version_and_rollback_works() {
    let mut cfg = GuestConfig::new("g");
    cfg.fuel = u64::MAX / 4;
    cfg.timeout = Duration::from_secs(10);
    cfg.retained_versions = 2;
    let host = WasmHost::new().unwrap();
    let slow_v1 = GuestSpec::echo("g", "1")
        .behaviour(Behaviour::SpinThenEcho(150_000_000))
        .probe_safe()
        .build()
        .unwrap();
    let s = GuestSlot::new(host, cfg, &slow_v1).unwrap();
    let s2 = s.clone();
    let inflight = tokio::spawn(async move { call(&s2, "/slow").await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !inflight.is_finished(),
        "guest call should still be running"
    );
    s.try_reload(&GuestSpec::echo("g", "2").build().unwrap())
        .unwrap();
    assert_eq!(
        call(&s, "/new").await.1,
        "g/2#2",
        "new requests use the new version"
    );
    let old = inflight.await.unwrap();
    assert_eq!(
        (old.0, old.1.as_str()),
        (200, "g/1#1"),
        "in-flight request finished on the old version"
    );

    s.try_reload(&GuestSpec::echo("g", "3").build().unwrap())
        .unwrap();
    s.try_reload(&GuestSpec::echo("g", "4").build().unwrap())
        .unwrap();
    assert_eq!(
        s.history().iter().map(|v| v.seq).collect::<Vec<_>>(),
        [2, 3],
        "bounded history"
    );
    assert_eq!(s.rollback().unwrap().seq, 3);
    assert_eq!(call(&s, "/x").await.1, "g/3#3");
    assert_eq!(s.rollback().unwrap().seq, 2);
    assert!(s.rollback().is_none(), "history exhausted");
    assert_eq!(
        s.try_reload(&GuestSpec::echo("g", "2").build().unwrap())
            .unwrap()
            .seq,
        2,
        "identical artefact is a no-op"
    );
    assert_eq!(s.events().last(), Some(&ReloadEvent::Unchanged));
}

#[tokio::test]
async fn concurrency_limit_and_isolated_stores() {
    let mut cfg = GuestConfig::new("g");
    cfg.max_concurrency = 1;
    cfg.fuel = u64::MAX / 4;
    cfg.timeout = Duration::from_secs(10);
    let bytes = GuestSpec::echo("g", "1")
        .behaviour(Behaviour::SpinThenEcho(100_000_000))
        .probe_safe()
        .build()
        .unwrap();
    let s = GuestSlot::new(WasmHost::new().unwrap(), cfg, &bytes).unwrap();
    let s2 = s.clone();
    let first = tokio::spawn(async move { call(&s2, "/a").await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let busy = call(&s, "/b").await;
    assert_eq!(busy.0, 503);
    assert!(busy.2.contains("guest_busy"));
    assert_eq!(first.await.unwrap().0, 200);
    // The bump allocator never frees: if stores were shared, memory would accumulate
    // across calls. A fresh store per call keeps every call identical.
    let calls_before = s.calls();
    for _ in 0..3 {
        assert_eq!(
            call(&s, "/probe-safe/isolated").await.2,
            "hello from g 1: /probe-safe/isolated"
        );
    }
    assert_eq!(s.calls(), calls_before + 3);
}
