//! CLI tests against a manifest snapshot produced by `poring-tests` (trace_flow.rs).

use std::process::Command;

fn manifest() -> String {
    format!(
        "{}/../../tests/snapshots/secure.manifest.json",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cargo-poring"))
        .args(args)
        .output()
        .expect("run cargo-poring");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn explain_shows_merged_policy_and_checks() {
    let m = manifest();
    let (ok, out, err) = run(&["poring", "explain", "--manifest", &m, "POST /notes"]);
    assert!(ok, "{err}");
    assert!(
        out.contains("| scopes (all required) | `notes:write` |"),
        "{out}"
    );
    assert!(out.contains("1. `post_notes.cors`"));
    assert!(out.contains("csrf=enforced"));
    assert!(out.contains("rate_limit=2/1000ms by principal <- route"));
    let (ok, out, _) = run(&["poring", "explain", "--manifest", &m, "GET", "/health"]);
    assert!(ok);
    assert!(out.contains("public (explicit exception: load balancer liveness probe)"));
}

#[test]
fn graph_formats() {
    let m = manifest();
    for (fmt, needle) in [
        ("mermaid", "flowchart TD"),
        ("dot", "digraph"),
        ("json", "\"nodes\""),
    ] {
        let (ok, out, err) = run(&[
            "poring",
            "graph",
            "--manifest",
            &m,
            "--route",
            "GET /notes",
            "--format",
            fmt,
        ]);
        assert!(ok, "{err}");
        assert!(out.contains(needle), "{fmt}: {out}");
        assert!(out.contains("get_notes"));
    }
}

#[test]
fn cli_audit_and_error_reporting() {
    let m = manifest();
    let (ok, out, _) = run(&["poring", "audit", "--manifest", &m]);
    assert!(ok);
    assert!(out.contains("# Security audit: SecureApp"));
    assert!(out.contains("| `POST /webhook` | static | public |"));
    let (ok, _, err) = run(&["poring", "explain", "--manifest", &m, "GET /missing"]);
    assert!(!ok);
    assert!(err.contains("no route matches"));
    let (ok, _, err) = run(&["poring", "graph"]);
    assert!(!ok);
    assert!(err.contains("--manifest"));
}
