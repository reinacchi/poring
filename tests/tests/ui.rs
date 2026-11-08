//! Compile-time guarantees, verified with trybuild. Each `fail/*.rs` case has a
//! checked-in `.stderr` snapshot of the diagnostic users will see.
//!
//! The snapshots are rustc's exact output, which depends on the toolchain: newer compilers
//! reorder some notes, and with the `rust-src` component installed rustc also prints lines
//! from the standard library's source. They are therefore recorded and compared on the
//! pinned toolchain only (the workspace `rust-version`, without `rust-src`, as in CI).
//! Elsewhere the `pass/*.rs` cases still run and the comparison is skipped with a note.
//! Set `PORING_UI_SNAPSHOTS=1` to compare anyway, for example to re-bless snapshots with
//! `TRYBUILD=overwrite` on the pinned toolchain.

use std::path::Path;
use std::process::Command;

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("ui/pass/*.rs");
    match snapshot_toolchain() {
        Ok(()) => t.compile_fail("ui/fail/*.rs"),
        Err(reason) => eprintln!(
            "note: skipping the compile-fail snapshot comparison: {reason}. The snapshots are \
             recorded with rustc {} without `rust-src` (as in CI). Run on that toolchain, or \
             set PORING_UI_SNAPSHOTS=1 to compare anyway.",
            env!("CARGO_PKG_RUST_VERSION")
        ),
    }
}

/// `Ok` when this toolchain produces the diagnostics the snapshots were recorded with.
fn snapshot_toolchain() -> Result<(), String> {
    if std::env::var_os("PORING_UI_SNAPSHOTS").is_some_and(|v| v == "1") {
        return Ok(());
    }
    // `rustc` resolves to the toolchain running this test (rustup sets RUSTUP_TOOLCHAIN).
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let version = Command::new(&rustc)
        .arg("-V")
        .output()
        .map_err(|e| format!("could not run `{rustc} -V` ({e})"))?;
    let version = String::from_utf8_lossy(&version.stdout).trim().to_owned();
    let pinned = format!("rustc {}.", env!("CARGO_PKG_RUST_VERSION"));
    if !version.starts_with(&pinned) {
        return Err(format!("this is {version}"));
    }
    let sysroot = Command::new(&rustc)
        .args(["--print", "sysroot"])
        .output()
        .map_err(|e| format!("could not run `{rustc} --print sysroot` ({e})"))?;
    let sysroot = String::from_utf8_lossy(&sysroot.stdout).trim().to_owned();
    if Path::new(&sysroot)
        .join("lib/rustlib/src/rust/library")
        .exists()
    {
        return Err("the `rust-src` component is installed".to_owned());
    }
    Ok(())
}
