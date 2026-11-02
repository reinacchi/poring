//! `poring` pins `poring-macros` exactly; the pin must name the macros crate's own version.

fn read(path: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    std::fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

/// The value of `version = "..."` on the first line starting with `prefix`.
fn version_on(manifest: &str, prefix: &str) -> String {
    let line = manifest
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no line starting with `{prefix}`"));
    let start = line.find("version = \"").expect("a version field") + "version = \"".len();
    line[start..]
        .split('"')
        .next()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn poring_pins_the_current_poring_macros_version_exactly() {
    let macros = version_on(&read("crates/poring-macros/Cargo.toml"), "version =");
    let pin = version_on(&read("Cargo.toml"), "poring-macros =");
    assert_eq!(
        pin,
        format!("={macros}"),
        "update the poring-macros pin in the root Cargo.toml"
    );
}

#[test]
fn published_crates_set_their_own_versions() {
    for krate in [
        "crates/poring/Cargo.toml",
        "crates/poring-macros/Cargo.toml",
    ] {
        let manifest = read(krate);
        let inherits = manifest
            .lines()
            .any(|l| l.trim_start().starts_with("version.workspace"));
        assert!(!inherits, "{krate} must not inherit the version");
        assert!(!version_on(&manifest, "version =").is_empty());
    }
    assert!(
        !read("Cargo.toml")
            .lines()
            .any(|l| l.trim_start().starts_with("version = ")),
        "[workspace.package] must not declare a shared version"
    );
}
