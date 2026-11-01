//! The README quickstart must stay identical to `examples/quickstart.rs` (which is compiled).
#[test]
fn readme_quickstart_matches_compiled_example() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let readme = std::fs::read_to_string(root.join("README.md")).unwrap();
    let snippet =
        readme.split("## Quickstart").nth(1).unwrap().split("```rust\n").nth(1).unwrap().split("```").next().unwrap();
    let example = std::fs::read_to_string(root.join("examples/quickstart.rs")).unwrap();
    assert!(example.ends_with(snippet), "README quickstart drifted from examples/quickstart.rs");
}
