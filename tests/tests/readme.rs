//! README code blocks must match compiled examples, so the documentation cannot drift.

use poring_tests::readme;

fn read(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn readme_websocket_example_matches_examples_websocket_managed() {
    let block = readme::block(&read("README.md"), "websocket").unwrap();
    let example = readme::example_body(&read("examples/websocket_managed.rs"));
    assert_eq!(
        block, example,
        "README WebSocket block differs from examples/websocket_managed.rs"
    );
}
