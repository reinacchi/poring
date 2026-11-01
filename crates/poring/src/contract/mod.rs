//! The serialisable intermediate representation (IR) shared by the runtime, the code
//! generators and the `cargo-poring` binary:
//!
//! * [`Manifest`]: every registered route with its *effective* (merged) security
//!   policy, extractors, hooks and source location.
//! * [`FlowGraph`]: the deterministic static lifecycle/security graph derived from a
//!   manifest, with Mermaid / Graphviz DOT / JSON renderers and a runtime overlay.
//! * [`explain()`] / [`audit_markdown()`]: human-readable policy explanations and audit exports.
//!
//! This module does not depend on the HTTP runtime, so inspection tooling can work from a
//! manifest file without starting a server.

pub mod explain;
pub mod graph;
pub mod manifest;
pub mod render;

pub use explain::{audit_markdown, explain};
pub use graph::{EdgeKind, FlowEdge, FlowGraph, FlowNode, NodeKind, RuntimeTrace, build_graph};
pub use manifest::*;
pub use render::{render_dot, render_json, render_mermaid, render_mermaid_with_trace};

/// Version of the manifest JSON format produced by this module.
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

/// Computes the stable, deterministic route identifier used for graph node IDs,
/// trace correlation and CLI lookups.
///
/// The ID is derived only from the HTTP method and the canonical path, so it is stable
/// across builds and machines: `GET /users/{id}` becomes `get_users_id`,
/// `GET /` becomes `get_root`, and `GET /files/{*rest}` becomes `get_files_rest_all`.
pub fn route_id(method: &str, path: &str) -> String {
    let mut out = method.to_ascii_lowercase();
    let mut any = false;
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        out.push('_');
        any = true;
        let (seg, catch_all) = match seg.strip_prefix("{*").and_then(|s| s.strip_suffix('}')) {
            Some(name) => (name, true),
            None => (seg, false),
        };
        for c in seg.chars() {
            if c.is_ascii_alphanumeric() {
                out.push(c.to_ascii_lowercase());
            } else if c == '-' || c == '_' || c == '.' {
                out.push('_');
            }
        }
        if catch_all {
            out.push_str("_all");
        }
    }
    if !any {
        out.push_str("_root");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::route_id;

    #[test]
    fn route_ids_are_stable() {
        assert_eq!(route_id("GET", "/users/{id}"), "get_users_id");
        assert_eq!(route_id("GET", "/"), "get_root");
        assert_eq!(route_id("POST", "/files/{*rest}"), "post_files_rest_all");
        assert_eq!(route_id("DELETE", "/a-b/c.d"), "delete_a_b_c_d");
    }
}
