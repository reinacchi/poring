//! Mermaid, Graphviz DOT and JSON renderers for [`FlowGraph`].

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::contract::graph::{EdgeKind, FlowGraph, NodeKind, RuntimeTrace};

fn mermaid_id(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn escape_label(s: &str) -> String {
    s.replace('"', "'")
        .replace('{', "#123;")
        .replace('}', "#125;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Renders the static graph as a Mermaid flowchart.
///
/// Solid arrows are normal transitions; dotted arrows are possible denial, error or
/// short-circuit branches.
pub fn render_mermaid(g: &FlowGraph) -> String {
    render_mermaid_inner(g, None)
}

/// Renders the static graph with the edges actually traversed by `trace` highlighted.
///
/// Static (possible) edges keep their normal style; runtime-traversed edges are drawn
/// thick and green and visited nodes get the `visited` class.
pub fn render_mermaid_with_trace(g: &FlowGraph, trace: &RuntimeTrace) -> String {
    render_mermaid_inner(g, Some(trace))
}

fn render_mermaid_inner(g: &FlowGraph, trace: Option<&RuntimeTrace>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "flowchart TD");
    for n in &g.nodes {
        let id = mermaid_id(&n.id);
        let label = escape_label(&n.label);
        let shape = match n.kind {
            NodeKind::Router => format!("{id}{{\"{label}\"}}"),
            NodeKind::Security => format!("{id}[/\"{label}\"/]"),
            NodeKind::Branch => format!("{id}([\"{label}\"])"),
            NodeKind::Edge => format!("{id}((\"{label}\"))"),
            NodeKind::Handler => format!("{id}[[\"{label}\"]]"),
            _ => format!("{id}[\"{label}\"]"),
        };
        let _ = writeln!(out, "    {shape}");
    }
    let traversed: BTreeSet<(String, String)> = trace
        .map(|t| {
            let p = t.path();
            p.windows(2)
                .map(|w| (w[0].to_owned(), w[1].to_owned()))
                .collect()
        })
        .unwrap_or_default();
    let mut highlight = Vec::new();
    for (i, e) in g.edges.iter().enumerate() {
        let arrow = match e.kind {
            EdgeKind::Next => "-->",
            _ => "-.->",
        };
        let from = mermaid_id(&e.from);
        let to = mermaid_id(&e.to);
        match &e.label {
            Some(l) => {
                let _ = writeln!(out, "    {from} {arrow}|\"{}\"| {to}", escape_label(l));
            }
            None => {
                let _ = writeln!(out, "    {from} {arrow} {to}");
            }
        }
        if traversed.contains(&(e.from.clone(), e.to.clone())) {
            highlight.push(i);
        }
    }
    let _ = writeln!(
        out,
        "    classDef deny fill:#fde2e2,stroke:#c0392b,color:#7b241c"
    );
    let _ = writeln!(out, "    classDef security fill:#e8f0fe,stroke:#1a5fb4");
    let _ = writeln!(out, "    classDef visited stroke:#1e8449,stroke-width:3px");
    let deny: Vec<String> = g
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Branch)
        .map(|n| mermaid_id(&n.id))
        .collect();
    if !deny.is_empty() {
        let _ = writeln!(out, "    class {} deny", deny.join(","));
    }
    let sec: Vec<String> = g
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Security)
        .map(|n| mermaid_id(&n.id))
        .collect();
    if !sec.is_empty() {
        let _ = writeln!(out, "    class {} security", sec.join(","));
    }
    if let Some(t) = trace {
        let visited: BTreeSet<String> = t.steps.iter().map(|s| mermaid_id(&s.node)).collect();
        let present: Vec<String> = g
            .nodes
            .iter()
            .map(|n| mermaid_id(&n.id))
            .filter(|id| visited.contains(id))
            .collect();
        if !present.is_empty() {
            let _ = writeln!(out, "    class {} visited", present.join(","));
        }
        for i in highlight {
            let _ = writeln!(out, "    linkStyle {i} stroke:#1e8449,stroke-width:3px");
        }
    }
    out
}

/// Renders the static graph as Graphviz DOT.
pub fn render_dot(g: &FlowGraph) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "digraph \"{}\" {{", g.app.replace('"', "'"));
    let _ = writeln!(
        out,
        "  rankdir=TB;\n  node [fontname=\"Helvetica\", fontsize=10];"
    );
    for n in &g.nodes {
        let shape = match n.kind {
            NodeKind::Router => "diamond",
            NodeKind::Security => "parallelogram",
            NodeKind::Branch => "octagon",
            NodeKind::Edge => "circle",
            NodeKind::Handler => "box3d",
            _ => "box",
        };
        let fill = match n.kind {
            NodeKind::Branch => ", style=filled, fillcolor=\"#fde2e2\"",
            NodeKind::Security => ", style=filled, fillcolor=\"#e8f0fe\"",
            _ => "",
        };
        let _ = writeln!(
            out,
            "  \"{}\" [label=\"{}\", shape={shape}{fill}];",
            n.id,
            n.label.replace('"', "'")
        );
    }
    for e in &g.edges {
        let style = match e.kind {
            EdgeKind::Next => "solid",
            _ => "dashed",
        };
        let label = e
            .label
            .as_deref()
            .map(|l| format!(", label=\"{}\"", l.replace('"', "'")))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "  \"{}\" -> \"{}\" [style={style}{label}];",
            e.from, e.to
        );
    }
    out.push_str("}\n");
    out
}

/// Renders the static graph as pretty JSON.
pub fn render_json(g: &FlowGraph) -> String {
    serde_json::to_string_pretty(g).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}
