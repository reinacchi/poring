//! Shared helpers for Poring's integration tests.
#![forbid(unsafe_code)]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Sends raw bytes over TCP and returns the raw response (until close or timeout).
pub async fn raw_http(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    s.write_all(request).await.expect("write");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

/// Status code of a raw HTTP/1.1 response.
pub fn status_of(raw: &str) -> u16 {
    raw.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

pub mod secure;
pub mod shop;

/// Compares `actual` with `tests/snapshots/{name}`. Line endings are normalised, so a
/// Windows checkout with CRLF line endings compares equal. Set `UPDATE_SNAPSHOTS=1` to
/// (re)write snapshots; a missing snapshot is an error otherwise.
pub fn snapshot(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots").join(name);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(path.parent().expect("snapshot directory")).expect("create snapshot directory");
        std::fs::write(&path, actual).expect("write snapshot");
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("snapshot {name} is missing ({e}); run with UPDATE_SNAPSHOTS=1 to create it"));
    assert_eq!(
        expected.replace("\r\n", "\n"),
        actual.replace("\r\n", "\n"),
        "snapshot {name} changed; rerun with UPDATE_SNAPSHOTS=1 if intended"
    );
}

/// Extraction of README code blocks that must match compiled examples.
pub mod readme {
    /// Normalises line endings and trims blank lines around a snippet.
    pub fn normalise(s: &str) -> String {
        let s = s.replace("\r\n", "\n").replace('\r', "\n");
        let lines: Vec<&str> = s.lines().map(str::trim_end).collect();
        let start = lines.iter().position(|l| !l.is_empty()).unwrap_or(lines.len());
        let end = lines.iter().rposition(|l| !l.is_empty()).map_or(start, |e| e + 1);
        let mut out = lines[start..end].join("\n");
        out.push('\n');
        out
    }

    /// Returns the single fenced Rust code block between
    /// `<!-- poring:{name}:start -->` and `<!-- poring:{name}:end -->`.
    pub fn block(markdown: &str, name: &str) -> Result<String, String> {
        let md = markdown.replace("\r\n", "\n");
        let start_marker = format!("<!-- poring:{name}:start -->");
        let end_marker = format!("<!-- poring:{name}:end -->");
        let starts: Vec<usize> = md.match_indices(&start_marker).map(|(i, _)| i).collect();
        let ends: Vec<usize> = md.match_indices(&end_marker).map(|(i, _)| i).collect();
        let (start, end) = match (starts.as_slice(), ends.as_slice()) {
            ([], _) => return Err(format!("README has no `{start_marker}` marker")),
            (_, []) => return Err(format!("README has no `{end_marker}` marker")),
            ([s], [e]) if s < e => (s + start_marker.len(), *e),
            ([_], [_]) => return Err(format!("`{end_marker}` comes before `{start_marker}`")),
            _ => return Err(format!("README marks `{name}` more than once")),
        };
        let region = &md[start..end];
        let mut blocks = Vec::new();
        let mut lines = region.lines();
        while let Some(line) = lines.next() {
            let t = line.trim_start();
            let Some(info) = t.strip_prefix("```") else { continue };
            let lang = info.split([',', ' ']).next().unwrap_or("").trim();
            let mut body = Vec::new();
            let mut closed = false;
            for l in lines.by_ref() {
                if l.trim_start().starts_with("```") {
                    closed = true;
                    break;
                }
                body.push(l);
            }
            if !closed {
                return Err(format!("unterminated code fence in README block `{name}`"));
            }
            if lang == "rust" {
                blocks.push(body.join("\n"));
            }
        }
        match blocks.len() {
            1 => Ok(normalise(&blocks[0])),
            0 => Err(format!("README block `{name}` contains no ```rust code fence")),
            n => Err(format!("README block `{name}` contains {n} Rust code fences; expected one")),
        }
    }

    /// An example file without its leading `//!` module documentation.
    pub fn example_body(source: &str) -> String {
        let source = source.replace("\r\n", "\n");
        let body: Vec<&str> = source.lines().skip_while(|l| l.trim_start().starts_with("//!")).collect();
        normalise(&body.join("\n"))
    }
}
