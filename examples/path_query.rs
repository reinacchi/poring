//! Typed path and query extraction with validation.
//!
//! ```text
//! cargo run -p poring-examples --example path_query
//! curl 'localhost:3000/repos/rust-lang/rust/issues?state=open&label=bug&label=ice&per_page=5'
//! curl 'localhost:3000/repos/rust-lang/rust/issues?per_page=500'   # 422: maximum is 100
//! ```
use poring::prelude::*;
use serde::Deserialize;

#[derive(Debug, Deserialize, PoringSchema)]
#[serde(rename_all = "snake_case")]
enum IssueState {
    Open,
    Closed,
}

/// Query parameters. Repeated `label` keys collect into the Vec.
#[derive(Debug, Deserialize, PoringSchema)]
struct IssueQuery {
    state: Option<IssueState>,
    label: Option<Vec<String>>,
    #[poring(minimum = 1, maximum = 100)]
    per_page: Option<u32>,
}

/// Path parameters by name.
#[derive(Debug, Deserialize, PoringSchema)]
struct RepoPath {
    #[poring(min_length = 1, max_length = 39)]
    owner: String,
    repo: String,
}

#[poring::get("/repos/{owner}/{repo}/issues")]
async fn issues(Path(p): Path<RepoPath>, Query(q): Query<IssueQuery>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "repo": format!("{}/{}", p.owner, p.repo),
        "state": format!("{:?}", q.state.unwrap_or(IssueState::Open)).to_lowercase(),
        "labels": q.label.unwrap_or_default(),
        "per_page": q.per_page.unwrap_or(30),
    }))
}

/// Tuple path parameters by position.
#[poring::get("/points/{x}/{y}")]
async fn point(Path((x, y)): Path<(i32, i32)>) -> String {
    format!(
        "({x}, {y}) is {} from the origin",
        f64::from(x).hypot(f64::from(y))
    )
}

poring_app! {
    pub PathQuery {
        routes: [issues, point],
    }
}

#[tokio::main]
async fn main() -> Result<(), poring::StartupError> {
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    PathQuery::builder().listen(addr).await
}
