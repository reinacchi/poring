//! A fluent app with shared state, an authenticator, policies, a group and hooks.
//!
//! ```text
//! cargo run -p poring-examples --example fluent_api
//! curl localhost:3000/health                                              # 200 (public)
//! curl -i localhost:3000/api/notes                                        # 401
//! curl -H 'authorization: Bearer reader' localhost:3000/api/notes         # 200
//! curl -X POST -H 'authorization: Bearer reader' -H 'content-type: application/json' \
//!      -d '{"text":"hi"}' localhost:3000/api/notes                        # 403 (scope)
//! curl -X POST -H 'authorization: Bearer writer' -H 'content-type: application/json' \
//!      -d '{"text":"hi"}' localhost:3000/api/notes                        # 201
//! ```
use std::sync::{Arc, Mutex};
use std::time::Duration;

use poring::policy::RateKey;
use poring::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Default)]
struct Notes(Arc<Mutex<Vec<Note>>>);

#[derive(Clone, Serialize, PoringSchema)]
struct Note {
    id: usize,
    text: String,
    author: String,
}

#[derive(Deserialize, PoringSchema)]
struct NewNote {
    #[poring(min_length = 1, max_length = 280)]
    text: String,
}

/// Demo bearer tokens.
struct Tokens;

impl Authenticator for Tokens {
    async fn authenticate(&self, req: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(match req.bearer_token() {
            Some("reader") => {
                Some(Identity::new("reader", Credential::Bearer).with_scopes(["notes:read"]))
            }
            Some("writer") => Some(
                Identity::new("writer", Credential::Bearer)
                    .with_scopes(["notes:read", "notes:write"]),
            ),
            Some(_) => return Err(AuthError::Invalid),
            None => None,
        })
    }
}

async fn list(State(notes): State<Notes>) -> Json<Vec<Note>> {
    Json(notes.0.lock().unwrap_or_else(|p| p.into_inner()).clone())
}

async fn create(
    State(notes): State<Notes>,
    Principal(who): Principal<Authenticated>,
    Json(new): Json<NewNote>,
) -> (StatusCode, Json<Note>) {
    let mut all = notes.0.lock().unwrap_or_else(|p| p.into_inner());
    let note = Note {
        id: all.len() + 1,
        text: new.text,
        author: who.subject.clone(),
    };
    all.push(note.clone());
    (StatusCode::CREATED, Json(note))
}

fn app() -> Result<poring::FluentApp<Notes, Tokens>, poring::StartupError> {
    Poring::with_state(Notes::default())
        .authenticator(Tokens)
        .name("notes")
        .policy(Policy::new().deny_anonymous().body_limit(64 * 1024))
        .security_headers(poring::SecurityHeaders::strict_api())
        .route_with(
            RouteMethod::Get,
            "/health",
            Policy::new().public_with_reason("load balancer probe"),
            || async { "ok" },
        )
        .group("/api", |api| {
            api.policy(Policy::new().scopes(["notes:read"]))
                .after(|_cx, res| {
                    res.headers_mut()
                        .insert("cache-control", HeaderValue::from_static("no-store"));
                })
                .get("/notes", list)
                .route_with(
                    RouteMethod::Post,
                    "/notes",
                    Policy::new()
                        .scopes(["notes:write"])
                        .body_limit(4 * 1024)
                        .rate_limit(30, Duration::from_secs(60), RateKey::Principal),
                    create,
                )
        })
        .build()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = app()?;
    if std::env::args().any(|a| a == "--graph") {
        if let Some(g) = app.graph(Some("POST /api/notes")) {
            println!("{}", poring::contract::render_mermaid(&g));
        }
        return Ok(());
    }
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    app.listen(addr).await?;
    Ok(())
}
