//! Secure fixture app for the security tests: strict `deny_anonymous` defaults, scopes, roles,
//! CSRF for cookie sessions, CORS with credentials, rate limits, timeouts, body/content gates.
//! Needs the `json` feature.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use poring::prelude::*;
use serde::{Deserialize, Serialize};

use crate::auth::TableAuth;

/// A note.
#[derive(Clone, Debug, Serialize, Deserialize, PoringSchema, PartialEq)]
pub struct Note {
    /// Owner subject.
    pub owner: String,
    /// Text.
    #[poring(min_length = 1, max_length = 280)]
    pub text: String,
}

/// New note payload.
#[derive(Debug, Serialize, Deserialize, PoringSchema)]
pub struct NewNote {
    /// Text.
    #[poring(min_length = 1, max_length = 280)]
    pub text: String,
}

/// Shared log of events (to assert hooks never run on denials).
#[derive(Clone, Default)]
pub struct Events(pub Arc<Mutex<Vec<String>>>);

/// Note storage.
#[derive(Clone, Default)]
pub struct Notes(pub Arc<Mutex<Vec<Note>>>);

/// App state.
#[derive(Clone, Default, PoringState)]
pub struct SecureState {
    /// Notes.
    pub notes: Notes,
    /// Events.
    pub events: Events,
}

/// Records that user code ran.
#[poring::hook]
async fn record(cx: &mut Ctx<'_, SecureState>) {
    cx.state()
        .events
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(format!("hook:{}", cx.route_id()));
}

/// Liveness probe: an explicit, documented public exception.
#[poring::get("/health", public(reason = "load balancer liveness probe"))]
async fn health() -> &'static str {
    "ok"
}

/// Read notes (scope `notes:read`).
#[poring::get("/notes", policy(scopes = ["notes:read"]))]
async fn list_notes(State(n): State<Notes>) -> Json<Vec<Note>> {
    Json(n.0.lock().unwrap_or_else(|p| p.into_inner()).clone())
}

/// Create a note (scope `notes:write`, JSON only, 1 KiB, 2/s per principal).
#[poring::post(
    "/notes",
    policy(scopes = ["notes:write"], body_limit = "1KiB", content_type = "application/json", rate_limit(requests = 2, per = "1s", key = principal))
)]
async fn create_note(
    Principal(who): Principal<Authenticated>,
    State(n): State<Notes>,
    Json(new): Json<NewNote>,
) -> (StatusCode, Json<Note>) {
    let note = Note {
        owner: who.subject.clone(),
        text: new.text,
    };
    n.0.lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(note.clone());
    (StatusCode::CREATED, Json(note))
}

/// Who am I.
#[poring::get("/me", policy(rate_limit = "3/s"))]
async fn me(Principal(who): Principal<Identity>) -> String {
    who.subject
}

/// A slow endpoint with a tight timeout.
#[poring::get("/slow", policy(timeout = "50ms"))]
async fn slow() -> &'static str {
    tokio::time::sleep(Duration::from_secs(5)).await;
    "too late"
}

/// HMAC-verified webhook: explicitly exempt from CSRF and public, with reasons.
#[poring::post("/webhook", policy(public(reason = "verified by HMAC signature"), csrf = exempt("no cookie auth; HMAC signed"), body_limit = "256B"))]
async fn webhook(body: Bytes) -> String {
    format!("got {} bytes", body.len())
}

/// Admin-only stats.
#[poring::get("/stats")]
async fn admin_stats(State(n): State<Notes>) -> String {
    n.0.lock()
        .unwrap_or_else(|p| p.into_inner())
        .len()
        .to_string()
}

poring_app! {
    /// The secure fixture.
    pub SecureApp {
        state: SecureState,
        auth: TableAuth,
        defaults: policy(deny_anonymous, body_limit = "64KiB"),
        cors: cors(origins = ["https://app.example"], credentials = true),
        before: [record],
        routes: [health, list_notes, create_note, me, slow, webhook],
        groups: [
            group("/admin", policy(roles = ["admin"])) { routes: [admin_stats] },
        ],
    }
}
