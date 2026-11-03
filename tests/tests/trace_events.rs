//! Flow-recorder tracing events carry static graph node IDs and never credentials.
//!
//! This test has a binary of its own on purpose. `tracing` caches, per call site and for the
//! whole process, whether any subscriber is interested. Tests running in parallel threads
//! of the same binary hit Poring's call sites with no subscriber installed, so a subscriber
//! installed by one test with `set_default` can miss them. With a single test per process,
//! the subscriber is installed before anything else can register those call sites.

use std::sync::{Arc, Mutex};

use poring::flow::FlowConfig;
use poring_tests::secure::{SecureApp, SecureState, TableAuth};

fn recording_app(capacity: usize) -> poring::App<SecureApp> {
    SecureApp::builder()
        .state(SecureState::default())
        .authenticator(TableAuth::fixture())
        .flow_recording(FlowConfig {
            sample_every: 1,
            capacity,
        })
        .build()
        .unwrap()
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);
impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(b).into_owned());
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn tracing_events_use_graph_node_ids_without_secrets() {
    let cap = Capture::default();
    let w = cap.clone();
    let sub = tracing_subscriber::fmt()
        .with_env_filter("poring::flow=trace")
        .with_writer(move || w.clone())
        .with_ansi(false)
        .finish();
    let _g = tracing::subscriber::set_default(sub);
    let app = recording_app(8);
    app.client()
        .get("/notes")
        .bearer("reader-token")
        .send()
        .await;
    let out = cap.0.lock().unwrap().concat();
    assert!(out.contains("node=get_notes.auth"), "{out}");
    assert!(out.contains("node=get_notes.handler"), "{out}");
    assert!(!out.contains("reader-token"));
}
