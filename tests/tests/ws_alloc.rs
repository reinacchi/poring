//! Allocation measurements for typed WebSocket messages. A typed echo round trip
//! over real TCP is measured with dhat. The numbers include the tokio-tungstenite test
//! client, so they are an upper bound on the server-side cost. The budget catches
//! regressions such as re-introducing a per-message payload copy in `TypedSocket::recv`.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use poring::prelude::*;
use poring::ws::WebSocketUpgrade;
use tokio_tungstenite::tungstenite::Message;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Debug, serde::Deserialize, serde::Serialize, PoringSchema)]
struct Chat {
    text: String,
}

/// Bytes allocated per typed echo round trip with a ~4 KiB payload: 20 670 measured on
/// Windows (24 777 with the old payload copy), plus headroom.
const BYTES_PER_ROUND_TRIP_4K: f64 = 22_500.0;
/// Allocations per round trip (6.0 measured, 7.0 with the old payload copy).
const BLOCKS_PER_ROUND_TRIP: f64 = 6.5;

#[tokio::test(flavor = "current_thread")]
async fn typed_echo_allocations_stay_within_budget() {
    let _profiler = dhat::Profiler::builder().testing().build();
    let server = Poring::new()
        .get("/chat", |ws: WebSocketUpgrade| async move {
            ws.typed::<Chat, Chat>().on_upgrade(|mut sock| async move {
                while let Some(Ok(m)) = sock.recv().await {
                    if sock.send(&m).await.is_err() {
                        break;
                    }
                }
            })
        })
        .build()
        .unwrap()
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr();
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut ws, _) = tokio_tungstenite::client_async(format!("ws://{addr}/chat"), tcp)
        .await
        .unwrap();
    let payload = format!(r#"{{"text":"{}"}}"#, "x".repeat(4096));
    let round_trip = async |ws: &mut tokio_tungstenite::WebSocketStream<_>| {
        ws.send(Message::text(payload.clone())).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => assert_eq!(t.len(), payload.len()),
            other => panic!("{other:?}"),
        }
    };
    for _ in 0..20 {
        round_trip(&mut ws).await;
    }
    const N: u64 = 200;
    let before = dhat::HeapStats::get();
    for _ in 0..N {
        round_trip(&mut ws).await;
    }
    let after = dhat::HeapStats::get();
    let blocks = (after.total_blocks - before.total_blocks) as f64 / N as f64;
    let bytes = (after.total_bytes - before.total_bytes) as f64 / N as f64;
    eprintln!("typed echo, 4 KiB JSON: {blocks:.1} allocations, {bytes:.0} bytes per round trip");
    assert!(
        blocks <= BLOCKS_PER_ROUND_TRIP,
        "{blocks:.1} allocations per round trip exceeds the budget of {BLOCKS_PER_ROUND_TRIP}"
    );
    assert!(
        bytes <= BYTES_PER_ROUND_TRIP_4K,
        "{bytes:.0} bytes per round trip exceeds the budget of {BYTES_PER_ROUND_TRIP_4K}"
    );
    let _ = ws.close(None).await;
    server.shutdown().await.unwrap();
}
