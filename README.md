<p align="center"><img src="https://raw.githubusercontent.com/reinacchi/poring/refs/heads/master/Poring.png" alt="Poring Logo" width="350"/></p>

<h1 align="center">Poring</h1>
<p align="center">
    <strong>Ergonomic Rust Web Framework</strong>
    <br>
    Poring is a high-performance, type-safe Rust web framework built on Tokio and Hyper. It simplifies building reliable web applications with expressive routing, first-class route policies, native tracing, and WebAssembly support.
</p>

<p align="center">
  <a href="https://poring.2rkf.fun"><strong>Website</strong></a>
  ·
  <a href="https://discord.gg/wynvba7skH"><strong>Discord</strong></a>
</p>

## Examples

### Fluent API

Build web applications with a clean, expressive API without route attributes.

```rust
use poring::prelude::*;

fn main() -> Result<(), poring::StartupError> {
    Poring::new()
        .get("/", || async {
            "Hello, Poring!"
        })
        .get("/hello", || async {
            "Hello, world!"
        })
        .run("127.0.0.1:3000")?;

    Ok(())
}
```

### Attribute Macros

Define routes using Rust attributes with compile-time route validation.

```rust
use poring::prelude::*;

#[poring::get("/")]
async fn index() -> &'static str {
    "Hello, Poring!"
}

#[poring::get("/hello")]
async fn hello() -> &'static str {
    "Hello, world!"
}

poring_app! {
    pub App {
        routes: [index, hello],
    }
}

#[tokio::main]
async fn main() -> Result<(), poring::StartupError> {
    App::builder()
        .listen("127.0.0.1:3000")
        .await
}
```

### WebSockets

Enable the `websocket` feature (add `http2` for RFC 8441 WebSockets over HTTP/2 and
`tls-rustls` for native `wss://`). WebSocket routes go through the same policy pipeline as
every route: origin check, rate limits, authentication and authorization run before the
upgrade.

<!-- poring:websocket:start -->
```rust
use poring::prelude::*;
use poring::ws::{ManagedSocket, WebSocketUpgrade};

fn main() -> Result<(), poring::StartupError> {
    Poring::new()
        .ws("/echo", |ws: WebSocketUpgrade| async move {
            // Managed sessions keep pinging, detect dead peers and close cleanly.
            ws.max_message_size(64 * 1024).managed().on_upgrade(
                |mut sock: ManagedSocket| async move {
                    while let Some(msg) = sock.recv().await {
                        if sock.send(msg).await.is_err() {
                            break;
                        }
                    }
                },
            )
        })
        .run("127.0.0.1:3000")?;

    Ok(())
}
```
<!-- poring:websocket:end -->

See the [WebSocket guide](docs/WEBSOCKETS.md) for transports, security, limits, heartbeats,
shutdown, observability and deployment, and the [Cargo feature reference](docs/FEATURES.md)
for every feature and its dependencies.

## Examples

See more examples [here](/examples/).