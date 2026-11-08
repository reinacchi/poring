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

See more examples [here](/examples/).

## Cargo features

| Feature | Default | Enables |
|---|---|---|
| `json` | yes | `Json<T>` extractor and response |
| `trace-flow` | yes | runtime flow recorder for the flow graph |
| `openapi` | yes | OpenAPI 3.1 document and TypeScript client generation |
| `http2` | | HTTP/2 alongside HTTP/1.1 (and RFC 8441 WebSockets) |
| `websocket` | | WebSocket routes: raw, typed and managed sessions |
| `multipart` | | `Multipart` extractor with size and part limits |
| `tls-rustls` | | native HTTPS/WSS with rustls |
| `wasm` | | sandboxed Wasm component guest routes (Wasmtime) |
| `hot-reload` | | Wasm guest hot reload (implies `wasm`) |
| `guest-kit` | | build guest components from WAT/Wasm (implies `wasm`) |
| `cli` | | the `cargo-poring` tool (implies the Wasm features) |

Minimum supported Rust version: **1.97** (edition 2024). Supported platform: Linux
x86_64. Others are expected to work but are not tested in CI.

## Production

* Start from `Limits::production()` and the endpoint presets `ws.production()` and
  `.managed().production()`, then tighten them for your workload.
  `production_warnings()` lists any setting that is still unbounded.
* [`examples/websocket_production.rs`](/examples/websocket_production.rs) shows a
  complete service: session caps, trusted proxies, origin checks, authentication for
  browser and non-browser clients, message quotas and metrics.
* Report security issues privately through
  [GitHub security advisories](https://github.com/reinacchi/poring/security/advisories/new).