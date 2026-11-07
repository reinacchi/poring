# Cargo feature reference (`poring`)

Defaults: `json`, `trace-flow`, `openapi`. Every feature compiles on its own with
`--no-default-features --features <name>` (verified in CI, see `.github/workflows`).

| Feature | Enables | Optional dependencies | Implies | Public API behind it |
|---|---|---|---|---|
| `json` | `Json<T>` extractor and response | — | — | `extract::Json`, `IntoResponse for Json<T>` |
| `trace-flow` | runtime flow recording (sampled, bounded) | — | — | recording only; `FlowRecorder`/`flow_recording` exist without it but record nothing, allocate nothing and log a warning at build if enabled in config |
| `openapi` | OpenAPI 3.1 document + TypeScript client | — | — | `poring::openapi`, `App::openapi` |
| `http2` | HTTP/2 (h2c prior knowledge; ALPN `h2` with TLS) next to HTTP/1.1 | hyper/h2, hyper-util `server-auto` | — | — (transport) |
| `websocket` | WebSockets over HTTP/1.1; with `http2`, RFC 8441 too | tokio-tungstenite, futures-util, data-encoding | — | `poring::ws`, `Poring::ws`, `App/Server::ws_stats`, `Limits::max_ws_sessions*` (fields always present) |
| `multipart` | bounded `Multipart` extractor | multer, futures-util | — | `extract::multipart` |
| `tls-rustls` | native TLS (HTTPS, `wss://`), rustls with the ring provider | tokio-rustls (rustls, ring) | — | `poring::tls`, `App::bind_tls`, `App::serve_tls` |
| `wasm` | sandboxed Wasm component guests (Wasmtime) | wasmtime, arc-swap, sha2 | — | `poring::wasm` |
| `hot-reload` | file watcher swapping guests, keeping the last good one | notify | `wasm` | hot-reload APIs |
| `guest-kit` | build components from WAT/core modules | wat, wit-component, wit-parser | `wasm` | guest-kit APIs |
| `cli` | the `cargo-poring` binary | tracing-subscriber | `wasm`, `hot-reload`, `guest-kit` | binary only |

Interactions: `websocket` + `http2` = RFC 8441; `tls-rustls` + `http2` = ALPN `h2`;
`websocket` and `multipart` are independent (they share only `futures-util`).
Internal serde/serde_json is always present (error bodies, contracts, typed WebSockets), so
`websocket` works without `json`.

## Workspace packages

* `poring-tests`: Poring with `default-features = false`; features `full` (= json,
  trace-flow, openapi, websocket, multipart), each of those individually, `http2`, `tls`,
  `wasm-guests`; default `full + wasm-guests`. Every test target declares
  `required-features`.
* `poring-examples`: Poring with `default-features = false`; features `json`,
  `trace-flow`, `openapi`, `websocket`, `wasm` (all default); each example declares what it
  needs.
* `examples/wasm-guest` and `benches/ws-bench` are standalone (excluded from the workspace).
