# WebSockets in Poring

This guide covers the `websocket` feature: transports, security, the three socket APIs,
limits, liveness, shutdown, observability and deployment. Every behaviour described here
is covered by integration tests over real sockets (`tests/tests/ws_*.rs`, `tls.rs`).

## Lifecycle: HTTP request vs WebSocket session

A WebSocket starts as an ordinary HTTP request and goes through the same pipeline as any
route: routing, WebSocket origin check, CORS, rate limit, authentication, authorization and
hooks. Only if all of them pass does the handler run and call `on_upgrade`, which answers
`101 Switching Protocols` (HTTP/1.1) or `200` (HTTP/2) and starts a **session**.

The session is a long-lived task owned by the server (not a detached `tokio::spawn`): it
holds a session permit (`Limits::max_ws_sessions`) and its connection's slot
(`Limits::max_connections`) until it ends, however it ends — normal close, error, panic,
lifetime or shutdown. HTTP request limits (body size, timeouts) do not apply to the session;
the session has its own limits below.

## Transports

| Transport | Cargo features | Handshake | Success |
|---|---|---|---|
| HTTP/1.1 Upgrade (RFC 6455) | `websocket` | `GET` + `Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Version: 13`, valid `Sec-WebSocket-Key` | `101` + `Sec-WebSocket-Accept` |
| HTTP/2 Extended CONNECT (RFC 8441) | `websocket,http2` | `:method CONNECT`, `:protocol websocket`, `:scheme`, `:authority`, `:path`, `sec-websocket-version: 13` | `200`, no body, no HTTP/1.1 headers |
| Either, over TLS (`wss://`) | `+ tls-rustls` | same, inside TLS; ALPN `h2`/`http/1.1` | same |

* With `websocket,http2`, Poring advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. An HTTP/2
  WebSocket request reaches only the path's `GET` route, and only if that route is a
  WebSocket route; every other `CONNECT` gets `404`/`405`, so Poring never opens a tunnel.
* Many WebSockets and ordinary requests can share one HTTP/2 connection; cancelling one
  stream ends only that session; HTTP/2 flow control back-pressures slow readers.
* HTTP/2 without TLS is h2c with prior knowledge. Browsers use HTTP/2 WebSockets only over
  TLS with ALPN (enable `tls-rustls`, or a proxy that speaks RFC 8441 to the backend).
* `WebSocketUpgrade::is_http2()` tells the handler which transport was used.

## Registering a route

```rust,ignore
use poring::prelude::*;
use poring::ws::WebSocketUpgrade;

// Attribute macro
#[poring::ws("/chat")]
async fn chat(ws: WebSocketUpgrade) -> Response { /* ... */ }

// Fluent API: a GET route that must take `WebSocketUpgrade` (checked at registration)
let app = Poring::new().ws("/chat", |ws: WebSocketUpgrade| async move { /* ... */ });
```

Handlers can take any other extractor too (`State`, `Principal`, `Path`, headers, …).
The upgrade also exposes `identity()`, `request_id()`, `route_id()`, `peer()`,
`client_ip()`, `protocol()` and `is_http2()`.

## Security

**Origin (cross-site WebSocket hijacking).** Browsers attach cookies to WebSocket
handshakes from any site, and a handshake is a `GET`, so CORS and CSRF do not protect it.
Poring checks `Origin` on every handshake before authentication and before `101`:

* no `Origin` → allowed (non-browser clients; `Origin` is not authentication);
* same-origin with the request (`Host`, HTTP/2 `:authority`, or the public host from
  trusted proxies' `Forwarded`/`X-Forwarded-Host`) → allowed;
* listed in the app's CORS origins (exact match), or in `WsOrigins::allow([...])` at app,
  group or route level → allowed;
* anything else (`null`, malformed, several `Origin` headers, wildcard-only) → `403`.

`WsOrigins::any()` opts out, and is refused at build time if the authenticator uses
cookies. The same check applies to HTTP/1.1 and HTTP/2 handshakes.

**Authentication and authorization** run as for every route (`401`/`403` before any
session starts). **Handshake validation**: wrong method/version, missing or malformed
`Sec-WebSocket-Key` (must decode to 16 bytes), duplicate singleton headers → `400`;
unsupported `Sec-WebSocket-Version` → `426` with `Sec-WebSocket-Version: 13`.

## Subprotocols

```rust,ignore
let ws = ws.protocols(["chat.v2", "chat.v1"]);   // server preference order
let ws = ws.require_protocol();                   // optional: 400 if none matches
match ws.protocol() { Some("chat.v2") => …, _ => … }
```

The first server-preferred protocol the client offered is selected and echoed; a protocol
the client did not offer is never selected; malformed offers get `400`.

## Three socket APIs

| API | Use when | Poring guarantees |
|---|---|---|
| `ws.on_upgrade(\|sock: RawSocket\| …)` | full control of the tungstenite stream | session supervision, limits on frame/message size, `max_lifetime` (cancel), shutdown signal via `ws.shutdown_signal()` |
| `ws.typed::<In, Out>().on_upgrade(…)` | JSON messages with `PoringSchema` validation | the above + decode/validate without copying the payload, `1001` at shutdown, `1002`/`1007`/`1009` on protocol errors, peer close answered, message rate limits |
| `ws.managed().on_upgrade(\|sock: ManagedSocket\| …)` (and `.managed().typed::<In, Out>()`) | long-lived sessions that must stay healthy while the app is busy | everything above + an I/O pump that keeps sending pings, detects silent peers (idle timeout), bounds writes to stuck peers, closes with proper codes even if the handler is stuck; `split()` for concurrent senders |

`RawSocket` users own the close handshake: Poring cannot send pings or close frames on a
socket it does not drive.

## Limits and backpressure

| Setting | Default | Effect |
|---|---|---|
| `max_message_size(n)` | 64 KiB | larger inbound messages fail the session with `1009` |
| `max_frame_size(n)` | = message size | larger single frames → `1009` |
| `max_write_buffer(n)` | 64 MiB + 16 KiB | largest single outbound message (+ coalescing buffer); larger sends return an error |
| `message_rate(n, per)` | off | per-session inbound message rate → `1008` |
| `message_quota(&WsMessageQuota::per_ip/per_principal(n, per))` | off | rate shared across sessions → `1008` |
| `Limits::max_ws_sessions` | 10 000 | concurrent sessions per listener → `503` |
| `Limits::max_ws_sessions_per_ip` / `_per_principal` | unlimited | concurrent sessions per client → `429` |
| `Limits::max_connections` | 10 000 | TCP connections, including upgraded ones |

`send` waits while the peer is slow (bounded buffers, never an unbounded queue); managed
sessions queue at most 16 messages per direction. The HTTP rate limiter still protects
handshakes; message limits apply after the upgrade.

## Liveness (managed sessions)

```rust,ignore
ws.managed()
  .ping_interval(Duration::from_secs(30))   // default 30 s; .no_ping()
  .idle_timeout(Duration::from_secs(75))    // nothing received for this long → 1001; .no_idle_timeout()
  .close_timeout(Duration::from_secs(5))    // wait for the peer's close reply
  .max_lifetime(Duration::from_secs(3600))  // optional, any socket type
  .on_upgrade(|sock| async move { … })
```

## Close codes

Poring sends `1000` (normal, handler finished), `1001` (shutdown, idle, lifetime), `1002`
(protocol violation), `1007` (invalid UTF-8), `1008` (message rate), `1009` (too big),
`1011` (an application close code that may not be sent, e.g. `1005`, is replaced), and
echoes the peer's own code. Reserved codes never reach the wire; reasons are cut to 123
bytes. Abrupt disconnects are not answered (nobody is listening).

## Graceful shutdown

`Server::shutdown()` / the `serve` shutdown future: new handshakes get `503`; sessions are
signalled (`WsShutdown`, typed/managed sessions send `1001`); the server waits up to
`Limits::shutdown_grace` (default 10 s); sessions still running are cancelled; `serve`
returns. Nothing outlives the server.

## Observability

`App::ws_stats()` / `Server::ws_stats()` return counters: handshakes accepted and refused
(session limit, client cap, shutdown, origin, auth), active/ended/panicked sessions, close
causes (protocol, rate, idle, lifetime, shutdown, abnormal disconnect) and messages/bytes
of managed and typed sessions. Debug-level `tracing` events carry route and request ID.
Payloads, headers, cookies and tokens are never logged.

## Deployment (`wss://`)

* **Native TLS** (`tls-rustls`): `App::bind_tls(addr, TlsConfig::from_pem_files(cert, key)?)`.
* **Behind a TLS-terminating proxy**: plain `bind`, plus `TrustedProxies` so that the
  origin check, rate limits and `client_ip()` see the public host and real client. The
  proxy must forward `Upgrade`/`Connection` (HTTP/1.1) or speak RFC 8441 (HTTP/2) and
  allow long-lived connections.

## Production recommendations

* Prefer managed sockets for long-lived sessions; set `idle_timeout` above the ping
  interval and below your proxy's idle timeout.
* Set `max_message_size` to what your protocol needs and add `message_rate`.
* Set `Limits::max_ws_sessions_per_principal` for authenticated apps; use the per-IP cap
  only when clients are not behind a shared NAT/proxy.
* Keep `shutdown_grace` above `close_timeout` so clients receive `1001`.
* Watch `ws_stats()`: rising `rejected_*`, `protocol_failures` or `abnormal_disconnects`
  point at capacity, client bugs or network problems.

## Performance notes

Typed messages are decoded straight from the received frame (one allocation fewer per
message than before; budgeted by `tests/tests/ws_alloc.rs`). Per-message counters are kept
per session and published when the session ends. `benches/ws-bench` compares Poring and
Axum echo servers; on the measured machine the two were within run-to-run noise
(`benches/ws-bench/RESULTS.md`) — no superiority is claimed.
