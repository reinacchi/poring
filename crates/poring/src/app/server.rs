//! The Hyper server: accept loop, connection handling and graceful shutdown.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::Request;

use crate::body::ReqBody;

use super::tasks::{TaskScope, TaskTracker};
use super::{App, AppSpec};

impl<A: AppSpec> App<A> {
    /// Binds `addr` and serves in a background task. Returns a handle for shutdown.
    pub async fn bind(self, addr: impl tokio::net::ToSocketAddrs) -> std::io::Result<Server> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        #[cfg(feature = "websocket")]
        let ws = self.inner.ws_counters.clone();
        let join = tokio::spawn(self.serve(listener, async move {
            let _ = rx.await;
        }));
        Ok(Server {
            addr: local,
            shutdown: Some(tx),
            join,
            #[cfg(feature = "websocket")]
            ws,
        })
    }

    /// Serves connections from `listener` until `shutdown` completes, then stops
    /// accepting, asks every connection to finish its in-flight request, and waits up to
    /// `Limits::shutdown_grace` for them to drain.
    pub async fn serve(
        self,
        listener: tokio::net::TcpListener,
        shutdown: impl Future<Output = ()> + Send,
    ) -> std::io::Result<()> {
        self.serve_transport(listener, shutdown, Transport::Plain)
            .await
    }

    /// [`bind`](Self::bind) with TLS (`tls-rustls` feature): HTTPS and `wss://`.
    #[cfg(feature = "tls-rustls")]
    pub async fn bind_tls(
        self,
        addr: impl tokio::net::ToSocketAddrs,
        tls: crate::tls::TlsConfig,
    ) -> std::io::Result<Server> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        #[cfg(feature = "websocket")]
        let ws = self.inner.ws_counters.clone();
        let join = tokio::spawn(self.serve_transport(
            listener,
            async move {
                let _ = rx.await;
            },
            Transport::Tls(tls.acceptor()),
        ));
        Ok(Server {
            addr: local,
            shutdown: Some(tx),
            join,
            #[cfg(feature = "websocket")]
            ws,
        })
    }

    /// [`serve`](Self::serve) with TLS (`tls-rustls` feature). Each connection's TLS
    /// handshake must finish within `Limits::header_read_timeout`.
    #[cfg(feature = "tls-rustls")]
    pub async fn serve_tls(
        self,
        listener: tokio::net::TcpListener,
        tls: crate::tls::TlsConfig,
        shutdown: impl Future<Output = ()> + Send,
    ) -> std::io::Result<()> {
        self.serve_transport(listener, shutdown, Transport::Tls(tls.acceptor()))
            .await
    }

    async fn serve_transport(
        self,
        listener: tokio::net::TcpListener,
        shutdown: impl Future<Output = ()> + Send,
        transport: Transport,
    ) -> std::io::Result<()> {
        // At least one connection (zero would never accept anything), at most what a
        // semaphore can count.
        let max = self
            .inner
            .limits
            .max_connections
            .clamp(1, tokio::sync::Semaphore::MAX_PERMITS);
        let permits = Arc::new(tokio::sync::Semaphore::new(max));
        // Every connection task is owned by this scope: dropping `serve` (or reaching the
        // end of shutdown) aborts whatever is left, so no connection outlives it.
        let connections = TaskScope(TaskTracker::new());
        #[cfg(feature = "websocket")]
        let sessions = Arc::new(crate::ws::Supervisor::new(
            self.inner.limits.max_ws_sessions,
            self.inner.ws_counters.clone(),
        ));
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        tokio::pin!(shutdown);
        loop {
            let permit = tokio::select! {
                _ = &mut shutdown => break,
                p = permits.clone().acquire_owned() => match p {
                    Ok(p) => p,
                    Err(_) => break,
                },
            };
            let (stream, peer) = tokio::select! {
                _ = &mut shutdown => break,
                r = listener.accept() => match r {
                    Ok(v) => v,
                    Err(e) => {
                        // Transient accept errors (EMFILE etc.): back off briefly.
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            let _ = stream.set_nodelay(true);
            let app = self.clone();
            let mut stop = stop_rx.clone();
            // Shared with any WebSocket session upgraded from this connection, so the slot
            // stays taken until both the connection task and the session have ended.
            let permit = Arc::new(permit);
            let conn = Conn {
                permit: permit.clone(),
                #[cfg(feature = "websocket")]
                sessions: sessions.clone(),
            };
            let transport = transport.clone();
            connections.0.spawn(async move {
                let _permit = permit;
                match transport {
                    Transport::Plain => serve_conn(app, stream, false, peer, conn, &mut stop).await,
                    #[cfg(feature = "tls-rustls")]
                    Transport::Tls(acceptor) => {
                        let limit = app.inner.limits.header_read_timeout;
                        let handshake = tokio::time::timeout(limit, acceptor.accept(stream));
                        let tls = tokio::select! {
                            r = handshake => r,
                            _ = stop.wait_for(|s| *s) => return,
                        };
                        match tls {
                            Ok(Ok(tls)) => serve_conn(app, tls, true, peer, conn, &mut stop).await,
                            // No key material or peer data in these messages.
                            Ok(Err(e)) => tracing::debug!(error = %e, "tls handshake failed"),
                            Err(_) => tracing::debug!("tls handshake timed out"),
                        }
                    }
                }
            });
        }
        drop(listener);
        // No new WebSocket sessions once shutdown has begun (late upgrades get 503).
        #[cfg(feature = "websocket")]
        sessions.close();
        let _ = stop_tx.send(true);
        connections.0.close();
        let grace = self.inner.limits.shutdown_grace;
        // Connections (and their HTTP/2 streams), including those carrying WebSocket
        // sessions, drain until `grace`. A WebSocket session holds its connection's permit,
        // so all permits back means every connection task *and* every session has ended.
        let all = u32::try_from(max).unwrap_or(u32::MAX);
        let drained = tokio::time::timeout(grace, async {
            connections.0.wait_idle().await;
            let _ = permits.acquire_many(all).await;
        })
        .await;
        if drained.is_err() {
            tracing::warn!("graceful shutdown grace period elapsed with connections still open");
        }
        // Whatever is still running after the grace period is cancelled, so nothing outlives
        // `serve`. That covers connection tasks (which aborts their HTTP/2 stream tasks too)
        // and WebSocket sessions.
        let bound = grace.max(Duration::from_millis(100));
        let aborted = connections.0.abort_all();
        if aborted > 0 {
            tracing::debug!(connections = aborted, "connections cancelled at shutdown");
        }
        #[cfg(feature = "websocket")]
        sessions.abort_all(bound).await;
        if tokio::time::timeout(bound, connections.0.wait_idle())
            .await
            .is_err()
        {
            tracing::warn!("connection tasks did not stop after cancellation");
        }
        Ok(())
    }
}

/// How accepted connections are wrapped.
#[derive(Clone)]
enum Transport {
    Plain,
    #[cfg(feature = "tls-rustls")]
    Tls(tokio_rustls::TlsAcceptor),
}

/// Per-connection resources handed to upgrade requests.
struct Conn {
    #[cfg_attr(not(feature = "websocket"), allow(dead_code))]
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    #[cfg(feature = "websocket")]
    sessions: Arc<crate::ws::Supervisor>,
}

async fn serve_conn<A: AppSpec, S>(
    app: App<A>,
    stream: S,
    tls: bool,
    peer: SocketAddr,
    conn: Conn,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Without WebSocket support no request can be upgraded into a session.
    #[cfg(not(feature = "websocket"))]
    let _ = (conn, tls);
    let io = hyper_util::rt::TokioIo::new(stream);
    let header_timeout = app.inner.limits.header_read_timeout;
    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let app = app.clone();
        #[cfg(feature = "websocket")]
        let mut req = req;
        // Only WebSocket upgrade requests pay for the admission handle.
        #[cfg(feature = "websocket")]
        if crate::policy::ws_origin::websocket_handshake(
            req.method(),
            req.version(),
            req.headers(),
            req.extensions(),
        )
        .is_some()
        {
            let client_ip = app.inner.proxies.client_ip(peer.ip(), req.headers());
            // The origin check compares origins with the endpoint's scheme.
            if tls {
                req.extensions_mut()
                    .insert(crate::policy::ws_origin::SecureTransport);
            }
            req.extensions_mut().insert(crate::ws::Admission {
                supervisor: conn.sessions.clone(),
                connection: conn.permit.clone(),
                client_ip,
            });
        }
        // One span per request (OpenTelemetry-compatible via a `tracing` layer). Only the
        // method and path are recorded: never query strings, headers, cookies or bodies.
        let span = tracing::info_span!(
            "poring.request",
            method = %req.method(),
            path = %req.uri().path(),
            route = tracing::field::Empty,
            status = tracing::field::Empty,
            request_id = tracing::field::Empty,
        );
        tracing::Instrument::instrument(
            async move {
                Ok::<_, Infallible>(
                    app.inner
                        .handle(req.map(ReqBody::Incoming), Some(peer))
                        .await,
                )
            },
            span,
        )
    });
    #[cfg(not(feature = "http2"))]
    let conn = {
        let mut b = hyper::server::conn::http1::Builder::new();
        b.timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(header_timeout);
        b.serve_connection(io, svc).with_upgrades()
    };
    // HTTP/2 stream tasks are owned by this connection: they are aborted when the
    // connection task ends or is cancelled, instead of running on detached.
    #[cfg(feature = "http2")]
    let streams = TaskScope(TaskTracker::new());
    #[cfg(feature = "http2")]
    let builder = {
        let mut b = hyper_util::server::conn::auto::Builder::new(StreamExecutor(streams.0.clone()));
        b.http1()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(header_timeout);
        // RFC 8441: let HTTP/2 clients open WebSockets with Extended CONNECT.
        #[cfg(feature = "websocket")]
        b.http2().enable_connect_protocol();
        b
    };
    #[cfg(feature = "http2")]
    let conn = builder.serve_connection_with_upgrades(io, svc);
    tokio::pin!(conn);
    tokio::select! {
        r = conn.as_mut() => {
            if let Err(e) = r {
                tracing::debug!(error = %e, "connection ended with error");
            }
            return;
        }
        _ = stop.wait_for(|s| *s) => {
            conn.as_mut().graceful_shutdown();
        }
    }
    if let Err(e) = conn.await {
        tracing::debug!(error = %e, "connection ended with error during shutdown");
    }
}

/// Spawns a connection's HTTP/2 stream tasks into that connection's [`TaskTracker`].
#[cfg(feature = "http2")]
#[derive(Clone)]
struct StreamExecutor(TaskTracker);

#[cfg(feature = "http2")]
impl<F> hyper::rt::Executor<F> for StreamExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        // Refused only once the connection was cancelled: the stream is dropped with it.
        self.0.spawn_draining(async move {
            fut.await;
        });
    }
}

/// Handle to a server started with [`App::bind`].
#[derive(Debug)]
pub struct Server {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<std::io::Result<()>>,
    #[cfg(feature = "websocket")]
    ws: Arc<crate::ws::WsCounters>,
}

impl Server {
    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// A snapshot of the app's WebSocket counters (`websocket` feature).
    #[cfg(feature = "websocket")]
    pub fn ws_stats(&self) -> crate::ws::WsStats {
        self.ws.snapshot()
    }

    /// Triggers graceful shutdown and waits for it to finish.
    pub async fn shutdown(mut self) -> std::io::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        match (&mut self.join).await {
            Ok(r) => r,
            Err(e) => Err(std::io::Error::other(e)),
        }
    }
}
