//! The Hyper server: accept loop, connection handling and graceful shutdown.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::Request;

use crate::body::ReqBody;

use super::{App, AppSpec};

impl<A: AppSpec> App<A> {
    /// Binds `addr` and serves in a background task; returns a handle for shutdown.
    pub async fn bind(self, addr: impl tokio::net::ToSocketAddrs) -> std::io::Result<Server> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(self.serve(listener, async move {
            let _ = rx.await;
        }));
        Ok(Server {
            addr: local,
            shutdown: Some(tx),
            join,
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
        let max = self.inner.limits.max_connections.max(1);
        let permits = Arc::new(tokio::sync::Semaphore::new(max));
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
            tokio::spawn(async move {
                let _permit = permit;
                serve_conn(app, stream, peer, &mut stop).await;
            });
        }
        drop(listener);
        let _ = stop_tx.send(true);
        let drained = tokio::time::timeout(
            self.inner.limits.shutdown_grace,
            permits.acquire_many(max as u32),
        )
        .await;
        if drained.is_err() {
            tracing::warn!("graceful shutdown grace period elapsed with connections still open");
        }
        Ok(())
    }
}

async fn serve_conn<A: AppSpec>(
    app: App<A>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) {
    let io = hyper_util::rt::TokioIo::new(stream);
    let header_timeout = app.inner.limits.header_read_timeout;
    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let app = app.clone();
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
    #[cfg(feature = "http2")]
    let builder = {
        let mut b =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        b.http1()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(header_timeout);
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

/// Handle to a server started with [`App::bind`].
#[derive(Debug)]
pub struct Server {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Server {
    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
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
