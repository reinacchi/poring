//! Native TLS (HTTPS and WSS) with rustls (`tls-rustls` feature).
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use poring::prelude::*;
//! use poring::tls::TlsConfig;
//!
//! let tls = TlsConfig::from_pem_files("cert.pem", "key.pem")?;
//! let server = Poring::new()
//!     .get("/", || async { "hello over TLS" })
//!     .build()?
//!     .bind_tls("0.0.0.0:8443", tls)
//!     .await?;
//! # server.shutdown().await?; Ok(()) }
//! ```
//!
//! * Protocols: TLS 1.3 and 1.2 with rustls' safe defaults (ring crypto provider). No
//!   client certificates. ALPN offers `h2` (with the `http2` feature) and `http/1.1`, so
//!   HTTP/2 clients (including RFC 8441 WebSockets) negotiate HTTP/2 and others HTTP/1.1.
//! * WebSockets work unchanged over TLS (`wss://`). The endpoint is known to be secure, so
//!   a same-origin match requires an `https://` origin: a page served over plain HTTP
//!   (`Origin: http://…`) is cross-origin for a `wss://` endpoint and is refused unless an
//!   allow-list entry names it.
//! * The TLS handshake of each connection runs in that connection's task, bounded by
//!   `Limits::header_read_timeout` and abandoned at shutdown, so slow or hostile clients
//!   cannot stall the accept loop. Handshake failures are logged at debug level without
//!   any key material.
//! * Behind a TLS-terminating reverse proxy, use plain [`App::bind`](crate::app::App::bind)
//!   and configure [`TrustedProxies`](crate::policy::TrustedProxies) instead.

use std::path::Path;
use std::sync::Arc;

use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Server TLS configuration for [`App::bind_tls`](crate::app::App::bind_tls) and
/// [`App::serve_tls`](crate::app::App::serve_tls).
#[derive(Clone)]
pub struct TlsConfig {
    pub(crate) server: Arc<rustls::ServerConfig>,
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("TlsConfig")
            .field("alpn", &self.alpn())
            .finish_non_exhaustive()
    }
}

/// Why a [`TlsConfig`] could not be built. Messages name the failing input but never
/// include key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// A PEM file could not be read.
    #[error("cannot read {what} file {path}: {source}")]
    Io {
        /// `"certificate"` or `"private key"`.
        what: &'static str,
        /// The path that failed.
        path: String,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The certificate PEM contained no certificate, or a malformed one.
    #[error("invalid certificate chain: {0}")]
    Certificate(String),
    /// The key PEM contained no usable private key (PKCS#8, PKCS#1 or SEC1).
    #[error("invalid private key: no usable PKCS#8, PKCS#1 or SEC1 key found")]
    PrivateKey,
    /// rustls rejected the certificate/key pair.
    #[error("rejected by rustls: {0}")]
    Rustls(#[from] rustls::Error),
}

impl TlsConfig {
    /// Builds a configuration from a PEM certificate chain (leaf first) and a PEM private
    /// key.
    pub fn from_pem(cert_chain: &[u8], private_key: &[u8]) -> Result<Self, TlsError> {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_chain)
            .collect::<Result<_, _>>()
            .map_err(|e| TlsError::Certificate(e.to_string()))?;
        if certs.is_empty() {
            return Err(TlsError::Certificate("no certificate found".into()));
        }
        let key = PrivateKeyDer::from_pem_slice(private_key).map_err(|_| TlsError::PrivateKey)?;
        Self::from_der(certs, key)
    }

    /// Like [`from_pem`](Self::from_pem), reading both PEM files from disk.
    pub fn from_pem_files(
        cert_chain: impl AsRef<Path>,
        private_key: impl AsRef<Path>,
    ) -> Result<Self, TlsError> {
        let read = |what, p: &Path| {
            std::fs::read(p).map_err(|source| TlsError::Io {
                what,
                path: p.display().to_string(),
                source,
            })
        };
        let certs = read("certificate", cert_chain.as_ref())?;
        let key = read("private key", private_key.as_ref())?;
        Self::from_pem(&certs, &key)
    }

    /// Builds a configuration from DER certificates and key.
    pub fn from_der(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, TlsError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;
        server.alpn_protocols = default_alpn();
        Ok(TlsConfig {
            server: Arc::new(server),
        })
    }

    /// Uses a caller-built rustls configuration as is (client authentication, custom
    /// providers, …). Its ALPN list is not modified: include `h2` and/or `http/1.1`.
    pub fn from_rustls(config: Arc<rustls::ServerConfig>) -> Self {
        TlsConfig { server: config }
    }

    /// The ALPN protocols offered, in preference order.
    pub fn alpn(&self) -> Vec<String> {
        self.server
            .alpn_protocols
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect()
    }

    pub(crate) fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(self.server.clone())
    }
}

fn default_alpn() -> Vec<Vec<u8>> {
    #[cfg(feature = "http2")]
    return vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    #[cfg(not(feature = "http2"))]
    vec![b"http/1.1".to_vec()]
}
