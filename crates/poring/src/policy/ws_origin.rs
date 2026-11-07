//! Origin validation for WebSocket handshakes (cross-site WebSocket hijacking defence).
//!
//! A browser WebSocket handshake is a `GET`, so the CORS check (which only rejects unsafe
//! methods) and CSRF protection (unsafe methods only) never stop it, while the browser
//! still attaches cookies. Any request carrying `Upgrade: websocket` is therefore checked
//! here, before authentication and before the handler can answer `101`:
//!
//! * no `Origin` header: allowed. Non-browser clients do not send one and can forge it
//!   anyway; Origin is a browser-side defence, **not** authentication.
//! * exactly one `Origin` that is same-origin with the request (`Host`, or the URI
//!   authority for HTTP/2), listed explicitly in the app's CORS origins, or listed in
//!   [`WsOrigins::allow`]: allowed.
//! * anything else — another origin, `null`, a malformed value, several `Origin`
//!   headers, or an origin only matched by the CORS wildcard `*` — is rejected with 403.
//!
//! Same-origin comparison is ASCII case-insensitive on scheme and host, and an origin
//! without a port uses its scheme's default (80 / 443). When `Host` has no port, any
//! `http`/`https` origin with the scheme's default port matches, because the server cannot
//! tell whether TLS was terminated in front of it.
//!
//! Behind a reverse proxy that rewrites `Host`, configure the proxy in `trusted_proxies`.
//! When the TCP peer is trusted, the public host it reports is an additional same-origin
//! target: RFC 7239 `Forwarded` (`host=` and optional `proto=`) if present, otherwise
//! `X-Forwarded-Host` (and optional `X-Forwarded-Proto`). A reported proto must equal the
//! origin's scheme and sets the default port. Only one unambiguous value is believed:
//! several header lines, comma-separated chains, unknown protos or malformed hosts are
//! ignored and the check falls back to `Host`. From untrusted peers these headers are
//! always ignored. Alternatively list the public origin with [`WsOrigins::allow`].
//!
//! [`WsOrigins::any`] disables the check; `build()` refuses it when the authenticator
//! accepts cookies, because that combination is exactly cross-site WebSocket hijacking.

use http::HeaderMap;
use http::header::{HOST, ORIGIN, UPGRADE};

use super::enforce::CorsRuntime;
use super::proxy::TrustedProxies;

/// WebSocket handshake origin policy for an app (`.ws_origins(..)` on `Poring` or a
/// `poring_app!` builder).
///
/// The default ([`WsOrigins::new`]) accepts handshakes without `Origin`, same-origin
/// handshakes and origins listed explicitly in the app's CORS configuration.
///
/// ```
/// use poring::policy::WsOrigins;
///
/// let origins = WsOrigins::new().allow(["https://app.example.com"]);
/// # let _ = origins;
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WsOrigins {
    origins: Vec<String>,
    any: bool,
}

impl WsOrigins {
    /// Same-origin plus explicit CORS origins (the default).
    pub fn new() -> Self {
        WsOrigins::default()
    }

    /// Additional allowed origins, as serialised origins (`https://host[:port]`). Scheme
    /// and host compare case-insensitively and a missing port means the scheme's default.
    /// Invalid entries (including `*` and `null`) are reported by `build()`.
    pub fn allow<I, T>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.origins.extend(origins.into_iter().map(Into::into));
        self
    }

    /// Accepts handshakes from **any** origin, for public endpoints whose clients
    /// authenticate with explicit tokens. Refused by `build()` when the app's
    /// authenticator accepts cookies.
    pub fn any() -> Self {
        WsOrigins {
            origins: Vec::new(),
            any: true,
        }
    }
}

impl WsOrigins {
    /// Manifest view: the listed origins, or `["*"]` for [`WsOrigins::any`].
    pub(crate) fn view(&self) -> Vec<String> {
        if self.any {
            vec!["*".to_owned()]
        } else {
            self.origins.clone()
        }
    }
}

/// Validated, normalised form of [`WsOrigins`].
#[derive(Clone, Debug, Default)]
pub(crate) struct WsOriginPolicy {
    any: bool,
    /// (https, lower-case host, effective port)
    allowed: Vec<(bool, String, u16)>,
}

impl WsOriginPolicy {
    pub(crate) fn from_config(c: &WsOrigins, auth_uses_cookies: bool) -> Result<Self, String> {
        if c.any && auth_uses_cookies {
            return Err("ws_origins: `WsOrigins::any()` cannot be combined with a cookie-capable authenticator (cross-site WebSocket hijacking); list                         the allowed origins with `WsOrigins::new().allow([..])`"
                .into());
        }
        let mut allowed = Vec::with_capacity(c.origins.len());
        for o in &c.origins {
            let p = parse_origin(o).ok_or_else(|| {
                format!("ws_origins: `{o}` is not an origin like `https://host[:port]`")
            })?;
            allowed.push((p.secure, p.host.to_ascii_lowercase(), p.port));
        }
        Ok(WsOriginPolicy {
            any: c.any,
            allowed,
        })
    }
}

/// Whether the request asks for a WebSocket upgrade (`Upgrade` contains `websocket`).
/// How a request asks to open a WebSocket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Handshake {
    /// HTTP/1.1 `Upgrade: websocket` (RFC 6455).
    Http1,
    /// HTTP/2 Extended CONNECT with `:protocol = websocket` (RFC 8441).
    #[cfg_attr(not(feature = "http2"), allow(dead_code))]
    H2,
}

/// Classifies a request as a WebSocket handshake. This is the single rule used for both
/// session admission and the origin check, so neither can be bypassed by switching between
/// HTTP/1.1 and HTTP/2.
pub(crate) fn websocket_handshake(
    method: &http::Method,
    version: http::Version,
    headers: &HeaderMap,
    extensions: &http::Extensions,
) -> Option<Handshake> {
    #[cfg(feature = "http2")]
    if version == http::Version::HTTP_2
        && method == http::Method::CONNECT
        && extensions
            .get::<hyper::ext::Protocol>()
            .is_some_and(|p| p.as_str().eq_ignore_ascii_case("websocket"))
    {
        return Some(Handshake::H2);
    }
    #[cfg(not(feature = "http2"))]
    let _ = (method, version, extensions);
    is_websocket_handshake(headers).then_some(Handshake::Http1)
}

/// Whether the request is an HTTP/2 Extended CONNECT with a WebSocket protocol.
pub(crate) fn is_h2_websocket_handshake(parts: &http::request::Parts) -> bool {
    websocket_handshake(
        &parts.method,
        parts.version,
        &parts.headers,
        &parts.extensions,
    ) == Some(Handshake::H2)
}

/// Whether the headers carry an HTTP/1.1 WebSocket upgrade (`Upgrade` lists `websocket`).
pub(crate) fn is_websocket_handshake(headers: &HeaderMap) -> bool {
    headers
        .get_all(UPGRADE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
}

/// Whether a WebSocket handshake with these headers may proceed.
pub(crate) fn origin_allowed(
    headers: &HeaderMap,
    uri: &http::Uri,
    cors: Option<&CorsRuntime>,
    policy: &WsOriginPolicy,
    proxies: &TrustedProxies,
    peer: Option<std::net::IpAddr>,
) -> bool {
    if policy.any {
        return true;
    }
    let mut origins = headers.get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return true;
    };
    if origins.next().is_some() {
        return false;
    }
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    if cors.is_some_and(|c| c.allows_explicit(origin)) {
        return true;
    }
    let Some(origin) = parse_origin(origin) else {
        return false;
    };
    if policy.allowed.iter().any(|(secure, host, port)| {
        *secure == origin.secure && *port == origin.port && host.eq_ignore_ascii_case(origin.host)
    }) {
        return true;
    }
    let authority = match uri.authority() {
        Some(a) => Some(a.as_str()),
        None => {
            let mut hosts = headers.get_all(HOST).iter();
            match (hosts.next(), hosts.next()) {
                (Some(h), None) => h.to_str().ok(),
                _ => None,
            }
        }
    };
    if let Some((host, port)) = authority.and_then(split_host_port)
        && host.eq_ignore_ascii_case(origin.host)
        && port.unwrap_or(origin.default_port) == origin.port
    {
        return true;
    }
    // The public host reported by a trusted reverse proxy.
    if let Some(peer) = peer
        && proxies.contains(peer)
        && let Some(fwd) = forwarded_target(headers)
    {
        let default_port = match fwd.secure {
            Some(secure) if secure != origin.secure => return false,
            Some(true) => 443,
            Some(false) => 80,
            None => origin.default_port,
        };
        return fwd.host.eq_ignore_ascii_case(origin.host)
            && fwd.port.unwrap_or(default_port) == origin.port;
    }
    false
}

/// Public host (and scheme, if reported) forwarded by a reverse proxy.
struct ForwardedTarget<'a> {
    host: &'a str,
    port: Option<u16>,
    secure: Option<bool>,
}

/// The single header line `name`, if it appears exactly once and is visible ASCII.
fn single_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut all = headers.get_all(name).iter();
    match (all.next(), all.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => v.to_str().map(Some).map_err(|_| ()),
        _ => Err(()),
    }
}

fn proto_secure(p: &str) -> Option<bool> {
    if p.eq_ignore_ascii_case("https") {
        Some(true)
    } else if p.eq_ignore_ascii_case("http") {
        Some(false)
    } else {
        None
    }
}

/// Reads RFC 7239 `Forwarded` (preferred) or `X-Forwarded-Host`/`-Proto`. Anything
/// ambiguous or malformed yields `None`.
fn forwarded_target(headers: &HeaderMap) -> Option<ForwardedTarget<'_>> {
    let mut host = None;
    let mut proto = None;
    if let Some(fwd) = single_str(headers, "forwarded").ok()? {
        if fwd.contains(',') {
            return None;
        }
        for pair in fwd.split(';') {
            let (k, v) = pair.trim().split_once('=')?;
            let v = match v.strip_prefix('"') {
                Some(q) => q.strip_suffix('"').filter(|q| !q.contains(['"', '\\']))?,
                None => v,
            };
            let slot = if k.eq_ignore_ascii_case("host") {
                &mut host
            } else if k.eq_ignore_ascii_case("proto") {
                &mut proto
            } else {
                continue;
            };
            if slot.replace(v).is_some() {
                return None;
            }
        }
    } else {
        host = single_str(headers, "x-forwarded-host").ok()?;
        proto = single_str(headers, "x-forwarded-proto").ok()?;
    }
    let (host, port) = split_host_port(host?.trim())?;
    let secure = match proto {
        Some(p) => Some(proto_secure(p.trim())?),
        None => None,
    };
    Some(ForwardedTarget { host, port, secure })
}

struct Origin<'a> {
    secure: bool,
    host: &'a str,
    port: u16,
    default_port: u16,
}

/// Parses a serialised tuple origin `scheme "://" host [ ":" port ]` (RFC 6454) with an
/// `http` or `https` scheme.
fn parse_origin(s: &str) -> Option<Origin<'_>> {
    let (scheme, rest) = s.split_once("://")?;
    let default_port = if scheme.eq_ignore_ascii_case("http") {
        80
    } else if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        return None;
    };
    let (host, port) = split_host_port(rest)?;
    Some(Origin {
        secure: default_port == 443,
        host,
        port: port.unwrap_or(default_port),
        default_port,
    })
}

/// Splits `host[:port]` (including `[v6]:port`). Rejects paths, userinfo, empty hosts,
/// whitespace and non-numeric ports.
fn split_host_port(s: &str) -> Option<(&str, Option<u16>)> {
    if s.is_empty()
        || s.bytes()
            .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\') || b <= b' ' || b >= 0x7f)
    {
        return None;
    }
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &s[..end + 2];
        match &rest[end + 1..] {
            "" => (host, None),
            p => (host, Some(p.strip_prefix(':')?)),
        }
    } else {
        match s.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    if host.is_empty() || (host.contains(['[', ']']) && !host.starts_with('[')) {
        return None;
    }
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            Some(p.parse::<u16>().ok()?)
        }
        Some(_) => return None,
    };
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(*k, v.parse().unwrap());
        }
        m
    }

    fn allowed(pairs: &[(&'static str, &str)]) -> bool {
        origin_allowed(
            &h(pairs),
            &http::Uri::from_static("/ws"),
            None,
            &WsOriginPolicy::default(),
            &TrustedProxies::default(),
            None,
        )
    }

    #[test]
    fn detects_upgrade_token() {
        assert!(is_websocket_handshake(&h(&[("upgrade", "WebSocket")])));
        assert!(is_websocket_handshake(&h(&[("upgrade", "h2c, websocket")])));
        assert!(!is_websocket_handshake(&h(&[("upgrade", "h2c")])));
        assert!(!is_websocket_handshake(&HeaderMap::new()));
    }

    #[test]
    fn same_origin_rules() {
        assert!(allowed(&[("host", "a.test:8080")]));
        assert!(allowed(&[
            ("host", "a.test:8080"),
            ("origin", "http://a.test:8080")
        ]));
        assert!(allowed(&[("host", "A.Test"), ("origin", "https://a.test")]));
        assert!(allowed(&[
            ("host", "a.test"),
            ("origin", "http://a.test:80")
        ]));
        assert!(allowed(&[
            ("host", "[::1]:9"),
            ("origin", "http://[::1]:9")
        ]));
        assert!(!allowed(&[
            ("host", "a.test"),
            ("origin", "http://a.test:8080")
        ]));
        assert!(!allowed(&[
            ("host", "a.test:443"),
            ("origin", "http://a.test")
        ]));
        assert!(!allowed(&[("host", "a.test"), ("origin", "http://b.test")]));
        assert!(!allowed(&[("host", "a.test"), ("origin", "null")]));
        assert!(!allowed(&[
            ("host", "a.test"),
            ("origin", "http://a.test/")
        ]));
        assert!(!allowed(&[
            ("host", "a.test"),
            ("origin", "http://u@a.test")
        ]));
        assert!(!allowed(&[("host", "a.test"), ("origin", "ws://a.test")]));
        assert!(!allowed(&[
            ("host", "a.test"),
            ("origin", "http://a.test:")
        ]));
        assert!(!allowed(&[
            ("host", "a.test"),
            ("origin", "http://a.test:99999")
        ]));
        assert!(!allowed(&[("origin", "http://a.test")]), "no Host");
        assert!(!allowed(&[
            ("host", "a.test"),
            ("host", "a.test"),
            ("origin", "http://a.test")
        ]));
        assert!(!allowed(&[
            ("host", "a.test"),
            ("origin", "http://a.test"),
            ("origin", "http://a.test")
        ]));
    }

    #[test]
    fn uri_authority_takes_precedence() {
        let m = h(&[("host", "evil.test"), ("origin", "https://a.test")]);
        let uri = http::Uri::from_static("https://a.test/ws");
        assert!(origin_allowed(
            &m,
            &uri,
            None,
            &WsOriginPolicy::default(),
            &TrustedProxies::default(),
            None
        ));
    }
}
