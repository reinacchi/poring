//! Origin validation for WebSocket handshakes (cross-site WebSocket hijacking defence).
//!
//! A browser WebSocket handshake is a `GET`, so the CORS check (which only rejects unsafe
//! methods) and CSRF protection (unsafe methods only) never stop it, while the browser
//! still attaches cookies. Any request carrying `Upgrade: websocket` is therefore checked
//! here, before authentication and before the handler can answer `101`:
//!
//! * no `Origin` header: allowed. Non-browser clients do not send one and can forge it
//!   anyway. Origin is a browser-side defence, **not** authentication.
//! * exactly one `Origin` that is same-origin with the request (`Host`, or the URI
//!   authority for HTTP/2), listed explicitly in the app's CORS origins, or listed in
//!   [`WsOrigins::allow`]: allowed.
//! * anything else is rejected with 403: another origin, `null`, a malformed value,
//!   several `Origin` headers, or an origin only matched by the CORS wildcard `*`.
//!   The `Origin` value is validated *before* any allowlist is consulted, so listing
//!   `"null"` (or any non-origin string) in the HTTP CORS configuration never admits a
//!   WebSocket handshake. Opaque origins cannot be allowed except through
//!   [`WsOrigins::any`], which `build()` refuses for cookie-capable authenticators.
//!
//! Same-origin comparison is ASCII case-insensitive on scheme and host, and an origin
//! without a port uses its scheme's default (80 / 443). The scheme must match too whenever
//! the endpoint's own scheme is known:
//!
//! * the connection uses Poring's native TLS (`tls-rustls`): the endpoint is `https`/`wss`.
//! * a trusted reverse proxy reports the public scheme (`Forwarded: proto=` or
//!   `X-Forwarded-Proto`): that scheme.
//! * otherwise an HTTP/2 request's `:scheme`.
//!
//! An `http://` origin is therefore never accepted implicitly for an HTTPS/WSS endpoint, and
//! a request `Host` without a port is compared with the endpoint scheme's default port. When
//! the scheme cannot be known (plain HTTP/1.1 with no trusted proxy report, for example
//! behind a TLS-terminating proxy that is not listed in `trusted_proxies`), either scheme
//! with the matching port is accepted, as a plain-HTTP deployment needs. Production
//! deployments behind TLS should configure `trusted_proxies` (so the scheme is known) and
//! may use [`WsOrigins::https_only`], which refuses every `http://` origin.
//!
//! Behind a reverse proxy that rewrites `Host`, configure the proxy in `trusted_proxies`.
//! When the TCP peer is trusted, the public host it reports is an additional same-origin
//! target: RFC 7239 `Forwarded` (`host=` and `proto=`) if present, otherwise
//! `X-Forwarded-Host` and `X-Forwarded-Proto`. A reported proto (with or without a host)
//! is the endpoint's scheme: the origin's scheme must equal it, and it sets the default
//! port. Only one unambiguous value is believed:
//! several header lines, comma-separated chains, unknown protos or malformed hosts are
//! ignored and the check falls back to `Host`. From untrusted peers these headers are
//! always ignored. Alternatively list the public origin with [`WsOrigins::allow`].
//!
//! [`WsOrigins::any`] disables the check. `build()` refuses it when the authenticator
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
    https_only: bool,
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
            https_only: false,
        }
    }

    /// Refuses every `http://` origin, whatever the endpoint's scheme, including same-host
    /// ones and entries of the app's CORS origins. Use it for public HTTPS/WSS deployments,
    /// in particular behind a TLS-terminating proxy whose scheme report Poring cannot see.
    /// `build()` rejects it together with an `http://` entry in [`allow`](Self::allow) and
    /// with [`WsOrigins::any`].
    pub fn https_only(mut self) -> Self {
        self.https_only = true;
        self
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
    https_only: bool,
    /// (https, lower-case host, effective port)
    allowed: Vec<(bool, String, u16)>,
}

impl WsOriginPolicy {
    pub(crate) fn from_config(c: &WsOrigins, auth_uses_cookies: bool) -> Result<Self, String> {
        if c.any && auth_uses_cookies {
            return Err("ws_origins: `WsOrigins::any()` cannot be combined with a cookie-capable authenticator (cross-site WebSocket hijacking); list                         the allowed origins with `WsOrigins::new().allow([..])`"
                .into());
        }
        if c.any && c.https_only {
            return Err(
                "ws_origins: `https_only()` cannot be combined with `WsOrigins::any()`".into(),
            );
        }
        let mut allowed = Vec::with_capacity(c.origins.len());
        for o in &c.origins {
            let p = parse_origin(o).ok_or_else(|| {
                format!("ws_origins: `{o}` is not an origin like `https://host[:port]`")
            })?;
            if c.https_only && !p.secure {
                return Err(format!(
                    "ws_origins: `{o}` is an `http://` origin, but `https_only()` refuses them"
                ));
            }
            allowed.push((p.secure, p.host.to_ascii_lowercase(), p.port));
        }
        Ok(WsOriginPolicy {
            any: c.any,
            https_only: c.https_only,
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

/// Marker inserted by the server into WebSocket handshake requests that arrived over
/// Poring's native TLS: the endpoint is `https`/`wss`.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(feature = "websocket"), allow(dead_code))]
pub(crate) struct SecureTransport;

/// Whether a WebSocket handshake with these headers may proceed. `tls` is whether the
/// request arrived over Poring's native TLS.
pub(crate) fn origin_allowed(
    headers: &HeaderMap,
    uri: &http::Uri,
    cors: Option<&CorsRuntime>,
    policy: &WsOriginPolicy,
    proxies: &TrustedProxies,
    peer: Option<std::net::IpAddr>,
    tls: bool,
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
    // Validate before consulting any allowlist: an opaque (`null`) or malformed origin is
    // never allowed, even if the HTTP CORS configuration lists it verbatim. A sandboxed
    // iframe or a `data:` page sends `Origin: null` and would otherwise ride the user's
    // cookies.
    let raw = origin;
    let Some(origin) = parse_origin(raw) else {
        return false;
    };
    if policy.https_only && !origin.secure {
        return false;
    }
    if cors.is_some_and(|c| c.allows_explicit(raw)) {
        return true;
    }
    if policy.allowed.iter().any(|(secure, host, port)| {
        *secure == origin.secure && *port == origin.port && host.eq_ignore_ascii_case(origin.host)
    }) {
        return true;
    }
    // The public target reported by a trusted reverse proxy, if any.
    let forwarded = match peer {
        Some(peer) if proxies.contains(peer) => forwarded_target(headers),
        _ => None,
    };
    // The endpoint's scheme, when it can be known: a trusted proxy's report describes the
    // public side, then native TLS, then HTTP/2's `:scheme`.
    let endpoint_secure = forwarded
        .as_ref()
        .and_then(|f| f.secure)
        .or(tls.then_some(true))
        .or_else(|| uri.scheme_str().and_then(proto_secure));
    if endpoint_secure.is_some_and(|secure| secure != origin.secure) {
        return false;
    }
    let default_port = match endpoint_secure {
        Some(true) => 443,
        Some(false) => 80,
        None => origin.default_port,
    };
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
        && port.unwrap_or(default_port) == origin.port
    {
        return true;
    }
    // The public host reported by a trusted reverse proxy.
    if let Some((host, port)) = forwarded.and_then(|f| f.host) {
        return host.eq_ignore_ascii_case(origin.host)
            && port.unwrap_or(default_port) == origin.port;
    }
    false
}

/// Public host and/or scheme forwarded by a reverse proxy (at least one is present).
struct ForwardedTarget<'a> {
    host: Option<(&'a str, Option<u16>)>,
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
    let host = match host {
        Some(h) => Some(split_host_port(h.trim())?),
        None => None,
    };
    let secure = match proto {
        Some(p) => Some(proto_secure(p.trim())?),
        None => None,
    };
    if host.is_none() && secure.is_none() {
        return None;
    }
    Some(ForwardedTarget { host, secure })
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
    // A serialised origin carries an ASCII (punycode) host: a DNS name or a bracketed IPv6
    // literal. Anything else (percent escapes, `_`, empty labels) cannot be same-site with
    // a browser origin and is rejected rather than canonicalised.
    let ok_host = match host.strip_prefix('[') {
        Some(v6) => v6
            .strip_suffix(']')
            .is_some_and(|a| a.parse::<std::net::Ipv6Addr>().is_ok()),
        None => host
            .split('.')
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
    };
    if !ok_host {
        return None;
    }
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
            false,
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
            ("origin", "http://a.test.")
        ]));
        assert!(!allowed(&[
            ("host", "a_b.test"),
            ("origin", "http://a_b.test")
        ]));
        assert!(!allowed(&[
            ("host", "a.test"),
            ("origin", "http://a..test")
        ]));
        assert!(!allowed(&[("host", "[::1]"), ("origin", "http://[zz]")]));
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
            None,
            false
        ));
    }

    #[test]
    fn cors_allowlist_never_admits_opaque_or_malformed_origins() {
        let cors = CorsRuntime::from_cors(&crate::policy::Cors::new().origins([
            "null",
            "not an origin",
            "https://ok.test",
        ]));
        let check = |origin: &str| {
            origin_allowed(
                &h(&[("host", "a.test"), ("origin", origin)]),
                &http::Uri::from_static("/ws"),
                Some(&cors),
                &WsOriginPolicy::default(),
                &TrustedProxies::default(),
                None,
                false,
            )
        };
        assert!(!check("null"));
        assert!(!check("not an origin"));
        assert!(check("https://ok.test"));
        assert!(!check("https://other.test"));
    }

    fn check_with(
        pairs: &[(&'static str, &str)],
        uri: &'static str,
        policy: &WsOriginPolicy,
        proxies: &TrustedProxies,
        peer: Option<&str>,
        tls: bool,
    ) -> bool {
        origin_allowed(
            &h(pairs),
            &http::Uri::from_static(uri),
            None,
            policy,
            proxies,
            peer.map(|p| p.parse().unwrap()),
            tls,
        )
    }

    #[test]
    fn native_tls_endpoints_refuse_http_origins() {
        let p = WsOriginPolicy::default();
        let t = TrustedProxies::default();
        let tls = |host: &str, origin: &str| {
            check_with(
                &[("host", host), ("origin", origin)],
                "/ws",
                &p,
                &t,
                None,
                true,
            )
        };
        assert!(tls("a.test", "https://a.test"));
        assert!(tls("a.test:8443", "https://a.test:8443"));
        // A `Host` without a port must not accept `http://a.test` (port 80) for a TLS
        // endpoint, or a network attacker's plain-HTTP page could ride the user's cookies.
        assert!(!tls("a.test", "http://a.test"));
        assert!(!tls("a.test:8443", "http://a.test:8443"));
        assert!(!tls("a.test", "http://a.test:443"));
        // Plain endpoints with an unknown public scheme keep accepting both schemes.
        let plain = |host: &str, origin: &str| {
            check_with(
                &[("host", host), ("origin", origin)],
                "/ws",
                &p,
                &t,
                None,
                false,
            )
        };
        assert!(plain("a.test:3000", "http://a.test:3000"));
        assert!(plain("a.test", "http://a.test"));
        assert!(plain("a.test", "https://a.test"));
    }

    #[test]
    fn http2_scheme_is_the_endpoint_scheme() {
        let p = WsOriginPolicy::default();
        let t = TrustedProxies::default();
        let m = [("origin", "http://a.test")];
        assert!(!check_with(&m, "https://a.test/ws", &p, &t, None, false));
        assert!(check_with(&m, "http://a.test/ws", &p, &t, None, false));
        let m = [("origin", "https://a.test")];
        assert!(check_with(&m, "https://a.test/ws", &p, &t, None, false));
        assert!(!check_with(&m, "http://a.test/ws", &p, &t, None, false));
    }

    #[test]
    fn trusted_proxy_scheme_is_enforced_on_the_host_path() {
        let p = WsOriginPolicy::default();
        let proxies = TrustedProxies::parse(["10.0.0.1"]).unwrap();
        let fwd_https = [
            ("host", "app.test"),
            ("x-forwarded-proto", "https"),
            ("origin", "http://app.test"),
        ];
        // From the trusted proxy the endpoint is HTTPS: the http origin is refused even
        // though `Host` matches.
        assert!(!check_with(
            &fwd_https,
            "/ws",
            &p,
            &proxies,
            Some("10.0.0.1"),
            false
        ));
        let ok = [
            ("host", "app.test"),
            ("x-forwarded-proto", "https"),
            ("origin", "https://app.test"),
        ];
        assert!(check_with(
            &ok,
            "/ws",
            &p,
            &proxies,
            Some("10.0.0.1"),
            false
        ));
        // An untrusted peer's report is ignored: unknown scheme, both accepted.
        assert!(check_with(
            &fwd_https,
            "/ws",
            &p,
            &proxies,
            Some("192.0.2.9"),
            false
        ));
        let fwd_http = [
            ("host", "app.test"),
            ("x-forwarded-proto", "http"),
            ("origin", "https://app.test"),
        ];
        assert!(!check_with(
            &fwd_http,
            "/ws",
            &p,
            &proxies,
            Some("10.0.0.1"),
            false
        ));
        // `Forwarded: proto=https` on a TLS connection from the proxy.
        let rfc = [
            ("host", "internal:8443"),
            ("forwarded", "host=app.test;proto=https"),
            ("origin", "https://app.test"),
        ];
        assert!(check_with(
            &rfc,
            "/ws",
            &p,
            &proxies,
            Some("10.0.0.1"),
            true
        ));
    }

    #[test]
    fn https_only_refuses_every_http_origin() {
        let strict = WsOriginPolicy::from_config(&WsOrigins::new().https_only(), false).unwrap();
        let t = TrustedProxies::default();
        let plain = |origin: &str| {
            check_with(
                &[("host", "a.test:3000"), ("origin", origin)],
                "/ws",
                &strict,
                &t,
                None,
                false,
            )
        };
        assert!(!plain("http://a.test:3000"));
        assert!(plain("https://a.test:3000"));
        // Not even an explicit CORS entry admits it.
        let cors = CorsRuntime::from_cors(&crate::policy::Cors::new().origins(["http://b.test"]));
        assert!(!origin_allowed(
            &h(&[("host", "a.test"), ("origin", "http://b.test")]),
            &http::Uri::from_static("/ws"),
            Some(&cors),
            &strict,
            &t,
            None,
            false,
        ));
        // Configuration errors.
        assert!(
            WsOriginPolicy::from_config(
                &WsOrigins::new().https_only().allow(["http://b.test"]),
                false
            )
            .is_err()
        );
        assert!(WsOriginPolicy::from_config(&WsOrigins::any().https_only(), false).is_err());
    }

    #[test]
    fn explicit_allow_entries_are_scheme_exact() {
        let p = WsOriginPolicy::from_config(&WsOrigins::new().allow(["https://b.test"]), false)
            .unwrap();
        let t = TrustedProxies::default();
        let m = |o: &str| {
            check_with(
                &[("host", "a.test"), ("origin", o)],
                "/ws",
                &p,
                &t,
                None,
                false,
            )
        };
        assert!(m("https://b.test"));
        assert!(m("https://B.test:443"));
        assert!(!m("http://b.test"));
        assert!(!m("https://b.test:8443"));
    }
}

/// Property tests: the origin and forwarding parsers never panic on hostile input, and the
/// scheme invariants hold for every header combination.
#[cfg(test)]
mod prop_tests {
    use super::*;
    use crate::policy::{TrustedProxies, WsOrigins};
    use proptest::prelude::*;

    /// Header-ish strings: mostly printable ASCII with origin/forwarding punctuation,
    /// sometimes arbitrary bytes.
    fn header_text() -> impl Strategy<Value = String> {
        prop_oneof![
            4 => "[a-zA-Z0-9.:/\\[\\]@?#;,= _\"-]{0,40}",
            2 => "(https?|wss?|ftp|null)://[a-z0-9.-]{0,12}(:[0-9]{0,6})?(/[a-z]{0,4})?",
            1 => "for=[0-9.]{0,15};proto=(https?|x);host=[a-z.:0-9]{0,12}",
            1 => prop::collection::vec(any::<u8>(), 0..40)
                .prop_map(|b| String::from_utf8_lossy(&b).into_owned()),
        ]
    }

    fn headers(pairs: &[(&'static str, String)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            if let Ok(v) = http::HeaderValue::from_str(v) {
                h.append(*k, v);
            }
        }
        h
    }

    proptest! {
        #[test]
        fn parsers_never_panic(s in header_text()) {
            let _ = parse_origin(&s);
            if let Some((host, _)) = split_host_port(&s) {
                prop_assert!(!host.is_empty());
            }
            let _ = forwarded_target(&headers(&[("forwarded", s.clone())]));
            let _ = forwarded_target(&headers(&[
                ("x-forwarded-host", s.clone()),
                ("x-forwarded-proto", s.clone()),
            ]));
        }

        #[test]
        fn parsed_origins_round_trip_their_port(host in "[a-z][a-z0-9-]{0,10}(\\.[a-z]{2,5})?",
                                               port in proptest::option::of(any::<u16>()),
                                               secure in any::<bool>()) {
            let scheme = if secure { "https" } else { "http" };
            let s = match port {
                Some(p) => format!("{scheme}://{host}:{p}"),
                None => format!("{scheme}://{host}"),
            };
            let o = parse_origin(&s).expect("valid origin");
            prop_assert_eq!(o.secure, secure);
            prop_assert_eq!(o.host, host.as_str());
            prop_assert_eq!(o.port, port.unwrap_or(if secure { 443 } else { 80 }));
        }

        /// Whatever the request says about itself, an `http://` origin is never accepted
        /// by an endpoint known to be secure (native TLS) without an explicit entry, and
        /// never by an `https_only` policy at all.
        #[test]
        fn insecure_origins_never_reach_secure_endpoints(
            origin_host in "[a-z]{1,8}(\\.test)?(:[0-9]{1,5})?",
            host in header_text(),
            fwd in header_text(),
            xfh in header_text(),
            xfp in header_text(),
            uri_secure in proptest::option::of(any::<bool>()),
            trusted in any::<bool>(),
        ) {
            let h = headers(&[
                ("origin", format!("http://{origin_host}")),
                ("host", host),
                ("forwarded", fwd),
                ("x-forwarded-host", xfh),
                ("x-forwarded-proto", xfp),
            ]);
            let uri: http::Uri = match uri_secure {
                Some(true) => "https://a.test/ws".parse().unwrap(),
                Some(false) => "http://a.test/ws".parse().unwrap(),
                None => "/ws".parse().unwrap(),
            };
            let proxies = if trusted {
                TrustedProxies::parse(["127.0.0.1"]).unwrap()
            } else {
                TrustedProxies::default()
            };
            let peer = Some("127.0.0.1".parse().unwrap());
            let default = WsOriginPolicy::default();
            // Native TLS with no trusted proxy: the endpoint is https, full stop.
            prop_assert!(!origin_allowed(&h, &uri, None, &default, &TrustedProxies::default(), peer, true));
            let strict = WsOriginPolicy::from_config(&WsOrigins::new().https_only(), false).unwrap();
            for tls in [false, true] {
                prop_assert!(!origin_allowed(&h, &uri, None, &strict, &proxies, peer, tls));
                // Must not panic with any combination.
                let _ = origin_allowed(&h, &uri, None, &default, &proxies, peer, tls);
            }
        }
    }
}
