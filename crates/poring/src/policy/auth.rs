//! The trusted authentication facility.

use std::future::Future;
use std::net::SocketAddr;

use http::{HeaderMap, Method, Uri};

/// How the principal presented its credentials. Drives CSRF enforcement: only
/// [`Credential::Cookie`] identities are subject to CSRF checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credential {
    /// `Authorization: Bearer ...`
    Bearer,
    /// A session cookie (ambient credential: CSRF-relevant).
    Cookie,
    /// An API key header.
    ApiKey,
    /// Anything else (mTLS identity, signed request, ...).
    Other,
}

/// An authenticated principal produced by the app's [`Authenticator`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Stable subject identifier.
    pub subject: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Granted roles.
    pub roles: Vec<String>,
    /// Credential type.
    pub credential: Credential,
}

impl Identity {
    /// Creates an identity with no scopes/roles.
    pub fn new(subject: impl Into<String>, credential: Credential) -> Self {
        Identity {
            subject: subject.into(),
            scopes: Vec::new(),
            roles: Vec::new(),
            credential,
        }
    }

    /// Builder: add scopes.
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes.extend(scopes.into_iter().map(Into::into));
        self
    }

    /// Builder: add roles.
    pub fn with_roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.roles.extend(roles.into_iter().map(Into::into));
        self
    }

    /// Whether the identity holds `scope`.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Whether the identity holds `role`.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|s| s == role)
    }
}

/// The request head an authenticator may inspect. The body is never available here, so
/// authentication always happens before any body bytes are read.
#[derive(Debug)]
pub struct AuthRequest<'a> {
    /// Method.
    pub method: &'a Method,
    /// URI.
    pub uri: &'a Uri,
    /// Headers.
    pub headers: &'a HeaderMap,
    /// Peer address.
    pub peer: Option<SocketAddr>,
}

impl AuthRequest<'_> {
    /// The bearer token from `Authorization: Bearer <token>`, if present and valid UTF-8.
    pub fn bearer_token(&self) -> Option<&str> {
        let v = self
            .headers
            .get(http::header::AUTHORIZATION)?
            .to_str()
            .ok()?;
        let (scheme, token) = v.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() {
            Some(token.trim())
        } else {
            None
        }
    }

    /// The value of cookie `name`, if present.
    pub fn cookie(&self, name: &str) -> Option<&str> {
        crate::extract::cookie::find_cookie(self.headers, name)
    }
}

/// Authentication failure.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Credentials were present but invalid (401).
    #[error("invalid credentials")]
    Invalid,
    /// The backing identity service failed (503). The message is logged, not sent.
    #[error("authentication backend unavailable: {0}")]
    Unavailable(String),
}

/// The app's trusted authentication facility.
///
/// Declared once per app (`auth: MyAuthenticator` in `poring_app!`) and supplied at
/// startup through the typed builder (`.authenticator(..)`). An app that declares an
/// authenticator cannot be started without one (compile error).
pub trait Authenticator: Send + Sync + 'static {
    /// Whether this authenticator may accept ambient cookie credentials. When `true`,
    /// unsafe-method routes enforce CSRF protection by default.
    const USES_COOKIES: bool = false;

    /// Authenticates the request head. `Ok(None)` means "no credentials" (401).
    fn authenticate(
        &self,
        req: &AuthRequest<'_>,
    ) -> impl Future<Output = Result<Option<Identity>, AuthError>> + Send;
}

/// Placeholder authenticator for apps that declare none. Never invoked: routes requiring
/// authentication in such apps are rejected at compile time.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoAuth;

impl Authenticator for NoAuth {
    async fn authenticate(&self, _req: &AuthRequest<'_>) -> Result<Option<Identity>, AuthError> {
        Ok(None)
    }
}
