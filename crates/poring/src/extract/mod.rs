//! Typed request extractors.
//!
//! An extractor implements [`FromRequest<S>`] (how to extract) and [`ExtractorMeta`]
//! (static facts used by macros at compile time: kind, whether it reads the body,
//! whether it validates, whether it needs an authenticated principal). Because
//! `ExtractorMeta` is not generic over the state type, route macros can evaluate it in
//! `const` assertions with precise source spans (e.g. "only the last argument may read
//! the body").

use std::future::Future;

use bytes::Bytes;

use crate::ctx::{Ctx, RequestId};
use crate::descriptor::{ExtractorKind, SchemaFn};
use crate::error::{ApiError, rejection};
use crate::policy::Identity;
use crate::response::IntoResponse;

pub mod cookie;
pub mod form;
pub mod header;
#[cfg(feature = "json")]
pub mod json;
#[cfg(feature = "multipart")]
pub mod multipart;
pub mod path;
pub mod query;
pub mod state;

pub use cookie::{Cookie, Cookies};
pub use form::Form;
pub use header::Header;
pub use path::Path;
pub use query::Query;
pub use state::{FromRef, State};

/// Static facts about an extractor, available in `const` contexts.
pub trait ExtractorMeta {
    /// Extractor kind.
    const KIND: ExtractorKind = ExtractorKind::Custom;
    /// Reads the request body (only one such extractor per handler, and it must be last).
    const CONSUMES_BODY: bool = false;
    /// Runs declarative validation.
    const VALIDATES: bool = false;
    /// Requires an authenticated principal (route must be `auth = required`).
    const USES_PRINCIPAL: bool = false;
    /// Schema of the extracted data (for OpenAPI).
    const SCHEMA: Option<SchemaFn> = None;
}

/// Extracts a value from the request.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be used as a Poring handler argument for app state `{S}`",
    label = "not an extractor for this app",
    note = "built-in extractors: Path<T>, Query<T>, Json<T>, Form<T>, Header<T>, Cookie<T>, State<T>, Principal<T>, Extension<T>, Bytes, String, Method, Uri, HeaderMap, RequestId; `State<T>` requires the app state to provide `T` (see `FromRef`)"
)]
pub trait FromRequest<S>: ExtractorMeta + Sized {
    /// Rejection returned when extraction fails.
    type Rejection: IntoResponse;

    /// Performs extraction.
    fn from_request(
        cx: &mut Ctx<'_, S>,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send;
}

/// The authenticated principal, converted to `T`.
///
/// Using `Principal<_>` on a route whose effective policy is not `auth = required` is a
/// compile-time error (whole-app check in `poring_app!`).
#[derive(Clone, Debug)]
pub struct Principal<T>(pub T);

/// Conversion from the authenticated [`Identity`] (may reject with 403).
pub trait FromIdentity: Sized {
    /// Converts, or rejects (typically `403`).
    fn from_identity(id: &Identity) -> Result<Self, ApiError>;
}

/// Any authenticated principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticated(pub Identity);

impl std::ops::Deref for Authenticated {
    type Target = Identity;
    fn deref(&self) -> &Identity {
        &self.0
    }
}

impl FromIdentity for Authenticated {
    fn from_identity(id: &Identity) -> Result<Self, ApiError> {
        Ok(Authenticated(id.clone()))
    }
}

impl FromIdentity for Identity {
    fn from_identity(id: &Identity) -> Result<Self, ApiError> {
        Ok(id.clone())
    }
}

impl<T: FromIdentity> ExtractorMeta for Principal<T> {
    const KIND: ExtractorKind = ExtractorKind::Principal;
    const USES_PRINCIPAL: bool = true;
}

impl<S: Sync, T: FromIdentity + Send> FromRequest<S> for Principal<T> {
    type Rejection = ApiError;
    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        match &cx.identity {
            Some(id) => T::from_identity(id).map(Principal),
            // Unreachable for verified static apps: the auth stage ran before extraction.
            None => Err(rejection::internal("principal_without_auth")),
        }
    }
}

/// A typed value inserted into request extensions by a hook.
#[derive(Clone, Debug)]
pub struct Extension<T>(pub T);

impl<T> ExtractorMeta for Extension<T> {
    const KIND: ExtractorKind = ExtractorKind::Extension;
}

impl<S: Sync, T: Clone + Send + Sync + 'static> FromRequest<S> for Extension<T> {
    type Rejection = ApiError;
    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        cx.parts
            .extensions
            .get::<T>()
            .cloned()
            .map(Extension)
            .ok_or_else(|| rejection::internal("missing_extension"))
    }
}

macro_rules! meta_request {
    ($($t:ty => $e:expr),*) => {$(
        impl ExtractorMeta for $t { const KIND: ExtractorKind = ExtractorKind::Request; }
        impl<S: Sync> FromRequest<S> for $t {
            type Rejection = std::convert::Infallible;
            async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, std::convert::Infallible> {
                let f: fn(&mut Ctx<'_, S>) -> $t = $e;
                Ok(f(cx))
            }
        }
    )*};
}

meta_request! {
    http::Method => |cx| cx.parts.method.clone(),
    http::Uri => |cx| cx.parts.uri.clone(),
    http::HeaderMap => |cx| cx.parts.headers.clone(),
    RequestId => |cx| cx.request_id.clone()
}

impl IntoResponse for std::convert::Infallible {
    fn into_response(self) -> crate::Response {
        match self {}
    }
}

impl ExtractorMeta for crate::policy::RateLimitStatus {
    const KIND: ExtractorKind = ExtractorKind::Request;
}

/// The rate-limit status recorded when the request was admitted (no second token is
/// taken). Use `Option<RateLimitStatus>` on routes that might not be rate limited.
impl<S: Sync> FromRequest<S> for crate::policy::RateLimitStatus {
    type Rejection = ApiError;
    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        cx.rate_limit()
            .copied()
            .ok_or_else(|| rejection::internal("route_not_rate_limited"))
    }
}

impl ExtractorMeta for Bytes {
    const KIND: ExtractorKind = ExtractorKind::Body;
    const CONSUMES_BODY: bool = true;
}

impl<S: Sync> FromRequest<S> for Bytes {
    type Rejection = ApiError;
    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        read_body(cx).await
    }
}

impl ExtractorMeta for String {
    const KIND: ExtractorKind = ExtractorKind::Body;
    const CONSUMES_BODY: bool = true;
}

impl<S: Sync> FromRequest<S> for String {
    type Rejection = ApiError;
    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        let b = read_body(cx).await?;
        String::from_utf8(b.to_vec())
            .map_err(|_| rejection::bad_request("invalid_utf8", "request body is not valid UTF-8"))
    }
}

/// Reads the whole body under the route's effective limit.
pub async fn read_body<S>(cx: &mut Ctx<'_, S>) -> Result<Bytes, ApiError> {
    let limit = cx.body_limit();
    let Some(body) = cx.take_body() else {
        return Err(rejection::internal("body_already_taken"));
    };
    crate::body::collect_limited(body, limit)
        .await
        .map_err(|e| match e {
            crate::body::CollectError::TooLarge { limit } => rejection::payload_too_large(limit),
            crate::body::CollectError::Read(_) => {
                rejection::bad_request("body_read_failed", "failed to read request body")
            }
        })
}

impl<T: ExtractorMeta> ExtractorMeta for Option<T> {
    const KIND: ExtractorKind = T::KIND;
    const CONSUMES_BODY: bool = T::CONSUMES_BODY;
    const VALIDATES: bool = T::VALIDATES;
    const USES_PRINCIPAL: bool = T::USES_PRINCIPAL;
    const SCHEMA: Option<SchemaFn> = T::SCHEMA;
}

/// `Option<T>` turns a rejection of `T` into `None`.
impl<S: Sync, T: FromRequest<S> + Send> FromRequest<S> for Option<T> {
    type Rejection = std::convert::Infallible;
    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, std::convert::Infallible> {
        Ok(T::from_request(cx).await.ok())
    }
}

#[cfg(feature = "json")]
/// Returns true if `ct` is `application/json` or `application/<x>+json` (params ignored).
pub(crate) fn is_json(ct: &str) -> bool {
    let essence = ct.split(';').next().unwrap_or("").trim().as_bytes();
    let prefix = b"application/";
    let suffix = b"+json";
    essence.eq_ignore_ascii_case(b"application/json")
        || (essence.len() > prefix.len() + suffix.len()
            && essence[..prefix.len()].eq_ignore_ascii_case(prefix)
            && essence[essence.len() - suffix.len()..].eq_ignore_ascii_case(suffix))
}
