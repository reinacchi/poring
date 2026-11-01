//! Typed errors and their HTTP mapping.
//!
//! Every framework-generated error response is a JSON document of the form
//! `{"error":{"status":422,"code":"validation_failed","message":"...","issues":[...]}}`
//! and carries a [`FrameworkError`] response extension so that a global error mapper
//! (see `Builder::map_errors`) can rewrite it consistently.

use std::borrow::Cow;

use http::StatusCode;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use serde::Serialize;

use crate::body::Body;
use crate::response::{APPLICATION_JSON, IntoResponse, Response};

/// One validation problem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ValidationIssue {
    /// JSON-pointer-like location, e.g. `/name` or `/items/2/qty`.
    pub path: String,
    /// The rule that failed, e.g. `min_length`.
    pub rule: &'static str,
    /// Human-readable message.
    pub message: String,
}

/// Marker extension attached to framework-generated error responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameworkError {
    /// HTTP status.
    pub status: StatusCode,
    /// Stable machine-readable code.
    pub code: &'static str,
}

/// A typed API error with a stable code, mapped to a JSON error response.
///
/// Use it directly as a handler error type, or convert your own error types into it.
/// `ApiError::internal(err)` logs the source error and returns a generic message, so
/// internal details are never leaked to clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    /// HTTP status.
    pub status: StatusCode,
    /// Stable machine-readable code.
    pub code: &'static str,
    /// Client-safe message.
    pub message: Cow<'static, str>,
    /// Validation issues, if any.
    pub issues: Vec<ValidationIssue>,
    headers: Vec<(HeaderName, HeaderValue)>,
    framework: bool,
}

impl ApiError {
    /// Creates an error.
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        ApiError { status, code, message: message.into(), issues: Vec::new(), headers: Vec::new(), framework: false }
    }

    pub(crate) fn framework(status: StatusCode, code: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        let mut e = Self::new(status, code, message);
        e.framework = true;
        e
    }

    /// `400 bad_request`.
    pub fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
    /// `404 not_found`.
    pub fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }
    /// `403 forbidden`.
    pub fn forbidden(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }
    /// `409 conflict`.
    pub fn conflict(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }
    /// `422 unprocessable`.
    pub fn unprocessable(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "unprocessable", message)
    }
    /// `500`, logging `source` server-side and returning a generic message.
    pub fn internal(source: impl std::fmt::Display) -> Self {
        tracing::error!(error = %source, "internal error");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal server error")
    }
    pub(crate) fn internal_message(msg: &'static str) -> Self {
        tracing::error!(error = msg, "internal error");
        Self::framework(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal server error")
    }

    /// Adds validation issues.
    pub fn with_issues(mut self, issues: Vec<ValidationIssue>) -> Self {
        self.issues = issues;
        self
    }

    /// Adds a response header (e.g. `Retry-After`).
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}: {}", self.status.as_u16(), self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

#[derive(Serialize)]
struct ErrorDoc<'a> {
    error: ErrorInner<'a>,
}

#[derive(Serialize)]
struct ErrorInner<'a> {
    status: u16,
    code: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    issues: &'a [ValidationIssue],
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let doc = ErrorDoc {
            error: ErrorInner {
                status: self.status.as_u16(),
                code: self.code,
                message: &self.message,
                issues: &self.issues,
            },
        };
        let body = serde_json::to_vec(&doc).unwrap_or_else(|_| b"{\"error\":{}}".to_vec());
        let mut r = http::Response::new(Body::from(body));
        *r.status_mut() = self.status;
        r.headers_mut().insert(CONTENT_TYPE, APPLICATION_JSON.clone());
        for (k, v) in self.headers {
            r.headers_mut().insert(k, v);
        }
        if self.framework {
            r.extensions_mut().insert(FrameworkError { status: self.status, code: self.code });
        }
        r
    }

    fn __poring_describe(reg: &mut crate::schema::SchemaRegistry) -> Vec<crate::descriptor::ResponseDoc> {
        <ApiError as crate::response::describe::DescribeResponse>::describe(reg)
    }
}

/// Framework rejections (extractor and policy failures).
pub mod rejection {
    use super::*;

    /// 400: malformed path parameter, query string, or body.
    pub fn bad_request(code: &'static str, message: impl Into<Cow<'static, str>>) -> ApiError {
        ApiError::framework(StatusCode::BAD_REQUEST, code, message)
    }
    /// 401 with `WWW-Authenticate`.
    pub fn unauthenticated() -> ApiError {
        ApiError::framework(StatusCode::UNAUTHORIZED, "unauthenticated", "authentication required")
            .with_header(http::header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))
    }
    /// 403.
    pub fn forbidden(code: &'static str, message: impl Into<Cow<'static, str>>) -> ApiError {
        ApiError::framework(StatusCode::FORBIDDEN, code, message)
    }
    /// 404.
    pub fn not_found() -> ApiError {
        ApiError::framework(StatusCode::NOT_FOUND, "not_found", "no route matches the request path")
    }
    /// 405 with `Allow`.
    pub fn method_not_allowed(allow: HeaderValue) -> ApiError {
        ApiError::framework(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "method not allowed for this path")
            .with_header(http::header::ALLOW, allow)
    }
    /// 413.
    pub fn payload_too_large(limit: u64) -> ApiError {
        ApiError::framework(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("request body exceeds the limit of {limit} bytes"),
        )
    }
    /// 415.
    pub fn unsupported_media_type(expected: &str) -> ApiError {
        ApiError::framework(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            format!("expected content type {expected}"),
        )
    }
    /// 422 with issues.
    pub fn validation(issues: Vec<ValidationIssue>) -> ApiError {
        ApiError::framework(StatusCode::UNPROCESSABLE_ENTITY, "validation_failed", "request validation failed")
            .with_issues(issues)
    }
    /// 429 with `Retry-After` (seconds, rounded up).
    pub fn too_many_requests(retry_after: std::time::Duration) -> ApiError {
        let secs = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
        ApiError::framework(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many requests")
            .with_header(http::header::RETRY_AFTER, HeaderValue::from(secs.max(1)))
    }
    /// 503 for handler timeouts.
    pub fn timeout() -> ApiError {
        ApiError::framework(StatusCode::SERVICE_UNAVAILABLE, "timeout", "request timed out")
    }
    /// 503 for unavailable dependencies.
    pub fn unavailable(message: impl Into<Cow<'static, str>>) -> ApiError {
        ApiError::framework(StatusCode::SERVICE_UNAVAILABLE, "unavailable", message)
    }
    /// 500 for missing internal wiring (should be unreachable for verified apps).
    pub fn internal(code: &'static str) -> ApiError {
        tracing::error!(code, "internal framework error");
        ApiError::framework(StatusCode::INTERNAL_SERVER_ERROR, code, "internal server error")
    }
}
