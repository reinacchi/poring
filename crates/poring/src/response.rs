//! Response types and the [`IntoResponse`] conversion trait.

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue, LOCATION};
use http::{HeaderMap, StatusCode};

use crate::body::Body;
use crate::descriptor::ResponseDoc;
use crate::schema::SchemaRegistry;

/// The response type produced by every handler.
pub type Response = http::Response<Body>;

/// Converts a handler return value into a [`Response`].
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be returned from a Poring handler",
    label = "does not implement `IntoResponse`",
    note = "return `&'static str`, `String`, `Bytes`, `Json<T>`, `Html<T>`, `StatusCode`, `(StatusCode, T)`, `Response`, or `Result<T, E>` where both implement `IntoResponse`"
)]
pub trait IntoResponse {
    /// Performs the conversion.
    fn into_response(self) -> Response;

    /// Responses documented for fluent routes (OpenAPI). Undocumented by default.
    #[doc(hidden)]
    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc>
    where
        Self: Sized,
    {
        let _ = reg;
        Vec::new()
    }
}

fn described<T: describe::DescribeResponse>(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
    T::describe(reg)
}

/// Marks a documented `200` as status-dependent (the status is chosen at runtime).
fn runtime_status(docs: Vec<ResponseDoc>) -> Vec<ResponseDoc> {
    docs.into_iter()
        .map(|mut d| {
            if d.status == 200 {
                d.status = 0;
            }
            d
        })
        .collect()
}

pub(crate) static TEXT_PLAIN: HeaderValue = HeaderValue::from_static("text/plain; charset=utf-8");
pub(crate) static APPLICATION_JSON: HeaderValue = HeaderValue::from_static("application/json");
pub(crate) static OCTET_STREAM: HeaderValue = HeaderValue::from_static("application/octet-stream");
pub(crate) static TEXT_HTML: HeaderValue = HeaderValue::from_static("text/html; charset=utf-8");

fn with_type(body: Body, ct: &HeaderValue) -> Response {
    let mut r = http::Response::new(body);
    r.headers_mut().insert(CONTENT_TYPE, ct.clone());
    r
}

impl IntoResponse for Response {
    fn into_response(self) -> Response {
        self
    }
}

impl IntoResponse for Body {
    fn into_response(self) -> Response {
        http::Response::new(self)
    }
}

impl IntoResponse for () {
    fn into_response(self) -> Response {
        http::Response::new(Body::empty())
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        described::<()>(reg)
    }
}

impl IntoResponse for &'static str {
    fn into_response(self) -> Response {
        with_type(Body::from(self), &TEXT_PLAIN)
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        described::<&'static str>(reg)
    }
}

impl IntoResponse for String {
    fn into_response(self) -> Response {
        with_type(Body::from(self), &TEXT_PLAIN)
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        described::<String>(reg)
    }
}

impl IntoResponse for std::borrow::Cow<'static, str> {
    fn into_response(self) -> Response {
        match self {
            std::borrow::Cow::Borrowed(s) => s.into_response(),
            std::borrow::Cow::Owned(s) => s.into_response(),
        }
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        described::<String>(reg)
    }
}

impl IntoResponse for Bytes {
    fn into_response(self) -> Response {
        with_type(Body::from(self), &OCTET_STREAM)
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        described::<Bytes>(reg)
    }
}

impl IntoResponse for Vec<u8> {
    fn into_response(self) -> Response {
        with_type(Body::from(self), &OCTET_STREAM)
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        described::<Bytes>(reg)
    }
}

impl IntoResponse for &'static [u8] {
    fn into_response(self) -> Response {
        with_type(Body::from(self), &OCTET_STREAM)
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        described::<Bytes>(reg)
    }
}

impl IntoResponse for StatusCode {
    fn into_response(self) -> Response {
        let mut r = http::Response::new(Body::empty());
        *r.status_mut() = self;
        r
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        described::<StatusCode>(reg)
    }
}

impl<T: IntoResponse, E: IntoResponse> IntoResponse for Result<T, E> {
    fn into_response(self) -> Response {
        match self {
            Ok(t) => t.into_response(),
            Err(e) => e.into_response(),
        }
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        let mut v = T::__poring_describe(reg);
        v.extend(E::__poring_describe(reg));
        v
    }
}

impl<T: IntoResponse> IntoResponse for (StatusCode, T) {
    fn into_response(self) -> Response {
        let mut r = self.1.into_response();
        *r.status_mut() = self.0;
        r
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        runtime_status(T::__poring_describe(reg))
    }
}

impl<T: IntoResponse> IntoResponse for (HeaderMap, T) {
    fn into_response(self) -> Response {
        let mut r = self.1.into_response();
        r.headers_mut().extend(self.0);
        r
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        T::__poring_describe(reg)
    }
}

impl<T: IntoResponse> IntoResponse for (StatusCode, HeaderMap, T) {
    fn into_response(self) -> Response {
        let mut r = self.2.into_response();
        *r.status_mut() = self.0;
        r.headers_mut().extend(self.1);
        r
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        runtime_status(T::__poring_describe(reg))
    }
}

impl<T: IntoResponse, const N: usize> IntoResponse for ([(HeaderName, HeaderValue); N], T) {
    fn into_response(self) -> Response {
        let mut r = self.1.into_response();
        for (k, v) in self.0 {
            r.headers_mut().insert(k, v);
        }
        r
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        T::__poring_describe(reg)
    }
}

impl<T: IntoResponse, const N: usize> IntoResponse for (StatusCode, [(HeaderName, HeaderValue); N], T) {
    fn into_response(self) -> Response {
        let mut r = self.2.into_response();
        *r.status_mut() = self.0;
        for (k, v) in self.1 {
            r.headers_mut().insert(k, v);
        }
        r
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        runtime_status(T::__poring_describe(reg))
    }
}

/// An HTML response.
#[derive(Clone, Debug)]
pub struct Html<T>(pub T);

impl<T: Into<Body>> IntoResponse for Html<T> {
    fn into_response(self) -> Response {
        with_type(self.0.into(), &TEXT_HTML)
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        described::<Html<()>>(reg)
    }
}

/// A redirect response.
#[derive(Clone, Debug)]
pub struct Redirect {
    status: StatusCode,
    location: HeaderValue,
}

impl Redirect {
    /// `303 See Other`.
    pub fn to(uri: &str) -> Self {
        Self::with(StatusCode::SEE_OTHER, uri)
    }
    /// `307 Temporary Redirect`.
    pub fn temporary(uri: &str) -> Self {
        Self::with(StatusCode::TEMPORARY_REDIRECT, uri)
    }
    /// `308 Permanent Redirect`.
    pub fn permanent(uri: &str) -> Self {
        Self::with(StatusCode::PERMANENT_REDIRECT, uri)
    }
    fn with(status: StatusCode, uri: &str) -> Self {
        // Invalid header characters are replaced by a safe root redirect instead of panicking.
        let location = HeaderValue::from_str(uri).unwrap_or_else(|_| HeaderValue::from_static("/"));
        Redirect { status, location }
    }
}

impl IntoResponse for Redirect {
    fn into_response(self) -> Response {
        let mut r = self.status.into_response();
        r.headers_mut().insert(LOCATION, self.location);
        r
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        described::<Redirect>(reg)
    }
}

/// A JSON request extractor / response.
///
/// As an extractor it requires `Content-Type: application/json` (or `+json`), enforces the
/// route's body limit while reading, deserializes with serde_json (recursion limit 128)
/// and then runs the type's declarative validation rules (see [`crate::PoringSchema`]).
#[cfg(feature = "json")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Json<T>(pub T);

#[cfg(feature = "json")]
impl<T: serde::Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        match serde_json::to_vec(&self.0) {
            Ok(v) => with_type(Body::from(v), &APPLICATION_JSON),
            Err(e) => {
                tracing::error!(error = %e, "failed to serialise JSON response");
                crate::error::ApiError::internal_message("response serialisation failed").into_response()
            }
        }
    }

    fn __poring_describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
        let _ = reg;
        // The body type is only known to be `Serialize` here, so its schema is not documented.
        vec![ResponseDoc { status: 200, content_type: Some("application/json"), schema: None }]
    }
}

/// Internal: response conversion that records whether a handler returned `Err` (for the
/// trace-flow `error` branch). Uses autoref specialisation on concrete return types.
#[doc(hidden)]
pub mod respond {
    use super::{IntoResponse, Response};

    pub struct Wrap<T>(pub Option<T>);

    pub trait RespondResult {
        fn __poring_respond(self) -> (Response, bool);
    }
    impl<T: IntoResponse, E: IntoResponse> RespondResult for &mut &mut Wrap<Result<T, E>> {
        fn __poring_respond(self) -> (Response, bool) {
            match self.0.take() {
                Some(Ok(t)) => (t.into_response(), false),
                Some(Err(e)) => (e.into_response(), true),
                None => (crate::error::ApiError::internal_message("response already taken").into_response(), true),
            }
        }
    }

    pub trait RespondPlain<T> {
        fn __poring_respond(self) -> (Response, bool)
        where
            T: IntoResponse;
    }
    impl<T> RespondPlain<T> for &mut Wrap<T> {
        fn __poring_respond(self) -> (Response, bool)
        where
            T: IntoResponse,
        {
            match self.0.take() {
                Some(t) => (t.into_response(), false),
                None => (crate::error::ApiError::internal_message("response already taken").into_response(), true),
            }
        }
    }
}

/// Response documentation derived from handler return types (for OpenAPI).
pub mod describe {
    use std::marker::PhantomData;

    use serde_json::json;

    use super::*;
    use crate::descriptor::ResponseDoc;
    use crate::schema::SchemaRegistry;

    /// Types that can describe the responses they produce.
    pub trait DescribeResponse {
        /// Documented responses.
        fn describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc>;
    }

    fn doc(status: u16, ct: Option<&'static str>, schema: Option<serde_json::Value>) -> Vec<ResponseDoc> {
        vec![ResponseDoc { status, content_type: ct, schema }]
    }

    impl DescribeResponse for &'static str {
        fn describe(_: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            doc(200, Some("text/plain"), Some(json!({"type": "string"})))
        }
    }
    impl DescribeResponse for String {
        fn describe(_: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            doc(200, Some("text/plain"), Some(json!({"type": "string"})))
        }
    }
    impl DescribeResponse for () {
        fn describe(_: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            doc(200, None, None)
        }
    }
    impl DescribeResponse for StatusCode {
        fn describe(_: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            doc(0, None, None)
        }
    }
    impl DescribeResponse for Bytes {
        fn describe(_: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            doc(200, Some("application/octet-stream"), Some(json!({"type": "string", "format": "binary"})))
        }
    }
    impl DescribeResponse for Vec<u8> {
        fn describe(r: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            Bytes::describe(r)
        }
    }
    impl<T> DescribeResponse for Html<T> {
        fn describe(_: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            doc(200, Some("text/html"), Some(json!({"type": "string"})))
        }
    }
    #[cfg(feature = "json")]
    impl<T: crate::schema::PoringSchema> DescribeResponse for Json<T> {
        fn describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            doc(200, Some("application/json"), Some(T::schema(reg)))
        }
    }
    impl DescribeResponse for Redirect {
        fn describe(_: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            doc(303, None, None)
        }
    }
    impl DescribeResponse for crate::error::ApiError {
        fn describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            let s = reg.component("ApiErrorBody", |_| {
                json!({
                    "type": "object",
                    "required": ["error"],
                    "properties": {"error": {
                        "type": "object",
                        "required": ["status", "code", "message"],
                        "properties": {
                            "status": {"type": "integer"},
                            "code": {"type": "string"},
                            "message": {"type": "string"},
                            "issues": {"type": "array", "items": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}, "rule": {"type": "string"}, "message": {"type": "string"}}
                            }}
                        }
                    }}
                })
            });
            doc(0, Some("application/json"), Some(s))
        }
    }
    impl<T: DescribeResponse, E: DescribeResponse> DescribeResponse for Result<T, E> {
        fn describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            let mut v = T::describe(reg);
            v.extend(E::describe(reg));
            v
        }
    }
    impl<T: DescribeResponse> DescribeResponse for (StatusCode, T) {
        fn describe(reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            // The status is a runtime value; document the body under "default".
            T::describe(reg)
                .into_iter()
                .map(|mut d| {
                    if d.status == 200 {
                        d.status = 0;
                    }
                    d
                })
                .collect()
        }
    }

    /// Autoref-specialisation probe used by route macros.
    pub struct Probe<T>(PhantomData<fn() -> T>);
    impl<T> Probe<T> {
        /// New probe.
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Probe(PhantomData)
        }
    }
    impl<T> Default for Probe<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Specific path: the type implements [`DescribeResponse`].
    pub trait DescribeViaTrait {
        /// Describe.
        fn __poring_describe(&self, reg: &mut SchemaRegistry) -> Vec<ResponseDoc>;
    }
    impl<T: DescribeResponse> DescribeViaTrait for &Probe<T> {
        fn __poring_describe(&self, reg: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            T::describe(reg)
        }
    }

    /// Fallback: undocumented response type.
    pub trait DescribeFallback {
        /// Describe (empty).
        fn __poring_describe(&self, reg: &mut SchemaRegistry) -> Vec<ResponseDoc>;
    }
    impl<T> DescribeFallback for Probe<T> {
        fn __poring_describe(&self, _: &mut SchemaRegistry) -> Vec<ResponseDoc> {
            Vec::new()
        }
    }
}
