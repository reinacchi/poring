//! `Multipart`: streaming `multipart/form-data` with ceilings (`multipart` feature).
//!
//! Limits: the whole stream is capped by the route's effective body limit, each field by
//! `per_field_limit` (default: the body limit), and the number of fields by
//! `MAX_FIELDS` (64). Exceeding any limit yields 413 (size) or 400 (count).

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;

use crate::ctx::Ctx;
use crate::descriptor::ExtractorKind;
use crate::error::{ApiError, rejection};
use crate::extract::{ExtractorMeta, FromRequest};

/// Maximum number of parts accepted per request.
pub const MAX_FIELDS: usize = 64;

/// A streaming multipart body.
pub struct Multipart {
    inner: multer::Multipart<'static>,
    fields: usize,
    limit: u64,
}

impl std::fmt::Debug for Multipart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Multipart")
            .field("fields", &self.fields)
            .finish_non_exhaustive()
    }
}

impl ExtractorMeta for Multipart {
    const KIND: ExtractorKind = ExtractorKind::Multipart;
    const CONSUMES_BODY: bool = true;
}

fn map_err(e: multer::Error, limit: u64) -> ApiError {
    match e {
        multer::Error::StreamSizeExceeded { .. } | multer::Error::FieldSizeExceeded { .. } => {
            rejection::payload_too_large(limit)
        }
        other => rejection::bad_request(
            "invalid_multipart",
            format!("invalid multipart body: {other}"),
        ),
    }
}

impl<S: Sync> FromRequest<S> for Multipart {
    type Rejection = ApiError;

    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        let ct = cx.content_type();
        let is_form_data = ct.is_some_and(|ct| {
            ct.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case("multipart/form-data"))
        });
        if !is_form_data {
            return Err(rejection::unsupported_media_type("multipart/form-data"));
        }
        // The right media type with a missing or malformed `boundary` is a bad request,
        // not an unsupported media type.
        let boundary = ct
            .and_then(|ct| multer::parse_boundary(ct).ok())
            .ok_or_else(|| {
                rejection::bad_request(
                    "multipart_boundary",
                    "multipart/form-data requires a valid boundary parameter",
                )
            })?;
        let limit = cx.body_limit();
        let body = cx
            .take_body()
            .ok_or_else(|| rejection::internal("body_already_taken"))?;
        let stream = body.into_data_stream();
        let constraints = multer::Constraints::new().size_limit(
            multer::SizeLimit::new()
                .whole_stream(limit)
                .per_field(limit),
        );
        Ok(Multipart {
            inner: multer::Multipart::with_constraints(stream, boundary, constraints),
            fields: 0,
            limit,
        })
    }
}

impl Multipart {
    /// The next part, or `None` at the end.
    pub async fn next_field(&mut self) -> Result<Option<Field>, ApiError> {
        let limit = self.limit;
        match self
            .inner
            .next_field()
            .await
            .map_err(|e| map_err(e, limit))?
        {
            None => Ok(None),
            Some(f) => {
                self.fields += 1;
                if self.fields > MAX_FIELDS {
                    return Err(rejection::bad_request(
                        "too_many_fields",
                        format!("more than {MAX_FIELDS} multipart fields"),
                    ));
                }
                Ok(Some(Field { inner: f, limit }))
            }
        }
    }
}

/// One multipart field.
pub struct Field {
    inner: multer::Field<'static>,
    limit: u64,
}

impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Field")
            .field("name", &self.inner.name())
            .finish_non_exhaustive()
    }
}

impl Field {
    /// Field name.
    pub fn name(&self) -> Option<&str> {
        self.inner.name()
    }
    /// File name, if this part is a file. Treat as untrusted (never use as a path).
    pub fn file_name(&self) -> Option<&str> {
        self.inner.file_name()
    }
    /// Declared content type.
    pub fn content_type(&self) -> Option<String> {
        self.inner.content_type().map(|m| m.to_string())
    }
    /// Reads the whole field (bounded by the limits).
    pub async fn bytes(self) -> Result<Bytes, ApiError> {
        let limit = self.limit;
        self.inner.bytes().await.map_err(|e| map_err(e, limit))
    }
    /// Reads the next chunk.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, ApiError> {
        let limit = self.limit;
        match self.inner.next().await {
            None => Ok(None),
            Some(r) => r.map(Some).map_err(|e| map_err(e, limit)),
        }
    }
}
