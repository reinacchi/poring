//! `Query<T>`: typed query string.
//!
//! Policy: the raw query is limited to `Limits::max_query_bytes` (default 8 KiB) and
//! `Limits::max_form_fields` pairs (default 256). Repeated keys deserialize into
//! `Vec<T>` fields; for a scalar field a repeated key is rejected (400) rather than
//! silently picking one occurrence. Values are coerced
//! from strings into the declared Rust types, then validated.

use serde::de::DeserializeOwned;

use crate::ctx::Ctx;
use crate::descriptor::{ExtractorKind, SchemaFn};
use crate::error::{ApiError, rejection};
use crate::extract::{ExtractorMeta, FromRequest};
use crate::schema::PoringSchema;

/// Typed query parameters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Query<T>(pub T);

impl<T: PoringSchema> ExtractorMeta for Query<T> {
    const KIND: ExtractorKind = ExtractorKind::Query;
    const VALIDATES: bool = T::HAS_RULES;
    const SCHEMA: Option<SchemaFn> = Some(T::schema);
}

/// Parses urlencoded pairs with size/count ceilings.
pub(crate) fn parse_urlencoded<T: DeserializeOwned>(
    raw: &[u8],
    max_bytes: usize,
    max_fields: usize,
    what: &'static str,
) -> Result<T, ApiError> {
    if raw.len() > max_bytes {
        return Err(rejection::bad_request("too_large", format!("{what} exceeds {max_bytes} bytes")));
    }
    let fields = if raw.is_empty() { 0 } else { raw.iter().filter(|b| **b == b'&').count() + 1 };
    if fields > max_fields {
        return Err(rejection::bad_request("too_many_fields", format!("{what} has more than {max_fields} fields")));
    }
    serde_html_form::from_bytes::<T>(raw)
        .map_err(|e| rejection::bad_request("invalid_urlencoded", format!("invalid {what}: {e}")))
}

impl<S: Sync, T: DeserializeOwned + PoringSchema + Send> FromRequest<S> for Query<T> {
    type Rejection = ApiError;

    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        let raw = cx.parts.uri.query().unwrap_or("");
        let limits = cx.limits();
        let v: T = parse_urlencoded(raw.as_bytes(), limits.max_query_bytes, limits.max_form_fields, "query string")?;
        if T::HAS_RULES {
            cx.__mark_validate();
            let issues = crate::schema::validate(&v);
            if !issues.is_empty() {
                return Err(rejection::validation(issues));
            }
        }
        Ok(Query(v))
    }
}
