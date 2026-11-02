//! `Json<T>` request extraction.

use serde::de::DeserializeOwned;

use crate::ctx::Ctx;
use crate::descriptor::{ExtractorKind, SchemaFn};
use crate::error::{ApiError, rejection};
use crate::extract::{ExtractorMeta, FromRequest, is_json, read_body};
use crate::response::Json;
use crate::schema::PoringSchema;

impl<T: PoringSchema> ExtractorMeta for Json<T> {
    const KIND: ExtractorKind = ExtractorKind::Json;
    const CONSUMES_BODY: bool = true;
    const VALIDATES: bool = T::HAS_RULES;
    const SCHEMA: Option<SchemaFn> = Some(T::schema);
}

impl<S: Sync, T: DeserializeOwned + PoringSchema + Send> FromRequest<S> for Json<T> {
    type Rejection = ApiError;

    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        if !cx.content_type().map(is_json).unwrap_or(false) {
            return Err(rejection::unsupported_media_type("application/json"));
        }
        let body = read_body(cx).await?;
        // serde_json enforces a recursion limit of 128 by default, bounding nesting depth.
        let v: T = serde_json::from_slice(&body).map_err(|e| {
            let code = if e.is_data() {
                "invalid_json_shape"
            } else {
                "malformed_json"
            };
            rejection::bad_request(code, format!("invalid JSON body: {e}"))
        })?;
        if T::HAS_RULES {
            cx.__mark_validate();
            let issues = crate::schema::validate(&v);
            if !issues.is_empty() {
                return Err(rejection::validation(issues));
            }
        }
        Ok(Json(v))
    }
}
