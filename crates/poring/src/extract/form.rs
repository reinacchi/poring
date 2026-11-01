//! `Form<T>`: `application/x-www-form-urlencoded` request bodies.

use serde::de::DeserializeOwned;

use crate::ctx::Ctx;
use crate::descriptor::{ExtractorKind, SchemaFn};
use crate::error::{ApiError, rejection};
use crate::extract::query::parse_urlencoded;
use crate::extract::{ExtractorMeta, FromRequest, read_body};
use crate::schema::PoringSchema;

/// Typed urlencoded form body (flat; no nesting, bounded field count).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Form<T>(pub T);

impl<T: PoringSchema> ExtractorMeta for Form<T> {
    const KIND: ExtractorKind = ExtractorKind::Form;
    const CONSUMES_BODY: bool = true;
    const VALIDATES: bool = T::HAS_RULES;
    const SCHEMA: Option<SchemaFn> = Some(T::schema);
}

impl<S: Sync, T: DeserializeOwned + PoringSchema + Send> FromRequest<S> for Form<T> {
    type Rejection = ApiError;

    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        let ok = cx
            .content_type()
            .map(|ct| {
                ct.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
            .unwrap_or(false);
        if !ok {
            return Err(rejection::unsupported_media_type("application/x-www-form-urlencoded"));
        }
        let body = read_body(cx).await?;
        let limits = cx.limits();
        let v: T = parse_urlencoded(&body, usize::MAX, limits.max_form_fields, "form body")?;
        if T::HAS_RULES {
            cx.__mark_validate();
            let issues = crate::schema::validate(&v);
            if !issues.is_empty() {
                return Err(rejection::validation(issues));
            }
        }
        Ok(Form(v))
    }
}
