//! Typed header extractor.

use std::str::FromStr;

use crate::ctx::Ctx;
use crate::descriptor::ExtractorKind;
use crate::error::{ApiError, rejection};
use crate::extract::{ExtractorMeta, FromRequest};

/// A type bound to a header or cookie name. Use [`crate::named_value!`] to declare one.
pub trait Named {
    /// Header/cookie name (lower-case for headers).
    const NAME: &'static str;
}

/// A typed header value (`T: Named + FromStr`). Missing or invalid headers are
/// rejected with 400; use `Option<Header<T>>` for optional headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header<T>(pub T);

impl<T> ExtractorMeta for Header<T> {
    const KIND: ExtractorKind = ExtractorKind::Header;
}

impl<S: Sync, T: Named + FromStr + Send> FromRequest<S> for Header<T> {
    type Rejection = ApiError;
    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        let v = cx
            .parts
            .headers
            .get(T::NAME)
            .ok_or_else(|| rejection::bad_request("missing_header", format!("missing header `{}`", T::NAME)))?;
        v.to_str()
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Header)
            .ok_or_else(|| rejection::bad_request("invalid_header", format!("invalid header `{}`", T::NAME)))
    }
}

/// Declares a newtype bound to a header/cookie name, parsed via the inner type's `FromStr`.
///
/// ```
/// poring::named_value!(pub ApiVersion: u32 = "x-api-version");
/// ```
#[macro_export]
macro_rules! named_value {
    ($vis:vis $name:ident : $inner:ty = $key:literal) => {
        #[derive(Clone, Debug, PartialEq)]
        $vis struct $name(pub $inner);
        impl $crate::extract::header::Named for $name {
            const NAME: &'static str = $key;
        }
        impl ::core::str::FromStr for $name {
            type Err = <$inner as ::core::str::FromStr>::Err;
            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                <$inner as ::core::str::FromStr>::from_str(s).map($name)
            }
        }
        impl ::core::ops::Deref for $name {
            type Target = $inner;
            fn deref(&self) -> &$inner { &self.0 }
        }
    };
}
