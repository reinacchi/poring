//! Cookie extractors.

use std::str::FromStr;

use http::HeaderMap;

use crate::ctx::Ctx;
use crate::descriptor::ExtractorKind;
use crate::error::{ApiError, rejection};
use crate::extract::header::Named;
use crate::extract::{ExtractorMeta, FromRequest};

/// Finds cookie `name` across all `Cookie` headers. Malformed pairs are skipped.
pub fn find_cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim_matches('"'))
}

/// A typed cookie value; `T` declares the cookie name via [`Named`] and parses with
/// `FromStr`. Missing or unparsable cookies are rejected with 400 (use `Option<Cookie<T>>`
/// for optional cookies).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cookie<T>(pub T);

impl<T> ExtractorMeta for Cookie<T> {
    const KIND: ExtractorKind = ExtractorKind::Cookie;
}

impl<S: Sync, T: Named + FromStr + Send> FromRequest<S> for Cookie<T> {
    type Rejection = ApiError;
    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        let raw = find_cookie(&cx.parts.headers, T::NAME).ok_or_else(|| {
            rejection::bad_request("missing_cookie", format!("missing cookie `{}`", T::NAME))
        })?;
        raw.parse().map(Cookie).map_err(|_| {
            rejection::bad_request("invalid_cookie", format!("invalid cookie `{}`", T::NAME))
        })
    }
}

/// All request cookies (name/value pairs in order).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cookies(pub Vec<(String, String)>);

impl Cookies {
    /// Looks up a cookie.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

impl ExtractorMeta for Cookies {
    const KIND: ExtractorKind = ExtractorKind::Cookie;
}

/// Maximum cookies parsed per request.
const MAX_COOKIES: usize = 64;

impl<S: Sync> FromRequest<S> for Cookies {
    type Rejection = std::convert::Infallible;
    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, std::convert::Infallible> {
        let v = cx
            .parts
            .headers
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|p| p.trim().split_once('='))
            .take(MAX_COOKIES)
            .map(|(k, v)| (k.to_owned(), v.trim_matches('"').to_owned()))
            .collect();
        Ok(Cookies(v))
    }
}
