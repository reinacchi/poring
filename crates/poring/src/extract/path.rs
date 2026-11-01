//! `Path<T>`: typed, percent-decoded path parameters.
//!
//! Decoding rules:
//! * routing matches the raw, still-encoded path; static segments never match encoded
//!   spellings (`/us%65rs` does not match `/users`);
//! * parameter values are percent-decoded after matching; `%2F` decodes to `/` inside a
//!   value (it is data, not a separator);
//! * a `%` not followed by two hex digits, or a decoded value that is not UTF-8, is
//!   rejected with `400 invalid_path_param`.

use std::borrow::Cow;

use serde::de::{self, DeserializeOwned, IntoDeserializer, Visitor};

use crate::ctx::Ctx;
use crate::descriptor::{ExtractorKind, SchemaFn};
use crate::error::{ApiError, rejection};
use crate::extract::{ExtractorMeta, FromRequest};
use crate::schema::PoringSchema;

/// Typed path parameters: a scalar for single-parameter routes, a tuple (by position) or
/// a struct (by name).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path<T>(pub T);

/// Malformed percent-encoding or invalid UTF-8.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodeError;

/// Strictly percent-decodes a path parameter.
pub fn decode(raw: &str) -> Result<Cow<'_, str>, DecodeError> {
    let b = raw.as_bytes();
    let mut i = 0;
    let mut any = false;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err(DecodeError);
            }
            if !(b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit()) {
                return Err(DecodeError);
            }
            any = true;
            i += 3;
        } else {
            i += 1;
        }
    }
    if !any {
        return Ok(Cow::Borrowed(raw));
    }
    percent_encoding::percent_decode_str(raw).decode_utf8().map_err(|_| DecodeError)
}

impl<T: PoringSchema> ExtractorMeta for Path<T> {
    const KIND: ExtractorKind = ExtractorKind::Path;
    const VALIDATES: bool = T::HAS_RULES;
    const SCHEMA: Option<SchemaFn> = Some(T::schema);
}

impl<S: Sync, T: DeserializeOwned + PoringSchema + Send> FromRequest<S> for Path<T> {
    type Rejection = ApiError;

    async fn from_request(cx: &mut Ctx<'_, S>) -> Result<Self, ApiError> {
        let path = cx.parts.uri.path();
        let mut values: Vec<(&str, Cow<'_, str>)> = Vec::with_capacity(cx.params.len());
        for (name, s, e) in cx.params.iter() {
            let raw = path.get(s..e).unwrap_or("");
            let v = decode(raw).map_err(|_| {
                rejection::bad_request(
                    "invalid_path_param",
                    format!("path parameter `{name}` is not valid percent-encoded UTF-8"),
                )
            })?;
            values.push((name, v));
        }
        let v = T::deserialize(PathDe { params: &values })
            .map_err(|e| rejection::bad_request("invalid_path_param", e.0))?;
        if T::HAS_RULES {
            let issues = crate::schema::validate(&v);
            cx.__mark_validate();
            if !issues.is_empty() {
                return Err(rejection::validation(issues));
            }
        }
        Ok(Path(v))
    }
}

#[derive(Debug)]
struct PathError(String);

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PathError {}
impl de::Error for PathError {
    fn custom<M: std::fmt::Display>(msg: M) -> Self {
        PathError(format!("invalid path parameters: {msg}"))
    }
}

struct PathDe<'p, 'v> {
    params: &'p [(&'v str, Cow<'v, str>)],
}

macro_rules! single {
    ($($m:ident),*) => {$(
        fn $m<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
            match self.params {
                [(name, val)] => ValueDe { name, val }.$m(v),
                _ => Err(PathError(format!("expected exactly 1 path parameter, route has {}", self.params.len()))),
            }
        }
    )*};
}

impl<'de, 'p, 'v> de::Deserializer<'de> for PathDe<'p, 'v> {
    type Error = PathError;

    single!(
        deserialize_bool,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_u128,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
        deserialize_unit,
        deserialize_identifier
    );

    fn deserialize_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
        if self.params.len() == 1 {
            ValueDe { name: self.params[0].0, val: &self.params[0].1 }.deserialize_any(v)
        } else {
            self.deserialize_map(v)
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
        v.visit_some(self)
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(self, _: &'static str, v: V) -> Result<V::Value, PathError> {
        v.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(self, _: &'static str, v: V) -> Result<V::Value, PathError> {
        v.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
        v.visit_seq(Seq { it: self.params.iter() })
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, PathError> {
        if len != self.params.len() {
            return Err(PathError(format!(
                "expected a tuple of {len} path parameters, route has {}",
                self.params.len()
            )));
        }
        self.deserialize_seq(v)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        len: usize,
        v: V,
    ) -> Result<V::Value, PathError> {
        self.deserialize_tuple(len, v)
    }

    fn deserialize_map<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
        v.visit_map(Map { it: self.params.iter(), value: None })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, PathError> {
        self.deserialize_map(v)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, PathError> {
        match self.params {
            [(_, val)] => v.visit_enum(val.as_ref().to_owned().into_deserializer()),
            _ => Err(PathError("expected exactly 1 path parameter for an enum".into())),
        }
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
        v.visit_unit()
    }
}

struct Seq<'p, 'v> {
    it: std::slice::Iter<'p, (&'v str, Cow<'v, str>)>,
}

impl<'de> de::SeqAccess<'de> for Seq<'_, '_> {
    type Error = PathError;
    fn next_element_seed<T: de::DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, PathError> {
        match self.it.next() {
            Some((name, val)) => seed.deserialize(ValueDe { name, val }).map(Some),
            None => Ok(None),
        }
    }
}

struct Map<'p, 'v> {
    it: std::slice::Iter<'p, (&'v str, Cow<'v, str>)>,
    value: Option<&'p (&'v str, Cow<'v, str>)>,
}

impl<'de> de::MapAccess<'de> for Map<'_, '_> {
    type Error = PathError;
    fn next_key_seed<K: de::DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, PathError> {
        match self.it.next() {
            Some(kv) => {
                self.value = Some(kv);
                seed.deserialize(kv.0.to_owned().into_deserializer()).map(Some)
            }
            None => Ok(None),
        }
    }
    fn next_value_seed<V: de::DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, PathError> {
        match self.value.take() {
            Some((name, val)) => seed.deserialize(ValueDe { name, val }),
            None => Err(PathError("value without key".into())),
        }
    }
}

struct ValueDe<'a> {
    name: &'a str,
    val: &'a Cow<'a, str>,
}

macro_rules! parse_num {
    ($($m:ident => $visit:ident : $t:ty),*) => {$(
        fn $m<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
            let parsed: $t = self.val.parse().map_err(|_| {
                PathError(format!("path parameter `{}` must be {} (got {:?})", self.name, stringify!($t), truncate(self.val)))
            })?;
            v.$visit(parsed)
        }
    )*};
}

fn truncate(s: &str) -> String {
    s.chars().take(64).collect()
}

impl<'de> de::Deserializer<'de> for ValueDe<'_> {
    type Error = PathError;

    parse_num!(
        deserialize_bool => visit_bool: bool,
        deserialize_i8 => visit_i8: i8, deserialize_i16 => visit_i16: i16,
        deserialize_i32 => visit_i32: i32, deserialize_i64 => visit_i64: i64,
        deserialize_i128 => visit_i128: i128,
        deserialize_u8 => visit_u8: u8, deserialize_u16 => visit_u16: u16,
        deserialize_u32 => visit_u32: u32, deserialize_u64 => visit_u64: u64,
        deserialize_u128 => visit_u128: u128,
        deserialize_f32 => visit_f32: f32, deserialize_f64 => visit_f64: f64,
        deserialize_char => visit_char: char
    );

    fn deserialize_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
        v.visit_string(self.val.as_ref().to_owned())
    }
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
        v.visit_string(self.val.as_ref().to_owned())
    }
    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
        v.visit_string(self.val.as_ref().to_owned())
    }
    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value, PathError> {
        v.visit_some(self)
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(self, _: &'static str, v: V) -> Result<V::Value, PathError> {
        v.visit_newtype_struct(self)
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, PathError> {
        v.visit_enum(self.val.as_ref().to_owned().into_deserializer())
    }

    serde::forward_to_deserialize_any! {
        bytes byte_buf unit unit_struct seq tuple tuple_struct map struct identifier ignored_any
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_decoding() {
        assert_eq!(decode("abc").unwrap(), "abc");
        assert_eq!(decode("a%20b").unwrap(), "a b");
        assert_eq!(decode("a%2Fb").unwrap(), "a/b");
        assert!(decode("a%2").is_err());
        assert!(decode("a%").is_err());
        assert!(decode("%zz").is_err());
        assert!(decode("%ff").is_err(), "invalid UTF-8 must be rejected");
        assert_eq!(decode("%E2%9C%93").unwrap(), "\u{2713}");
    }

    #[test]
    fn deserialises_common_shapes() {
        let one = [("id", Cow::Borrowed("42"))];
        let v: u64 = serde::Deserialize::deserialize(PathDe { params: &one }).unwrap();
        assert_eq!(v, 42);
        let bad = [("id", Cow::Borrowed("x"))];
        assert!(<u64 as serde::Deserialize>::deserialize(PathDe { params: &bad }).is_err());
        let two = [("a", Cow::Borrowed("1")), ("b", Cow::Borrowed("x"))];
        let t: (u8, String) = serde::Deserialize::deserialize(PathDe { params: &two }).unwrap();
        assert_eq!(t, (1, "x".to_owned()));
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct P {
            b: String,
            a: u8,
        }
        let p: P = serde::Deserialize::deserialize(PathDe { params: &two }).unwrap();
        assert_eq!(p, P { a: 1, b: "x".into() });
    }
}
