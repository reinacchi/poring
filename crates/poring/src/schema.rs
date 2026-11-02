//! Request/response contracts: JSON Schema generation and declarative validation.
//!
//! [`PoringSchema`] is implemented by `#[derive(PoringSchema)]` and for common std types.
//! It is the single source of truth for (a) validation of extracted request data,
//! (b) OpenAPI component schemas and (c) the generated TypeScript client.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Value, json};

use crate::error::ValidationIssue;

/// Collects named component schemas (`#/components/schemas/<Name>`).
#[derive(Debug, Default, Clone)]
pub struct SchemaRegistry {
    /// Registered components by name.
    pub components: BTreeMap<String, Value>,
}

impl SchemaRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a named component (once; recursion-safe) and returns a `$ref` to it.
    pub fn component(
        &mut self,
        name: &str,
        build: impl FnOnce(&mut SchemaRegistry) -> Value,
    ) -> Value {
        if !self.components.contains_key(name) {
            self.components.insert(name.to_owned(), Value::Null);
            let s = build(self);
            self.components.insert(name.to_owned(), s);
        }
        json!({ "$ref": format!("#/components/schemas/{name}") })
    }

    /// Resolves a `$ref` produced by this registry.
    pub fn resolve<'a>(&'a self, schema: &'a Value) -> &'a Value {
        if let Some(r) = schema.get("$ref").and_then(Value::as_str)
            && let Some(name) = r.strip_prefix("#/components/schemas/")
            && let Some(s) = self.components.get(name)
        {
            return s;
        }
        schema
    }
}

/// Maximum validation issues collected per request (bounded output).
pub const MAX_ISSUES: usize = 32;

/// Validation context: tracks the current location and collects issues.
#[derive(Debug, Default)]
pub struct ValidationCx {
    path: Vec<String>,
    issues: Vec<ValidationIssue>,
}

impl ValidationCx {
    /// New, empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `f` with `seg` appended to the location.
    pub fn at<F: FnOnce(&mut Self)>(&mut self, seg: impl std::fmt::Display, f: F) {
        self.path.push(seg.to_string());
        f(self);
        self.path.pop();
    }

    /// Records an issue at the current location.
    pub fn issue(&mut self, rule: &'static str, message: impl Into<String>) {
        if self.issues.len() < MAX_ISSUES {
            let path = if self.path.is_empty() {
                "/".to_owned()
            } else {
                format!("/{}", self.path.join("/"))
            };
            self.issues.push(ValidationIssue {
                path,
                rule,
                message: message.into(),
            });
        }
    }

    /// Whether issues were recorded.
    pub fn has_issues(&self) -> bool {
        !self.issues.is_empty()
    }

    /// Consumes the context.
    pub fn into_issues(self) -> Vec<ValidationIssue> {
        self.issues
    }
}

/// Validates `value`, returning the collected issues (empty if valid).
pub fn validate<T: PoringSchema + ?Sized>(value: &T) -> Vec<ValidationIssue> {
    let mut cx = ValidationCx::new();
    value.validate(&mut cx);
    cx.into_issues()
}

/// A Rust type with a declared contract (schema + validation rules).
///
/// Derive it with `#[derive(PoringSchema)]`. Field rules:
/// `#[poring(min_length = 1, max_length = 64, minimum = 0, maximum = 100, non_empty)]`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no Poring contract",
    label = "missing `PoringSchema`",
    note = "add `#[derive(PoringSchema)]` to the type; Poring requires a declared schema for typed request/response bodies so it can validate them and generate OpenAPI"
)]
pub trait PoringSchema {
    /// Whether any validation rule applies to this type (transitively).
    const HAS_RULES: bool = false;

    /// JSON Schema (draft 2020-12 subset, OpenAPI 3.1 compatible).
    fn schema(reg: &mut SchemaRegistry) -> Value;

    /// Declarative validation.
    fn validate(&self, cx: &mut ValidationCx) {
        let _ = cx;
    }
}

macro_rules! prim {
    ($($t:ty => $s:expr),* $(,)?) => {$(
        impl PoringSchema for $t {
            fn schema(_: &mut SchemaRegistry) -> Value { $s }
        }
    )*};
}

prim! {
    bool => json!({"type": "boolean"}),
    i8 => json!({"type": "integer", "format": "int8"}),
    i16 => json!({"type": "integer", "format": "int16"}),
    i32 => json!({"type": "integer", "format": "int32"}),
    i64 => json!({"type": "integer", "format": "int64"}),
    isize => json!({"type": "integer"}),
    u8 => json!({"type": "integer", "format": "uint8", "minimum": 0}),
    u16 => json!({"type": "integer", "format": "uint16", "minimum": 0}),
    u32 => json!({"type": "integer", "format": "uint32", "minimum": 0}),
    u64 => json!({"type": "integer", "format": "uint64", "minimum": 0}),
    usize => json!({"type": "integer", "minimum": 0}),
    f32 => json!({"type": "number", "format": "float"}),
    f64 => json!({"type": "number", "format": "double"}),
    String => json!({"type": "string"}),
    &'static str => json!({"type": "string"}),
    char => json!({"type": "string", "minLength": 1, "maxLength": 1}),
    () => json!({"type": "null"}),
    Value => json!({}),
}

impl<T: PoringSchema> PoringSchema for Vec<T> {
    const HAS_RULES: bool = T::HAS_RULES;
    fn schema(reg: &mut SchemaRegistry) -> Value {
        json!({"type": "array", "items": T::schema(reg)})
    }
    fn validate(&self, cx: &mut ValidationCx) {
        if T::HAS_RULES {
            for (i, v) in self.iter().enumerate() {
                cx.at(i, |cx| v.validate(cx));
            }
        }
    }
}

impl<T: PoringSchema> PoringSchema for Option<T> {
    const HAS_RULES: bool = T::HAS_RULES;
    fn schema(reg: &mut SchemaRegistry) -> Value {
        let inner = T::schema(reg);
        json!({"anyOf": [inner, {"type": "null"}]})
    }
    fn validate(&self, cx: &mut ValidationCx) {
        if let Some(v) = self {
            v.validate(cx);
        }
    }
}

impl<T: PoringSchema> PoringSchema for Box<T> {
    const HAS_RULES: bool = T::HAS_RULES;
    fn schema(reg: &mut SchemaRegistry) -> Value {
        T::schema(reg)
    }
    fn validate(&self, cx: &mut ValidationCx) {
        (**self).validate(cx);
    }
}

impl<T: PoringSchema, H: std::hash::BuildHasher> PoringSchema for HashMap<String, T, H> {
    const HAS_RULES: bool = T::HAS_RULES;
    fn schema(reg: &mut SchemaRegistry) -> Value {
        json!({"type": "object", "additionalProperties": T::schema(reg)})
    }
    fn validate(&self, cx: &mut ValidationCx) {
        if T::HAS_RULES {
            let mut keys: Vec<&String> = self.keys().collect();
            keys.sort();
            for k in keys {
                if let Some(v) = self.get(k) {
                    cx.at(k, |cx| v.validate(cx));
                }
            }
        }
    }
}

impl<T: PoringSchema> PoringSchema for BTreeMap<String, T> {
    const HAS_RULES: bool = T::HAS_RULES;
    fn schema(reg: &mut SchemaRegistry) -> Value {
        json!({"type": "object", "additionalProperties": T::schema(reg)})
    }
    fn validate(&self, cx: &mut ValidationCx) {
        if T::HAS_RULES {
            for (k, v) in self {
                cx.at(k, |cx| v.validate(cx));
            }
        }
    }
}

macro_rules! tuple_schema {
    ($($n:tt $t:ident),+) => {
        impl<$($t: PoringSchema),+> PoringSchema for ($($t,)+) {
            const HAS_RULES: bool = false $(|| $t::HAS_RULES)+;
            fn schema(reg: &mut SchemaRegistry) -> Value {
                let items = vec![$($t::schema(reg)),+];
                let n = items.len();
                json!({"type": "array", "prefixItems": items, "minItems": n, "maxItems": n})
            }
            fn validate(&self, cx: &mut ValidationCx) {
                $( cx.at($n, |cx| self.$n.validate(cx)); )+
            }
        }
    };
}
tuple_schema!(0 A);
tuple_schema!(0 A, 1 B);
tuple_schema!(0 A, 1 B, 2 C);
tuple_schema!(0 A, 1 B, 2 C, 3 D);

/// Rule helpers used by `#[derive(PoringSchema)]`.
#[doc(hidden)]
pub mod rules {
    use super::ValidationCx;

    /// Types with a length for `min_length`/`max_length`/`non_empty`.
    pub trait HasLen {
        /// Length (characters for strings, elements for collections), `None` to skip.
        fn rule_len(&self) -> Option<usize>;
    }
    impl HasLen for String {
        fn rule_len(&self) -> Option<usize> {
            Some(self.chars().count())
        }
    }
    impl HasLen for &str {
        fn rule_len(&self) -> Option<usize> {
            Some(self.chars().count())
        }
    }
    impl<T> HasLen for Vec<T> {
        fn rule_len(&self) -> Option<usize> {
            Some(self.len())
        }
    }
    impl<T: HasLen> HasLen for Option<T> {
        fn rule_len(&self) -> Option<usize> {
            self.as_ref().and_then(HasLen::rule_len)
        }
    }

    /// Numeric types for `minimum`/`maximum`.
    pub trait AsNumber {
        /// Value as f64, `None` to skip.
        fn rule_num(&self) -> Option<f64>;
    }
    macro_rules! num {
        ($($t:ty),*) => {$(
            impl AsNumber for $t {
                #[allow(clippy::cast_lossless, clippy::cast_precision_loss)]
                fn rule_num(&self) -> Option<f64> { Some(*self as f64) }
            }
        )*};
    }
    num!(i8, i16, i32, i64, isize, u8, u16, u32, u64, usize, f32, f64);
    impl<T: AsNumber> AsNumber for Option<T> {
        fn rule_num(&self) -> Option<f64> {
            self.as_ref().and_then(AsNumber::rule_num)
        }
    }

    /// `min_length = n`
    pub fn min_length<T: HasLen>(cx: &mut ValidationCx, v: &T, n: usize) {
        if let Some(l) = v.rule_len()
            && l < n
        {
            cx.issue(
                "min_length",
                format!("must have at least {n} characters/items (got {l})"),
            );
        }
    }
    /// `max_length = n`
    pub fn max_length<T: HasLen>(cx: &mut ValidationCx, v: &T, n: usize) {
        if let Some(l) = v.rule_len()
            && l > n
        {
            cx.issue(
                "max_length",
                format!("must have at most {n} characters/items (got {l})"),
            );
        }
    }
    /// `non_empty`
    pub fn non_empty<T: HasLen>(cx: &mut ValidationCx, v: &T) {
        if v.rule_len() == Some(0) {
            cx.issue("non_empty", "must not be empty");
        }
    }
    /// `minimum = x`
    pub fn minimum<T: AsNumber>(cx: &mut ValidationCx, v: &T, min: f64) {
        if let Some(x) = v.rule_num()
            && x < min
        {
            cx.issue("minimum", format!("must be >= {min}"));
        }
    }
    /// `maximum = x`
    pub fn maximum<T: AsNumber>(cx: &mut ValidationCx, v: &T, max: f64) {
        if let Some(x) = v.rule_num()
            && x > max
        {
            cx.issue("maximum", format!("must be <= {max}"));
        }
    }
    /// `ascii`: only printable ASCII (useful for identifiers/usernames).
    pub fn ascii(cx: &mut ValidationCx, v: &str) {
        if !v.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            cx.issue("ascii", "must contain only printable ASCII characters");
        }
    }
}
