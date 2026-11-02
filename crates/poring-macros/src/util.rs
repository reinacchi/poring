//! Shared helpers: path canonicalisation, type pretty-printing, doc extraction.

use proc_macro2::Span;
use quote::ToTokens;
use syn::{Attribute, Expr, Lit, Meta};

/// Maximum path parameters per route (mirrors `poring::ctx::MAX_PARAMS`).
pub const MAX_PARAMS: usize = 8;

/// Canonicalises a route path. Accepts `{name}`, `{*rest}`, and the shorthand
/// `:name` and a trailing `*` (normalised to `{*rest}`). Returns the canonical path and
/// parameter names.
pub fn canonicalise(path: &str) -> Result<(String, Vec<String>), String> {
    if !path.starts_with('/') {
        return Err(format!("route path `{path}` must start with `/`"));
    }
    if path.contains("//") {
        return Err(format!("route path `{path}` must not contain `//`"));
    }
    if path.contains(['?', '#']) || path.chars().any(char::is_whitespace) {
        return Err(format!(
            "route path `{path}` must not contain `?`, `#` or whitespace"
        ));
    }
    if path.contains("{{") || path.contains("}}") {
        return Err("escaped braces `{{`/`}}` are not supported in Poring route paths".into());
    }
    let segs: Vec<&str> = path[1..].split('/').collect();
    let mut out = String::new();
    let mut params: Vec<String> = Vec::new();
    for (i, seg) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        out.push('/');
        if *seg == "." || *seg == ".." {
            return Err(format!("route path `{path}` must not contain dot segments"));
        }
        if seg.contains('%') {
            return Err(format!(
                "route path `{path}`: static segments must not be percent-encoded (Poring matches the raw path)"
            ));
        }
        let (name, catch_all) = if let Some(n) = seg.strip_prefix(':') {
            (Some(n), false)
        } else if *seg == "*" {
            (Some("rest"), true)
        } else if let Some(inner) = seg.strip_prefix('{') {
            let inner = inner
                .strip_suffix('}')
                .ok_or_else(|| format!("route path `{path}`: unterminated parameter `{seg}`"))?;
            match inner.strip_prefix('*') {
                Some(n) => (Some(n), true),
                None => (Some(inner), false),
            }
        } else {
            if seg.contains(['{', '}', ':', '*']) {
                return Err(format!(
                    "route path `{path}`: parameters must span a whole segment (`/{{id}}`), found `{seg}`"
                ));
            }
            (None, false)
        };
        match name {
            None => out.push_str(seg),
            Some(n) => {
                if n.is_empty()
                    || !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    || n.starts_with(|c: char| c.is_ascii_digit())
                {
                    return Err(format!(
                        "route path `{path}`: invalid parameter name `{n}` (use [A-Za-z_][A-Za-z0-9_]*)"
                    ));
                }
                if params.iter().any(|p| p == n) {
                    return Err(format!("route path `{path}`: duplicate parameter `{n}`"));
                }
                if catch_all && !last {
                    return Err(format!(
                        "route path `{path}`: catch-all `{{*{n}}}` must be the last segment"
                    ));
                }
                params.push(n.to_owned());
                if catch_all {
                    out.push_str(&format!("{{*{n}}}"));
                } else {
                    out.push_str(&format!("{{{n}}}"));
                }
            }
        }
    }
    if params.len() > MAX_PARAMS {
        return Err(format!(
            "route path `{path}` has more than {MAX_PARAMS} parameters"
        ));
    }
    Ok((out, params))
}

/// Validates a static group prefix.
pub fn validate_prefix(prefix: &str) -> Result<String, String> {
    let (canon, params) = canonicalise(prefix)?;
    if !params.is_empty() {
        return Err("group prefixes must be static (no parameters)".into());
    }
    if canon.len() > 1 && canon.ends_with('/') {
        return Err("group prefixes must not end with `/`".into());
    }
    Ok(canon)
}

/// Pretty-prints a type or path without token spacing artefacts.
pub fn pretty<T: ToTokens>(t: &T) -> String {
    let s = t.to_token_stream().to_string();
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ' ' {
            let prev = out.chars().last();
            let next = chars.peek().copied();
            let drop = matches!(prev, Some('<' | ':' | '&' | '(' | '[' | '\''))
                || matches!(next, Some('<' | '>' | ':' | ',' | ')' | ']'));
            if drop {
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// First paragraph of `///` docs.
pub fn doc_summary(attrs: &[Attribute]) -> String {
    let mut lines = Vec::new();
    for a in attrs {
        if !a.path().is_ident("doc") {
            continue;
        }
        if let Meta::NameValue(nv) = &a.meta
            && let Expr::Lit(l) = &nv.value
            && let Lit::Str(s) = &l.lit
        {
            let v = s.value();
            let t = v.trim();
            if t.is_empty() && !lines.is_empty() {
                break;
            }
            if !t.is_empty() {
                lines.push(t.to_owned());
            }
        }
    }
    lines.join(" ")
}

/// Builds a `syn::Error`.
pub fn err(span: Span, msg: impl std::fmt::Display) -> syn::Error {
    syn::Error::new(span, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_paths() {
        assert_eq!(
            canonicalise("/users/:id").unwrap(),
            ("/users/{id}".into(), vec!["id".into()])
        );
        assert_eq!(canonicalise("/files/*").unwrap().0, "/files/{*rest}");
        assert_eq!(canonicalise("/a/{b}/c/{*d}").unwrap().1, vec!["b", "d"]);
        assert_eq!(canonicalise("/").unwrap().0, "/");
        assert_eq!(canonicalise("/a/").unwrap().0, "/a/");
        assert!(canonicalise("users").is_err());
        assert!(canonicalise("/a//b").is_err());
        assert!(canonicalise("/a/{*b}/c").is_err());
        assert!(canonicalise("/a/x{b}").is_err());
        assert!(canonicalise("/a/{b}/{b}").is_err());
        assert!(canonicalise("/a/%41").is_err());
        assert!(canonicalise("/a/../b").is_err());
        assert!(canonicalise("/a/{1x}").is_err());
    }

    #[test]
    fn pretty_types() {
        let t: syn::Type = syn::parse_str("Result < Json < User > , ApiError >").unwrap();
        assert_eq!(pretty(&t), "Result<Json<User>, ApiError>");
        let t: syn::Type = syn::parse_str("Path<(u64, String)>").unwrap();
        assert_eq!(pretty(&t), "Path<(u64, String)>");
    }
}
