//! The `policy(..)` DSL shared by routes, groups, plugins and app defaults.
//!
//! ```text
//! policy(
//!     auth = required | public,            // or: public / public(reason = "...") / public("...")
//!     deny_anonymous,                      // app/group only: strict + auth = required
//!     scopes = ["users:read"], roles = ["admin"],
//!     body_limit = "64KiB",                // alias: max_body
//!     content_type = "application/json",   // or content_types = [..]
//!     csrf = enforce | exempt("reason"),   // `csrf = off` is rejected
//!     timeout = "5s" | none,
//!     rate_limit = "10/s",                 // or rate_limit(requests = 10, per = "1s", key = ip|principal)
//! )
//! ```

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Expr, ExprLit, Lit, Meta, Token};

use crate::util::err;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Level {
    App,
    Group,
    Route,
}

#[derive(Clone, Debug)]
pub enum AuthDecl {
    Required,
    Public(Option<String>),
}

#[derive(Clone, Debug)]
pub enum CsrfDecl {
    Enforce,
    Exempt(String),
}

#[derive(Clone, Debug)]
pub enum TimeoutDecl {
    Disabled,
    Ms(u64),
}

#[derive(Clone, Debug)]
pub struct RateDecl {
    pub requests: u32,
    pub per_ms: u64,
    pub principal: bool,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyDecl {
    pub auth: Option<AuthDecl>,
    pub strict: bool,
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub body_limit: Option<u64>,
    pub content_types: Vec<String>,
    pub csrf: Option<CsrfDecl>,
    pub timeout: Option<TimeoutDecl>,
    pub rate_limit: Option<RateDecl>,
}

pub fn lit_str(e: &Expr) -> syn::Result<String> {
    match e {
        Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) => Ok(s.value()),
        _ => Err(err(e.span(), "expected a string literal")),
    }
}

pub fn str_list(e: &Expr) -> syn::Result<Vec<String>> {
    match e {
        Expr::Array(a) => a.elems.iter().map(lit_str).collect(),
        Expr::Lit(_) => Ok(vec![lit_str(e)?]),
        _ => Err(err(e.span(), "expected a list of string literals, e.g. [\"a\", \"b\"]")),
    }
}

fn ident_of(e: &Expr) -> Option<String> {
    match e {
        Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
        _ => None,
    }
}

pub fn parse_size(e: &Expr) -> syn::Result<u64> {
    if let Expr::Lit(ExprLit { lit: Lit::Int(i), .. }) = e {
        return i.base10_parse();
    }
    let s = lit_str(e)?;
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().map_err(|_| err(e.span(), format!("invalid size `{s}`")))?;
    let mul: u64 = match unit.trim() {
        "" | "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "KB" | "kB" => 1000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        u => return Err(err(e.span(), format!("unknown size unit `{u}` (use B, KiB, MiB, GiB, KB, MB, GB)"))),
    };
    n.checked_mul(mul).ok_or_else(|| err(e.span(), "size overflows u64"))
}

pub fn parse_duration(s: &str, span: Span) -> syn::Result<u64> {
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 =
        if num.is_empty() { 1 } else { num.parse().map_err(|_| err(span, format!("invalid duration `{s}`")))? };
    let mul = match unit.trim() {
        "ms" => 1,
        "s" => 1000,
        "m" | "min" => 60_000,
        "h" => 3_600_000,
        u => return Err(err(span, format!("unknown duration unit `{u}` (use ms, s, min, h)"))),
    };
    n.checked_mul(mul).ok_or_else(|| err(span, "duration overflows"))
}

fn parse_rate_str(s: &str, span: Span) -> syn::Result<RateDecl> {
    let (count, window) =
        s.split_once('/').ok_or_else(|| err(span, "rate_limit must look like \"10/s\", \"100/min\" or \"5/10s\""))?;
    let requests: u32 = count.trim().parse().map_err(|_| err(span, "rate_limit count must be a positive integer"))?;
    if requests == 0 {
        return Err(err(span, "rate_limit count must be > 0"));
    }
    let per_ms = parse_duration(window.trim(), span)?;
    if per_ms == 0 {
        return Err(err(span, "rate_limit window must be > 0"));
    }
    Ok(RateDecl { requests, per_ms, principal: false })
}

fn parse_public(meta: &Meta) -> syn::Result<Option<String>> {
    match meta {
        Meta::Path(_) => Ok(None),
        Meta::List(l) => {
            let args = l.parse_args_with(Punctuated::<Expr, Token![,]>::parse_terminated)?;
            let mut reason = None;
            for a in args {
                match &a {
                    Expr::Assign(asg) if ident_of(&asg.left).as_deref() == Some("reason") => {
                        reason = Some(lit_str(&asg.right)?);
                    }
                    Expr::Lit(_) => reason = Some(lit_str(&a)?),
                    _ => return Err(err(a.span(), "expected `reason = \"...\"`")),
                }
            }
            match reason {
                Some(r) if r.trim().is_empty() => Err(err(l.span(), "public exception reason must not be empty")),
                r => Ok(r),
            }
        }
        Meta::NameValue(nv) => Err(err(nv.span(), "use `public` or `public(reason = \"...\")`")),
    }
}

/// Parses policy items (the content of `policy(...)` or bare route-level items).
pub fn parse_policy(items: &[Meta], level: Level) -> syn::Result<PolicyDecl> {
    let mut d = PolicyDecl::default();
    let mut seen: Vec<String> = Vec::new();
    let mut scope_span = None;
    let mut public_span = None;
    for m in items {
        let key = m.path().get_ident().map(|i| i.to_string()).ok_or_else(|| err(m.span(), "expected a policy key"))?;
        let canonical_key = match key.as_str() {
            "max_body" => "body_limit".to_owned(),
            "content_type" => "content_types".to_owned(),
            "public" | "deny_anonymous" => "auth".to_owned(),
            k => k.to_owned(),
        };
        if canonical_key != "auth" || key != "deny_anonymous" {
            if seen.contains(&canonical_key) {
                return Err(err(m.span(), format!("policy key `{key}` is declared more than once")));
            }
            seen.push(canonical_key.clone());
        }
        match key.as_str() {
            "public" => {
                if level == Level::App {
                    return Err(err(
                        m.span(),
                        "`public` is a route/group exception; app defaults cannot be public (omit `auth` instead)",
                    ));
                }
                d.auth = Some(AuthDecl::Public(parse_public(m)?));
                public_span = Some(m.span());
            }
            "deny_anonymous" | "strict" => {
                if level == Level::Route {
                    return Err(err(
                        m.span(),
                        format!("`{key}` applies to app defaults and groups, not to single routes"),
                    ));
                }
                if !matches!(m, Meta::Path(_)) {
                    return Err(err(m.span(), format!("`{key}` takes no value")));
                }
                d.strict = true;
                if key == "deny_anonymous" {
                    if matches!(d.auth, Some(AuthDecl::Public(_))) {
                        return Err(err(m.span(), "`deny_anonymous` contradicts `public` at the same level"));
                    }
                    d.auth = Some(AuthDecl::Required);
                }
            }
            "auth" => {
                let Meta::NameValue(nv) = m else {
                    return Err(err(m.span(), "use `auth = required` or `auth = public`"));
                };
                match ident_of(&nv.value).as_deref() {
                    Some("required") => {
                        if matches!(d.auth, Some(AuthDecl::Public(_))) {
                            return Err(err(m.span(), "`auth = required` contradicts `public`"));
                        }
                        d.auth = Some(AuthDecl::Required)
                    }
                    Some("public") => {
                        if level == Level::App {
                            return Err(err(m.span(), "app defaults cannot be public; omit `auth` instead"));
                        }
                        if d.strict {
                            return Err(err(
                                m.span(),
                                "`auth = public` contradicts `deny_anonymous` at the same level",
                            ));
                        }
                        d.auth = Some(AuthDecl::Public(None));
                        public_span = Some(m.span());
                    }
                    _ => return Err(err(nv.value.span(), "expected `required` or `public`")),
                }
            }
            "scopes" | "roles" => {
                let Meta::NameValue(nv) = m else {
                    return Err(err(m.span(), format!("use `{key} = [\"...\"]`")));
                };
                let v = str_list(&nv.value)?;
                if v.iter().any(|s| s.trim().is_empty()) {
                    return Err(err(nv.value.span(), format!("{key} must not contain empty strings")));
                }
                scope_span = Some(m.span());
                if key == "scopes" {
                    d.scopes = v;
                } else {
                    d.roles = v;
                }
            }
            "body_limit" | "max_body" => {
                let Meta::NameValue(nv) = m else {
                    return Err(err(m.span(), "use `body_limit = \"64KiB\"`"));
                };
                let n = parse_size(&nv.value)?;
                if n == 0 {
                    return Err(err(nv.value.span(), "body_limit must be > 0"));
                }
                d.body_limit = Some(n);
            }
            "content_type" | "content_types" => {
                let Meta::NameValue(nv) = m else {
                    return Err(err(m.span(), "use `content_type = \"application/json\"`"));
                };
                d.content_types = str_list(&nv.value)?.into_iter().map(|s| s.to_ascii_lowercase()).collect();
            }
            "csrf" => {
                let Meta::NameValue(nv) = m else {
                    return Err(err(m.span(), "use `csrf = enforce` or `csrf = exempt(\"reason\")`"));
                };
                d.csrf = Some(match &nv.value {
                    Expr::Path(_) => match ident_of(&nv.value).as_deref() {
                        Some("enforce") => CsrfDecl::Enforce,
                        Some("off" | "disabled" | "none" | "false") => {
                            return Err(err(
                                nv.value.span(),
                                "CSRF protection cannot be disabled without a documented reason; use `csrf = exempt(\"why this endpoint is safe\")`",
                            ));
                        }
                        _ => return Err(err(nv.value.span(), "expected `enforce` or `exempt(\"reason\")`")),
                    },
                    Expr::Call(c) if ident_of(&c.func).as_deref() == Some("exempt") => {
                        let reason = c.args.first().map(lit_str).transpose()?.unwrap_or_default();
                        if reason.trim().is_empty() {
                            return Err(err(c.span(), "`csrf = exempt(..)` requires a non-empty reason"));
                        }
                        CsrfDecl::Exempt(reason)
                    }
                    Expr::Lit(ExprLit { lit: Lit::Bool(_), .. }) => {
                        return Err(err(
                            nv.value.span(),
                            "CSRF protection cannot be toggled with a bool; use `csrf = enforce` or `csrf = exempt(\"reason\")`",
                        ));
                    }
                    _ => return Err(err(nv.value.span(), "expected `enforce` or `exempt(\"reason\")`")),
                });
            }
            "timeout" => {
                let Meta::NameValue(nv) = m else {
                    return Err(err(m.span(), "use `timeout = \"5s\"` or `timeout = none`"));
                };
                d.timeout = Some(match ident_of(&nv.value).as_deref() {
                    Some("none") => TimeoutDecl::Disabled,
                    _ => {
                        let s = lit_str(&nv.value)?;
                        let ms = parse_duration(&s, nv.value.span())?;
                        if ms == 0 {
                            return Err(err(nv.value.span(), "timeout must be > 0 (use `none` to disable)"));
                        }
                        TimeoutDecl::Ms(ms)
                    }
                });
            }
            "rate_limit" => {
                d.rate_limit = Some(match m {
                    Meta::NameValue(nv) => parse_rate_str(&lit_str(&nv.value)?, nv.value.span())?,
                    Meta::List(l) => {
                        let args = l.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
                        let mut requests = None;
                        let mut per = None;
                        let mut principal = false;
                        for a in &args {
                            let Meta::NameValue(nv) = a else {
                                return Err(err(
                                    a.span(),
                                    "expected `requests = N`, `per = \"1s\"`, `key = ip|principal`",
                                ));
                            };
                            match nv.path.get_ident().map(|i| i.to_string()).as_deref() {
                                Some("requests") => {
                                    let Expr::Lit(ExprLit { lit: Lit::Int(i), .. }) = &nv.value else {
                                        return Err(err(nv.value.span(), "expected an integer"));
                                    };
                                    let n: u32 = i.base10_parse()?;
                                    if n == 0 {
                                        return Err(err(i.span(), "requests must be > 0"));
                                    }
                                    requests = Some(n);
                                }
                                Some("per") => per = Some(parse_duration(&lit_str(&nv.value)?, nv.value.span())?),
                                Some("key") => match ident_of(&nv.value).as_deref() {
                                    Some("ip") => principal = false,
                                    Some("principal") => principal = true,
                                    _ => return Err(err(nv.value.span(), "expected `ip` or `principal`")),
                                },
                                _ => return Err(err(nv.path.span(), "unknown rate_limit option")),
                            }
                        }
                        let per_ms = per.unwrap_or(1000);
                        if per_ms == 0 {
                            return Err(err(l.span(), "rate_limit window must be > 0"));
                        }
                        RateDecl {
                            requests: requests
                                .ok_or_else(|| err(l.span(), "rate_limit(..) requires `requests = N`"))?,
                            per_ms,
                            principal,
                        }
                    }
                    Meta::Path(_) => return Err(err(m.span(), "use `rate_limit = \"10/s\"`")),
                });
            }
            other => {
                return Err(err(
                    m.span(),
                    format!(
                        "unknown policy key `{other}` (expected auth, public, deny_anonymous, scopes, roles, body_limit, content_type, csrf, timeout, rate_limit)"
                    ),
                ));
            }
        }
    }
    if matches!(d.auth, Some(AuthDecl::Public(_))) && (!d.scopes.is_empty() || !d.roles.is_empty()) {
        return Err(err(
            scope_span.or(public_span).unwrap_or_else(Span::call_site),
            "a public endpoint cannot require scopes or roles; remove `public` or the scope/role requirement",
        ));
    }
    Ok(d)
}

impl PolicyDecl {
    pub fn tokens(&self) -> TokenStream {
        let p = quote!(::poring::__private);
        let auth = match &self.auth {
            None => quote!(#p::AuthSpec::Inherit),
            Some(AuthDecl::Required) => quote!(#p::AuthSpec::Required),
            Some(AuthDecl::Public(r)) => {
                let r = r.clone().unwrap_or_default();
                quote!(#p::AuthSpec::Public { reason: #r })
            }
        };
        let strict = self.strict;
        let scopes = &self.scopes;
        let roles = &self.roles;
        let body = match self.body_limit {
            Some(n) => quote!(::core::option::Option::Some(#n)),
            None => quote!(::core::option::Option::None),
        };
        let cts = &self.content_types;
        let csrf = match &self.csrf {
            None => quote!(#p::CsrfSpec::Inherit),
            Some(CsrfDecl::Enforce) => quote!(#p::CsrfSpec::Enforce),
            Some(CsrfDecl::Exempt(r)) => quote!(#p::CsrfSpec::Exempt { reason: #r }),
        };
        let timeout = match &self.timeout {
            None => quote!(#p::TimeoutSpec::Inherit),
            Some(TimeoutDecl::Disabled) => quote!(#p::TimeoutSpec::Disabled),
            Some(TimeoutDecl::Ms(ms)) => quote!(#p::TimeoutSpec::Ms(#ms)),
        };
        let rate = match &self.rate_limit {
            None => quote!(::core::option::Option::None),
            Some(r) => {
                let (n, per) = (r.requests, r.per_ms);
                let key = if r.principal { quote!(#p::RateKey::Principal) } else { quote!(#p::RateKey::Ip) };
                quote!(::core::option::Option::Some(#p::RateLimitSpec { requests: #n, per_ms: #per, key: #key }))
            }
        };
        quote! {
            #p::PolicySpec {
                auth: #auth,
                strict: #strict,
                scopes: &[#(#scopes),*],
                roles: &[#(#roles),*],
                body_limit: #body,
                content_types: &[#(#cts),*],
                csrf: #csrf,
                timeout: #timeout,
                rate_limit: #rate,
            }
        }
    }
}

/// Parses `policy(...)` or `policy!(...)` given as an expression/meta.
pub fn parse_policy_meta(m: &Meta, level: Level) -> syn::Result<PolicyDecl> {
    match m {
        Meta::List(l) if l.path.is_ident("policy") => {
            let items = l.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
            parse_policy(&items.into_iter().collect::<Vec<_>>(), level)
        }
        _ => Err(err(m.span(), "expected `policy(...)`")),
    }
}
