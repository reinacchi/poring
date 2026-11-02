//! `#[derive(PoringSchema)]` and `#[derive(PoringState)]`.

use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Expr, ExprLit, Fields, Lit, Meta, Token, Type};

use crate::policy::lit_str;
use crate::util::{doc_summary, err};

fn serde_metas(attrs: &[syn::Attribute], which: &str) -> syn::Result<Vec<Meta>> {
    let mut out = Vec::new();
    for a in attrs {
        if a.path().is_ident(which) {
            let items = a.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
            out.extend(items);
        }
    }
    Ok(out)
}

fn rename_case(name: &str, rule: &str, is_variant: bool) -> String {
    // Split into words: fields are snake_case, variants are PascalCase.
    let words: Vec<String> = if is_variant {
        let mut w = Vec::new();
        let mut cur = String::new();
        for c in name.chars() {
            if c.is_uppercase() && !cur.is_empty() {
                w.push(cur.clone());
                cur.clear();
            }
            cur.push(c);
        }
        if !cur.is_empty() {
            w.push(cur);
        }
        w.into_iter().map(|s| s.to_lowercase()).collect()
    } else {
        name.split('_')
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase)
            .collect()
    };
    let cap = |s: &str| {
        let mut c = s.chars();
        match c.next() {
            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            None => String::new(),
        }
    };
    match rule {
        "lowercase" => words.concat(),
        "UPPERCASE" => words.concat().to_uppercase(),
        "PascalCase" => words.iter().map(|w| cap(w)).collect(),
        "camelCase" => words
            .iter()
            .enumerate()
            .map(|(i, w)| if i == 0 { w.clone() } else { cap(w) })
            .collect(),
        "snake_case" => words.join("_"),
        "SCREAMING_SNAKE_CASE" => words.join("_").to_uppercase(),
        "kebab-case" => words.join("-"),
        "SCREAMING-KEBAB-CASE" => words.join("-").to_uppercase(),
        _ => name.to_owned(),
    }
}

fn is_named(ty: &Type, n: &str) -> bool {
    matches!(ty, Type::Path(p) if p.path.segments.last().map(|s| s.ident == n).unwrap_or(false))
}

fn inner_is_vec(ty: &Type) -> bool {
    if is_named(ty, "Vec") {
        return true;
    }
    if let Type::Path(p) = ty
        && let Some(seg) = p.path.segments.last()
        && seg.ident == "Option"
        && let syn::PathArguments::AngleBracketed(a) = &seg.arguments
        && let Some(syn::GenericArgument::Type(t)) = a.args.first()
    {
        return is_named(t, "Vec");
    }
    false
}

struct FieldRules {
    schema_kv: Vec<(String, TokenStream)>,
    checks: Vec<TokenStream>,
}

fn field_rules(
    attrs: &[syn::Attribute],
    ty: &Type,
    access: &TokenStream,
) -> syn::Result<FieldRules> {
    let p = quote!(::poring::__private);
    let mut r = FieldRules {
        schema_kv: Vec::new(),
        checks: Vec::new(),
    };
    let vec = inner_is_vec(ty);
    for m in serde_metas(attrs, "poring")? {
        let key = m
            .path()
            .get_ident()
            .map(|i| i.to_string())
            .unwrap_or_default();
        let num = |m: &Meta| -> syn::Result<Expr> {
            match m {
                Meta::NameValue(nv) => Ok(nv.value.clone()),
                _ => Err(err(m.span(), format!("use `{key} = <number>`"))),
            }
        };
        match key.as_str() {
            "min_length" | "max_length" => {
                let v = num(&m)?;
                let n: usize = match &v {
                    Expr::Lit(ExprLit {
                        lit: Lit::Int(i), ..
                    }) => i.base10_parse()?,
                    _ => return Err(err(v.span(), "expected an integer")),
                };
                let kw = match (key.as_str(), vec) {
                    ("min_length", true) => "minItems",
                    ("max_length", true) => "maxItems",
                    ("min_length", false) => "minLength",
                    _ => "maxLength",
                };
                r.schema_kv.push((kw.to_owned(), quote!(#n)));
                let f = if key == "min_length" {
                    quote!(min_length)
                } else {
                    quote!(max_length)
                };
                r.checks
                    .push(quote_spanned!(m.span()=> #p::rules::#f(cx, &#access, #n);));
            }
            "minimum" | "maximum" => {
                let v = num(&m)?;
                let x: f64 = match &v {
                    Expr::Lit(ExprLit {
                        lit: Lit::Int(i), ..
                    }) => i.base10_parse::<i64>()? as f64,
                    Expr::Lit(ExprLit {
                        lit: Lit::Float(f), ..
                    }) => f.base10_parse()?,
                    Expr::Unary(u) => match &*u.expr {
                        Expr::Lit(ExprLit {
                            lit: Lit::Int(i), ..
                        }) => -(i.base10_parse::<i64>()? as f64),
                        Expr::Lit(ExprLit {
                            lit: Lit::Float(f), ..
                        }) => -f.base10_parse::<f64>()?,
                        _ => return Err(err(v.span(), "expected a number")),
                    },
                    _ => return Err(err(v.span(), "expected a number")),
                };
                let schema_lit = match &v {
                    Expr::Lit(ExprLit {
                        lit: Lit::Int(i), ..
                    }) => {
                        let n: i64 = i.base10_parse()?;
                        quote!(#n)
                    }
                    Expr::Unary(u)
                        if matches!(
                            &*u.expr,
                            Expr::Lit(ExprLit {
                                lit: Lit::Int(_),
                                ..
                            })
                        ) =>
                    {
                        let n = x as i64;
                        quote!(#n)
                    }
                    _ => quote!(#x),
                };
                r.schema_kv.push((key.clone(), schema_lit));
                let f = if key == "minimum" {
                    quote!(minimum)
                } else {
                    quote!(maximum)
                };
                r.checks
                    .push(quote_spanned!(m.span()=> #p::rules::#f(cx, &#access, #x);));
            }
            "non_empty" => {
                let kw = if vec { "minItems" } else { "minLength" };
                r.schema_kv.push((kw.to_owned(), quote!(1)));
                r.checks
                    .push(quote_spanned!(m.span()=> #p::rules::non_empty(cx, &#access);));
            }
            "ascii" => {
                r.schema_kv
                    .push(("pattern".to_owned(), quote!("^[\\x20-\\x7E]*$")));
                r.checks
                    .push(quote_spanned!(m.span()=> #p::rules::ascii(cx, &#access);));
            }
            _ => {
                return Err(err(
                    m.span(),
                    format!(
                        "unknown validation rule `{key}` (min_length, max_length, minimum, maximum, non_empty, ascii)"
                    ),
                ));
            }
        }
    }
    Ok(r)
}

fn merge_kv(schema: TokenStream, kv: &[(String, TokenStream)]) -> TokenStream {
    if kv.is_empty() {
        return schema;
    }
    let p = quote!(::poring::__private);
    let inserts = kv
        .iter()
        .map(|(k, v)| quote!(__m.insert(#k.to_owned(), #p::serde_json::json!(#v));));
    quote!({
        let __s = #schema;
        let mut __s = if __s.get("$ref").is_some() { #p::serde_json::json!({"allOf": [__s]}) } else { __s };
        if let ::core::option::Option::Some(__m) = __s.as_object_mut() { #(#inserts)* }
        __s
    })
}

pub fn expand_schema(input: TokenStream) -> syn::Result<TokenStream> {
    let d: DeriveInput = syn::parse2(input)?;
    let p = quote!(::poring::__private);
    let name = &d.ident;
    let mut generics = d.generics.clone();
    let generic = !generics.params.is_empty();
    for tp in generics.type_params_mut() {
        tp.bounds.push(syn::parse_quote!(::poring::PoringSchema));
    }
    let (ig, tg, wc) = generics.split_for_impl();
    let container = serde_metas(&d.attrs, "serde")?;
    let mut rename_all: Option<String> = None;
    let mut deny_unknown = false;
    let mut comp_name = name.to_string();
    for m in &container {
        let key = m
            .path()
            .get_ident()
            .map(|i| i.to_string())
            .unwrap_or_default();
        match (key.as_str(), m) {
            ("rename_all", Meta::NameValue(nv)) => rename_all = Some(lit_str(&nv.value)?),
            ("deny_unknown_fields", _) => deny_unknown = true,
            ("rename", Meta::NameValue(nv)) => comp_name = lit_str(&nv.value)?,
            ("tag" | "content" | "untagged", _) => {
                return Err(err(
                    m.span(),
                    "PoringSchema does not support tagged/untagged enum representations yet",
                ));
            }
            _ => {}
        }
    }
    let doc = doc_summary(&d.attrs);

    let (schema_body, validate_body, has_rules) = match &d.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(f) => {
                let mut props = Vec::new();
                let mut required = Vec::new();
                let mut checks = Vec::new();
                let mut rule_flags = Vec::new();
                for field in &f.named {
                    let ident = field
                        .ident
                        .as_ref()
                        .ok_or_else(|| err(field.span(), "unnamed field"))?;
                    let ty = &field.ty;
                    let fmetas = serde_metas(&field.attrs, "serde")?;
                    let mut fname = match &rename_all {
                        Some(r) => rename_case(&ident.to_string(), r, false),
                        None => ident.to_string(),
                    };
                    let mut skip = false;
                    let mut has_default = false;
                    for m in &fmetas {
                        let key = m
                            .path()
                            .get_ident()
                            .map(|i| i.to_string())
                            .unwrap_or_default();
                        match (key.as_str(), m) {
                            ("rename", Meta::NameValue(nv)) => fname = lit_str(&nv.value)?,
                            ("skip" | "skip_deserializing", _) => skip = true,
                            ("default", _) => has_default = true,
                            ("flatten", _) => {
                                return Err(err(
                                    m.span(),
                                    "PoringSchema does not support `#[serde(flatten)]` yet",
                                ));
                            }
                            _ => {}
                        }
                    }
                    if skip {
                        continue;
                    }
                    let access = quote!(self.#ident);
                    let rules = field_rules(&field.attrs, ty, &access)?;
                    let fdoc = doc_summary(&field.attrs);
                    let base = quote!(<#ty as ::poring::PoringSchema>::schema(reg));
                    let mut kv = rules.schema_kv.clone();
                    if !fdoc.is_empty() {
                        kv.push(("description".into(), quote!(#fdoc)));
                    }
                    let fs = merge_kv(base, &kv);
                    props.push(quote!(__props.insert(#fname.to_owned(), #fs);));
                    if !has_default && !is_named(ty, "Option") {
                        required.push(fname.clone());
                    }
                    let c = &rules.checks;
                    if rules.checks.is_empty() {
                        rule_flags.push(quote!(<#ty as ::poring::PoringSchema>::HAS_RULES));
                        checks.push(quote! {
                            if <#ty as ::poring::PoringSchema>::HAS_RULES {
                                cx.at(#fname, |cx| ::poring::PoringSchema::validate(&self.#ident, cx));
                            }
                        });
                    } else {
                        rule_flags.push(quote!(true));
                        checks.push(quote! {
                            cx.at(#fname, |cx| {
                                #(#c)*
                                if <#ty as ::poring::PoringSchema>::HAS_RULES {
                                    ::poring::PoringSchema::validate(&self.#ident, cx);
                                }
                            });
                        });
                    }
                }
                let addl = if deny_unknown {
                    quote!(__o.insert("additionalProperties".to_owned(), #p::serde_json::Value::Bool(false));)
                } else {
                    quote!()
                };
                let desc = if doc.is_empty() {
                    quote!()
                } else {
                    quote!(__o.insert("description".to_owned(), #p::serde_json::json!(#doc));)
                };
                let schema = quote!({
                    let mut __props = #p::serde_json::Map::new();
                    #(#props)*
                    let mut __o = #p::serde_json::Map::new();
                    __o.insert("type".to_owned(), #p::serde_json::json!("object"));
                    __o.insert("properties".to_owned(), #p::serde_json::Value::Object(__props));
                    __o.insert("required".to_owned(), #p::serde_json::json!([#(#required),*]));
                    #addl
                    #desc
                    #p::serde_json::Value::Object(__o)
                });
                (
                    schema,
                    quote!(#(#checks)*),
                    quote!(false #(|| #rule_flags)*),
                )
            }
            Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                let field = &f.unnamed[0];
                let ty = &field.ty;
                let access = quote!(self.0);
                let rules = field_rules(&field.attrs, ty, &access)?;
                let schema = merge_kv(
                    quote!(<#ty as ::poring::PoringSchema>::schema(reg)),
                    &rules.schema_kv,
                );
                let c = &rules.checks;
                let flag = if rules.checks.is_empty() {
                    quote!(<#ty as ::poring::PoringSchema>::HAS_RULES)
                } else {
                    quote!(true)
                };
                (
                    schema,
                    quote! {
                        #(#c)*
                        if <#ty as ::poring::PoringSchema>::HAS_RULES { ::poring::PoringSchema::validate(&self.0, cx); }
                    },
                    flag,
                )
            }
            Fields::Unnamed(f) => {
                let tys: Vec<&Type> = f.unnamed.iter().map(|x| &x.ty).collect();
                let idx = (0..tys.len()).map(syn::Index::from);
                let n = tys.len();
                (
                    quote!(#p::serde_json::json!({
                        "type": "array",
                        "prefixItems": [#(<#tys as ::poring::PoringSchema>::schema(reg)),*],
                        "minItems": #n, "maxItems": #n
                    })),
                    quote!(#( cx.at(#idx, |cx| ::poring::PoringSchema::validate(&self.#idx, cx)); )*),
                    quote!(false #(|| <#tys as ::poring::PoringSchema>::HAS_RULES)*),
                )
            }
            Fields::Unit => (
                quote!(#p::serde_json::json!({"type": "null"})),
                quote!(),
                quote!(false),
            ),
        },
        Data::Enum(e) => {
            let mut names = Vec::new();
            for v in &e.variants {
                if !matches!(v.fields, Fields::Unit) {
                    return Err(err(
                        v.span(),
                        "PoringSchema supports only fieldless enums (serialised as strings) for now",
                    ));
                }
                let mut n = match &rename_all {
                    Some(r) => rename_case(&v.ident.to_string(), r, true),
                    None => v.ident.to_string(),
                };
                let mut skip = false;
                for m in serde_metas(&v.attrs, "serde")? {
                    let key = m
                        .path()
                        .get_ident()
                        .map(|i| i.to_string())
                        .unwrap_or_default();
                    match (key.as_str(), &m) {
                        ("rename", Meta::NameValue(nv)) => n = lit_str(&nv.value)?,
                        ("skip" | "skip_deserializing", _) => skip = true,
                        _ => {}
                    }
                }
                if !skip {
                    names.push(n);
                }
            }
            (
                quote!(#p::serde_json::json!({"type": "string", "enum": [#(#names),*]})),
                quote!(),
                quote!(false),
            )
        }
        Data::Union(u) => {
            return Err(err(
                u.union_token.span(),
                "PoringSchema cannot be derived for unions",
            ));
        }
    };

    let schema_fn = if generic {
        quote!(#schema_body)
    } else {
        quote!(reg.component(#comp_name, |reg| #schema_body))
    };
    Ok(quote! {
        impl #ig ::poring::PoringSchema for #name #tg #wc {
            const HAS_RULES: bool = #has_rules;
            #[allow(unused_variables)]
            fn schema(reg: &mut #p::SchemaRegistry) -> #p::serde_json::Value {
                #schema_fn
            }
            #[allow(unused_variables)]
            fn validate(&self, cx: &mut #p::ValidationCx) {
                #validate_body
            }
        }
    })
}

pub fn expand_state(input: TokenStream) -> syn::Result<TokenStream> {
    let d: DeriveInput = syn::parse2(input)?;
    let name = &d.ident;
    if !d.generics.params.is_empty() {
        return Err(err(
            d.generics.span(),
            "PoringState cannot be derived for generic structs",
        ));
    }
    let Data::Struct(s) = &d.data else {
        return Err(err(
            d.ident.span(),
            "PoringState can only be derived for structs with named fields",
        ));
    };
    let Fields::Named(f) = &s.fields else {
        return Err(err(
            d.ident.span(),
            "PoringState can only be derived for structs with named fields",
        ));
    };
    let mut impls = Vec::new();
    for field in &f.named {
        let mut skip = false;
        for m in serde_metas(&field.attrs, "poring")? {
            if m.path().is_ident("skip") {
                skip = true;
            } else {
                return Err(err(m.span(), "PoringState supports only `#[poring(skip)]`"));
            }
        }
        if skip {
            continue;
        }
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| err(field.span(), "unnamed field"))?;
        let ty = &field.ty;
        impls.push(quote_spanned! {field.span()=>
            impl ::poring::__private::FromRef<#name> for #ty {
                fn from_ref(state: &#name) -> Self {
                    ::core::clone::Clone::clone(&state.#ident)
                }
            }
        });
    }
    Ok(quote!(#(#impls)*))
}
