//! `#[get]`, `#[post]`, ..., `#[route(METHOD, ..)]`, `#[ws]` attribute macros.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    Expr, FnArg, GenericArgument, Ident, ItemFn, LitStr, Meta, PathArguments, ReturnType, Token,
    Type,
};

use crate::policy::{Level, PolicyDecl, parse_policy, parse_policy_meta, str_list};
use crate::util::{canonicalise, doc_summary, err, pretty};

pub struct RouteArgs {
    method: Option<Ident>,
    path: LitStr,
    items: Vec<Meta>,
}

pub fn parse_args(input: ParseStream<'_>, with_method: bool) -> syn::Result<RouteArgs> {
    let method = if with_method {
        let m: Ident = input.parse()?;
        input.parse::<Token![,]>()?;
        Some(m)
    } else {
        None
    };
    let path: LitStr = input.parse().map_err(|e| {
        syn::Error::new(
            e.span(),
            "expected the route path as a string literal, e.g. #[poring::get(\"/users/{id}\")]",
        )
    })?;
    let mut items = Vec::new();
    if input.peek(Token![,]) {
        input.parse::<Token![,]>()?;
        let rest = Punctuated::<Meta, Token![,]>::parse_terminated(input)?;
        items.extend(rest);
    }
    Ok(RouteArgs {
        method,
        path,
        items,
    })
}

struct WithMethod(RouteArgs);
impl Parse for WithMethod {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        parse_args(input, true).map(WithMethod)
    }
}
struct NoMethod(RouteArgs);
impl Parse for NoMethod {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        parse_args(input, false).map(NoMethod)
    }
}

fn hook_paths(e: &Expr) -> syn::Result<Vec<syn::Path>> {
    match e {
        Expr::Array(a) => a
            .elems
            .iter()
            .map(|x| match x {
                Expr::Path(p) => Ok(p.path.clone()),
                _ => Err(err(
                    x.span(),
                    "expected a hook path (a function annotated with #[poring::hook])",
                )),
            })
            .collect(),
        Expr::Path(p) => Ok(vec![p.path.clone()]),
        _ => Err(err(e.span(), "expected `[hook_a, hook_b]`")),
    }
}

fn method_variant(m: &str, span: Span) -> syn::Result<TokenStream> {
    let v = match m.to_ascii_uppercase().as_str() {
        "GET" => quote!(Get),
        "POST" => quote!(Post),
        "PUT" => quote!(Put),
        "PATCH" => quote!(Patch),
        "DELETE" => quote!(Delete),
        "HEAD" => quote!(Head),
        "OPTIONS" => quote!(Options),
        other => {
            return Err(err(
                span,
                format!(
                    "unsupported method `{other}` (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)"
                ),
            ));
        }
    };
    Ok(quote!(::poring::__private::Method::#v))
}

fn last_ident(ty: &Type) -> Option<(&Ident, &PathArguments)> {
    match ty {
        Type::Path(p) => p.path.segments.last().map(|s| (&s.ident, &s.arguments)),
        _ => None,
    }
}

fn first_generic(args: &PathArguments) -> Option<&Type> {
    match args {
        PathArguments::AngleBracketed(a) => a.args.iter().find_map(|g| match g {
            GenericArgument::Type(t) => Some(t),
            _ => None,
        }),
        _ => None,
    }
}

const SCALARS: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32",
    "f64", "bool", "char", "String",
];

/// Compile-time `Path<T>` shape checks against the declared parameters.
fn check_path_extractor(ty: &Type, params: &[String], path: &str) -> syn::Result<()> {
    let Some((id, args)) = last_ident(ty) else {
        return Ok(());
    };
    if id != "Path" {
        return Ok(());
    }
    if params.is_empty() {
        return Err(err(
            ty.span(),
            format!(
                "`{}` used, but route `{path}` declares no path parameters",
                pretty(ty)
            ),
        ));
    }
    let Some(inner) = first_generic(args) else {
        return Ok(());
    };
    match inner {
        Type::Tuple(t) if t.elems.len() != params.len() => Err(err(
            ty.span(),
            format!(
                "`{}` extracts {} values, but route `{path}` declares {} parameter(s): {}",
                pretty(ty),
                t.elems.len(),
                params.len(),
                params.join(", ")
            ),
        )),
        Type::Path(_) if params.len() != 1 => match last_ident(inner) {
            Some((i, _)) if SCALARS.contains(&i.to_string().as_str()) => Err(err(
                ty.span(),
                format!(
                    "`{}` extracts one value, but route `{path}` declares {} parameters ({}); use a tuple or a struct",
                    pretty(ty),
                    params.len(),
                    params.join(", ")
                ),
            )),
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}

pub enum Kind {
    Method(&'static str),
    Generic,
    Ws,
}

pub fn expand(kind: Kind, attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let args = match kind {
        Kind::Generic => syn::parse2::<WithMethod>(attr)?.0,
        _ => syn::parse2::<NoMethod>(attr)?.0,
    };
    let func: ItemFn = syn::parse2(item)?;
    let (method_str, method_span) = match (&kind, &args.method) {
        (Kind::Method(m), _) => (m.to_string(), args.path.span()),
        (Kind::Ws, _) => ("GET".to_owned(), args.path.span()),
        (Kind::Generic, Some(m)) => (m.to_string(), m.span()),
        (Kind::Generic, None) => return Err(err(Span::call_site(), "expected a method")),
    };
    let method = method_variant(&method_str, method_span)?;
    let upper = method_str.to_ascii_uppercase();
    let (canon, params) = canonicalise(&args.path.value()).map_err(|m| err(args.path.span(), m))?;

    let mut policy = PolicyDecl::default();
    let mut policy_set = false;
    let mut before: Vec<syn::Path> = Vec::new();
    let mut after: Vec<syn::Path> = Vec::new();
    let mut annotations: Vec<String> = Vec::new();
    for m in &args.items {
        let key = m
            .path()
            .get_ident()
            .map(|i| i.to_string())
            .unwrap_or_default();
        match key.as_str() {
            "policy" => {
                if policy_set {
                    return Err(err(m.span(), "policy declared more than once"));
                }
                policy = parse_policy_meta(m, Level::Route)?;
                policy_set = true;
            }
            "public" => {
                if policy_set {
                    return Err(err(
                        m.span(),
                        "declare `public` inside `policy(..)` when a policy is also given",
                    ));
                }
                policy = parse_policy(std::slice::from_ref(m), Level::Route)?;
                policy_set = true;
            }
            "before" | "after" => {
                let Meta::NameValue(nv) = m else {
                    return Err(err(m.span(), format!("use `{key} = [hook, ..]`")));
                };
                let v = hook_paths(&nv.value)?;
                if key == "before" {
                    before = v
                } else {
                    after = v
                }
            }
            "annotate" => {
                let Meta::NameValue(nv) = m else {
                    return Err(err(m.span(), "use `annotate = [\"db: load user\"]`"));
                };
                annotations = str_list(&nv.value)?;
            }
            _ => {
                return Err(err(
                    m.span(),
                    format!(
                        "unknown route option `{key}` (expected policy(..), public, before = [..], after = [..], annotate = [..])"
                    ),
                ));
            }
        }
    }

    if !func.sig.generics.params.is_empty() {
        return Err(err(
            func.sig.generics.span(),
            "route handlers cannot be generic; Poring monomorphises the app state in poring_app!",
        ));
    }
    let name = &func.sig.ident;
    let vis = &func.vis;
    let is_async = func.sig.asyncness.is_some();
    let mut tys: Vec<&Type> = Vec::new();
    for a in &func.sig.inputs {
        match a {
            FnArg::Receiver(r) => {
                return Err(err(
                    r.span(),
                    "route handlers must be free functions (no `self`)",
                ));
            }
            FnArg::Typed(t) => {
                if matches!(*t.ty, Type::ImplTrait(_)) {
                    return Err(err(
                        t.ty.span(),
                        "`impl Trait` is not supported as an extractor type",
                    ));
                }
                check_path_extractor(&t.ty, &params, &canon)?;
                tys.push(&t.ty);
            }
        }
    }

    let p = quote!(::poring::__private);
    let name_str = name.to_string();
    let doc = doc_summary(&func.attrs);
    let ws = matches!(kind, Kind::Ws);
    let policy_tokens = policy.tokens();
    let ty_strs: Vec<String> = tys.iter().map(|t| pretty(*t)).collect();
    let before_strs: Vec<String> = before.iter().map(pretty).collect();
    let after_strs: Vec<String> = after.iter().map(pretty).collect();
    let line = quote_spanned!(name.span()=> ::core::line!());

    let mut asserts = Vec::new();
    let n = tys.len();
    for (i, ty) in tys.iter().enumerate() {
        if i + 1 < n {
            let msg = format!(
                "poring: argument {} (`{}`) of handler `{}` reads the request body; only the last argument may read the body",
                i + 1,
                ty_strs[i],
                name_str
            );
            asserts.push(quote_spanned! {ty.span()=>
                const _: () = ::core::assert!(!<#ty as #p::ExtractorMeta>::CONSUMES_BODY, #msg);
            });
        } else if upper == "GET" || upper == "HEAD" {
            let msg = format!(
                "poring: {upper} handler `{name_str}` reads the request body via `{}`; {upper} requests have no defined body semantics",
                ty_strs[i]
            );
            asserts.push(quote_spanned! {ty.span()=>
                const _: () = ::core::assert!(!<#ty as #p::ExtractorMeta>::CONSUMES_BODY, #msg);
            });
        }
    }

    let arg_idents: Vec<Ident> = (0..n).map(|i| format_ident!("__poring_arg{}", i)).collect();
    let extract_steps = tys.iter().zip(&arg_idents).map(|(ty, id)| {
        quote_spanned! {ty.span()=>
            cx.__mark_extract();
            let #id = match <#ty as #p::FromRequest<S>>::from_request(cx).await {
                ::core::result::Result::Ok(v) => v,
                ::core::result::Result::Err(e) => {
                    #p::mark(cx, #p::Stage::Reject);
                    return #p::IntoResponse::into_response(e);
                }
            };
        }
    });
    let call = if is_async {
        quote!(#name(#(#arg_idents),*).await)
    } else {
        quote!(#name(#(#arg_idents),*))
    };
    let ret_ty: Type = match &func.sig.output {
        ReturnType::Default => syn::parse_quote!(()),
        ReturnType::Type(_, t) => (**t).clone(),
    };
    let has_impl = ret_ty_contains_impl(&ret_ty);
    let response_fn = if has_impl {
        quote!({
            fn __poring_response(_: &mut #p::SchemaRegistry) -> ::std::vec::Vec<#p::ResponseDoc> { ::std::vec::Vec::new() }
            __poring_response
        })
    } else {
        quote!({
            fn __poring_response(reg: &mut #p::SchemaRegistry) -> ::std::vec::Vec<#p::ResponseDoc> {
                #[allow(unused_imports)]
                use #p::{DescribeFallback as _, DescribeViaTrait as _};
                (&&#p::Probe::<#ret_ty>::new()).__poring_describe(reg)
            }
            __poring_response
        })
    };

    let ret_span = match &func.sig.output {
        ReturnType::Default => name.span(),
        ReturnType::Type(_, t) => t.span(),
    };
    let respond_call = quote_spanned!(ret_span=> (&mut &mut __w).__poring_respond());
    let before_bounds = before
        .iter()
        .map(|h| quote_spanned!(h.span()=> #h: #p::BeforeHook<S>,));
    let after_bounds = after
        .iter()
        .map(|h| quote_spanned!(h.span()=> #h: #p::AfterHook<S>,));
    let before_calls = before.iter().map(|h| {
        quote_spanned! {h.span()=>
            cx.__mark_before();
            <#h as #p::BeforeHook<S>>::before(cx).await?;
        }
    });
    let after_calls = after.iter().map(|h| {
        quote_spanned! {h.span()=>
            cx.__mark_after();
            <#h as #p::AfterHook<S>>::after(cx, res).await;
        }
    });
    let ty_bounds = tys
        .iter()
        .map(|ty| quote_spanned!(ty.span()=> #ty: #p::FromRequest<S>,));
    let param_strs = &params;

    Ok(quote! {
        #func

        #[doc(hidden)]
        #[allow(non_camel_case_types)]
        #vis struct #name {}

        #(#asserts)*

        impl #p::RouteInfo for #name {
            const DESCRIPTOR: #p::RouteDescriptor = #p::RouteDescriptor {
                name: #name_str,
                method: #method,
                path: #canon,
                params: &[#(#param_strs),*],
                extractors: &[#( #p::extractor::<#tys>(#ty_strs) ),*],
                before: &[#(#before_strs),*],
                after: &[#(#after_strs),*],
                policy: #policy_tokens,
                annotations: &[#(#annotations),*],
                doc: #doc,
                file: ::core::file!(),
                line: #line,
                websocket: #ws,
                response: #response_fn,
            };
        }

        impl<S> #p::RouteHandler<S> for #name
        where
            S: ::core::marker::Send + ::core::marker::Sync + 'static,
            #(#ty_bounds)*
            #(#before_bounds)*
            #(#after_bounds)*
        {
            #[allow(clippy::needless_lifetimes)]
            fn before<'a, 'c>(cx: &'c mut #p::Ctx<'a, S>)
                -> impl ::core::future::Future<Output = ::core::result::Result<(), #p::Response>> + ::core::marker::Send + 'c
            {
                async move {
                    #(#before_calls)*
                    let _ = &cx;
                    ::core::result::Result::Ok(())
                }
            }

            #[allow(clippy::needless_lifetimes, unused_mut)]
            fn handle<'a, 'c>(cx: &'c mut #p::Ctx<'a, S>)
                -> impl ::core::future::Future<Output = #p::Response> + ::core::marker::Send + 'c
            {
                async move {
                    #(#extract_steps)*
                    #p::mark(cx, #p::Stage::Handler);
                    let __ret = #call;
                    let mut __w = #p::Wrap(::core::option::Option::Some(__ret));
                    #[allow(unused_imports)]
                    use #p::{RespondPlain as _, RespondResult as _};
                    let (__res, __is_err) = #respond_call;
                    if __is_err {
                        #p::mark(cx, #p::Stage::Error);
                    }
                    __res
                }
            }

            #[allow(clippy::needless_lifetimes)]
            fn after<'a, 'c>(cx: &'c mut #p::Ctx<'a, S>, res: &'c mut #p::Response)
                -> impl ::core::future::Future<Output = ()> + ::core::marker::Send + 'c
            {
                async move {
                    #(#after_calls)*
                    let _ = (&cx, &res);
                }
            }
        }
    })
}

fn ret_ty_contains_impl(t: &Type) -> bool {
    let s = quote!(#t).to_string();
    s.contains("impl ")
}
