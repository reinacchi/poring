//! `#[poring::hook]`: turns an `async fn` into a statically dispatched lifecycle hook.
//!
//! * `async fn name(cx: &mut Ctx<'_, S>) -> R` becomes a *before* hook (guard). `R` is
//!   `()`, `Result<(), E: IntoResponse>` or `Option<Response>`; `Err`/`Some` short-circuits.
//! * `async fn name(cx: &Ctx<'_, S>, res: &mut Response)` becomes an *after* hook.

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{FnArg, GenericArgument, ItemFn, PathArguments, Type};

use crate::util::err;

fn ctx_state(ty: &Type) -> Option<(Type, bool)> {
    let Type::Reference(r) = ty else { return None };
    let Type::Path(p) = &*r.elem else { return None };
    let seg = p.path.segments.last()?;
    if seg.ident != "Ctx" {
        return None;
    }
    let PathArguments::AngleBracketed(a) = &seg.arguments else {
        return None;
    };
    let st = a.args.iter().find_map(|g| match g {
        GenericArgument::Type(t) => Some(t.clone()),
        _ => None,
    })?;
    Some((st, r.mutability.is_some()))
}

pub fn expand(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    if !attr.is_empty() {
        return Err(err(attr.span(), "#[poring::hook] takes no arguments"));
    }
    let func: ItemFn = syn::parse2(item)?;
    let name = &func.sig.ident;
    let vis = &func.vis;
    let name_str = name.to_string();
    let p = quote!(::poring::__private);
    let inputs: Vec<&FnArg> = func.sig.inputs.iter().collect();
    let first = inputs.first().ok_or_else(|| {
        err(
            func.sig.span(),
            "a hook takes `cx: &mut Ctx<'_, S>` (before) or `cx: &Ctx<'_, S>, res: &mut Response` (after)",
        )
    })?;
    let FnArg::Typed(first) = first else {
        return Err(err(first.span(), "hooks must be free functions"));
    };
    let (state, mutable) = ctx_state(&first.ty).ok_or_else(|| {
        err(
            first.ty.span(),
            "the first hook argument must be `&mut Ctx<'_, S>` or `&Ctx<'_, S>`",
        )
    })?;
    let (impl_generics, _, where_clause) = func.sig.generics.split_for_impl();
    let await_ = if func.sig.asyncness.is_some() {
        quote!(.await)
    } else {
        quote!()
    };
    let body = match inputs.len() {
        1 => {
            if !mutable {
                return Err(err(
                    first.ty.span(),
                    "a before hook takes `&mut Ctx<'_, S>`",
                ));
            }
            quote! {
                impl #impl_generics #p::BeforeHook<#state> for #name #where_clause {
                    const NAME: &'static str = #name_str;
                    fn before<'__a, '__c>(cx: &'__c mut #p::Ctx<'__a, #state>)
                        -> impl ::core::future::Future<Output = ::core::result::Result<(), #p::Response>> + ::core::marker::Send + '__c
                    {
                        async move { #p::HookOutcome::into_outcome(#name(cx)#await_) }
                    }
                }
            }
        }
        2 => {
            if mutable {
                return Err(err(
                    first.ty.span(),
                    "an after hook takes `&Ctx<'_, S>` as its first argument",
                ));
            }
            quote! {
                impl #impl_generics #p::AfterHook<#state> for #name #where_clause {
                    const NAME: &'static str = #name_str;
                    fn after<'__a, '__c>(cx: &'__c #p::Ctx<'__a, #state>, res: &'__c mut #p::Response)
                        -> impl ::core::future::Future<Output = ()> + ::core::marker::Send + '__c
                    {
                        async move { let _: () = #name(cx, res)#await_; }
                    }
                }
            }
        }
        _ => {
            return Err(err(
                func.sig.inputs.span(),
                "a hook takes `cx: &mut Ctx<'_, S>` (before) or `cx: &Ctx<'_, S>, res: &mut Response` (after)",
            ));
        }
    };
    Ok(quote! {
        #func

        #[doc(hidden)]
        #[allow(non_camel_case_types)]
        #vis struct #name {}

        #body
    })
}
