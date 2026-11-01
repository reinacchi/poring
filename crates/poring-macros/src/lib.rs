//! Procedural macros for [Poring](https://docs.rs/poring). Use them through the `poring`
//! crate (`#[poring::get]`, `poring::poring_app!`, ...); generated code refers to the
//! documented private namespace `::poring::__private`.
#![forbid(unsafe_code)]

use proc_macro::TokenStream;

mod app;
mod derive;
mod hook;
mod policy;
mod route;
mod util;

fn out(r: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    match r {
        Ok(t) => t.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

macro_rules! method_attr {
    ($($name:ident => $m:literal),*) => {$(
        #[doc = concat!("Declares a `", $m, "` route: `#[poring::", stringify!($name), "(\"/path\", policy(..), before = [..], after = [..], annotate = [..])]`.")]
        #[proc_macro_attribute]
        pub fn $name(attr: TokenStream, item: TokenStream) -> TokenStream {
            out(route::expand(route::Kind::Method($m), attr.into(), item.into()))
        }
    )*};
}

method_attr!(get => "GET", post => "POST", put => "PUT", patch => "PATCH", delete => "DELETE", head => "HEAD", options => "OPTIONS");

/// Declares a route with an explicit method: `#[poring::route(PUT, "/path", ..)]`.
#[proc_macro_attribute]
pub fn route(attr: TokenStream, item: TokenStream) -> TokenStream {
    out(route::expand(route::Kind::Generic, attr.into(), item.into()))
}

/// Declares a WebSocket route (a `GET` that upgrades): `#[poring::ws("/chat")]`.
#[proc_macro_attribute]
pub fn ws(attr: TokenStream, item: TokenStream) -> TokenStream {
    out(route::expand(route::Kind::Ws, attr.into(), item.into()))
}

/// Declares a lifecycle hook (before: `async fn(&mut Ctx<'_, S>) -> R`; after:
/// `async fn(&Ctx<'_, S>, &mut Response)`).
#[proc_macro_attribute]
pub fn hook(attr: TokenStream, item: TokenStream) -> TokenStream {
    out(hook::expand(attr.into(), item.into()))
}

/// Assembles an application from routes, groups, plugins, hooks and policies, and
/// generates whole-app compile-time checks.
#[proc_macro]
pub fn poring_app(input: TokenStream) -> TokenStream {
    out(app::expand_app(input.into()))
}

/// Declares a reusable plugin (a group of routes and hooks generic over any app state
/// that satisfies its requirements).
#[proc_macro]
pub fn poring_plugin(input: TokenStream) -> TokenStream {
    out(app::expand_plugin(input.into()))
}

/// Derives the request/response contract (JSON Schema + validation rules).
#[proc_macro_derive(PoringSchema, attributes(poring))]
pub fn derive_schema(input: TokenStream) -> TokenStream {
    out(derive::expand_schema(input.into()))
}

/// Derives `FromRef<Self>` for every field type, making each field available as `State<T>`.
#[proc_macro_derive(PoringState, attributes(poring))]
pub fn derive_state(input: TokenStream) -> TokenStream {
    out(derive::expand_state(input.into()))
}
