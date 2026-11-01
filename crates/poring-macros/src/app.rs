//! `poring_app!` and `poring_plugin!`.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    Attribute, Expr, ExprLit, Ident, Lit, LitStr, Meta, Path, Token, Type, Visibility, braced, bracketed, parenthesized,
};

use crate::policy::{Level, PolicyDecl, parse_policy, str_list};
use crate::util::{err, pretty, validate_prefix};

fn parse_path_list(input: ParseStream<'_>) -> syn::Result<Vec<Path>> {
    let content;
    bracketed!(content in input);
    Ok(Punctuated::<Path, Token![,]>::parse_terminated(&content)?.into_iter().collect())
}

/// Parses `name(...)` or `name!(...)` and returns the inner metas.
fn parse_call_metas(input: ParseStream<'_>, expected: &str) -> syn::Result<(Vec<Meta>, Span)> {
    let id: Ident = input.parse()?;
    if id != expected {
        return Err(err(id.span(), format!("expected `{expected}(...)`")));
    }
    if input.peek(Token![!]) {
        input.parse::<Token![!]>()?;
    }
    let content;
    parenthesized!(content in input);
    let items = Punctuated::<Meta, Token![,]>::parse_terminated(&content)?;
    Ok((items.into_iter().collect(), id.span()))
}

struct GroupInput {
    prefix: LitStr,
    policy: PolicyDecl,
    before: Vec<Path>,
    after: Vec<Path>,
    routes: Vec<Path>,
}

impl Parse for GroupInput {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let kw: Ident = input.parse()?;
        if kw != "group" {
            return Err(err(kw.span(), "expected `group(\"/prefix\", ...) { routes: [...] }`"));
        }
        let args;
        parenthesized!(args in input);
        let prefix: LitStr = args.parse()?;
        let mut policy = PolicyDecl::default();
        let mut before = Vec::new();
        let mut after = Vec::new();
        if args.peek(Token![,]) {
            args.parse::<Token![,]>()?;
            let items = Punctuated::<Meta, Token![,]>::parse_terminated(&args)?;
            for m in items {
                let key = m.path().get_ident().map(|i| i.to_string()).unwrap_or_default();
                match (key.as_str(), &m) {
                    ("policy", Meta::List(l)) => {
                        let inner = l.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
                        policy = parse_policy(&inner.into_iter().collect::<Vec<_>>(), Level::Group)?;
                    }
                    ("before" | "after", Meta::NameValue(nv)) => {
                        let paths = match &nv.value {
                            Expr::Array(a) => a
                                .elems
                                .iter()
                                .map(|e| match e {
                                    Expr::Path(p) => Ok(p.path.clone()),
                                    _ => Err(err(e.span(), "expected a hook path")),
                                })
                                .collect::<syn::Result<Vec<_>>>()?,
                            _ => return Err(err(nv.value.span(), "expected `[hook, ..]`")),
                        };
                        if key == "before" { before = paths } else { after = paths }
                    }
                    _ => return Err(err(m.span(), "expected `policy(..)`, `before = [..]` or `after = [..]`")),
                }
            }
        }
        let body;
        braced!(body in input);
        let mut routes = Vec::new();
        while !body.is_empty() {
            let k: Ident = body.parse()?;
            body.parse::<Token![:]>()?;
            if k == "routes" {
                routes = parse_path_list(&body)?;
            } else {
                return Err(err(k.span(), "a group body supports `routes: [...]` (nested groups are not supported)"));
            }
            if body.peek(Token![,]) {
                body.parse::<Token![,]>()?;
            }
        }
        Ok(GroupInput { prefix, policy, before, after, routes })
    }
}

struct AppInput {
    attrs: Vec<Attribute>,
    vis: Visibility,
    name: Ident,
    state: Option<Type>,
    auth: Option<Type>,
    defaults: PolicyDecl,
    cors: Option<(Vec<Meta>, Span)>,
    before: Vec<Path>,
    after: Vec<Path>,
    routes: Vec<Path>,
    groups: Vec<GroupInput>,
    plugins: Vec<Path>,
    prefix: Option<LitStr>,
}

fn parse_app(input: ParseStream<'_>, plugin: bool) -> syn::Result<AppInput> {
    let attrs = input.call(Attribute::parse_outer)?;
    let vis: Visibility = input.parse()?;
    let name: Ident = input.parse()?;
    let body;
    braced!(body in input);
    let mut a = AppInput {
        attrs,
        vis,
        name,
        state: None,
        auth: None,
        defaults: PolicyDecl::default(),
        cors: None,
        before: Vec::new(),
        after: Vec::new(),
        routes: Vec::new(),
        groups: Vec::new(),
        plugins: Vec::new(),
        prefix: None,
    };
    let mut seen: Vec<String> = Vec::new();
    while !body.is_empty() {
        let key: Ident = body.parse()?;
        body.parse::<Token![:]>()?;
        let k = key.to_string();
        if seen.contains(&k) {
            return Err(err(key.span(), format!("`{k}` is declared more than once")));
        }
        seen.push(k.clone());
        match (k.as_str(), plugin) {
            ("state", false) => a.state = Some(body.parse()?),
            ("auth", false) => a.auth = Some(body.parse()?),
            ("defaults", false) | ("policy", true) => {
                let (items, _) = parse_call_metas(&body, "policy")?;
                a.defaults = parse_policy(&items, if plugin { Level::Group } else { Level::App })?;
            }
            ("cors", false) => a.cors = Some(parse_call_metas(&body, "cors")?),
            ("before", _) => a.before = parse_path_list(&body)?,
            ("after", _) => a.after = parse_path_list(&body)?,
            ("routes", _) => a.routes = parse_path_list(&body)?,
            ("groups", false) => {
                let content;
                bracketed!(content in body);
                a.groups = Punctuated::<GroupInput, Token![,]>::parse_terminated(&content)?.into_iter().collect();
            }
            ("plugins", false) => a.plugins = parse_path_list(&body)?,
            ("prefix", true) => a.prefix = Some(body.parse()?),
            _ => {
                let expected = if plugin {
                    "prefix, policy, before, after, routes"
                } else {
                    "state, auth, defaults, cors, before, after, routes, groups, plugins"
                };
                return Err(err(key.span(), format!("unknown key `{k}` (expected one of: {expected})")));
            }
        }
        if body.peek(Token![,]) {
            body.parse::<Token![,]>()?;
        }
    }
    Ok(a)
}

struct AppParse(AppInput);
impl Parse for AppParse {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        parse_app(input, false).map(AppParse)
    }
}
struct PluginParse(AppInput);
impl Parse for PluginParse {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        parse_app(input, true).map(PluginParse)
    }
}

struct CorsDecl {
    origins: Vec<String>,
    credentials: bool,
    headers: Vec<String>,
    max_age: u64,
}

fn parse_cors(items: &[Meta], span: Span) -> syn::Result<CorsDecl> {
    let mut c = CorsDecl { origins: Vec::new(), credentials: false, headers: Vec::new(), max_age: 600 };
    for m in items {
        let Meta::NameValue(nv) = m else {
            return Err(err(
                m.span(),
                "expected `origins = [..]`, `credentials = bool`, `headers = [..]`, `max_age = secs`",
            ));
        };
        match nv.path.get_ident().map(|i| i.to_string()).as_deref() {
            Some("origins") => c.origins = str_list(&nv.value)?,
            Some("headers") => c.headers = str_list(&nv.value)?,
            Some("credentials") => match &nv.value {
                Expr::Lit(ExprLit { lit: Lit::Bool(b), .. }) => c.credentials = b.value,
                _ => return Err(err(nv.value.span(), "expected `true` or `false`")),
            },
            Some("max_age") => match &nv.value {
                Expr::Lit(ExprLit { lit: Lit::Int(i), .. }) => c.max_age = i.base10_parse()?,
                _ => return Err(err(nv.value.span(), "expected seconds as an integer")),
            },
            _ => return Err(err(nv.path.span(), "unknown cors option")),
        }
    }
    if c.origins.is_empty() {
        return Err(err(span, "cors(..) requires `origins = [..]`"));
    }
    for o in &c.origins {
        if o == "*" && c.credentials {
            return Err(err(
                span,
                "credentialed CORS with wildcard origin `*` is unsafe (and rejected by browsers); list explicit origins",
            ));
        }
        if o != "*" && !(o.starts_with("https://") || o.starts_with("http://")) {
            return Err(err(span, format!("CORS origin `{o}` must be `*` or start with http:// or https://")));
        }
        if o.ends_with('/') {
            return Err(err(span, format!("CORS origin `{o}` must not end with `/` (origins have no path)")));
        }
    }
    Ok(c)
}

fn check_unique(paths: &[&Path]) -> syn::Result<()> {
    for (i, a) in paths.iter().enumerate() {
        for b in &paths[i + 1..] {
            if pretty(a) == pretty(b) {
                return Err(err(b.span(), format!("route `{}` is listed more than once", pretty(b))));
            }
        }
    }
    Ok(())
}

fn hook_names(v: &[Path]) -> Vec<String> {
    v.iter().map(pretty).collect()
}

fn before_calls(hooks: &[Path], st: &TokenStream) -> Vec<TokenStream> {
    let p = quote!(::poring::__private);
    hooks
        .iter()
        .map(|h| {
            quote_spanned! {h.span()=>
                cx.__mark_before();
                if let ::core::result::Result::Err(r) = <#h as #p::BeforeHook<#st>>::before(cx).await {
                    #p::mark(cx, #p::Stage::ShortCircuit);
                    break 'run r;
                }
            }
        })
        .collect()
}

fn after_calls(hooks: &[Path], st: &TokenStream) -> Vec<TokenStream> {
    let p = quote!(::poring::__private);
    hooks
        .iter()
        .map(|h| {
            quote_spanned! {h.span()=>
                cx.__mark_after();
                <#h as #p::AfterHook<#st>>::after(cx, &mut __res).await;
            }
        })
        .collect()
}

fn after_calls_ref(hooks: &[Path], st: &TokenStream) -> Vec<TokenStream> {
    let p = quote!(::poring::__private);
    hooks
        .iter()
        .map(|h| {
            quote_spanned! {h.span()=>
                cx.__mark_after();
                <#h as #p::AfterHook<#st>>::after(cx, __res).await;
            }
        })
        .collect()
}

fn group_tokens(
    name: &str,
    prefix: &str,
    policy: &PolicyDecl,
    before: &[Path],
    after: &[Path],
    plugin: bool,
) -> TokenStream {
    let p = quote!(::poring::__private);
    let pol = policy.tokens();
    let b = hook_names(before);
    let a = hook_names(after);
    quote! {
        #p::GroupDescriptor {
            name: #name,
            prefix: #prefix,
            policy: #pol,
            before: &[#(#b),*],
            after: &[#(#a),*],
            plugin: #plugin,
        }
    }
}

pub fn expand_app(input: TokenStream) -> syn::Result<TokenStream> {
    let AppParse(a) = syn::parse2(input)?;
    let p = quote!(::poring::__private);
    let name = &a.name;
    let vis = &a.vis;
    let attrs = &a.attrs;
    let name_str = name.to_string();
    let upper = name_str.to_ascii_uppercase();
    let st: TokenStream = match &a.state {
        Some(t) => quote!(#t),
        None => quote!(()),
    };
    let au: TokenStream = match &a.auth {
        Some(t) => quote!(#t),
        None => quote!(#p::NoAuth),
    };
    let has_auth = a.auth.is_some();
    let auth_type = a.auth.as_ref().map(pretty).unwrap_or_default();
    let defaults = a.defaults.tokens();
    let cors = match &a.cors {
        None => quote!(::core::option::Option::None),
        Some((items, span)) => {
            let c = parse_cors(items, *span)?;
            let (o, h, cr, ma) = (&c.origins, &c.headers, c.credentials, c.max_age);
            quote!(::core::option::Option::Some(#p::CorsSpec {
                origins: &[#(#o),*], credentials: #cr, headers: &[#(#h),*], max_age_secs: #ma,
            }))
        }
    };

    let mut all_routes: Vec<&Path> = a.routes.iter().collect();
    for g in &a.groups {
        all_routes.extend(g.routes.iter());
    }
    check_unique(&all_routes)?;
    for g in &a.groups {
        validate_prefix(&g.prefix.value()).map_err(|m| err(g.prefix.span(), m))?;
    }

    // Static route list: ungrouped, then each group's routes.
    let mut route_refs = Vec::new();
    let mut arms = Vec::new();
    let gb = before_calls(&a.before, &st);
    let ga = after_calls(&a.after, &st);
    let ga_ref = after_calls_ref(&a.after, &st);
    let mut idx: u16 = 0;
    let mut push_route = |r: &Path,
                          group: Option<(u16, &GroupInput)>,
                          route_refs: &mut Vec<TokenStream>,
                          arms: &mut Vec<TokenStream>| {
        let gi = match group {
            Some((g, _)) => quote!(::core::option::Option::Some(#g)),
            None => quote!(::core::option::Option::None),
        };
        let at = idx as usize;
        route_refs.push(quote_spanned! {r.span()=>
            a[#at] = #p::RouteRef { desc: &<#r as #p::RouteInfo>::DESCRIPTOR, group: #gi };
        });
        let (grp_before, grp_after) = match group {
            Some((_, g)) => (before_calls(&g.before, &st), after_calls(&g.after, &st)),
            None => (Vec::new(), Vec::new()),
        };
        let i = idx;
        let route_before = quote_spanned! {r.span()=>
            if let ::core::result::Result::Err(r) = <#r as #p::RouteHandler<#st>>::before(cx).await {
                #p::mark(cx, #p::Stage::ShortCircuit);
                break 'run r;
            }
        };
        let route_handle = quote_spanned!(r.span()=> <#r as #p::RouteHandler<#st>>::handle(cx).await);
        let route_after = quote_spanned!(r.span()=> <#r as #p::RouteHandler<#st>>::after(cx, &mut __res).await;);
        arms.push(quote! {
            #i => ::std::boxed::Box::pin(async move {
                let mut __res = 'run: {
                    #(#gb)*
                    #(#grp_before)*
                    #route_before
                    #route_handle
                };
                #route_after
                #(#grp_after)*
                #(#ga)*
                __res
            }),
        });
        idx += 1;
    };
    for r in &a.routes {
        push_route(r, None, &mut route_refs, &mut arms);
    }
    let mut group_descs = Vec::new();
    for (gi, g) in a.groups.iter().enumerate() {
        let gname = g.prefix.value();
        group_descs.push(group_tokens(&gname, &gname, &g.policy, &g.before, &g.after, false));
        for r in &g.routes {
            push_route(r, Some((gi as u16, g)), &mut route_refs, &mut arms);
        }
    }
    let n_static = idx as usize;
    let n_groups_static = a.groups.len();

    // Plugins: appended after static routes; lengths are only known in const context.
    let mut plugin_consts = Vec::new();
    let mut plugin_fill = Vec::new();
    let mut plugin_arms = Vec::new();
    let mut prev_end = quote!(#n_static);
    for (k, pl) in a.plugins.iter().enumerate() {
        let base = format_ident!("__PORING_{}_PLUGIN{}_BASE", upper, k);
        let end = format_ident!("__PORING_{}_PLUGIN{}_END", upper, k);
        let group_index = (n_groups_static + k) as u16;
        plugin_consts.push(quote_spanned! {pl.span()=>
            #[doc(hidden)]
            const #base: usize = #prev_end;
            #[doc(hidden)]
            const #end: usize = #base + <#pl as #p::PluginSpec>::ROUTES.len();
        });
        plugin_fill.push(quote_spanned! {pl.span()=>
            a = #p::fill_routes(a, #base, <#pl as #p::PluginSpec>::ROUTES, ::core::option::Option::Some(#group_index));
        });
        group_descs.push(quote_spanned!(pl.span()=> <#pl as #p::PluginSpec>::GROUP));
        plugin_arms.push(quote_spanned! {pl.span()=>
            i if (i as usize) >= #base && (i as usize) < #end => ::std::boxed::Box::pin(async move {
                let __local = (i as usize - #base) as u16;
                let mut __res = 'run: {
                    #(#gb)*
                    <#pl as #p::PluginDispatch<#st>>::run(__local, cx).await
                };
                <#pl as #p::PluginDispatch<#st>>::after(__local, cx, &mut __res).await;
                #(#ga)*
                __res
            }),
        });
        prev_end = quote!(#end);
    }
    let total = format_ident!("__PORING_{}_TOTAL", upper);
    let routes_const = format_ident!("__PORING_{}_ROUTES", upper);
    let groups_const = format_ident!("__PORING_{}_GROUPS", upper);
    let n_groups_total = n_groups_static + a.plugins.len();
    let gb_names = hook_names(&a.before);
    let ga_names = hook_names(&a.after);
    let (st_ty, st_init) = match &a.state {
        Some(_) => (quote!(#p::Missing), quote!(#p::Missing)),
        None => (quote!(#p::Provided<()>), quote!(#p::provided(()))),
    };
    let (au_ty, au_init) = match &a.auth {
        Some(_) => (quote!(#p::Missing), quote!(#p::Missing)),
        None => (quote!(#p::Provided<#p::NoAuth>), quote!(#p::provided(#p::NoAuth))),
    };
    let check = quote_spanned!(name.span()=> const _: () = #p::check_app(&<#name as #p::AppSpec>::APP););
    let unused_label = quote!(#[allow(unreachable_code, unused_labels, clippy::diverging_sub_expression)]);

    Ok(quote! {
        #(#attrs)*
        #vis struct #name;

        #(#plugin_consts)*
        #[doc(hidden)]
        const #total: usize = #prev_end;
        #[doc(hidden)]
        const #routes_const: [#p::RouteRef; #total] = {
            let mut a = [#p::RouteRef { desc: &#p::PLACEHOLDER_ROUTE, group: ::core::option::Option::None }; #total];
            #(#route_refs)*
            #(#plugin_fill)*
            a
        };
        #[doc(hidden)]
        const #groups_const: [#p::GroupDescriptor; #n_groups_total] = [#(#group_descs),*];

        impl #p::AppSpec for #name {
            type State = #st;
            type Auth = #au;
            const APP: #p::AppDescriptor = #p::AppDescriptor {
                name: #name_str,
                defaults: #defaults,
                has_authenticator: #has_auth,
                auth_type: #auth_type,
                auth_uses_cookies: <#au as #p::Authenticator>::USES_COOKIES,
                cors: #cors,
                before: &[#(#gb_names),*],
                after: &[#(#ga_names),*],
                groups: &#groups_const,
                routes: &#routes_const,
            };

            #unused_label
            fn dispatch<'a, 'c>(index: u16, cx: &'c mut #p::Ctx<'a, #st>)
                -> impl ::core::future::Future<Output = #p::Response> + ::core::marker::Send + 'c
            {
                // Select the route synchronously and box only its pipeline: the per-request
                // future then has the size of one route, independent of the route count
                // (a single `match` inside one `async` block grows with every route).
                let fut: ::core::pin::Pin<::std::boxed::Box<dyn ::core::future::Future<Output = #p::Response> + ::core::marker::Send + 'c>> =
                    match index {
                        #(#arms)*
                        #(#plugin_arms)*
                        _ => ::std::boxed::Box::pin(async move { #p::unknown_route() }),
                    };
                fut
            }

            #unused_label
            fn __global_before<'a, 'c>(cx: &'c mut #p::Ctx<'a, #st>)
                -> impl ::core::future::Future<Output = ::core::result::Result<(), #p::Response>> + ::core::marker::Send + 'c
            {
                async move {
                    let __early: #p::Response = 'run: {
                        #(#gb)*
                        let _ = &cx;
                        return ::core::result::Result::Ok(());
                    };
                    ::core::result::Result::Err(__early)
                }
            }

            #[allow(clippy::needless_lifetimes)]
            fn __global_after<'a, 'c>(cx: &'c mut #p::Ctx<'a, #st>, __res: &'c mut #p::Response)
                -> impl ::core::future::Future<Output = ()> + ::core::marker::Send + 'c
            {
                async move {
                    #(#ga_ref)*
                    let _ = (&cx, &__res);
                }
            }
        }

        #check

        impl #name {
            /// Starts the typed builder for this app.
            #[allow(dead_code)]
            pub fn builder() -> #p::Builder<#name, #st_ty, #au_ty> {
                #p::Builder::__new(#st_init, #au_init)
            }

            /// Resolves the manifest without constructing state or starting a server.
            #[allow(dead_code)]
            pub fn manifest() -> ::core::result::Result<::poring::contract::Manifest, ::poring::StartupError> {
                ::poring::app::static_manifest::<#name>()
            }
        }
    })
}

pub fn expand_plugin(input: TokenStream) -> syn::Result<TokenStream> {
    let PluginParse(a) = syn::parse2(input)?;
    let p = quote!(::poring::__private);
    let name = &a.name;
    let vis = &a.vis;
    let attrs = &a.attrs;
    let name_str = name.to_string();
    let prefix = match &a.prefix {
        Some(l) => validate_prefix(&l.value()).map_err(|m| err(l.span(), m))?,
        None => String::new(),
    };
    let refs: Vec<&Path> = a.routes.iter().collect();
    check_unique(&refs)?;
    let group = group_tokens(&name_str, &prefix, &a.defaults, &a.before, &a.after, true);
    let st = quote!(S);
    let gb = before_calls(&a.before, &st);
    let routes = &a.routes;
    let route_bounds = routes.iter().map(|r| quote_spanned!(r.span()=> #r: #p::RouteHandler<S>,));
    let hb = a.before.iter().map(|h| quote_spanned!(h.span()=> #h: #p::BeforeHook<S>,));
    let ha = a.after.iter().map(|h| quote_spanned!(h.span()=> #h: #p::AfterHook<S>,));
    let run_arms = routes.iter().enumerate().map(|(i, r)| {
        let i = i as u16;
        quote_spanned! {r.span()=>
            #i => {
                #(#gb)*
                if let ::core::result::Result::Err(r) = <#r as #p::RouteHandler<S>>::before(cx).await {
                    #p::mark(cx, #p::Stage::ShortCircuit);
                    break 'run r;
                }
                <#r as #p::RouteHandler<S>>::handle(cx).await
            }
        }
    });
    let after_arms = routes.iter().enumerate().map(|(i, r)| {
        let i = i as u16;
        quote_spanned! {r.span()=>
            #i => {
                <#r as #p::RouteHandler<S>>::after(cx, __res).await;
            }
        }
    });
    let ga_ref: Vec<TokenStream> = a
        .after
        .iter()
        .map(|h| {
            quote_spanned! {h.span()=>
                cx.__mark_after();
                <#h as #p::AfterHook<S>>::after(cx, __res).await;
            }
        })
        .collect();
    Ok(quote! {
        #(#attrs)*
        #vis struct #name;

        impl #p::PluginSpec for #name {
            const GROUP: #p::GroupDescriptor = #group;
            const ROUTES: &'static [&'static #p::RouteDescriptor] = &[#( &<#routes as #p::RouteInfo>::DESCRIPTOR ),*];
        }

        impl<S> #p::PluginDispatch<S> for #name
        where
            S: ::core::marker::Send + ::core::marker::Sync + 'static,
            #(#route_bounds)*
            #(#hb)*
            #(#ha)*
        {
            #[allow(unreachable_code, unused_labels)]
            fn run<'a, 'c>(index: u16, cx: &'c mut #p::Ctx<'a, S>)
                -> impl ::core::future::Future<Output = #p::Response> + ::core::marker::Send + 'c
            {
                async move {
                    'run: {
                        match index {
                            #(#run_arms)*
                            _ => #p::unknown_route(),
                        }
                    }
                }
            }

            fn after<'a, 'c>(index: u16, cx: &'c mut #p::Ctx<'a, S>, __res: &'c mut #p::Response)
                -> impl ::core::future::Future<Output = ()> + ::core::marker::Send + 'c
            {
                async move {
                    match index {
                        #(#after_arms)*
                        _ => {}
                    }
                    #(#ga_ref)*
                }
            }
        }
    })
}
