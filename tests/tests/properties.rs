//! Property tests for parsers, decoding, routing and limits (no panics, round trips, and
//! agreement between the compile-time conflict checker and matchit).

use poring::prelude::*;
use proptest::prelude::*;
use serde::Deserialize;

#[derive(Deserialize, PoringSchema)]
struct Q {
    a: Option<u32>,
    b: Option<Vec<String>>,
}

#[derive(Deserialize, PoringSchema)]
struct Body {
    #[poring(max_length = 8)]
    s: String,
    n: Option<i64>,
}

#[poring::get("/u/{id}")]
async fn u(Path(id): Path<u64>) -> String {
    id.to_string()
}
#[poring::get("/s/{name}/x")]
async fn s(Path(name): Path<String>) -> String {
    name
}
#[poring::get("/f/{*rest}")]
async fn f(Path(rest): Path<String>) -> String {
    rest
}
#[poring::get("/q")]
async fn q(Query(_q): Query<Q>) -> &'static str {
    "q"
}
#[poring::post("/j", policy(body_limit = "256B"))]
async fn j(Json(_b): Json<Body>) -> &'static str {
    "j"
}
#[poring::post("/form")]
async fn form(Form(_b): Form<Q>) -> &'static str {
    "form"
}

poring_app! { Fuzz { routes: [u, s, f, q, j, form] } }

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

const ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.');

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn decode_roundtrips_and_never_panics(s in "\\PC{0,40}", raw in "[%a-zA-Z0-9/]{0,20}") {
        let enc = percent_encoding::utf8_percent_encode(&s, ENCODE).to_string();
        prop_assert_eq!(poring::extract::path::decode(&enc).unwrap(), s);
        let _ = poring::extract::path::decode(&raw);
    }

    #[test]
    fn router_never_panics_and_maps_to_known_statuses(segs in proptest::collection::vec("[a-z0-9%~._-]{0,6}", 0..5), method in prop::sample::select(vec!["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])) {
        let path = format!("/{}", segs.join("/"));
        prop_assume!(path.parse::<http::Uri>().is_ok());
        let app = Fuzz::builder().build().unwrap();
        let status = rt().block_on(app.client().request(method.parse().unwrap(), &path).send()).status.as_u16();
        prop_assert!([200, 204, 400, 404, 405, 415].contains(&status), "{} {} -> {}", method, path, status);
    }

    #[test]
    fn query_and_form_parsers_never_panic(query in "[a-z=&%0-9+]{0,120}") {
        let app = Fuzz::builder().build().unwrap();
        let c = app.client();
        let r = rt().block_on(c.get(&format!("/q?{query}")).send());
        prop_assert!(r.status == 200 || r.status == 400, "{}", r.status);
        let r = rt().block_on(c.post("/form").header("content-type", "application/x-www-form-urlencoded").body(query.clone()).send());
        prop_assert!(r.status == 200 || r.status == 400, "{}", r.status);
    }

    #[test]
    fn json_bodies_never_panic(body in proptest::collection::vec(any::<u8>(), 0..300)) {
        let app = Fuzz::builder().build().unwrap();
        let r = rt().block_on(app.client().post("/j").header("content-type", "application/json").body(body).send());
        prop_assert!([200, 400, 413, 422].contains(&r.status.as_u16()), "{}", r.status);
    }

    #[test]
    fn const_conflict_checker_agrees_with_matchit(
        a in proptest::collection::vec(prop::sample::select(vec!["a", "b", "{x}", "{y}"]), 1..4),
        b in proptest::collection::vec(prop::sample::select(vec!["a", "b", "{x}", "{y}"]), 1..4),
        a_tail in prop::sample::select(vec!["", "/{*r}", "/{*q}", "/"]),
        b_tail in prop::sample::select(vec!["", "/{*r}", "/{*q}", "/"]),
    ) {
        // Build canonical paths with unique parameter names per path.
        let mk = |segs: &[&str], tail: &str| {
            let mut n = 0;
            let mut out = String::new();
            for s in segs {
                out.push('/');
                if s.starts_with('{') { n += 1; out.push_str(&format!("{{{}{n}}}", &s[1..2])); } else { out.push_str(s); }
            }
            out + tail
        };
        let (pa, pb) = (mk(&a, a_tail), mk(&b, b_tail));
        let mut r = matchit::Router::new();
        prop_assume!(r.insert(pa.as_str(), ()).is_ok());
        let matchit_conflict = r.insert(pb.as_str(), ()).is_err();
        prop_assert_eq!(poring::policy::check::paths_conflict(&pa, &pb), matchit_conflict, "{} vs {}", pa, pb);
    }

    #[test]
    fn rate_limiter_memory_is_bounded(keys in proptest::collection::vec(any::<u32>(), 1..2000)) {
        use poring::policy::enforce::{RateKeyValue, RateLimiter};
        use poring::policy::{RateKey, RateLimitSpec};
        let rl = RateLimiter::new(256);
        let spec = RateLimitSpec { requests: 1, per_ms: 60_000, key: RateKey::Ip };
        let now = std::time::Instant::now();
        for k in keys {
            let _ = rl.check(0, RateKeyValue::Subject(k.to_string()), &spec, now);
        }
        prop_assert!(rl.len() <= 256 + 16, "{}", rl.len());
    }
}
