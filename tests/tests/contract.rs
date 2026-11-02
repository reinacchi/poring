//! Multi-route app over HTTP, OpenAPI snapshot, generated TypeScript client.

use poring_tests::shop::{Category, NewProduct, Product, ProductPage, Shop, ShopState};

use poring_tests::snapshot;

#[tokio::test]
async fn shop_app_end_to_end() {
    let app = Shop::builder().state(ShopState::default()).build().unwrap();
    let c = app.client();
    assert_eq!(c.get("/health").send().await.text(), "ok");
    let r = c
        .post("/v1/products")
        .json(&NewProduct {
            name: "Rust in Action".into(),
            price_cents: 3999,
            category: Category::Books,
        })
        .send()
        .await;
    assert_eq!(r.status, 201);
    assert_eq!(r.header("x-api-version"), Some("1"));
    let p: Product = r.json();
    assert_eq!(p.id, 1);
    let r = c
        .post("/v1/products")
        .json(&serde_json::json!({"name": "Toaster\u{1F35E}", "price_cents": 0, "category": "home-appliances"}))
        .send()
        .await;
    assert_eq!(r.status, 422);
    let rules: Vec<String> = r.json::<serde_json::Value>()["error"]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["rule"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(rules, ["ascii", "minimum"]);
    let page: ProductPage = c
        .get("/v1/products?category=books&limit=5")
        .send()
        .await
        .json();
    assert_eq!(page.total, 1);
    assert_eq!(c.get("/v1/products?category=toys").send().await.status, 400);
    assert_eq!(c.get("/v1/products/99").send().await.status, 404);
    assert_eq!(c.delete("/v1/products/1").send().await.status, 204);
    assert_eq!(c.get("/metrics/hits").send().await.text(), "1");
}

#[test]
fn openapi_snapshot_is_deterministic() {
    let info = poring::openapi::Info::new("Shop", "1.0.0");
    let a = poring::openapi::openapi::<Shop>(&info).unwrap();
    let b = poring::openapi::openapi::<Shop>(&info).unwrap();
    assert_eq!(a, b);
    let doc = serde_json::to_string_pretty(&a).unwrap();
    snapshot("shop.openapi.json", &doc);
    // Spot checks independent of the snapshot.
    assert_eq!(
        a["paths"]["/v1/products/{id}"]["get"]["parameters"][0]["schema"]["type"],
        "integer"
    );
    assert_eq!(
        a["components"]["schemas"]["Category"]["enum"],
        serde_json::json!(["books", "home-appliances"])
    );
    assert_eq!(
        a["components"]["schemas"]["NewProduct"]["additionalProperties"],
        false
    );
    assert_eq!(
        a["paths"]["/v1/products"]["post"]["x-poring-policy"]["body_limit"],
        8192
    );
    assert!(a["paths"]["/v1/products"]["post"]["responses"]["422"].is_object());
}

#[test]
fn typescript_client_typechecks() {
    let doc =
        poring::openapi::openapi::<Shop>(&poring::openapi::Info::new("Shop", "1.0.0")).unwrap();
    let ts = poring::openapi::typescript_client(&doc);
    snapshot("shop.client.ts", &ts);
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("ts-client");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("client.ts"), &ts).unwrap();
    // A usage file that must type-check against the generated client.
    std::fs::write(
        dir.join("usage.ts"),
        r#"import { createClient, Product, ProductPage, NewProduct } from "./client";
const api = createClient("http://localhost:3000");
async function main(): Promise<void> {
  const created: Product = await api.create_product({ body: { name: "x", price_cents: 1, category: "books" } satisfies NewProduct });
  const page: ProductPage = await api.list_products({ query: { category: "home-appliances", limit: 5 } });
  const one: Product = await api.get_product({ path: { id: created.id } });
  const hits: number = await api.hits();
  console.log(page.total, one.name, hits);
  // @ts-expect-error: category must be one of the declared variants
  await api.create_product({ body: { name: "x", price_cents: 1, category: "toys" } });
}
void main;
"#,
    )
    .unwrap();
    // npm installs `tsc.cmd` on Windows; `Command` does not resolve `.cmd` through PATHEXT.
    let program = if cfg!(windows) { "tsc.cmd" } else { "tsc" };
    let tsc = std::process::Command::new(program)
        .args([
            "--noEmit",
            "--strict",
            "--target",
            "es2022",
            "--module",
            "es2022",
            "--moduleResolution",
            "bundler",
            "--lib",
            "es2022,dom",
        ])
        .arg(dir.join("usage.ts"))
        .output();
    match tsc {
        Ok(out) => assert!(
            out.status.success(),
            "generated TypeScript client failed to type-check:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        // CI installs TypeScript, so a missing compiler there is a failure, not a skip.
        Err(e) if std::env::var_os("CI").is_some() => panic!("`{program}` is required in CI: {e}"),
        Err(e) => eprintln!(
            "SKIPPED: `{program}` not available ({e}); TS client was generated but not type-checked"
        ),
    }
}
