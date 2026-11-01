//! A multi-route fixture app: groups + typed state + a plugin + validation + typed
//! responses. Used by the contract tests (HTTP, OpenAPI snapshot, TS client check).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use poring::prelude::*;
use serde::{Deserialize, Serialize};

/// A product.
#[derive(Clone, Debug, Serialize, Deserialize, PoringSchema, PartialEq)]
pub struct Product {
    /// Identifier.
    pub id: u64,
    /// Display name.
    pub name: String,
    /// Price in cents.
    pub price_cents: u32,
    /// Category.
    pub category: Category,
}

/// Product category.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PoringSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Books.
    Books,
    /// Home appliances.
    HomeAppliances,
}

/// Payload to create a product.
#[derive(Debug, Deserialize, Serialize, PoringSchema)]
#[serde(deny_unknown_fields)]
pub struct NewProduct {
    /// 1..=80 printable characters.
    #[poring(min_length = 1, max_length = 80, ascii)]
    pub name: String,
    /// Price in cents, 1..=1_000_000.
    #[poring(minimum = 1, maximum = 1000000)]
    pub price_cents: u32,
    /// Category.
    pub category: Category,
}

/// List filters.
#[derive(Debug, Deserialize, PoringSchema)]
pub struct ListQuery {
    /// Filter by category.
    pub category: Option<Category>,
    /// Page size, 1..=50.
    #[poring(minimum = 1, maximum = 50)]
    pub limit: Option<u32>,
}

/// Paged list response.
#[derive(Debug, Serialize, Deserialize, PoringSchema)]
pub struct ProductPage {
    /// Items.
    pub items: Vec<Product>,
    /// Total matching items.
    pub total: u64,
}

/// In-memory catalogue.
#[derive(Clone, Default)]
pub struct Catalogue(Arc<Mutex<BTreeMap<u64, Product>>>);

/// Request counter used by the metrics plugin.
#[derive(Clone, Default)]
pub struct Metrics(Arc<Mutex<u64>>);

/// App state.
#[derive(Clone, Default, PoringState)]
pub struct ShopState {
    /// Catalogue.
    pub catalogue: Catalogue,
    /// Metrics.
    pub metrics: Metrics,
}

/// Liveness probe.
#[poring::get("/health")]
async fn health() -> &'static str {
    "ok"
}

/// List products.
#[poring::get("/products")]
async fn list_products(State(c): State<Catalogue>, Query(q): Query<ListQuery>) -> Json<ProductPage> {
    let map = c.0.lock().unwrap_or_else(|p| p.into_inner());
    let matching: Vec<Product> = map.values().filter(|p| q.category.is_none_or(|c| c == p.category)).cloned().collect();
    let total = matching.len() as u64;
    let items = matching.into_iter().take(q.limit.unwrap_or(20) as usize).collect();
    Json(ProductPage { items, total })
}

/// Get one product.
#[poring::get("/products/{id}")]
async fn get_product(Path(id): Path<u64>, State(c): State<Catalogue>) -> Result<Json<Product>, ApiError> {
    let map = c.0.lock().unwrap_or_else(|p| p.into_inner());
    map.get(&id).cloned().map(Json).ok_or_else(|| ApiError::not_found(format!("product {id} not found")))
}

/// Create a product.
#[poring::post("/products", policy(body_limit = "8KiB"))]
async fn create_product(State(c): State<Catalogue>, Json(n): Json<NewProduct>) -> (StatusCode, Json<Product>) {
    let mut map = c.0.lock().unwrap_or_else(|p| p.into_inner());
    let id = map.keys().next_back().copied().unwrap_or(0) + 1;
    let p = Product { id, name: n.name, price_cents: n.price_cents, category: n.category };
    map.insert(id, p.clone());
    (StatusCode::CREATED, Json(p))
}

/// Delete a product.
#[poring::delete("/products/{id}")]
async fn delete_product(Path(id): Path<u64>, State(c): State<Catalogue>) -> Result<StatusCode, ApiError> {
    let mut map = c.0.lock().unwrap_or_else(|p| p.into_inner());
    map.remove(&id).map(|_| StatusCode::NO_CONTENT).ok_or_else(|| ApiError::not_found("no such product"))
}

/// Adds `x-api-version` to every v1 response.
#[poring::hook]
async fn version_header(_cx: &Ctx<'_, ShopState>, res: &mut Response) {
    res.headers_mut().insert("x-api-version", HeaderValue::from_static("1"));
}

/// Metrics plugin (generic over any state that provides `Metrics`).
pub mod metrics {
    use super::*;

    /// Counts every request routed to the plugin.
    #[poring::hook]
    pub async fn count<S: Send + Sync>(cx: &mut Ctx<'_, S>)
    where
        Metrics: FromRef<S>,
    {
        let m = Metrics::from_ref(cx.state());
        *m.0.lock().unwrap_or_else(|p| p.into_inner()) += 1;
    }

    /// Number of metrics requests served.
    #[poring::get("/hits")]
    pub async fn hits(State(m): State<Metrics>) -> Json<u64> {
        Json(*m.0.lock().unwrap_or_else(|p| p.into_inner()))
    }

    poring_plugin! {
        /// Exposes request metrics under `/metrics`.
        pub MetricsPlugin {
            prefix: "/metrics",
            before: [count],
            routes: [hits],
        }
    }
}

poring_app! {
    /// The shop fixture app.
    pub Shop {
        state: ShopState,
        routes: [health],
        groups: [
            group("/v1", after = [version_header]) {
                routes: [list_products, get_product, create_product, delete_product],
            },
        ],
        plugins: [metrics::MetricsPlugin],
    }
}
