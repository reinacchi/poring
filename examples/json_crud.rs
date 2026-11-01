//! JSON CRUD with typed shared state, validation and error mapping.
//!
//! ```text
//! cargo run -p poring-examples --example json_crud
//! curl -X POST localhost:3000/todos -H 'content-type: application/json' -d '{"title":"write docs"}'
//! curl localhost:3000/todos
//! curl -X PATCH localhost:3000/todos/1 -H 'content-type: application/json' -d '{"done":true}'
//! curl -X DELETE localhost:3000/todos/1
//! curl -X POST localhost:3000/todos -H 'content-type: application/json' -d '{"title":""}'  # 422
//! ```
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use poring::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, PoringSchema)]
struct Todo {
    id: u64,
    title: String,
    done: bool,
}

#[derive(Deserialize, PoringSchema)]
#[serde(deny_unknown_fields)]
struct NewTodo {
    #[poring(min_length = 1, max_length = 200)]
    title: String,
}

#[derive(Deserialize, PoringSchema)]
#[serde(deny_unknown_fields)]
struct TodoPatch {
    #[poring(min_length = 1, max_length = 200)]
    title: Option<String>,
    done: Option<bool>,
}

/// Domain errors mapped to HTTP through `ApiError`.
#[derive(Debug)]
enum TodoError {
    NotFound(u64),
}

impl From<TodoError> for ApiError {
    fn from(e: TodoError) -> Self {
        match e {
            TodoError::NotFound(id) => ApiError::not_found(format!("todo {id} does not exist")),
        }
    }
}

#[derive(Clone, Default)]
struct TodoStore {
    inner: Arc<Mutex<(u64, BTreeMap<u64, Todo>)>>,
}

impl TodoStore {
    fn with<R>(&self, f: impl FnOnce(&mut (u64, BTreeMap<u64, Todo>)) -> R) -> R {
        // A poisoned mutex only means another request panicked mid-update; the map is
        // still structurally valid for this demo store.
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut g)
    }
}

#[derive(Clone, PoringState)]
struct AppState {
    todos: TodoStore,
}

#[poring::get("/todos")]
async fn list(State(s): State<TodoStore>) -> Json<Vec<Todo>> {
    Json(s.with(|(_, m)| m.values().cloned().collect()))
}

#[poring::post("/todos", policy(body_limit = "4KiB"))]
async fn create(State(s): State<TodoStore>, Json(new): Json<NewTodo>) -> (StatusCode, Json<Todo>) {
    let todo = s.with(|(next, m)| {
        *next += 1;
        let t = Todo { id: *next, title: new.title, done: false };
        m.insert(t.id, t.clone());
        t
    });
    (StatusCode::CREATED, Json(todo))
}

#[poring::patch("/todos/{id}", policy(body_limit = "4KiB"))]
async fn update(
    Path(id): Path<u64>,
    State(s): State<TodoStore>,
    Json(p): Json<TodoPatch>,
) -> Result<Json<Todo>, ApiError> {
    s.with(|(_, m)| {
        let t = m.get_mut(&id).ok_or(TodoError::NotFound(id))?;
        if let Some(title) = p.title {
            t.title = title;
        }
        if let Some(done) = p.done {
            t.done = done;
        }
        Ok(Json(t.clone()))
    })
}

#[poring::delete("/todos/{id}")]
async fn remove(Path(id): Path<u64>, State(s): State<TodoStore>) -> Result<StatusCode, ApiError> {
    s.with(|(_, m)| m.remove(&id)).map(|_| StatusCode::NO_CONTENT).ok_or_else(|| TodoError::NotFound(id).into())
}

poring_app! {
    Todos {
        state: AppState,
        routes: [list, create, update, remove],
    }
}

#[tokio::main]
async fn main() -> Result<(), poring::StartupError> {
    let addr = std::env::var("PORING_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    Todos::builder()
        .state(AppState { todos: TodoStore::default() })
        // Uniform envelope for framework errors (404/405/415/422...).
        .map_errors(|e, mut res| {
            res.headers_mut().insert("x-poring-error", HeaderValue::from_static(e.code));
            res
        })
        .listen(addr)
        .await
}
