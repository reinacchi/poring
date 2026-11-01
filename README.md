<p align="center"><img src="Poring.png" alt="Poring Logo" width="350"/></p>

<h1 align="center">Poring</h1>
<p align="center">
    <strong>Ergonomic Rust web framework built on Tokio and Hyper.</strong>
    <br>
    Poring is a fast, type-safe Rust web framework designed for simplicity, performance, and developer experience. Build robust web applications with intuitive routing, compile-time security policies, built-in tracing, and WebAssembly support.
</p>

<p align="center">
  <a href="https://poring.2rkf.fun"><strong>Website</strong></a>
  ·
  <a href="https://discord.gg/wynvba7skH"><strong>Discord</strong></a>
</p>

## Examples

### Fluent API

Build web applications with a clean, expressive API without route attributes.

```rust
use poring::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Poring::new()
        .get("/", || async {
            "Hello, Poring!"
        })
        .get("/hello", || async {
            "Hello, world!"
        })
        .run("127.0.0.1:3000")?;

    Ok(())
}
```

### Attribute Macros

Define routes using Rust attributes with compile-time route validation.

```rust
use poring::prelude::*;

#[poring::get("/")]
async fn index() -> &'static str {
    "Hello, Poring!"
}

#[poring::get("/hello")]
async fn hello() -> &'static str {
    "Hello, world!"
}

poring_app! {
    pub App {
        routes: [index, hello],
    }
}

#[tokio::main]
async fn main() -> Result<(), poring::StartupError> {
    App::builder()
        .listen("127.0.0.1:3000")
        .await
}
```

## Examples

See more examples [here](/examples/).