//! `cargo poring`: inspect a Poring app without starting it.
//!
//! ```text
//! cargo poring manifest --example secure_admin [-p poring-examples] [-o manifest.json]
//! cargo poring graph    (--manifest FILE | --example NAME) [--route "GET /users/{id}"] [--format mermaid|dot|json] [--trace trace.json]
//! cargo poring explain  (--manifest FILE | --example NAME) "DELETE /admin/users/{id}"
//! cargo poring audit    (--manifest FILE | --example NAME) [--format md|json]
//! ```
//!
//! With `--example`, the CLI runs the example with `PORING_DUMP_MANIFEST=<tmp>`. The app's
//! `main` must call `poring::dump_manifest_if_requested::<App>()` first, so only the static
//! manifest is produced: no state is constructed and no server is started.
#![forbid(unsafe_code)]

mod dev;

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use poring::contract::{Manifest, RuntimeTrace};

const USAGE: &str =
    "usage: cargo poring <manifest|graph|explain|audit> [--manifest FILE | --example NAME [-p PKG]] [options]
  graph   [--route \"METHOD /path\"] [--format mermaid|dot|json] [--trace runtime-trace.json]
  explain \"METHOD /path\"
  audit   [--format md|json]
  manifest [-o FILE]";

struct Args {
    cmd: String,
    manifest: Option<PathBuf>,
    example: Option<String>,
    package: Option<String>,
    route: Option<String>,
    format: Option<String>,
    trace: Option<PathBuf>,
    out: Option<PathBuf>,
    wasm: Option<PathBuf>,
    addr: Option<String>,
    method: Option<String>,
    name: Option<String>,
    version: Option<String>,
    grant: Vec<String>,
    positional: Vec<String>,
}

fn parse() -> Result<Args, String> {
    let mut it = std::env::args().skip(1).peekable();
    // Invoked as `cargo poring ...` => argv[1] == "poring".
    if it.peek().map(String::as_str) == Some("poring") {
        it.next();
    }
    let cmd = it.next().ok_or_else(|| USAGE.to_owned())?;
    let mut a = Args {
        cmd,
        manifest: None,
        example: None,
        package: None,
        route: None,
        format: None,
        trace: None,
        out: None,
        wasm: None,
        addr: None,
        method: None,
        name: None,
        version: None,
        grant: Vec::new(),
        positional: Vec::new(),
    };
    while let Some(x) = it.next() {
        let mut val = |name: &str| it.next().ok_or_else(|| format!("{name} requires a value"));
        match x.as_str() {
            "--manifest" => a.manifest = Some(val("--manifest")?.into()),
            "--example" => a.example = Some(val("--example")?),
            "-p" | "--package" => a.package = Some(val("-p")?),
            "--route" => a.route = Some(val("--route")?),
            "--format" => a.format = Some(val("--format")?),
            "--trace" => a.trace = Some(val("--trace")?.into()),
            "-o" | "--out" => a.out = Some(val("-o")?.into()),
            "--wasm" => a.wasm = Some(val("--wasm")?.into()),
            "--addr" => a.addr = Some(val("--addr")?),
            "--method" => a.method = Some(val("--method")?),
            "--name" => a.name = Some(val("--name")?),
            "--version" => a.version = Some(val("--version")?),
            "--grant" => a.grant.push(val("--grant")?),
            "-h" | "--help" => return Err(USAGE.to_owned()),
            s if s.starts_with('-') => return Err(format!("unknown option {s}\n{USAGE}")),
            s => a.positional.push(s.to_owned()),
        }
    }
    Ok(a)
}

fn load(a: &Args) -> Result<Manifest, String> {
    let path = match (&a.manifest, &a.example) {
        (Some(p), _) => p.clone(),
        (None, Some(ex)) => {
            let tmp = std::env::temp_dir().join(format!("poring-manifest-{}-{ex}.json", std::process::id()));
            let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
            c.args(["run", "-q", "--example", ex]);
            if let Some(p) = &a.package {
                c.args(["-p", p]);
            }
            c.env("PORING_DUMP_MANIFEST", &tmp);
            let status = c.status().map_err(|e| format!("failed to run cargo: {e}"))?;
            if !status.success() {
                return Err(format!(
                    "example `{ex}` did not produce a manifest (exit {status}); does its main() call poring::dump_manifest_if_requested::<App>() first?"
                ));
            }
            tmp
        }
        (None, None) => return Err(format!("need --manifest FILE or --example NAME\n{USAGE}")),
    };
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{} is not a Poring manifest: {e}", path.display()))
}

fn run() -> Result<String, String> {
    let a = parse()?;
    match a.cmd.as_str() {
        "manifest" => {
            let m = load(&a)?;
            let s = serde_json::to_string_pretty(&m).map_err(|e| e.to_string())?;
            match &a.out {
                Some(p) => {
                    std::fs::write(p, &s).map_err(|e| e.to_string())?;
                    Ok(format!("wrote {}\n", p.display()))
                }
                None => Ok(s + "\n"),
            }
        }
        "graph" => {
            let m = load(&a)?;
            let route = a.route.as_deref().or(a.positional.first().map(String::as_str));
            let g = poring::contract::build_graph(&m, route).ok_or_else(|| format!("no route matches {route:?}"))?;
            match a.format.as_deref().unwrap_or("mermaid") {
                "mermaid" => match &a.trace {
                    Some(t) => {
                        let bytes = std::fs::read(t).map_err(|e| e.to_string())?;
                        let trace: RuntimeTrace = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                        Ok(poring::contract::render_mermaid_with_trace(&g, &trace))
                    }
                    None => Ok(poring::contract::render_mermaid(&g)),
                },
                "dot" => Ok(poring::contract::render_dot(&g)),
                "json" => Ok(poring::contract::render_json(&g) + "\n"),
                f => Err(format!("unknown format `{f}` (mermaid, dot, json)")),
            }
        }
        "explain" => {
            let m = load(&a)?;
            let q = a.route.clone().or_else(|| (!a.positional.is_empty()).then(|| a.positional.join(" ")));
            let q = q.ok_or("explain needs a route, e.g. \"GET /users/{id}\"")?;
            poring::contract::explain(&m, &q).ok_or_else(|| format!("no route matches `{q}`"))
        }
        "audit" => {
            let m = load(&a)?;
            match a.format.as_deref().unwrap_or("md") {
                "md" | "markdown" => Ok(poring::contract::audit_markdown(&m)),
                "json" => serde_json::to_string_pretty(
                    &m.routes.iter().map(|r| (format!("{} {}", r.method, r.path), &r.policy)).collect::<Vec<_>>(),
                )
                .map(|s| s + "\n")
                .map_err(|e| e.to_string()),
                f => Err(format!("unknown format `{f}` (md, json)")),
            }
        }
        "dev" => dev::run_dev(dev::DevArgs {
            wasm: a.wasm.clone().ok_or("dev needs --wasm <artefact>")?,
            addr: a.addr.clone().unwrap_or_else(|| "127.0.0.1:3000".into()),
            route: a.route.clone().unwrap_or_else(|| "/guest/{*rest}".into()),
            method: a.method.clone().unwrap_or_else(|| "GET".into()),
            name: a.name.clone(),
            grant: a.grant.clone(),
        }),
        "wasm" => match a.positional.first().map(String::as_str) {
            Some("componentise") => {
                let input: PathBuf = a.positional.get(1).ok_or("componentise needs an input file")?.into();
                dev::componentise_file(&input, a.out.as_ref().ok_or("componentise needs -o <out.wasm>")?)
            }
            Some("new-echo") => dev::new_echo(
                a.name.as_deref().ok_or("new-echo needs --name")?,
                a.version.as_deref().unwrap_or("0.1.0"),
                a.out.as_ref().ok_or("new-echo needs -o <out.wat>")?,
            ),
            _ => Err(format!("unknown wasm subcommand\n{USAGE}")),
        },
        other => Err(format!("unknown command `{other}`\n{USAGE}")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(out) => {
            print!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}
