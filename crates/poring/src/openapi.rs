//! OpenAPI 3.1 and TypeScript client generation from compile-time route descriptors.
//!
//! The contract is derived from the same data the runtime uses: route descriptors
//! (methods, paths, extractor schemas, response types from return types) and effective
//! policies. Output is deterministic (sorted maps), suitable for snapshot tests.
//!
//! The TypeScript client is generated from the OpenAPI document: Rust types are the source
//! of truth and the TypeScript types are emitted code.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Map, Value, json};

use crate::app::{AppSpec, RouteDoc, StartupError, static_contract};
use crate::contract::Manifest;
use crate::descriptor::ExtractorKind;
use crate::schema::SchemaRegistry;

/// Document metadata.
#[derive(Clone, Debug)]
pub struct Info {
    /// API title.
    pub title: String,
    /// API version.
    pub version: String,
    /// Optional description.
    pub description: Option<String>,
}

impl Info {
    /// Creates metadata.
    pub fn new(title: impl Into<String>, version: impl Into<String>) -> Self {
        Info {
            title: title.into(),
            version: version.into(),
            description: None,
        }
    }
}

fn openapi_path(p: &str) -> String {
    p.replace("{*", "{")
}

fn param_entries(
    location: &str,
    schema: &Value,
    names: &[&str],
    reg: &SchemaRegistry,
) -> Vec<Value> {
    let resolved = reg.resolve(schema);
    let mut out = Vec::new();
    if let Some(props) = resolved.get("properties").and_then(Value::as_object) {
        let required: Vec<&str> = resolved
            .get("required")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for (k, v) in props {
            out.push(json!({
                "name": k,
                "in": location,
                "required": location == "path" || required.contains(&k.as_str()),
                "schema": v,
            }));
        }
    } else if let Some(items) = resolved.get("prefixItems").and_then(Value::as_array) {
        for (k, v) in names.iter().zip(items) {
            out.push(json!({"name": k, "in": location, "required": true, "schema": v}));
        }
    } else if let Some(name) = names.first() {
        out.push(json!({"name": name, "in": location, "required": true, "schema": resolved}));
    }
    out
}

fn status_key(s: u16) -> String {
    if s == 0 {
        "default".to_owned()
    } else {
        s.to_string()
    }
}

/// Builds the OpenAPI 3.1 document for the `poring_app!` routes of app `A`, without state
/// or a server. Use [`App::openapi`](crate::App::openapi) to include fluent and dynamic
/// routes registered on a built app.
pub fn openapi<A: AppSpec>(info: &Info) -> Result<Value, StartupError> {
    let (manifest, docs) = static_contract::<A>()?;
    Ok(document(info, &manifest, &docs))
}

pub(crate) fn document(info: &Info, manifest: &Manifest, docs: &[RouteDoc]) -> Value {
    let mut reg = SchemaRegistry::new();
    let mut paths: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut op_ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut uses_bearer = false;
    for (entry, d) in manifest.routes.iter().zip(docs) {
        let params_names: Vec<&str> = d.params.iter().map(String::as_str).collect();
        let mut op = Map::new();
        let base_id = d.name.clone();
        let n = op_ids.entry(base_id.clone()).or_insert(0);
        *n += 1;
        let op_id = if *n == 1 { base_id } else { entry.id.clone() };
        op.insert("operationId".into(), json!(op_id));
        if !d.doc.is_empty() {
            op.insert("summary".into(), json!(d.doc));
        }
        if let Some(g) = &entry.group {
            op.insert("tags".into(), json!([g]));
        }
        let mut params = Vec::new();
        let mut body = None;
        for e in &d.extractors {
            let Some(sf) = e.schema else { continue };
            let s = sf(&mut reg);
            match e.kind {
                ExtractorKind::Path => {
                    params.extend(param_entries("path", &s, &params_names, &reg))
                }
                ExtractorKind::Query => params.extend(param_entries("query", &s, &[], &reg)),
                ExtractorKind::Json => body = Some(("application/json", s)),
                ExtractorKind::Form => body = Some(("application/x-www-form-urlencoded", s)),
                _ => {}
            }
        }
        // Path params declared in the route but not extracted are still part of the path.
        for p in &d.params {
            if !params.iter().any(|v| v["in"] == "path" && v["name"] == *p) {
                params.push(json!({"name": p, "in": "path", "required": true, "schema": {"type": "string"}}));
            }
        }
        if !params.is_empty() {
            op.insert("parameters".into(), Value::Array(params));
        }
        if let Some((ct, s)) = body {
            op.insert(
                "requestBody".into(),
                json!({"required": true, "content": {ct: {"schema": s}}}),
            );
        }
        let mut responses = Map::new();
        let documented = d.responses.map(|f| f(&mut reg)).unwrap_or_default();
        for doc in documented {
            let key = status_key(doc.status);
            let mut resp = json!({"description": if doc.status == 0 { "Response or error" } else { "Success" }});
            match (doc.content_type, doc.schema) {
                (Some(ct), Some(s)) => resp["content"] = json!({ct: {"schema": s}}),
                (Some(ct), None) => resp["content"] = json!({ct: {}}),
                _ => {}
            }
            responses.entry(key).or_insert(resp);
        }
        if entry.policy.auth == "required" {
            uses_bearer = true;
            responses
                .entry("401".to_owned())
                .or_insert(json!({"description": "Authentication required"}));
            if !entry.policy.scopes.is_empty() || !entry.policy.roles.is_empty() {
                responses
                    .entry("403".to_owned())
                    .or_insert(json!({"description": "Missing scope or role"}));
            }
            op.insert(
                "security".into(),
                json!([{"bearerAuth": entry.policy.scopes}]),
            );
        } else {
            op.insert("security".into(), json!([]));
        }
        if entry.extractors.iter().any(|e| e.validates) {
            responses
                .entry("422".to_owned())
                .or_insert(json!({"description": "Validation failed"}));
        }
        if responses.is_empty() {
            responses.insert("default".into(), json!({"description": "Response"}));
        }
        op.insert("responses".into(), Value::Object(responses));
        op.insert(
            "x-poring-policy".into(),
            json!({
                "route_id": entry.id,
                "auth": entry.policy.auth,
                "public_reason": entry.policy.public_reason,
                "scopes": entry.policy.scopes,
                "roles": entry.policy.roles,
                "body_limit": entry.policy.body_limit,
                "rate_limit": entry.policy.rate_limit.as_ref().map(|r| json!({"requests": r.requests, "per_ms": r.per_ms, "key": r.key})),
                "timeout_ms": entry.policy.timeout_ms,
                "checks": entry.policy.checks,
            }),
        );
        paths
            .entry(openapi_path(&entry.path))
            .or_default()
            .insert(entry.method.to_ascii_lowercase(), Value::Object(op));
    }
    let mut components = json!({ "schemas": reg.components });
    if uses_bearer {
        components["securitySchemes"] = json!({"bearerAuth": {"type": "http", "scheme": "bearer"}});
    }
    let mut info_v = json!({"title": info.title, "version": info.version});
    if let Some(d) = &info.description {
        info_v["description"] = json!(d);
    }
    json!({
        "openapi": "3.1.0",
        "info": info_v,
        "paths": paths,
        "components": components,
    })
}

fn ts_ident(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

fn ts_key(k: &str) -> String {
    if !k.is_empty()
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !k.starts_with(|c: char| c.is_ascii_digit())
    {
        k.to_owned()
    } else {
        format!("{k:?}")
    }
}

/// Converts a JSON Schema fragment into a TypeScript type expression.
pub fn ts_type(s: &Value) -> String {
    if let Some(r) = s.get("$ref").and_then(Value::as_str) {
        return ts_ident(r.rsplit('/').next().unwrap_or("unknown"));
    }
    if let Some(any) = s
        .get("anyOf")
        .or_else(|| s.get("oneOf"))
        .and_then(Value::as_array)
    {
        let parts: Vec<String> = any.iter().map(ts_type).collect();
        return parts.join(" | ");
    }
    if let Some(all) = s.get("allOf").and_then(Value::as_array) {
        let parts: Vec<String> = all.iter().map(ts_type).collect();
        return parts.join(" & ");
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array) {
        return e
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(" | ");
    }
    match s.get("type").and_then(Value::as_str) {
        Some("string") => "string".into(),
        Some("integer" | "number") => "number".into(),
        Some("boolean") => "boolean".into(),
        Some("null") => "null".into(),
        Some("array") => {
            if let Some(items) = s.get("prefixItems").and_then(Value::as_array) {
                format!(
                    "[{}]",
                    items.iter().map(ts_type).collect::<Vec<_>>().join(", ")
                )
            } else {
                let inner = s
                    .get("items")
                    .map(ts_type)
                    .unwrap_or_else(|| "unknown".into());
                format!("Array<{inner}>")
            }
        }
        Some("object") => {
            let required: Vec<&str> = s
                .get("required")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            match s.get("properties").and_then(Value::as_object) {
                Some(props) => {
                    let fields: Vec<String> = props
                        .iter()
                        .map(|(k, v)| {
                            let opt = if required.contains(&k.as_str()) {
                                ""
                            } else {
                                "?"
                            };
                            format!("{}{opt}: {}", ts_key(k), ts_type(v))
                        })
                        .collect();
                    format!("{{ {} }}", fields.join("; "))
                }
                None => match s.get("additionalProperties") {
                    Some(v) if v.is_object() => format!("Record<string, {}>", ts_type(v)),
                    _ => "Record<string, unknown>".into(),
                },
            }
        }
        _ => "unknown".into(),
    }
}

/// Generates a dependency-free TypeScript client (uses `fetch`) from an OpenAPI document
/// produced by [`openapi`].
pub fn typescript_client(doc: &Value) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "// Generated by Poring from the route contract. Do not edit."
    );
    let _ = writeln!(o, "/* eslint-disable */\n");
    if let Some(schemas) = doc
        .pointer("/components/schemas")
        .and_then(Value::as_object)
    {
        for (name, s) in schemas {
            let _ = writeln!(o, "export type {} = {};\n", ts_ident(name), ts_type(s));
        }
    }
    let _ = writeln!(
        o,
        r#"export class PoringError extends Error {{
  constructor(public readonly status: number, public readonly body: unknown) {{
    super(`HTTP ${{status}}`);
  }}
}}

export interface ClientOptions {{
  headers?: Record<string, string>;
  fetch?: typeof fetch;
}}

function query(q: Record<string, unknown> | undefined): string {{
  if (!q) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {{
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) for (const x of v) p.append(k, String(x));
    else p.append(k, String(v));
  }}
  const s = p.toString();
  return s ? `?${{s}}` : "";
}}
"#
    );
    let _ = writeln!(
        o,
        "export function createClient(baseUrl: string, options: ClientOptions = {{}}) {{"
    );
    let _ = writeln!(o, "  const f = options.fetch ?? fetch;");
    let _ = writeln!(
        o,
        "  async function call<T>(method: string, path: string, body: unknown, ct: string | undefined, headers?: Record<string, string>): Promise<T> {{"
    );
    let _ = writeln!(
        o,
        "    const h: Record<string, string> = {{ ...(options.headers ?? {{}}), ...(headers ?? {{}}) }};"
    );
    let _ = writeln!(o, "    let payload: string | undefined;");
    let _ = writeln!(
        o,
        "    if (body !== undefined && ct === \"application/json\") {{ h[\"content-type\"] = ct; payload = JSON.stringify(body); }}"
    );
    let _ = writeln!(
        o,
        "    else if (body !== undefined && ct) {{ h[\"content-type\"] = ct; payload = new URLSearchParams(body as Record<string, string>).toString(); }}"
    );
    let _ = writeln!(
        o,
        "    const res = await f(baseUrl + path, {{ method, headers: h, body: payload }});"
    );
    let _ = writeln!(o, "    const text = await res.text();");
    let _ = writeln!(
        o,
        "    const isJson = (res.headers.get(\"content-type\") ?? \"\").includes(\"json\");"
    );
    let _ = writeln!(
        o,
        "    const data = isJson && text ? JSON.parse(text) : text;"
    );
    let _ = writeln!(
        o,
        "    if (!res.ok) throw new PoringError(res.status, data);"
    );
    let _ = writeln!(o, "    return data as T;");
    let _ = writeln!(o, "  }}");
    let _ = writeln!(o, "  return {{");
    if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
        for (path, ops) in paths {
            let Some(ops) = ops.as_object() else { continue };
            for (method, op) in ops {
                let id = op
                    .get("operationId")
                    .and_then(Value::as_str)
                    .unwrap_or("op");
                let params = op
                    .get("parameters")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let path_params: Vec<&Value> =
                    params.iter().filter(|p| p["in"] == "path").collect();
                let query_params: Vec<&Value> =
                    params.iter().filter(|p| p["in"] == "query").collect();
                let mut arg_fields = Vec::new();
                if !path_params.is_empty() {
                    let f: Vec<String> = path_params
                        .iter()
                        .map(|p| {
                            format!(
                                "{}: {}",
                                ts_key(p["name"].as_str().unwrap_or("p")),
                                ts_type(&p["schema"])
                            )
                        })
                        .collect();
                    arg_fields.push(format!("path: {{ {} }}", f.join("; ")));
                }
                if !query_params.is_empty() {
                    let f: Vec<String> = query_params
                        .iter()
                        .map(|p| {
                            let opt = if p["required"] == true { "" } else { "?" };
                            format!(
                                "{}{opt}: {}",
                                ts_key(p["name"].as_str().unwrap_or("q")),
                                ts_type(&p["schema"])
                            )
                        })
                        .collect();
                    arg_fields.push(format!("query?: {{ {} }}", f.join("; ")));
                }
                let mut ct = "undefined".to_owned();
                if let Some(content) = op
                    .pointer("/requestBody/content")
                    .and_then(Value::as_object)
                    && let Some((c, v)) = content.iter().next()
                {
                    arg_fields.push(format!("body: {}", ts_type(&v["schema"])));
                    ct = format!("{c:?}");
                }
                let all_optional = path_params.is_empty() && ct == "undefined";
                arg_fields.push("headers?: Record<string, string>".into());
                let ok = op
                    .get("responses")
                    .and_then(Value::as_object)
                    .and_then(|r| {
                        r.iter()
                            .find(|(k, _)| k.starts_with('2'))
                            .or_else(|| r.iter().find(|(k, _)| *k == "default"))
                    })
                    .map(|(_, v)| v);
                let ret = ok
                    .and_then(|v| v.pointer("/content"))
                    .and_then(Value::as_object)
                    .and_then(|c| c.values().next())
                    .map(|c| ts_type(&c["schema"]))
                    .unwrap_or_else(|| "unknown".into());
                let mut url = String::from("`");
                for seg in path.split('/').filter(|s| !s.is_empty()) {
                    url.push('/');
                    if let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                        let _ = write!(
                            url,
                            "${{encodeURIComponent(String(args.path.{}))}}",
                            ts_ident(name)
                        );
                    } else {
                        url.push_str(seg);
                    }
                }
                if path == "/" {
                    url.push('/');
                }
                url.push('`');
                let q = if query_params.is_empty() {
                    ""
                } else {
                    " + query(args.query)"
                };
                let body = if ct == "undefined" {
                    "undefined"
                } else {
                    "args.body"
                };
                let _ = writeln!(
                    o,
                    "    {}: (args: {{ {} }}{}): Promise<{ret}> =>\n      call<{ret}>({:?}, {url}{q}, {body}, {ct}, args.headers),",
                    ts_ident(id),
                    arg_fields.join("; "),
                    if all_optional { " = {}" } else { "" },
                    method.to_ascii_uppercase()
                );
            }
        }
    }
    let _ = writeln!(o, "  }};\n}}");
    o
}
