//! Build Poring guest components without a `wasm32` Rust toolchain (`guest-kit` feature).
//!
//! * [`componentise`] wraps a **core** Wasm module (binary or WAT text) that follows the
//!   canonical ABI for the Poring WIT world into a Component Model component. If the core
//!   module already embeds component-type metadata (as produced by `wit-bindgen`), that
//!   metadata is used; otherwise the bundled `wit/poring-plugin.wit` is embedded.
//! * [`GuestSpec`] generates small, readable core-WAT guests with configurable behaviour.
//!   The test suite and the hot-reload demo use them.

use std::fmt::Write as _;

/// The bundled WIT package (ABI version 1).
pub const WIT: &str = include_str!("../../wit/poring-plugin.wit");

/// Errors building a guest.
#[derive(Debug, thiserror::Error)]
pub enum KitError {
    /// WAT parse error.
    #[error("invalid WAT: {0}")]
    Wat(String),
    /// Component encoding error.
    #[error("cannot componentise: {0}")]
    Component(String),
}

fn has_component_type_section(module: &[u8]) -> bool {
    // Cheap scan for an embedded `component-type*` custom section name.
    module.windows(14).any(|w| w == b"component-type")
}

/// Converts a core module (binary or WAT text) into a Poring guest component.
pub fn componentise(core: &[u8]) -> Result<Vec<u8>, KitError> {
    let mut module = if core.starts_with(b"\0asm") {
        core.to_vec()
    } else {
        let text = std::str::from_utf8(core).map_err(|e| KitError::Wat(e.to_string()))?;
        wat::parse_str(text).map_err(|e| KitError::Wat(e.to_string()))?
    };
    if !has_component_type_section(&module) {
        let mut resolve = wit_parser::Resolve::default();
        let pkg = resolve
            .push_str("poring-plugin.wit", WIT)
            .map_err(|e| KitError::Component(e.to_string()))?;
        let world = resolve
            .select_world(&[pkg], Some("guest"))
            .map_err(|e| KitError::Component(e.to_string()))?;
        wit_component::embed_component_metadata(
            &mut module,
            &resolve,
            world,
            wit_component::StringEncoding::UTF8,
            false,
        )
        .map_err(|e| KitError::Component(e.to_string()))?;
    }
    wit_component::ComponentEncoder::default()
        .module(&module)
        .map_err(|e| KitError::Component(format!("{e:#}")))?
        .validate(true)
        .encode()
        .map_err(|e| KitError::Component(format!("{e:#}")))
}

/// What a generated guest does when `handle` is called.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Behaviour {
    /// Responds `status` with body `"<prefix><path>"` and `content-type: text/plain`.
    Echo,
    /// Busy-loops `n` iterations, then behaves like `Echo` (for in-flight tests).
    SpinThenEcho(u32),
    /// Traps (`unreachable`).
    Trap,
    /// Infinite loop (exhausts fuel / hits the epoch deadline).
    Forever,
    /// Grows memory until the host limiter refuses, then traps.
    MemoryBomb,
    /// Returns `err(guest-error { status, message })`.
    Error(u16, String),
    /// Calls the `log` capability, then echoes.
    LogThenEcho,
}

/// Declarative description of a generated guest.
#[derive(Clone, Debug)]
pub struct GuestSpec {
    /// `guest-info.name`.
    pub name: String,
    /// `guest-info.version`.
    pub version: String,
    /// `guest-info.abi` (the host supports 1).
    pub abi: u32,
    /// `guest-info.capabilities`.
    pub capabilities: Vec<String>,
    /// Response status for echo responses.
    pub status: u16,
    /// Echo body prefix.
    pub body_prefix: String,
    /// Behaviour of `handle`.
    pub behaviour: Behaviour,
    /// If true, the host's preflight probe (`/__poring/probe`) gets a normal echo and only
    /// real requests see `behaviour`. Used to test runtime (post-activation) failures.
    pub probe_safe: bool,
}

impl GuestSpec {
    /// An echo guest: `name`/`version`, ABI 1, no capabilities, 200, prefix
    /// `"hello from <name> <version>: "`.
    pub fn echo(name: &str, version: &str) -> Self {
        GuestSpec {
            name: name.into(),
            version: version.into(),
            abi: 1,
            capabilities: Vec::new(),
            status: 200,
            body_prefix: format!("hello from {name} {version}: "),
            behaviour: Behaviour::Echo,
            probe_safe: false,
        }
    }

    /// Sets the behaviour.
    pub fn behaviour(mut self, b: Behaviour) -> Self {
        if b == Behaviour::LogThenEcho && !self.capabilities.iter().any(|c| c == "log") {
            self.capabilities.push("log".into());
        }
        self.behaviour = b;
        self
    }

    /// Only real requests see the behaviour; the preflight probe gets an echo.
    pub fn probe_safe(mut self) -> Self {
        self.probe_safe = true;
        self
    }

    /// Sets the echo status.
    pub fn status(mut self, s: u16) -> Self {
        self.status = s;
        self
    }

    /// Generates the core-module WAT text.
    pub fn core_wat(&self) -> String {
        fn bytes_lit(b: &[u8]) -> String {
            b.iter().map(|x| format!("\\{x:02x}")).collect()
        }
        // Static layout (all below the 4096 heap start).
        const NAME: u32 = 16;
        const VERSION: u32 = 80;
        const CAPS_STR: u32 = 144;
        const CAPS_LIST: u32 = 400;
        const INFO: u32 = 512;
        const HDR_NAME: u32 = 1024;
        const HDR_VALUE: u32 = 1040;
        const HDR_REC: u32 = 1056;
        const PREFIX: u32 = 1088;
        const ERRMSG: u32 = 1600;
        const LOGMSG: u32 = 1900;
        const RESULT: u32 = 2048;
        let name = self.name.as_bytes();
        let version = self.version.as_bytes();
        let prefix = self.body_prefix.as_bytes();
        let mut caps_strings = Vec::new();
        let mut caps_list = Vec::new();
        let mut off = CAPS_STR;
        for c in &self.capabilities {
            caps_list.extend_from_slice(&off.to_le_bytes());
            caps_list.extend_from_slice(&(c.len() as u32).to_le_bytes());
            caps_strings.push((off, c.as_bytes().to_vec()));
            off += c.len() as u32;
        }
        let mut info = Vec::new();
        for v in [
            NAME,
            name.len() as u32,
            VERSION,
            version.len() as u32,
            self.abi,
            CAPS_LIST,
            self.capabilities.len() as u32,
        ] {
            info.extend_from_slice(&v.to_le_bytes());
        }
        let mut hdr = Vec::new();
        for v in [HDR_NAME, 12, HDR_VALUE, 10] {
            hdr.extend_from_slice(&v.to_le_bytes());
        }
        let imports_log = self.behaviour == Behaviour::LogThenEcho;
        let mut w = String::new();
        let _ = writeln!(w, "(module");
        if imports_log {
            let _ = writeln!(
                w,
                "  (import \"poring:plugin/log@0.1.0\" \"write\" (func $log (param i32 i32 i32)))"
            );
        }
        let _ = writeln!(w, "  (memory (export \"memory\") 1)");
        let _ = writeln!(w, "  (global $heap (mut i32) (i32.const 4096))");
        let _ = writeln!(
            w,
            r#"  (func $realloc (export "cabi_realloc") (param $old i32) (param $old_size i32) (param $align i32) (param $size i32) (result i32)
    (local $p i32) (local $need i32)
    (local.set $p (i32.and (i32.add (global.get $heap) (i32.sub (local.get $align) (i32.const 1)))
                           (i32.xor (i32.sub (local.get $align) (i32.const 1)) (i32.const -1))))
    (global.set $heap (i32.add (local.get $p) (local.get $size)))
    (local.set $need (i32.sub (global.get $heap) (i32.mul (memory.size) (i32.const 65536))))
    (if (i32.gt_s (local.get $need) (i32.const 0))
      (then
        (if (i32.eq (memory.grow (i32.add (i32.div_u (local.get $need) (i32.const 65536)) (i32.const 1))) (i32.const -1))
          (then unreachable))))
    (if (local.get $old) (then (memory.copy (local.get $p) (local.get $old) (local.get $old_size))))
    (local.get $p))"#
        );
        let _ = writeln!(w, "  (data (i32.const {NAME}) \"{}\")", bytes_lit(name));
        let _ = writeln!(
            w,
            "  (data (i32.const {VERSION}) \"{}\")",
            bytes_lit(version)
        );
        for (o, b) in &caps_strings {
            let _ = writeln!(w, "  (data (i32.const {o}) \"{}\")", bytes_lit(b));
        }
        if !caps_list.is_empty() {
            let _ = writeln!(
                w,
                "  (data (i32.const {CAPS_LIST}) \"{}\")",
                bytes_lit(&caps_list)
            );
        }
        let _ = writeln!(w, "  (data (i32.const {INFO}) \"{}\")", bytes_lit(&info));
        let _ = writeln!(w, "  (data (i32.const {HDR_NAME}) \"content-type\")");
        let _ = writeln!(w, "  (data (i32.const {HDR_VALUE}) \"text/plain\")");
        let _ = writeln!(w, "  (data (i32.const {HDR_REC}) \"{}\")", bytes_lit(&hdr));
        let _ = writeln!(w, "  (data (i32.const {PREFIX}) \"{}\")", bytes_lit(prefix));
        let _ = writeln!(
            w,
            "  (func (export \"poring:plugin/handler@0.1.0#info\") (result i32) (i32.const {INFO}))"
        );
        let echo = format!(
            r#"    (local.set $len (i32.add (i32.const {plen}) (local.get $path_len)))
    (local.set $buf (call $realloc (i32.const 0) (i32.const 0) (i32.const 1) (local.get $len)))
    (memory.copy (local.get $buf) (i32.const {PREFIX}) (i32.const {plen}))
    (memory.copy (i32.add (local.get $buf) (i32.const {plen})) (local.get $path_ptr) (local.get $path_len))
    (i32.store8 (i32.const {RESULT}) (i32.const 0))
    (i32.store16 (i32.const {r4}) (i32.const {status}))
    (i32.store (i32.const {r8}) (i32.const {HDR_REC}))
    (i32.store (i32.const {r12}) (i32.const 1))
    (i32.store (i32.const {r16}) (local.get $buf))
    (i32.store (i32.const {r20}) (local.get $len))
    (i32.const {RESULT})"#,
            plen = prefix.len(),
            status = self.status,
            r4 = RESULT + 4,
            r8 = RESULT + 8,
            r12 = RESULT + 12,
            r16 = RESULT + 16,
            r20 = RESULT + 20,
        );
        let probe_len = "/__poring/probe".len();
        let echo_stmt = echo
            .trim_end()
            .trim_end_matches(&format!("(i32.const {RESULT})"))
            .to_owned();
        let guard = if self.probe_safe && self.behaviour != Behaviour::Echo {
            format!(
                "    (if (i32.eq (local.get $path_len) (i32.const {probe_len}))\n      (then\n{echo_stmt}\n      (return (i32.const {RESULT}))))\n"
            )
        } else {
            String::new()
        };
        let body = match &self.behaviour {
            Behaviour::Echo => echo,
            Behaviour::SpinThenEcho(n) => format!(
                "    (loop $spin (local.set $i (i32.add (local.get $i) (i32.const 1))) (br_if $spin (i32.lt_u (local.get $i) (i32.const {n}))))\n{echo}"
            ),
            Behaviour::Trap => "    unreachable".to_owned(),
            Behaviour::Forever => "    (loop $l (br $l))\n    unreachable".to_owned(),
            Behaviour::MemoryBomb => {
                "    (loop $g (br_if $g (i32.ne (memory.grow (i32.const 16)) (i32.const -1))))\n    unreachable"
                    .to_owned()
            }
            Behaviour::Error(status, msg) => {
                let _ = writeln!(w, "  (data (i32.const {ERRMSG}) \"{}\")", bytes_lit(msg.as_bytes()));
                format!(
                    "    (i32.store8 (i32.const {RESULT}) (i32.const 1))\n    (i32.store16 (i32.const {}) (i32.const {status}))\n    (i32.store (i32.const {}) (i32.const {ERRMSG}))\n    (i32.store (i32.const {}) (i32.const {}))\n    (i32.const {RESULT})",
                    RESULT + 4,
                    RESULT + 8,
                    RESULT + 12,
                    msg.len()
                )
            }
            Behaviour::LogThenEcho => {
                let _ = writeln!(w, "  (data (i32.const {LOGMSG}) \"guest says hi\")");
                format!("    (call $log (i32.const 2) (i32.const {LOGMSG}) (i32.const 13))\n{echo}")
            }
        };
        let body = format!("{guard}{body}");
        let _ = writeln!(
            w,
            r#"  (func (export "poring:plugin/handler@0.1.0#handle")
    (param $method_ptr i32) (param $method_len i32) (param $path_ptr i32) (param $path_len i32)
    (param $query_ptr i32) (param $query_len i32) (param $headers_ptr i32) (param $headers_len i32)
    (param $body_ptr i32) (param $body_len i32) (param $params_ptr i32) (param $params_len i32)
    (param $principal_tag i32) (param $principal_ptr i32) (param $principal_len i32)
    (result i32)
    (local $buf i32) (local $len i32) (local $i i32)
{body})"#
        );
        let _ = writeln!(w, ")");
        w
    }

    /// Builds the component binary.
    pub fn build(&self) -> Result<Vec<u8>, KitError> {
        componentise(self.core_wat().as_bytes())
    }
}
