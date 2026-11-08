#!/usr/bin/env bash
# One-command CI verification for Poring. GitHub Actions runs these same targets (see
# .github/workflows/ci.yml and heavy.yml call this script), so a green local run means the
# same commands pass. The remote CI is still the authoritative check.
#
# Usage:
#   scripts/verify-ci.sh [--fail-fast] [TARGET [ENTRY]]
#
# Targets (default: ci):
#   ci              lint core features isolated-tests examples docs   (every PR/push)
#   heavy           wasm-features wasm-tests all-features package stress-smoke (local only)
#                                                                     (weekly / on demand)
#   everything      ci + heavy
#   security        cargo audit of every lockfile against the RustSec advisory DB
#   release         everything + security: the gate a release tag must pass
#   lint | core | examples | docs | wasm-tests | all-features | package | stress-smoke
#   features [FLAGS]        one feature-matrix entry, or all of them
#   isolated-tests [FEATS]  one integration-test feature group, or all of them
#   wasm-features [FEAT]    one Wasm-family feature, or all of them
#   list                    print the matrix entries (used by the workflows' sync check)
#
# Environment:
#   RUST_TOOLCHAIN   run cargo as `cargo +$RUST_TOOLCHAIN` (e.g. 1.97.0, the pinned MSRV
#                    that CI uses and the ui snapshots were recorded with)
#
# Setup (Linux, e.g. Ubuntu 24.04):
#   rustup toolchain install 1.97.0 -c rustfmt -c clippy -t wasm32-unknown-unknown
#   Node.js 22 and `npm install -g typescript@7.0.2` (core, isolated-tests, all-features)
#   curl (wasm-tests demo)
#   cargo install --locked cargo-audit (security, release)
#
# Failures are aggregated: every command runs, each failure is reported with its exit
# code, and the script exits non-zero if any failed (with --fail-fast it stops at the
# first failure and exits with that command's code).

set -u
cd "$(dirname "$0")/.."

FEATURE_MATRIX=(
  "--no-default-features"
  "--no-default-features --features json"
  "--no-default-features --features trace-flow"
  "--no-default-features --features openapi"
  "--no-default-features --features http2"
  "--no-default-features --features websocket"
  "--no-default-features --features multipart"
  "--no-default-features --features tls-rustls"
  "--no-default-features --features websocket,http2"
  "--no-default-features --features websocket,multipart"
  "--no-default-features --features websocket,multipart,http2"
  "--no-default-features --features websocket,tls-rustls"
  "--no-default-features --features websocket,http2,tls-rustls"
  "default"
)
ISOLATED_TESTS=(
  "json,trace-flow"
  "json,openapi,trace-flow"
  "websocket"
  "multipart"
  "websocket,http2"
  "websocket,tls"
  "websocket,http2,tls"
)
WASM_FEATURES=(wasm hot-reload guest-kit cli)

FAIL_FAST=0
if [[ "${1:-}" == "--fail-fast" ]]; then
  FAIL_FAST=1
  shift
fi
TARGET="${1:-ci}"
ENTRY="${2-}"

CARGO=(cargo)
if [[ -n "${RUST_TOOLCHAIN:-}" ]]; then
  CARGO=(cargo "+$RUST_TOOLCHAIN")
fi

FAILED=()
PASSED=0

run() {
  echo
  echo "==> $*"
  "$@"
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "FAILED (exit $rc): $*"
    FAILED+=("[exit $rc] $*")
    if [[ $FAIL_FAST -eq 1 ]]; then
      summary
      exit "$rc"
    fi
  else
    PASSED=$((PASSED + 1))
  fi
  return 0
}

c() { run "${CARGO[@]}" "$@"; }

summary() {
  echo
  echo "======================================================================"
  echo "verify-ci: $PASSED command(s) passed, ${#FAILED[@]} failed"
  for f in "${FAILED[@]}"; do
    echo "  $f"
  done
}

# Fails the target when a tool that CI installs is missing: a missing tool must never turn
# into a silently skipped check.
need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    run false "required tool \`$1\` not found ($2)"
    return 1
  fi
}

in_list() {
  local needle="$1"
  shift
  local x
  for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
  return 1
}

t_lint() {
  c fmt --all -- --check
  c clippy --locked -p poring --all-targets --features websocket,multipart,http2,tls-rustls -- -D warnings
  c clippy --locked -p poring --all-targets --no-default-features -- -D warnings
  c clippy --locked -p poring --all-targets --no-default-features --features websocket -- -D warnings
  c clippy --locked -p poring-macros --all-targets -- -D warnings
  c clippy --locked -p poring-tests --all-targets --no-default-features --features full,http2,tls -- -D warnings
  c clippy --locked -p poring-tests --all-targets --no-default-features -- -D warnings
  c clippy --locked -p poring-examples --all-targets --no-default-features --features json,trace-flow,openapi,websocket -- -D warnings
}

t_core() {
  # The contract test type-checks the generated TypeScript client with `tsc`, and the
  # ignored ws_h2 test drives an independent Node.js HTTP/2 client.
  need node "install Node.js 22"
  need tsc "npm install -g typescript@7.0.2"
  c test --locked -p poring --features websocket,multipart,http2,tls-rustls
  c test --locked -p poring-macros
  CI="${CI:-1}" c test --locked -p poring-tests --no-default-features --features full,http2,tls
  c test --locked -p poring-tests --no-default-features --features websocket,http2 --test ws_h2 -- --ignored
  c test --locked -p poring-examples --no-default-features --features json --example secure_admin
}

features_one() {
  local flags="$1"
  [[ "$flags" == "default" ]] && flags=""
  # shellcheck disable=SC2086 # the flags are a word list by design
  c check --locked -p poring --all-targets $flags
  # shellcheck disable=SC2086
  c test --locked -p poring $flags
}

t_features() {
  if [[ -n "$ENTRY" ]]; then
    in_list "$ENTRY" "${FEATURE_MATRIX[@]}" || { run false "unknown feature-matrix entry: $ENTRY"; return; }
    features_one "$ENTRY"
  else
    local f
    for f in "${FEATURE_MATRIX[@]}"; do features_one "$f"; done
  fi
}

isolated_one() {
  CI="${CI:-1}" c test --locked -p poring-tests --no-default-features --features "$1"
}

t_isolated_tests() {
  need tsc "npm install -g typescript@7.0.2"
  if [[ -n "$ENTRY" ]]; then
    in_list "$ENTRY" "${ISOLATED_TESTS[@]}" || { run false "unknown isolated-tests entry: $ENTRY"; return; }
    isolated_one "$ENTRY"
  else
    local f
    for f in "${ISOLATED_TESTS[@]}"; do isolated_one "$f"; done
  fi
}

t_examples() {
  c check --locked -p poring-examples --examples --no-default-features
  c check --locked -p poring-examples --examples --no-default-features --features json
  c check --locked -p poring-examples --examples --no-default-features --features websocket
  c check --locked -p poring-examples --examples --no-default-features --features json,trace-flow,openapi,websocket
}

t_docs() {
  RUSTDOCFLAGS="-D warnings" c doc --locked --no-deps -p poring -p poring-macros \
    --features poring/websocket,poring/multipart,poring/http2,poring/tls-rustls
}

wasm_features_one() {
  c check --locked -p poring --all-targets --no-default-features --features "$1"
  c test --locked -p poring --no-default-features --features "$1"
}

t_wasm_features() {
  if [[ -n "$ENTRY" ]]; then
    in_list "$ENTRY" "${WASM_FEATURES[@]}" || { run false "unknown wasm feature: $ENTRY"; return; }
    wasm_features_one "$ENTRY"
  else
    local f
    for f in "${WASM_FEATURES[@]}"; do wasm_features_one "$f"; done
  fi
}

t_wasm_tests() {
  need curl "the hot-reload demo talks to the host over HTTP"
  c test --locked -p poring-tests --no-default-features --features wasm-guests
  run bash scripts/wasm_demo.sh
  # The standalone guest is not a workspace member (excluded in the root manifest).
  c build --release --target wasm32-unknown-unknown --manifest-path examples/wasm-guest/Cargo.toml
}

t_all_features() {
  need tsc "npm install -g typescript@7.0.2"
  c clippy --locked -p poring --all-targets --all-features -- -D warnings
  CI="${CI:-1}" c test --locked --workspace --all-features
  RUSTDOCFLAGS="-D warnings" c doc --locked --workspace --all-features --no-deps
}

t_package() {
  c package --locked -p poring-macros
  c package --locked -p poring --list
  # Both crates packaged together: `poring`'s verify build uses the packaged
  # `poring-macros`, so this also checks the exact version pin between them.
  c package --locked -p poring-macros -p poring
  run package_consumer
}

# Builds and runs scripts/consumer (HTTP, macros, WebSocket origin policy, typed managed
# WebSockets) against the extracted `.crate` files only, outside the workspace.
package_consumer() {
  local dir version_p version_m pkg="${CARGO_TARGET_DIR:-target}/package"
  dir="$(mktemp -d)"
  version_p="$("${CARGO[@]}" pkgid -p poring | sed 's/.*[#@]//')"
  version_m="$("${CARGO[@]}" pkgid -p poring-macros | sed 's/.*[#@]//')"
  mkdir -p "$dir/vendor" "$dir/src" &&
    tar xzf "$pkg/poring-$version_p.crate" -C "$dir/vendor" &&
    tar xzf "$pkg/poring-macros-$version_m.crate" -C "$dir/vendor" &&
    mv "$dir/vendor/poring-$version_p" "$dir/vendor/poring" &&
    mv "$dir/vendor/poring-macros-$version_m" "$dir/vendor/poring-macros" &&
    cp scripts/consumer/Cargo.toml.in "$dir/Cargo.toml" &&
    cp scripts/consumer/src/main.rs "$dir/src/main.rs" &&
    (cd "$dir" && CARGO_TARGET_DIR="$dir/target" "${CARGO[@]}" run --quiet)
  local rc=$?
  rm -rf "$dir"
  return $rc
}

t_ci() {
  t_lint
  t_core
  t_features
  t_isolated_tests
  t_examples
  t_docs
}

# Builds the benchmark harness and runs a small sustained-load pass: every profile
# (idle, echo, slow readers, churn, abrupt disconnects, shutdown under load) at 100
# connections. The harness asserts nothing about speed. It fails if sessions leak.
# The harness (benches/) is local only and not in the repository, so the target is
# skipped when it is absent.
t_stress_smoke() {
  if [[ ! -f benches/ws-bench/Cargo.toml ]]; then
    echo "==> stress-smoke skipped: benches/ws-bench is not present (local only)"
    return 0
  fi
  run "${CARGO[@]}" build --release --locked --manifest-path benches/ws-bench/Cargo.toml &&
    run stress_smoke_check
}

stress_smoke_check() {
  local out
  local exe="${CARGO_TARGET_DIR:-benches/ws-bench/target}/release/ws-bench"
  [[ -x "$exe" ]] || exe="$exe.exe"
  out="$("$exe" stress --conns 100 --secs 2)" || return 1
  echo "$out"
  # Every row must have no failed handshakes and a completed cleanup (or shutdown).
  echo "$out" | awk -F'|' '/^\| (idle|small|medium|large|slow|churn|abrupt|shutdown) /{
      gsub(/ /,"",$5); gsub(/ /,"",$16); gsub(/ /,"",$17);
      if ($5 != "0" || ($16 == "n/a" && $17 == "n/a")) { print "leak or failure: " $0; bad=1 }
      rows++ }
    END { exit (bad || rows != 8) }'
}

# RustSec advisories for the workspace and every standalone lockfile (benches, guest).
# Warnings (unmaintained/yanked crates) are printed. Vulnerabilities fail the target.
t_security() {
  need cargo-audit "cargo install --locked cargo-audit" || return
  local lock
  while IFS= read -r lock; do
    run cargo audit --file "$lock"
  done < <(find . -name Cargo.lock -not -path '*/target/*' -not -path './.git/*' | sort)
}

t_heavy() {
  t_wasm_features
  t_wasm_tests
  t_all_features
  t_package
  t_stress_smoke
}

case "$TARGET" in
  list)
    printf 'features: %s\n' "${FEATURE_MATRIX[@]}"
    printf 'isolated-tests: %s\n' "${ISOLATED_TESTS[@]}"
    printf 'wasm-features: %s\n' "${WASM_FEATURES[@]}"
    exit 0
    ;;
  ci) t_ci ;;
  heavy) t_heavy ;;
  everything) t_ci; t_heavy ;;
  security) t_security ;;
  release) t_ci; t_heavy; t_security ;;
  lint) t_lint ;;
  core) t_core ;;
  features) t_features ;;
  isolated-tests) t_isolated_tests ;;
  examples) t_examples ;;
  docs) t_docs ;;
  wasm-features) t_wasm_features ;;
  wasm-tests) t_wasm_tests ;;
  all-features) t_all_features ;;
  package) t_package ;;
  stress-smoke) t_stress_smoke ;;
  *)
    echo "unknown target: $TARGET (see the header of $0)" >&2
    exit 2
    ;;
esac

summary
[[ ${#FAILED[@]} -eq 0 ]]
