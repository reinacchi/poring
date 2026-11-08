#!/usr/bin/env bash
# External HTTP load test for the `bench_server` example (or any server exposing the same
# endpoints). Results are written as oha JSON under target/perf/<label>/.
#
#   scripts/perf.sh <label> <server-binary> [extra env assignments...]
#
# Example (server on CPU 0, load generator on CPU 1):
#   cargo build --release -p poring-examples --no-default-features --example bench_server
#   PERF_SERVER_CPUS=0 PERF_CLIENT_CPUS=1 \
#     scripts/perf.sh fluent target/release/examples/bench_server PORING_BENCH_MODE=fluent
#
# Tunables (environment): PERF_DURATION (default 10s), PERF_WARMUP (3s), PERF_REPEAT (5),
# PERF_CONCURRENCY (64), PERF_ENDPOINTS (space-separated paths), PERF_PORT (3990),
# PERF_SERVER_CPUS / PERF_CLIENT_CPUS (taskset lists, empty = unpinned), PERF_HEADERS
# (extra oha -H arguments, e.g. "Authorization: Bearer bench").
set -euo pipefail

label=${1:?label}
server=${2:?server binary}
shift 2

cd "$(dirname "$0")/.."
command -v oha >/dev/null || { echo "oha is required (cargo install oha)"; exit 1; }

duration=${PERF_DURATION:-10s}
warmup=${PERF_WARMUP:-3s}
repeat=${PERF_REPEAT:-5}
concurrency=${PERF_CONCURRENCY:-64}
port=${PERF_PORT:-3990}
endpoints=${PERF_ENDPOINTS:-/bench/plain /bench/path/12345 /bench/json /bench/post /bench/cpu /bench/large /bench/heavy}
out="target/perf/$label"
mkdir -p "$out"

pin() {
    local cpus=$1
    shift
    if [[ -n "$cpus" ]] && command -v taskset >/dev/null; then
        taskset -c "$cpus" "$@"
    else
        "$@"
    fi
}

body="$out/post-body.json"
python3 -c 'import json; print(json.dumps(list(range(256))))' >"$body"

launcher=()
if [[ -n "${PERF_SERVER_CPUS:-}" ]] && command -v taskset >/dev/null; then
    launcher=(taskset -c "$PERF_SERVER_CPUS")
fi
env PORING_BENCH_ADDR="127.0.0.1:$port" "$@" "${launcher[@]}" "$server" 2>"$out/server.log" &
server_pid=$!
trap 'kill $server_pid 2>/dev/null || true' EXIT
auth=()
[[ -n "${PERF_HEADERS:-}" ]] && auth=(-H "$PERF_HEADERS")
for _ in $(seq 1 100); do
    curl -sf -o /dev/null "${auth[@]}" "http://127.0.0.1:$port/bench/plain" && break
    sleep 0.1
done

oha_args=(--no-tui --output-format json -c "$concurrency")
[[ -n "${PERF_HEADERS:-}" ]] && oha_args+=(-H "$PERF_HEADERS")

for ep in $endpoints; do
    name=$(echo "$ep" | tr '/' '_' | sed 's/^_//')
    url="http://127.0.0.1:$port$ep"
    method=(-m GET)
    if [[ "$ep" == /bench/post ]]; then
        method=(-m POST -T application/json -D "$body")
    fi
    # Fail early on a wrong status. Keep the body for byte-for-byte comparison.
    if [[ "$ep" == /bench/post ]]; then
        curl -sf "${auth[@]}" -H content-type:application/json --data-binary "@$body" "$url" \
            -o "$out/$name.body"
    else
        curl -sf "${auth[@]}" -D "$out/$name.headers" "$url" -o "$out/$name.body"
    fi
    pin "${PERF_CLIENT_CPUS:-}" oha "${oha_args[@]}" -z "$warmup" "${method[@]}" "$url" >/dev/null
    for run in $(seq 1 "$repeat"); do
        pin "${PERF_CLIENT_CPUS:-}" oha "${oha_args[@]}" -z "$duration" "${method[@]}" "$url" \
            >"$out/$name.c$concurrency.run$run.json"
    done
done
echo "results: $out"
