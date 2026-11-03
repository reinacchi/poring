#!/usr/bin/env bash
# Interleaved A/B load test of two `bench_server` builds (for example before and after a
# change). Both servers run side by side on the same CPUs and oha alternates between them
# in ABBA order, so drift on a shared host affects both builds equally. Results are written
# as oha JSON under target/perf/ab-<mode>/ and can be compared pair by pair.
#
#   scripts/perf-ab.sh <mode> <baseline-binary> <candidate-binary>
#
# Tunables (environment): AB_PAIRS (10), AB_DURATION (4s), AB_CONCURRENCY (64),
# AB_ENDPOINTS (space-separated paths), AB_SERVER_CPUS (0), AB_CLIENT_CPUS (1),
# AB_HEADERS (extra oha -H argument, e.g. "Authorization: Bearer bench").
set -euo pipefail

mode=${1:?mode}
base=${2:?baseline binary}
cand=${3:?candidate binary}

cd "$(dirname "$0")/.."
command -v oha >/dev/null || { echo "oha is required (cargo install oha)"; exit 1; }
command -v taskset >/dev/null || { echo "taskset is required"; exit 1; }

pairs=${AB_PAIRS:-10}
duration=${AB_DURATION:-4s}
concurrency=${AB_CONCURRENCY:-64}
endpoints=${AB_ENDPOINTS:-/bench/plain /bench/path/12345 /bench/json /bench/post}
out="target/perf/ab-$mode"
mkdir -p "$out"
body="$out/post-body.json"
python3 -c 'import json; print(json.dumps(list(range(256))))' >"$body"
headers=()
[[ -n "${AB_HEADERS:-}" ]] && headers=(-H "$AB_HEADERS")

start() {
    env PORING_BENCH_MODE="$mode" PORING_BENCH_WORKERS=1 PORING_BENCH_ADDR="127.0.0.1:$2" \
        taskset -c "${AB_SERVER_CPUS:-0}" "$1" >/dev/null 2>&1 &
    echo $!
}
base_pid=$(start "$base" 3991)
cand_pid=$(start "$cand" 3992)
trap 'kill "$base_pid" "$cand_pid" 2>/dev/null || true' EXIT
sleep 1

for ep in $endpoints; do
    name=$(echo "$ep" | tr '/' '_' | sed 's/^_//')
    method=(-m GET)
    [[ "$ep" == /bench/post ]] && method=(-m POST -T application/json -D "$body")
    for port in 3991 3992; do
        taskset -c "${AB_CLIENT_CPUS:-1}" oha --no-tui -z 2s -c "$concurrency" "${headers[@]}" \
            "${method[@]}" "http://127.0.0.1:$port$ep" >/dev/null
    done
    for i in $(seq 1 "$pairs"); do
        order="3991 3992"
        (( i % 2 == 0 )) && order="3992 3991"
        for port in $order; do
            label=base
            [[ $port == 3992 ]] && label=new
            taskset -c "${AB_CLIENT_CPUS:-1}" oha --no-tui --output-format json -z "$duration" \
                -c "$concurrency" "${headers[@]}" "${method[@]}" "http://127.0.0.1:$port$ep" \
                >"$out/$label.$name.c$concurrency.run$i.json"
        done
    done
done
echo "results: $out"
