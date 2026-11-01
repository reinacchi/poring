#!/usr/bin/env bash
# Smoke demo: change a mounted Wasm guest's response while the native host
# process keeps running (same PID); a broken artefact leaves traffic working.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p poring --features cli --bin cargo-poring
BIN=target/debug/cargo-poring
WORK=$(mktemp -d); trap 'kill $HOST 2>/dev/null || true; rm -rf "$WORK"' EXIT
PORT=${PORT:-3920}
$BIN poring wasm new-echo --name demo --version 1 -o "$WORK/guest.wat" >/dev/null
$BIN poring dev --wasm "$WORK/guest.wat" --addr 127.0.0.1:$PORT 2>"$WORK/host.log" &
HOST=$!
for _ in $(seq 1 100); do curl -sf "localhost:$PORT/__poring/health" >/dev/null && break; sleep 0.1; done
pid_before=$(curl -s "localhost:$PORT/__poring/health")
r1=$(curl -s "localhost:$PORT/guest/hello")
echo "before reload: $r1   [$pid_before, host pid $HOST]"
$BIN poring wasm new-echo --name demo --version 2 -o "$WORK/next.wat" >/dev/null
cp "$WORK/next.wat" "$WORK/guest.wat"
for _ in $(seq 1 60); do r2=$(curl -s "localhost:$PORT/guest/hello"); [[ "$r2" == *"demo 2"* ]] && break; sleep 0.1; done
echo "after reload:  $r2"
printf 'this is not wasm' > "$WORK/guest.wat"
sleep 1.5
r3=$(curl -s -w ' [%{http_code}]' "localhost:$PORT/guest/hello")
echo "after broken artefact: $r3"
pid_after=$(curl -s "localhost:$PORT/__poring/health")
echo "host: $pid_before -> $pid_after"
grep -E "hot reload applied|cannot read artefact|hot reload rejected" "$WORK/host.log" | sed -E 's/^[^ ]+ +[A-Z]+ +//' | cut -c1-150 || true
[[ "$r1" == *"demo 1"* && "$r2" == *"demo 2"* && "$r3" == *"demo 2"*"[200]" && "$pid_before" == "$pid_after" && "$pid_before" == "ok pid=$HOST" ]] \
  && echo "DEMO PASSED: guest changed, broken artefact rejected, same host PID" || { echo "DEMO FAILED"; exit 1; }
