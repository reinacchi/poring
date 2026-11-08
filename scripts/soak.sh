#!/usr/bin/env bash
# Soak test with explicit pass/fail budgets (Linux, uses /proc).
#
# Usage: scripts/soak.sh [CONNS] [SECS] [PROFILES]
#   CONNS     concurrent WebSocket connections (default 1000)
#   SECS      load phase per profile in seconds (default 1800)
#   PROFILES  comma-separated ws-bench stress profiles (default small,churn)
#
# For each profile, ws-bench starts a fresh managed-session server process and drives it
# for SECS. This script samples that server's RSS and open file descriptors every 10 s
# (CSV under $SOAK_OUT, default target/soak) and fails the profile if:
#   * any handshake failed, or the harness reports sessions left after cleanup.
#   * RSS grew during steady state: mean RSS of the last quarter of the samples exceeds
#     the mean of the second quarter by more than max(10 %, 16 MiB) (leak / unbounded
#     retention, the first quarter is warm-up).
#   * peak RSS exceeds RSS_BUDGET_MIB (default 2048).
#   * open descriptors exceed CONNS + 256 at any sample.
# The harness itself asserts cleanup. This script adds the time-series checks. Results
# depend on the machine: record the metadata printed at the start with the results.
set -u
cd "$(dirname "$0")/.."

CONNS="${1:-1000}"
SECS="${2:-1800}"
PROFILES="${3:-small,churn}"
OUT="${SOAK_OUT:-target/soak}"
RSS_BUDGET_MIB="${RSS_BUDGET_MIB:-2048}"
FD_BUDGET=$((CONNS + 256))
BENCH="${CARGO_TARGET_DIR:-benches/ws-bench/target}/release/ws-bench"
mkdir -p "$OUT"

echo "soak: conns=$CONNS secs=$SECS profiles=$PROFILES rss_budget=${RSS_BUDGET_MIB}MiB fd_budget=$FD_BUDGET"
echo "host: $(uname -srm), cpus=$(nproc), mem=$(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
echo "rust: $(rustc --version 2>/dev/null)"
echo "fd limit: $(ulimit -n)"
if (( $(ulimit -n) < CONNS * 2 + 256 )); then
  echo "warning: ulimit -n is below 2*CONNS+256; the client and server share this host" >&2
fi
if [[ ! -f benches/ws-bench/Cargo.toml ]]; then
  echo "soak: benches/ws-bench is not present (it is kept out of the repository)" >&2
  exit 1
fi
cargo build --release --locked --manifest-path benches/ws-bench/Cargo.toml || exit 1

FAILED=0
IFS=',' read -r -a profiles <<< "$PROFILES"
for profile in "${profiles[@]}"; do
  csv="$OUT/$profile-$CONNS-$SECS.csv"
  log="$OUT/$profile-$CONNS-$SECS.log"
  echo "t_s,rss_kib,fds" > "$csv"
  "$BENCH" stress --conns "$CONNS" --secs "$SECS" --profiles "$profile" > "$log" 2>&1 &
  bench=$!
  start=$(date +%s)
  server=""
  while kill -0 "$bench" 2>/dev/null; do
    [[ -z "$server" ]] && server="$(pgrep -P "$bench" -f stress-server | head -1)"
    if [[ -n "$server" && -r "/proc/$server/status" ]]; then
      rss=$(awk '/VmRSS/{print $2}' "/proc/$server/status" 2>/dev/null)
      fds=$(ls "/proc/$server/fd" 2>/dev/null | wc -l)
      [[ -n "$rss" ]] && echo "$(( $(date +%s) - start )),$rss,$fds" >> "$csv"
    fi
    sleep 10
  done
  wait "$bench"
  rc=$?
  verdict=$(awk -F, -v budget="$RSS_BUDGET_MIB" -v fdb="$FD_BUDGET" -v secs="$SECS" '
    NR > 1 && $1 <= secs { t[n] = $1; r[n] = $2; f[n] = $3; n++ }
    END {
      if (n < 8) { print "FAIL too few samples (" n ")"; exit }
      q = int(n / 4); a = 0; b = 0; peak = 0; fmax = 0
      for (i = q; i < 2 * q; i++) a += r[i]
      for (i = n - q; i < n; i++) b += r[i]
      a /= q; b /= q
      for (i = 0; i < n; i++) { if (r[i] > peak) peak = r[i]; if (f[i] > fmax) fmax = f[i] }
      allow = a * 0.10; if (allow < 16384) allow = 16384
      msg = sprintf("samples=%d rss_q2=%.1fMiB rss_q4=%.1fMiB growth=%.1fMiB (allowed %.1f) peak=%.1fMiB fds_max=%d",
                    n, a / 1024, b / 1024, (b - a) / 1024, allow / 1024, peak / 1024, fmax)
      if (b - a > allow) { print "FAIL rss growth " msg; exit }
      if (peak / 1024 > budget) { print "FAIL rss budget " msg; exit }
      if (fmax > fdb) { print "FAIL fd budget " msg; exit }
      print "PASS " msg
    }' "$csv")
  row=$(grep -E "^\| $profile " "$log" | head -1)
  failed=$(echo "$row" | awk -F'|' '{gsub(/ /,"",$5); print $5}')
  cleanup=$(echo "$row" | awk -F'|' '{gsub(/ /,"",$16); print $16}')
  echo "$profile: harness exit $rc, failed handshakes ${failed:-?}, cleanup ${cleanup:-?} ms, $verdict"
  echo "$row"
  if [[ $rc -ne 0 || "${failed:-x}" != "0" || "${cleanup:-n/a}" == "n/a" || "$verdict" != PASS* ]]; then
    FAILED=1
  fi
done
exit $FAILED
