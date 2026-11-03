#!/usr/bin/env python3
"""Summarise oha JSON written by scripts/perf.sh and scripts/perf-ab.sh: median requests/s
and latency percentiles, plus paired before/after ratios for A/B directories.

    scripts/perf-summary.py target/perf/<label> [target/perf/<label> ...]
"""
import json
import pathlib
import re
import statistics
import sys


def load(directory):
    rows = {}
    for path in sorted(pathlib.Path(directory).glob("*.run*.json")):
        m = re.match(r"(.+)\.c(\d+)\.run\d+\.json$", path.name)
        if not m:
            continue
        data = json.loads(path.read_text())
        summary = data["summary"]
        pct = data.get("latencyPercentiles", {})
        codes = data.get("statusCodeDistribution", {})
        ok = sum(v for k, v in codes.items() if k.startswith("2"))
        bad = sum(v for k, v in codes.items() if not k.startswith("2"))
        key = (m.group(1), int(m.group(2)))
        rows.setdefault(key, []).append(
            (summary["requestsPerSec"], pct.get("p50", 0), pct.get("p95", 0), pct.get("p99", 0), ok, bad)
        )
    return rows


def paired(directory):
    """Paired comparison for perf-ab.sh output (`base.*` and `new.*` runs with equal indices)."""
    runs = {}
    for path in pathlib.Path(directory).glob("*.run*.json"):
        m = re.match(r"(base|new)\.(.+)\.c\d+\.run(\d+)\.json$", path.name)
        if m:
            data = json.loads(path.read_text())
            runs.setdefault(m.group(2), {}).setdefault(m.group(1), {})[int(m.group(3))] = data[
                "summary"
            ]["requestsPerSec"]
    for endpoint, sides in sorted(runs.items()):
        base, new = sides.get("base", {}), sides.get("new", {})
        common = sorted(set(base) & set(new))
        if not common:
            continue
        ratios = [new[i] / base[i] for i in common]
        faster = sum(r > 1 for r in ratios)
        print(f"{pathlib.Path(directory).name:<22} {endpoint:<22} pairs={len(common)}"
              f" paired median {100 * (statistics.median(ratios) - 1):+.1f}%"
              f" (range {100 * (min(ratios) - 1):+.1f}% .. {100 * (max(ratios) - 1):+.1f}%),"
              f" candidate faster in {faster}/{len(common)}")


def main():
    print(f"{'label':<22} {'endpoint':<22} {'c':>4} {'runs':>4} {'median rps':>11} {'min':>9} {'max':>9}"
          f" {'p50 ms':>7} {'p95 ms':>7} {'p99 ms':>7} {'non-2xx':>7}")
    for directory in sys.argv[1:]:
        label = pathlib.Path(directory).name
        for (endpoint, c), runs in sorted(load(directory).items()):
            rps = [r[0] for r in runs]
            med = lambda i: statistics.median(r[i] for r in runs) * 1000
            print(f"{label:<22} {endpoint:<22} {c:>4} {len(runs):>4} {statistics.median(rps):>11.0f}"
                  f" {min(rps):>9.0f} {max(rps):>9.0f} {med(1):>7.3f} {med(2):>7.3f} {med(3):>7.3f}"
                  f" {sum(r[5] for r in runs):>7}")
    for directory in sys.argv[1:]:
        paired(directory)


if __name__ == "__main__":
    main()
