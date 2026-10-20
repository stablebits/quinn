"""Summarize retry-e2e results: medians over rounds, relative to main with manual Retry"""
import statistics
import sys
from collections import defaultdict

LABELS = {
    ("base", "manual"): "main, manual Retry",
    ("v3", "manual"): "series, manual Retry",
    ("v3", "manual-mac"): "series, manual Retry, MAC tokens",
    ("v3", "fast"): "series, fast Retry",
    ("v3", "fast-mac"): "series, fast Retry, MAC tokens",
}

runs = defaultdict(list)
for line in open(sys.argv[1]):
    fields = dict(f.split("=", 1) for f in line.split() if "=" in f and not f.startswith(("wall=", "cpu=")))
    key = (int(fields["workers"]), fields["kind"], fields["build"], fields["mode"])
    runs[key].append({k: float(fields[k]) for k in ("wall_ns", "rate_k", "server_cpu_ns", "p99_rtt_us")})

for workers, kind in sorted({(k[0], k[1]) for k in runs}):
    base = runs.get((workers, kind, "base", "manual"))
    base_cpu = base and statistics.median(r["server_cpu_ns"] for r in base)
    base_rate = base and statistics.median(r["rate_k"] for r in base)
    print(f"\n### {workers} server worker(s), {'no token' if kind == 'empty' else 'bogus token'}\n")
    print("| Configuration | Server CPU per Initial (µs) | vs main | Retries/s (k) | vs main | p99 RTT (µs) | Rounds |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for (build, mode), label in LABELS.items():
        rs = runs.get((workers, kind, build, mode))
        if not rs:
            continue
        cpu = statistics.median(r["server_cpu_ns"] for r in rs)
        rate = statistics.median(r["rate_k"] for r in rs)
        p99 = statistics.median(r["p99_rtt_us"] for r in rs)
        cpu_x = f"{base_cpu / cpu:.2f}x" if base_cpu else ""
        rate_x = f"{rate / base_rate:.2f}x" if base_rate else ""
        print(f"| {label} | {cpu / 1e3:.2f} | {cpu_x} | {rate:.1f} | {rate_x} | {p99:.0f} | {len(rs)} |")
