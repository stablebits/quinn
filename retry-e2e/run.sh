#!/usr/bin/env bash
# End-to-end Retry benchmark: main@7616e6b2 vs this branch, over loopback UDP
#
# Usage: retry-e2e/run.sh [rounds]
#
# Environment: WINDOW (outstanding Initials, default 64), WORKERS (server runtime threads,
# default "1 2"), KINDS (default "empty bogus"), RCVBUF_KB (default 4096), and CLIENT_CPUS /
# SERVER_CPUS to pin the processes with taskset, e.g. CLIENT_CPUS=0 SERVER_CPUS=2,3.
set -euo pipefail
cd "$(dirname "$0")"
ROUNDS=${1:-5}
WINDOW=${WINDOW:-64}
WORKERS=${WORKERS:-"1 2"}
KINDS=${KINDS:-"empty bogus"}
export RETRY_E2E_RCVBUF_KB=${RCVBUF_KB:-4096}
CLIENT_WRAP=()
if [ -n "${CLIENT_CPUS:-}" ]; then CLIENT_WRAP=(taskset -c "$CLIENT_CPUS"); fi
if [ -n "${SERVER_CPUS:-}" ]; then export RETRY_E2E_SERVER_WRAP="taskset -c $SERVER_CPUS"; fi

(cd base && cargo build --release --quiet)
(cd v3 && cargo build --release --quiet --features filter)
BASE=base/target/release/retry_e2e
V3=v3/target/release/retry_e2e

OUT=results/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
{
    uname -a
    lscpu 2>/dev/null | grep -E "Model name|^CPU\(s\)" || true
    git -C .. rev-parse HEAD
    sysctl net.core.rmem_max 2>/dev/null || true
    echo "rounds=$ROUNDS window=$WINDOW workers=$WORKERS kinds=$KINDS rcvbuf_kb=$RETRY_E2E_RCVBUF_KB"
    echo "client_cpus=${CLIENT_CPUS:-} server_cpus=${SERVER_CPUS:-}"
} > "$OUT/env.txt"
cat "$OUT/env.txt"

RUNS=("base manual" "v3 manual" "v3 manual-mac" "v3 fast" "v3 fast-mac")
for round in $(seq "$ROUNDS"); do
    # Alternate the order between rounds to spread drift evenly
    order=("${RUNS[@]}")
    if (( round % 2 == 0 )); then
        order=()
        for ((i = ${#RUNS[@]} - 1; i >= 0; i--)); do order+=("${RUNS[i]}"); done
    fi
    for workers in $WORKERS; do
        for kind in $KINDS; do
            for run in "${order[@]}"; do
                read -r build mode <<< "$run"
                bin=$BASE
                if [ "$build" = v3 ]; then bin=$V3; fi
                line=$(${CLIENT_WRAP[@]+"${CLIENT_WRAP[@]}"} "$bin" client "$mode" "$workers" "$kind" "$WINDOW" \
                    | grep '^RESULT')
                echo "build=$build round=$round $line" | tee -a "$OUT/results.txt"
            done
        done
    done
done
python3 summarize.py "$OUT/results.txt" | tee "$OUT/summary.md"
