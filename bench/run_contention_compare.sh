#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$ROOT_DIR/target/release"

SERVER_BIN="$BIN_DIR/server"
THROUGHPUT_BIN="$BIN_DIR/throughput-client"
NEW_CONN_BIN="$BIN_DIR/new-conn-client"

LISTEN="${LISTEN:-127.0.0.1:4433}"
SERVER_WORKER_THREADS="${SERVER_WORKER_THREADS:-8}"
SERVER_INITIAL_MTU="${SERVER_INITIAL_MTU:-1200}"
SERVER_MAX_CONCURRENT_UNI_STREAMS="${SERVER_MAX_CONCURRENT_UNI_STREAMS:-131072}"
SERVER_MAX_CONCURRENT_HANDSHAKES="${SERVER_MAX_CONCURRENT_HANDSHAKES:-0}"
SERVER_HANDSHAKE_THREADS="${SERVER_HANDSHAKE_THREADS:-0}"
SERVER_READ_UNORDERED="${SERVER_READ_UNORDERED:-0}"

THROUGHPUT_DURATION_SECS="${THROUGHPUT_DURATION_SECS:-10}"
THROUGHPUT_CONNECTIONS="${THROUGHPUT_CONNECTIONS:-1}"
THROUGHPUT_STREAMS_PER_CONNECTION="${THROUGHPUT_STREAMS_PER_CONNECTION:-1}"
THROUGHPUT_STREAM_SIZE="${THROUGHPUT_STREAM_SIZE:-1600M}"
THROUGHPUT_STREAM_RUNS="${THROUGHPUT_STREAM_RUNS:-1}"
THROUGHPUT_INITIAL_MTU="${THROUGHPUT_INITIAL_MTU:-1200}"

NEW_CONN_RATE="${NEW_CONN_RATE:-2500}"
NEW_CONN_WORKERS="${NEW_CONN_WORKERS:-16}"
NEW_CONN_INITIAL_MTU="${NEW_CONN_INITIAL_MTU:-1200}"
MIXED_WARMUP_SECS="${MIXED_WARMUP_SECS:-2}"

# perf sampling of the throughput window (Linux only). PERF_LOCK=auto enables it
# when `perf` is available; set to 1/0 to force. BPF lock contention (-b) and
# tracepoints usually need root: run the whole script via sudo. (Setting
# PERF_BIN="sudo perf" instead would leave perf unkillable by the script.)
PERF_LOCK="${PERF_LOCK:-auto}"
PERF_BIN="${PERF_BIN:-perf}"
PERF_LOCK_TOP="${PERF_LOCK_TOP:-16}"
# bpf: live `perf lock con -ab` (needs perf built with BUILD_BPF_SKEL=1).
# record: `perf lock record -a` + offline `perf lock contention -i` (needs the
# lock:contention_begin/end tracepoints, kernel >= 5.19). auto picks bpf if available.
PERF_LOCK_MODE="${PERF_LOCK_MODE:-auto}"

if [[ -n "${NEW_CONN_DURATION_SECS:-}" ]]; then
    CHURN_DURATION_SECS="$NEW_CONN_DURATION_SECS"
elif [[ "$THROUGHPUT_STREAM_RUNS" == "0" ]]; then
    CHURN_DURATION_SECS="$((THROUGHPUT_DURATION_SECS + MIXED_WARMUP_SECS + 5))"
else
    CHURN_DURATION_SECS="30"
fi

TMP_DIR="$(mktemp -d)"
SERVER_PID=""
CHURN_PID=""
PERF_LOCK_PID=""
PERF_TRACE_PID=""
PERF_LOCK_DATA=""
PERF_LOCK_LOG=""

cleanup() {
    stop_perf
    if [[ -n "$CHURN_PID" ]]; then
        kill "$CHURN_PID" >/dev/null 2>&1 || true
        wait "$CHURN_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT

require_bin() {
    local bin="$1"
    if [[ ! -x "$bin" ]]; then
        echo "missing binary: $bin" >&2
        echo "build once with: cargo build -p bench --release --bin server --bin throughput-client --bin new-conn-client" >&2
        exit 1
    fi
}

start_server() {
    local log_file="$1"
    local -a args=(
        --listen "$LISTEN"
        --worker-threads "$SERVER_WORKER_THREADS"
        --initial-mtu "$SERVER_INITIAL_MTU"
        --max-concurrent-uni-streams "$SERVER_MAX_CONCURRENT_UNI_STREAMS"
        --max-concurrent-handshakes "$SERVER_MAX_CONCURRENT_HANDSHAKES"
        --handshake-threads "$SERVER_HANDSHAKE_THREADS"
    )
    if [[ "$SERVER_READ_UNORDERED" == "1" ]]; then
        args+=(--read-unordered)
    fi
    "$SERVER_BIN" "${args[@]}" >"$log_file" 2>&1 &
    SERVER_PID="$!"
    sleep 1
    # A dead server here usually means the listen port is taken by a leftover server
    # from an earlier run; without this check the clients silently measure against it.
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "server failed to start:" >&2
        cat "$log_file" >&2
        exit 1
    fi
}

stop_server() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
        SERVER_PID=""
    fi
}

extract_value() {
    local key="$1"
    local file="$2"
    awk -F= -v key="$key" '$1 == key { print $2; exit }' "$file"
}

# System-wide UDP receive drop counter (socket buffer overflows). A rising delta during a
# phase means a receiver (here: the server endpoint driver) was not draining its socket
# fast enough and the kernel dropped datagrams.
udp_recv_drops() {
    case "$(uname -s)" in
        Linux)
            awk '/^Udp:/ {
                if (!header_seen) {
                    for (i = 1; i <= NF; i++) col[$i] = i
                    header_seen = 1
                } else {
                    print $col["InErrors"] + $col["RcvbufErrors"]
                }
            }' /proc/net/snmp
            ;;
        Darwin)
            netstat -s -p udp | awk '/dropped due to full socket buffers/ { print $1; found = 1 }
                END { if (!found) print 0 }'
            ;;
        *)
            echo 0
            ;;
    esac
}

perf_enabled() {
    case "$PERF_LOCK" in
        1) return 0 ;;
        0) return 1 ;;
        *)
            [[ "$(uname -s)" == "Linux" ]] || return 1
            command -v "${PERF_BIN%% *}" >/dev/null 2>&1 || return 1
            ;;
    esac
}

resolve_perf_lock_mode() {
    [[ "$PERF_LOCK_MODE" == "auto" ]] || return 0
    if $PERF_BIN lock con -ab -E 1 -- true >/dev/null 2>&1; then
        PERF_LOCK_MODE="bpf"
    else
        PERF_LOCK_MODE="record"
    fi
}

# Sample kernel lock contention (system-wide) plus the server's futex blocking while
# the throughput client runs. `perf lock con` only sees kernel locks (UDP socket lock
# etc.); waits on the user-space endpoint mutex surface as futex syscalls instead,
# which the `perf trace` summary reports per server thread. Both run until SIGINT,
# which is what makes perf finalize its data and print.
start_perf() {
    local lock_log="$1"
    local futex_log="$2"
    perf_enabled || return 0
    resolve_perf_lock_mode
    PERF_LOCK_LOG="$lock_log"
    if [[ "$PERF_LOCK_MODE" == "bpf" ]]; then
        $PERF_BIN lock con -ab -E "$PERF_LOCK_TOP" >"$lock_log" 2>&1 &
        PERF_LOCK_PID="$!"
    else
        PERF_LOCK_DATA="$lock_log.data"
        $PERF_BIN lock record -a -o "$PERF_LOCK_DATA" >"$lock_log" 2>&1 &
        PERF_LOCK_PID="$!"
    fi
    $PERF_BIN trace -p "$SERVER_PID" -e futex --summary >"$futex_log" 2>&1 &
    PERF_TRACE_PID="$!"
    # Give perf a moment to attach before the measured window starts
    sleep 0.3
}

stop_perf() {
    if [[ -n "$PERF_LOCK_PID" ]]; then
        kill -INT "$PERF_LOCK_PID" >/dev/null 2>&1 || true
        wait "$PERF_LOCK_PID" >/dev/null 2>&1 || true
        PERF_LOCK_PID=""
        if [[ "$PERF_LOCK_MODE" == "record" && -s "$PERF_LOCK_DATA" ]]; then
            $PERF_BIN lock contention -i "$PERF_LOCK_DATA" -E "$PERF_LOCK_TOP" \
                >"$PERF_LOCK_LOG" 2>&1 || true
            rm -f "$PERF_LOCK_DATA"
        fi
        PERF_LOCK_DATA=""
        PERF_LOCK_LOG=""
    fi
    if [[ -n "$PERF_TRACE_PID" ]]; then
        kill -INT "$PERF_TRACE_PID" >/dev/null 2>&1 || true
        wait "$PERF_TRACE_PID" >/dev/null 2>&1 || true
        PERF_TRACE_PID=""
    fi
}

print_perf_section() {
    local title="$1"
    local lock_log="$2"
    local futex_log="$3"
    perf_enabled || return 0
    printf '\nperf lock contention (%s, kernel locks, top %s):\n' "$title" "$PERF_LOCK_TOP"
    cat "$lock_log"
    printf '\nserver futex blocking (%s, per thread):\n' "$title"
    grep -E 'events|futex' "$futex_log" || cat "$futex_log"
    if grep -qiE 'permission|not permitted|capabilit|privilege' "$lock_log" "$futex_log"; then
        printf 'hint: perf needs privileges; re-run this script via sudo.\n'
    fi
}

baseline_server_log="$TMP_DIR/server_baseline.log"
mixed_server_log="$TMP_DIR/server_mixed.log"
baseline_throughput_log="$TMP_DIR/throughput_baseline.log"
mixed_throughput_log="$TMP_DIR/throughput_mixed.log"
mixed_new_conn_log="$TMP_DIR/new_conn_mixed.log"
baseline_perf_lock_log="$TMP_DIR/perf_lock_baseline.log"
baseline_perf_futex_log="$TMP_DIR/perf_futex_baseline.log"
mixed_perf_lock_log="$TMP_DIR/perf_lock_mixed.log"
mixed_perf_futex_log="$TMP_DIR/perf_futex_mixed.log"

require_bin "$SERVER_BIN"
require_bin "$THROUGHPUT_BIN"
require_bin "$NEW_CONN_BIN"

printf 'Using binaries from %s\n' "$BIN_DIR"
printf 'listen=%s\n' "$LISTEN"
printf 'throughput: connections=%s streams_per_connection=%s stream_size=%s' \
    "$THROUGHPUT_CONNECTIONS" "$THROUGHPUT_STREAMS_PER_CONNECTION" "$THROUGHPUT_STREAM_SIZE"
if [[ "$THROUGHPUT_STREAM_RUNS" != "0" ]]; then
    printf ' stream_runs=%s' "$THROUGHPUT_STREAM_RUNS"
else
    printf ' duration_secs=%s' "$THROUGHPUT_DURATION_SECS"
fi
printf '\n'
printf 'new-conn: rate=%s/s workers=%s duration_secs=%s warmup_secs=%s\n' \
    "$NEW_CONN_RATE" "$NEW_CONN_WORKERS" "$CHURN_DURATION_SECS" "$MIXED_WARMUP_SECS"
printf '\n'

baseline_args=(
    --connect "$LISTEN"
    --duration-secs "$THROUGHPUT_DURATION_SECS"
    --connections "$THROUGHPUT_CONNECTIONS"
    --streams-per-connection "$THROUGHPUT_STREAMS_PER_CONNECTION"
    --stream-size "$THROUGHPUT_STREAM_SIZE"
    --initial-mtu "$THROUGHPUT_INITIAL_MTU"
)
if [[ "$THROUGHPUT_STREAM_RUNS" != "0" ]]; then
    baseline_args+=(--stream-runs "$THROUGHPUT_STREAM_RUNS")
fi

mixed_new_conn_args=(
    --connect "$LISTEN"
    --duration-secs "$CHURN_DURATION_SECS"
    --connections-per-second "$NEW_CONN_RATE"
    --workers "$NEW_CONN_WORKERS"
    --initial-mtu "$NEW_CONN_INITIAL_MTU"
)

drops_before="$(udp_recv_drops)"
start_server "$baseline_server_log"
start_perf "$baseline_perf_lock_log" "$baseline_perf_futex_log"
"$THROUGHPUT_BIN" "${baseline_args[@]}" | tee "$baseline_throughput_log"
stop_perf
stop_server
baseline_udp_drops="$(($(udp_recv_drops) - drops_before))"

printf '\n'

drops_before="$(udp_recv_drops)"
start_server "$mixed_server_log"
"$NEW_CONN_BIN" "${mixed_new_conn_args[@]}" >"$mixed_new_conn_log" 2>&1 &
CHURN_PID="$!"
sleep "$MIXED_WARMUP_SECS"
start_perf "$mixed_perf_lock_log" "$mixed_perf_futex_log"
"$THROUGHPUT_BIN" "${baseline_args[@]}" | tee "$mixed_throughput_log"
stop_perf
wait "$CHURN_PID"
CHURN_PID=""
stop_server
mixed_udp_drops="$(($(udp_recv_drops) - drops_before))"

baseline_tput="$(extract_value throughput_mib_per_s "$baseline_throughput_log")"
mixed_tput="$(extract_value throughput_mib_per_s "$mixed_throughput_log")"
baseline_elapsed="$(extract_value elapsed_secs "$baseline_throughput_log")"
mixed_elapsed="$(extract_value elapsed_secs "$mixed_throughput_log")"
mixed_rate="$(extract_value achieved_connections_per_second "$mixed_new_conn_log")"
mixed_rate_actual="$(extract_value actual_connections_per_second "$mixed_new_conn_log")"
mixed_churn_wall="$(extract_value wall_elapsed_secs "$mixed_new_conn_log")"
baseline_lost="$(extract_value lost_packets "$baseline_throughput_log")"
mixed_lost="$(extract_value lost_packets "$mixed_throughput_log")"
baseline_congestion="$(extract_value congestion_events "$baseline_throughput_log")"
mixed_congestion="$(extract_value congestion_events "$mixed_throughput_log")"
mixed_connect_p50="$(extract_value connect_latency_p50_ms "$mixed_new_conn_log")"
mixed_connect_p99="$(extract_value connect_latency_p99_ms "$mixed_new_conn_log")"
mixed_connect_max="$(extract_value connect_latency_max_ms "$mixed_new_conn_log")"

degradation="$(awk -v baseline="$baseline_tput" -v mixed="$mixed_tput" 'BEGIN {
    if (baseline == 0) {
        printf "0.00";
    } else {
        printf "%.2f", (1 - mixed / baseline) * 100;
    }
}')"

printf '\nSummary\n'
printf 'baseline throughput: %s MiB/s (elapsed %ss)\n' "$baseline_tput" "$baseline_elapsed"
printf 'mixed throughput:    %s MiB/s (elapsed %ss)\n' "$mixed_tput" "$mixed_elapsed"
printf 'mixed new-conn rate: %s /s scheduled, %s /s actual (busy for %ss)\n' \
    "$mixed_rate" "$mixed_rate_actual" "$mixed_churn_wall"
printf 'degradation:         %s%%\n' "$degradation"
printf 'baseline client loss: %s packets, %s congestion events, %s system-wide udp rx drops\n' \
    "$baseline_lost" "$baseline_congestion" "$baseline_udp_drops"
printf 'mixed client loss:    %s packets, %s congestion events, %s system-wide udp rx drops\n' \
    "$mixed_lost" "$mixed_congestion" "$mixed_udp_drops"
printf 'mixed connect latency: p50=%sms p99=%sms max=%sms\n' \
    "$mixed_connect_p50" "$mixed_connect_p99" "$mixed_connect_max"
mixed_accept_timing="$(grep accept_timing "$mixed_server_log" | tail -1 || true)"
printf 'server accept timing:  %s\n' "${mixed_accept_timing:-n/a}"

print_perf_section "baseline" "$baseline_perf_lock_log" "$baseline_perf_futex_log"
print_perf_section "mixed" "$mixed_perf_lock_log" "$mixed_perf_futex_log"
