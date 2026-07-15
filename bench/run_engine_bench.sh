#!/usr/bin/env bash
# run_engine_bench.sh — replay a PCAP into the engine and sample /metrics.
#
# Workflow (matches Task 26 plan, lines 1811-1866):
#   1. Start packet-engine on veth0 (veth1 is the replay side).
#   2. tcpreplay --intf1=veth1 --mbps=$MBPS --duration=$DURATION $PCAP
#   3. Sample http://127.0.0.1:9090/metrics every 1s for $DURATION seconds;
#      collect pps, drops/s, and histogram-derived p50/p99 bounds.
#   4. Write a CSV row per sample: timestamp,backend,pps,drops,p50_us,p99_us.
#
# Outputs:
#   bench/results/engine_<backend>.csv   — per-second samples
#   bench/results/engine_<backend>.log   — engine stdout/stderr
#
# Knobs (env):
#   BACKEND         af_xdp | dpdk (default: af_xdp)
#   DURATION        seconds (default: 60)
#   MBPS            tcpreplay rate (default: 1000)
#   PCAP            input pcap   (default: bench/traffic_baseline.pcap)
#   METRICS_URL     metrics endpoint (default: http://127.0.0.1:9090/metrics)
#   ENGINE_BIN      engine path  (default: build/packet-engine)
#   REPLAY_IFACE    replay side  (default: veth1)
#   ENGINE_IFACE    engine side  (default: veth0)
#   TRIAL           trial label  (default: 1; appended to result file name)
#
# This script does NOT require root inside the script.  The engine, the
# veth pair, and tcpreplay all need CAP_NET_ADMIN — run under
# `nix develop --command ...` or with sudo from outside the script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${BACKEND:=af_xdp}"
: "${DURATION:=60}"
: "${MBPS:=1000}"
: "${PCAP:=$REPO_ROOT/bench/traffic_baseline.pcap}"
: "${METRICS_PORT:=9090}"
: "${METRICS_URL:=http://127.0.0.1:${METRICS_PORT}/metrics}"
: "${ENGINE_BIN:=$REPO_ROOT/build/packet-engine}"
: "${REPLAY_IFACE:=veth1}"
: "${ENGINE_IFACE:=veth0}"
: "${TRIAL:=1}"
: "${RESULTS_DIR:=$REPO_ROOT/bench/results}"

mkdir -p "$RESULTS_DIR"

CSV_PATH="$RESULTS_DIR/engine_${BACKEND}_trial${TRIAL}.csv"
LOG_PATH="$RESULTS_DIR/engine_${BACKEND}_trial${TRIAL}.log"
CONTROL_SOCKET="/tmp/packet-engine-bench-$$.sock"

echo "[engine-bench] backend=$BACKEND duration=${DURATION}s mbps=$MBPS pcap=$PCAP"
echo "[engine-bench] csv=$CSV_PATH log=$LOG_PATH"

if ! command -v tcpreplay >/dev/null 2>&1; then
    echo "[engine-bench] tcpreplay not in PATH." >&2
    echo "[engine-bench] Run under nix develop." >&2
    exit 127
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "[engine-bench] curl not in PATH." >&2
    exit 127
fi
if [[ ! -x "$ENGINE_BIN" ]]; then
    echo "[engine-bench] engine binary $ENGINE_BIN not built." >&2
    echo "[engine-bench] Build first: scripts/build.sh" >&2
    exit 1
fi
if [[ ! -f "$PCAP" ]]; then
    echo "[engine-bench] pcap $PCAP not found." >&2
    echo "[engine-bench] Capture first: bench/capture_baseline.sh -d 10" >&2
    exit 1
fi
if [[ "$BACKEND" != "af_xdp" ]]; then
    echo "[engine-bench] live replay currently supports BACKEND=af_xdp only." >&2
    echo "[engine-bench] Use bench/run_pcap_benchmark.sh for unprivileged DPDK net_pcap." >&2
    exit 64
fi
if ! ip link show "$ENGINE_IFACE" >/dev/null 2>&1; then
    echo "[engine-bench] interface $ENGINE_IFACE not present." >&2
    echo "[engine-bench] Start the harness: sudo scripts/dev-run.sh shell" >&2
    exit 1
fi

ENGINE_PID=""
TCPREPLAY_PID=""
cleanup() {
    local rc=$?
    if [[ -n "$ENGINE_PID" ]] && kill -0 "$ENGINE_PID" 2>/dev/null; then
        echo "[engine-bench] stopping engine PID $ENGINE_PID"
        kill -TERM "$ENGINE_PID" 2>/dev/null || true
        sleep 0.5
        kill -KILL "$ENGINE_PID" 2>/dev/null || true
        wait "$ENGINE_PID" 2>/dev/null || true
    fi
    if [[ -n "$TCPREPLAY_PID" ]] && kill -0 "$TCPREPLAY_PID" 2>/dev/null; then
        echo "[engine-bench] stopping tcpreplay PID $TCPREPLAY_PID"
        kill -TERM "$TCPREPLAY_PID" 2>/dev/null || true
        wait "$TCPREPLAY_PID" 2>/dev/null || true
    fi
    rm -f "$CONTROL_SOCKET"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# 1. Start engine.
echo "[engine-bench] launching $ENGINE_BIN --backend=$BACKEND"
"$ENGINE_BIN" --backend=af_xdp --interface="$ENGINE_IFACE" \
    --metrics-port="$METRICS_PORT" \
    --control-socket="$CONTROL_SOCKET" \
    >"$LOG_PATH" 2>&1 &
ENGINE_PID=$!

# Wait for /metrics to become reachable (engine exposes a TCP listener on 9090).
echo "[engine-bench] waiting for /metrics ..."
for _ in $(seq 1 50); do
    if curl -sf -m 1 "$METRICS_URL" >/dev/null 2>&1; then
        echo "[engine-bench] /metrics is up"
        break
    fi
    sleep 0.1
done
if ! curl -sf -m 1 "$METRICS_URL" >/dev/null 2>&1; then
    cat "$LOG_PATH" >&2
    echo "[engine-bench] /metrics not reachable; AF_XDP setup is unavailable or failed." >&2
    exit 1
fi

# 2. Replay the PCAP into the engine (in background, for DURATION seconds).
#    --duration=N caps the replay at N wall-seconds; --mbps caps the rate.
echo "[engine-bench] tcpreplay --intf1=$REPLAY_IFACE --mbps=$MBPS --duration=$DURATION $PCAP"
tcpreplay --intf1="$REPLAY_IFACE" --mbps="$MBPS" --duration="$DURATION" "$PCAP" \
    >"$RESULTS_DIR/engine_${BACKEND}_trial${TRIAL}.tcpreplay.log" 2>&1 &
TCPREPLAY_PID=$!

# 3. Sample /metrics every 1s for DURATION seconds.
#    CSV header: timestamp,backend,pps,drops,p50_us,p99_us
echo "timestamp,backend,pps,drops,p50_us,p99_us" > "$CSV_PATH"

sample_once() {
    local now
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local body
    body="$(curl -sf -m 1 "$METRICS_URL" 2>/dev/null || true)"
    if [[ -z "$body" ]]; then
        echo "$now,$BACKEND,N/A,N/A,N/A,N/A" >> "$CSV_PATH"
        return
    fi
    local rx drops p50 p99
    rx=$(printf '%s\n' "$body"  | awk '/^engine_rx_packets_total /{print $2; exit}')
    drops=$(printf '%s\n' "$body" | awk '/^engine_drops_total /{print $2; exit}')
    p50=$(printf '%s\n' "$body" | awk '
        /^engine_latency_seconds_count / { total=$2 }
        /^engine_latency_seconds_bucket\{le="/ {
            line=$0; sub(/^.*le="/, "", line); sub(/"\}.*/, "", line)
            n++; bound[n]=line; count[n]=$2
        }
        END {
            target=int(total*0.50 + 0.999999)
            for (i=1; i<=n; i++) if (count[i] >= target) {
                if (bound[i] == "+Inf") print "N/A"; else printf "%.3f", bound[i]*1000000
                exit
            }
            print "N/A"
        }')
    p99=$(printf '%s\n' "$body" | awk '
        /^engine_latency_seconds_count / { total=$2 }
        /^engine_latency_seconds_bucket\{le="/ {
            line=$0; sub(/^.*le="/, "", line); sub(/"\}.*/, "", line)
            n++; bound[n]=line; count[n]=$2
        }
        END {
            target=int(total*0.99 + 0.999999)
            for (i=1; i<=n; i++) if (count[i] >= target) {
                if (bound[i] == "+Inf") print "N/A"; else printf "%.3f", bound[i]*1000000
                exit
            }
            print "N/A"
        }')

    local pps="N/A"
    if [[ -n "${PREV_RX:-}" && -n "$rx" ]]; then
        # pps = (rx_now - rx_prev) / 1s
        pps=$(( ${rx%.*} - ${PREV_RX%.*} ))
    fi
    local drops_per_second="N/A"
    if [[ -n "${PREV_DROPS:-}" && -n "$drops" ]]; then
        drops_per_second=$(( ${drops%.*} - ${PREV_DROPS%.*} ))
    fi
    PREV_RX="$rx"
    PREV_DROPS="$drops"
    echo "$now,engine_af_xdp,${pps},${drops_per_second},${p50:-N/A},${p99:-N/A}" >> "$CSV_PATH"
}

end=$(( $(date +%s) + DURATION ))
unset PREV_RX
unset PREV_DROPS
while [[ $(date +%s) -lt $end ]]; do
    sample_once
    sleep 1
done

# Wait for tcpreplay to fully terminate so the cleanup trap doesn't leak it.
wait "$TCPREPLAY_PID" 2>/dev/null || true
TCPREPLAY_PID=""

# Stop the engine explicitly.
if [[ -n "$ENGINE_PID" ]] && kill -0 "$ENGINE_PID" 2>/dev/null; then
    kill -TERM "$ENGINE_PID" 2>/dev/null || true
    sleep 0.5
    kill -KILL "$ENGINE_PID" 2>/dev/null || true
fi
wait "$ENGINE_PID" 2>/dev/null || true
ENGINE_PID=""

# A friendly summary so the user can eyeball the run.
echo "---- engine-bench summary ($BACKEND trial $TRIAL) ----"
if command -v awk >/dev/null 2>&1; then
    awk -F, 'NR>1 {
        if ($3 != "N/A") { pps_sum += $3; pps_n++; if ($3+0 > pps_max+0) pps_max = $3 }
        if ($4 != "N/A") { drops = $4+0 }
        if ($5 != "N/A") { p50s[NR] = $5+0 }
        if ($6 != "N/A") { p99s[NR] = $6+0 }
    }
    END {
        if (pps_n > 0) {
            printf("samples: %d  avg pps: %d  max pps: %d  last drops: %.0f\n", pps_n, pps_sum/pps_n, pps_max, drops)
        } else {
            print "samples: 0  (CSV rows present but pps column is N/A)"
        }
    }' "$CSV_PATH"
fi
echo "-----------------------------------------------------"
