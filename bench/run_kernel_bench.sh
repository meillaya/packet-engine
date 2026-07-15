#!/usr/bin/env bash
# run_kernel_bench.sh — replay the same PCAP through the Linux kernel stack
#                       (iptables/nftables) for direct comparison with the
#                       packet-engine.  No engine process is started.
#
# This script installs an nftables rule that drops packets matching the
# `engine_af_xdp` DROP rule used in run_engine_bench.sh, so the kernel's
# packet-processing cost is approximately equivalent to the engine's
# default-rule workload.  It then samples the kernel's per-second drop
# counters via /proc/net/netfilter and emits a CSV with the same schema
# as the engine bench:
#
#   timestamp,backend,pps,drops,p50_us,p99_us
#
# Backend label: kernel_nftables
#
# Knobs (env):
#   DURATION   seconds (default: 60)
#   MBPS       tcpreplay rate (default: 1000)
#   PCAP       input pcap (default: bench/traffic_baseline.pcap)
#   REPLAY_IFACE  default: veth1
#   RESULTS_DIR   default: bench/results
#   TRIAL         default: 1
#   RULE_FAMILY   "nft" | "iptables" (default: nft)
#   NO_RULES      if set, install only the count rule (no drop) — measures
#                 pass-through cost only.  Useful to separate the cost of
#                 rule evaluation from the cost of dropping.
#
# Latency (p50/p99) is reported as N/A for the kernel stack: the
# /proc/net/netfilter counters do not expose per-packet latency, and the
# kernel's `xt_quota`/`nft limit` features do not record histograms.
# Use bench/latency_probe.py to capture latency for both backends on a
# separate run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${DURATION:=60}"
: "${MBPS:=1000}"
: "${PCAP:=$REPO_ROOT/bench/traffic_baseline.pcap}"
: "${REPLAY_IFACE:=veth1}"
: "${RESULTS_DIR:=$REPO_ROOT/bench/results}"
: "${TRIAL:=1}"
: "${RULE_FAMILY:=nft}"
: "${NO_RULES:=}"
: "${BACKEND:=kernel_nftables}"
: "${NFT_TABLE:=packet_engine_bench_$$}"

if [[ "$RULE_FAMILY" != "nft" && "$RULE_FAMILY" != "iptables" ]]; then
    echo "[kernel-bench] RULE_FAMILY must be nft or iptables" >&2
    exit 64
fi
if [[ "$RULE_FAMILY" == "iptables" ]]; then
    BACKEND="kernel_iptables"
fi

mkdir -p "$RESULTS_DIR"
CSV_PATH="$RESULTS_DIR/${BACKEND}_trial${TRIAL}.csv"
COUNTERS_BEFORE=""
COUNTERS_AFTER=""
RULES_CREATED="false"
IPTABLES_RULE=""

echo "[kernel-bench] backend=$BACKEND duration=${DURATION}s mbps=$MBPS pcap=$PCAP"
echo "[kernel-bench] csv=$CSV_PATH"

if ! command -v tcpreplay >/dev/null 2>&1; then
    echo "[kernel-bench] tcpreplay not in PATH." >&2
    exit 127
fi
if [[ ! -f "$PCAP" ]]; then
    echo "[kernel-bench] pcap $PCAP not found." >&2
    exit 1
fi
if ! ip link show "$REPLAY_IFACE" >/dev/null 2>&1; then
    echo "[kernel-bench] interface $REPLAY_IFACE not present." >&2
    exit 1
fi

cleanup() {
    local rc=$?
    if [[ -n "${TCPREPLAY_PID:-}" ]] && kill -0 "$TCPREPLAY_PID" 2>/dev/null; then
        kill -TERM "$TCPREPLAY_PID" 2>/dev/null || true
        wait "$TCPREPLAY_PID" 2>/dev/null || true
    fi
    if [[ "$RULES_CREATED" == "true" ]]; then
        case "$RULE_FAMILY" in
            nft)
                nft delete table inet "$NFT_TABLE" 2>/dev/null || true
                ;;
            iptables)
                if [[ "$IPTABLES_RULE" == "drop" ]]; then
                    iptables -D INPUT -s 10.99.0.2 -j DROP 2>/dev/null || true
                elif [[ "$IPTABLES_RULE" == "count" ]]; then
                    iptables -D INPUT -s 10.99.0.2 2>/dev/null || true
                fi
                ;;
        esac
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# Setup rules and remember the previous counter snapshot for delta.
case "$RULE_FAMILY" in
    nft)
        if ! command -v nft >/dev/null 2>&1; then
            echo "[kernel-bench] nft not in PATH" >&2
            exit 127
        fi
        if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
            echo "[kernel-bench] refusing to reuse existing nft table $NFT_TABLE" >&2
            exit 1
        fi
        nft add table inet "$NFT_TABLE"
        RULES_CREATED="true"
        nft add chain inet "$NFT_TABLE" input \
            '{ type filter hook input priority 0 ; policy accept ; }'
        if [[ -z "$NO_RULES" ]]; then
            # Mirror the engine's default DROP rule (from the engine bench):
            nft add rule inet "$NFT_TABLE" input \
                ip saddr 10.99.0.2 drop counter name pkts_dropped
            echo "[kernel-bench] installed nftables DROP rule"
        else
            nft add rule inet "$NFT_TABLE" input \
                ip saddr 10.99.0.2 counter name pkts_dropped
            echo "[kernel-bench] installed nftables count-only rule (NO_RULES set)"
        fi
        # Snapshot the counter so we can compute drops/s.
        COUNTERS_BEFORE="$(nft list counter inet "$NFT_TABLE" pkts_dropped 2>/dev/null \
            | awk '/packets/ {print $2; exit}')"
        COUNTERS_BEFORE="${COUNTERS_BEFORE:-0}"
        ;;

    iptables)
        if ! command -v iptables >/dev/null 2>&1; then
            echo "[kernel-bench] iptables not in PATH" >&2
            exit 127
        fi
        # Use the legacy iptables counters.  We don't have named counters,
        # so we sample the INPUT chain's total packet count instead.
        if [[ -z "$NO_RULES" ]]; then
            iptables -I INPUT -s 10.99.0.2 -j DROP
            RULES_CREATED="true"
            IPTABLES_RULE="drop"
            echo "[kernel-bench] installed iptables DROP rule"
        else
            iptables -I INPUT -s 10.99.0.2
            RULES_CREATED="true"
            IPTABLES_RULE="count"
            echo "[kernel-bench] installed iptables count-only rule (NO_RULES set)"
        fi
        COUNTERS_BEFORE="$(iptables -L INPUT -n -v -x | awk 'NR==3 {print $1; exit}')"
        COUNTERS_BEFORE="${COUNTERS_BEFORE:-0}"
        ;;
esac

# Replay (in background).
echo "[kernel-bench] tcpreplay --intf1=$REPLAY_IFACE --mbps=$MBPS --duration=$DURATION $PCAP"
tcpreplay --intf1="$REPLAY_IFACE" --mbps="$MBPS" --duration="$DURATION" "$PCAP" \
    >"$RESULTS_DIR/${BACKEND}_trial${TRIAL}.tcpreplay.log" 2>&1 &
TCPREPLAY_PID=$!

# Read the kernel counter every 1s and emit a CSV row.
echo "timestamp,backend,pps,drops,p50_us,p99_us" > "$CSV_PATH"

read_counter() {
    case "$RULE_FAMILY" in
        nft)
            nft list counter inet "$NFT_TABLE" pkts_dropped 2>/dev/null \
                | awk '/packets/ {print $2; exit}'
            ;;
        iptables)
            iptables -L INPUT -n -v -x 2>/dev/null | awk 'NR==3 {print $1; exit}'
            ;;
    esac
}

end=$(( $(date +%s) + DURATION ))
prev="${COUNTERS_BEFORE:-0}"
while [[ $(date +%s) -lt $end ]]; do
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cur="$(read_counter || echo 0)"
    cur="${cur:-0}"
    delta=$(( cur - prev ))
    echo "$now,$BACKEND,N/A,$delta,N/A,N/A" >> "$CSV_PATH"
    prev="$cur"
    sleep 1
done

wait "$TCPREPLAY_PID" 2>/dev/null || true
TCPREPLAY_PID=""

# Final counter snapshot for the summary.
COUNTERS_AFTER="$(read_counter || echo 0)"
COUNTERS_AFTER="${COUNTERS_AFTER:-0}"
total_drops=$(( COUNTERS_AFTER - COUNTERS_BEFORE ))

echo "---- kernel-bench summary ($BACKEND trial $TRIAL) ----"
echo "  total drops/seen: $total_drops"
echo "----------------------------------------------------"
