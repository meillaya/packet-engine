#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

: "${PACKETS:=10000}"
: "${WARMUP_TRIALS:=1}"
: "${MEASURED_TRIALS:=5}"
: "${TIMEOUT_SECONDS:=30}"
: "${EAL_LCORE:=$(awk '/^Cpus_allowed_list:/ { value=$2; sub(/[-,].*/, "", value); print value; exit }' /proc/self/status)}"

ENGINE="$REPO_ROOT/build-dpdk/packet-engine"
OUTPUT_DIR="$REPO_ROOT/bench/results/dpdk-net-pcap"
WORK_DIR=""
CURRENT_PID=""
DPDK_PREFIXES=()

remove_dpdk_prefixes() {
  local root prefix
  for root in "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/dpdk" /var/run/dpdk; do
    [[ -d $root ]] || continue
    for prefix in "${DPDK_PREFIXES[@]}"; do
      [[ $prefix == pe-bench-* ]] && rm -rf -- "${root:?}/${prefix:?}"
    done
  done
}

usage() {
  cat <<EOF
Usage: $0 [--engine PATH] [--output-dir DIR]

Runs a deterministic DPDK net_pcap offline replay benchmark without root.
The workload includes one warmup and at least five measured process runs.

Environment:
  PACKETS=N           packets in the generated PCAP (default: 10000)
  WARMUP_TRIALS=N     warmup process runs (default: 1)
  MEASURED_TRIALS=N   measured process runs, minimum 5 (default: 5)
  TIMEOUT_SECONDS=N   timeout for each bounded engine run (default: 30)
  EAL_LCORE=N         allowed logical CPU for DPDK (default: first allowed CPU)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --engine)
      ENGINE=${2:?missing value for --engine}
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR=${2:?missing value for --output-dir}
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

for value in "$PACKETS" "$WARMUP_TRIALS" "$MEASURED_TRIALS" "$TIMEOUT_SECONDS"; do
  if [[ ! $value =~ ^[1-9][0-9]*$ ]]; then
    echo "benchmark counts and timeout must be positive integers: $value" >&2
    exit 64
  fi
done
if [[ ! $EAL_LCORE =~ ^[0-9]+$ ]]; then
  echo "EAL_LCORE must be a non-negative integer: $EAL_LCORE" >&2
  exit 64
fi
if (( MEASURED_TRIALS < 5 )); then
  echo "MEASURED_TRIALS must be at least 5" >&2
  exit 64
fi
if [[ ! -x $ENGINE ]]; then
  echo "DPDK-enabled packet-engine is not executable: $ENGINE" >&2
  exit 66
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "GNU timeout is required" >&2
  exit 69
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
ENGINE=$(cd "$(dirname "$ENGINE")" && pwd)/$(basename "$ENGINE")
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/packet-engine-pcap-bench.XXXXXX")

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [[ -n $CURRENT_PID ]] && kill -0 "$CURRENT_PID" 2>/dev/null; then
    kill -TERM "$CURRENT_PID" 2>/dev/null || true
    wait "$CURRENT_PID" 2>/dev/null || true
  fi
  remove_dpdk_prefixes
  rm -rf "$WORK_DIR"
  exit "$rc"
}
trap cleanup EXIT INT TERM

INPUT_PCAP="$OUTPUT_DIR/input.pcap"
ROWS="$WORK_DIR/rows.csv"
printf 'phase,trial,status,elapsed_seconds,input_packets,output_packets,dropped_packets,packets_per_second\n' >"$ROWS"

python3 - "$INPUT_PCAP" "$PACKETS" <<'PY'
import struct
import sys

path = sys.argv[1]
count = int(sys.argv[2])
ethernet = bytes.fromhex("00112233445566778899aabb0800")
payload = bytes(range(18))

with open(path, "wb") as stream:
    stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for sequence in range(count):
        ipv4_without_checksum = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 20 + 8 + len(payload), sequence & 0xFFFF, 0, 64, 17, 0,
            bytes((192, 0, 2, 1)), bytes((198, 51, 100, 2)),
        )
        words = struct.unpack("!10H", ipv4_without_checksum)
        checksum = sum(words)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = (~checksum) & 0xFFFF
        ipv4 = (
            ipv4_without_checksum[:10]
            + struct.pack("!H", checksum)
            + ipv4_without_checksum[12:]
        )
        udp = struct.pack("!HHHH", 12345, 4321, 8 + len(payload), 0)
        frame = ethernet + ipv4 + udp + payload
        stream.write(struct.pack("<IIII", 1_700_000_000 + sequence, sequence % 1_000_000,
                                 len(frame), len(frame)))
        stream.write(frame)
PY

pcap_verify() {
  python3 - "$1" "$2" <<'PY'
import struct
import sys

def packets(path):
    with open(path, "rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise SystemExit(f"{path}: truncated PCAP global header")
        magic = header[:4]
        if magic in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("4d3cb2a1")):
            endian = "<"
        elif magic in (bytes.fromhex("a1b2c3d4"), bytes.fromhex("a1b23c4d")):
            endian = ">"
        else:
            raise SystemExit(f"{path}: unsupported PCAP magic: {magic.hex()}")
        while record := stream.read(16):
            if len(record) != 16:
                raise SystemExit(f"{path}: truncated PCAP record header")
            included = struct.unpack(endian + "IIII", record)[2]
            packet = stream.read(included)
            if len(packet) != included:
                raise SystemExit(f"{path}: truncated PCAP packet")
            yield packet

source = iter(packets(sys.argv[1]))
output = iter(packets(sys.argv[2]))
count = 0
while True:
    source_packet = next(source, None)
    output_packet = next(output, None)
    if source_packet is None and output_packet is None:
        break
    if source_packet != output_packet:
        raise SystemExit(f"output PCAP differs from deterministic input at record {count}")
    count += 1
print(count)
PY
}

free_port() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

run_trial() {
  local phase=$1
  local trial=$2
  local ordinal=$3
  local output_pcap="$OUTPUT_DIR/${phase}-${trial}.pcap"
  local stdout_log="$OUTPUT_DIR/${phase}-${trial}.stdout.log"
  local stderr_log="$OUTPUT_DIR/${phase}-${trial}.stderr.log"
  local prefix="pe-bench-$$-$ordinal"
  DPDK_PREFIXES+=("$prefix")
  local port_name="net_pcap_pe_bench_$ordinal"
  local control_socket="$WORK_DIR/control-$ordinal.sock"
  local metrics_port
  metrics_port=$(free_port)
  rm -f "$output_pcap" "$control_socket"

  local started_ns ended_ns status output_packets dropped elapsed pps
  started_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
  timeout --signal=TERM --kill-after=2s "${TIMEOUT_SECONDS}s" \
    "$ENGINE" \
    --backend=dpdk \
    --dpdk-port="$port_name" \
    --max-packets="$PACKETS" \
    --max-idle-ms=1000 \
    --default-action=allow \
    --control-socket="$control_socket" \
    --metrics-port="$metrics_port" \
    -- \
    -l "$EAL_LCORE" -n 1 --no-huge --no-pci \
    "--file-prefix=$prefix" \
    "--vdev=$port_name,rx_pcap=$INPUT_PCAP,tx_pcap=$output_pcap" \
    >"$stdout_log" 2>"$stderr_log" &
  CURRENT_PID=$!
  set +e
  wait "$CURRENT_PID"
  status=$?
  set -e
  CURRENT_PID=""
  remove_dpdk_prefixes
  ended_ns=$(python3 -c 'import time; print(time.monotonic_ns())')

  if (( status != 0 )); then
    cat "$stdout_log" >&2
    cat "$stderr_log" >&2
    echo "benchmark $phase trial $trial failed with status $status" >&2
    return "$status"
  fi
  if [[ ! -s $output_pcap ]]; then
    echo "benchmark $phase trial $trial produced no output PCAP" >&2
    return 1
  fi
  output_packets=$(pcap_verify "$INPUT_PCAP" "$output_pcap")
  dropped=$((PACKETS - output_packets))
  read -r elapsed pps < <(python3 - "$started_ns" "$ended_ns" "$output_packets" <<'PY'
import sys

elapsed = (int(sys.argv[2]) - int(sys.argv[1])) / 1_000_000_000
pps = int(sys.argv[3]) / elapsed
print(f"{elapsed:.9f} {pps:.3f}")
PY
  )
  printf '%s,%d,PASS,%s,%d,%d,%d,%s\n' \
    "$phase" "$trial" "$elapsed" "$PACKETS" "$output_packets" "$dropped" "$pps" >>"$ROWS"
  echo "[$phase $trial] elapsed=${elapsed}s packets=$output_packets drops=$dropped pps=$pps"
}

ordinal=0
for ((trial = 1; trial <= WARMUP_TRIALS; ++trial)); do
  ordinal=$((ordinal + 1))
  run_trial warmup "$trial" "$ordinal"
done
for ((trial = 1; trial <= MEASURED_TRIALS; ++trial)); do
  ordinal=$((ordinal + 1))
  run_trial measured "$trial" "$ordinal"
done

cp "$ROWS" "$OUTPUT_DIR/trials.csv"
ENGINE_SHA=$(sha256sum "$ENGINE" | awk '{print $1}')
INPUT_SHA=$(sha256sum "$INPUT_PCAP" | awk '{print $1}')
DPDK_VERSION=$(pkg-config --modversion libdpdk 2>/dev/null || printf 'unknown')
export ENGINE ENGINE_SHA INPUT_PCAP INPUT_SHA OUTPUT_DIR PACKETS WARMUP_TRIALS MEASURED_TRIALS TIMEOUT_SECONDS EAL_LCORE DPDK_VERSION

python3 - "$OUTPUT_DIR/trials.csv" "$OUTPUT_DIR/result.json" <<'PY'
import csv
import datetime
import json
import os
import platform
import statistics
import sys

rows_path, result_path = sys.argv[1:]
with open(rows_path, newline="", encoding="utf-8") as stream:
    rows = list(csv.DictReader(stream))

def record(row):
    return {
        "trial": int(row["trial"]),
        "status": row["status"],
        "elapsed_seconds": float(row["elapsed_seconds"]),
        "input_packets": int(row["input_packets"]),
        "output_packets": int(row["output_packets"]),
        "dropped_packets": int(row["dropped_packets"]),
        "packets_per_second": float(row["packets_per_second"]),
        "p50_latency_seconds": None,
        "p99_latency_seconds": None,
    }

warmup = [record(row) for row in rows if row["phase"] == "warmup"]
trials = [record(row) for row in rows if row["phase"] == "measured"]
pps_values = [trial["packets_per_second"] for trial in trials]
cpu_model = "unknown"
try:
    with open("/proc/cpuinfo", encoding="utf-8") as stream:
        for line in stream:
            if line.startswith("model name"):
                cpu_model = line.partition(":")[2].strip()
                break
except OSError:
    pass
numa_nodes = "unknown"
try:
    with open("/sys/devices/system/node/possible", encoding="utf-8") as stream:
        numa_nodes = stream.read().strip()
except OSError:
    pass
result = {
    "schema_version": 1,
    "status": "PASS",
    "benchmark": "dpdk_net_pcap_offline_replay",
    "measurement_scope": "end-to-end process startup, EAL initialization, replay, TX flush, and teardown",
    "parameters": {
        "packets_per_trial": int(os.environ["PACKETS"]),
        "warmup_trials": int(os.environ["WARMUP_TRIALS"]),
        "measured_trials": int(os.environ["MEASURED_TRIALS"]),
        "timeout_seconds": int(os.environ["TIMEOUT_SECONDS"]),
        "eal_lcore": int(os.environ["EAL_LCORE"]),
    },
    "provenance": {
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "engine_path": os.environ["ENGINE"],
        "engine_sha256": os.environ["ENGINE_SHA"],
        "input_pcap_path": os.environ["INPUT_PCAP"],
        "input_pcap_sha256": os.environ["INPUT_SHA"],
        "hostname": platform.node(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu_model": cpu_model,
        "logical_cpu_count": os.cpu_count(),
        "numa_nodes_possible": numa_nodes,
        "python": platform.python_version(),
        "dpdk_version": os.environ["DPDK_VERSION"],
        "build_configuration": "DPDK enabled; exact compiler flags are not embedded in the executable",
        "clock": "time.monotonic_ns",
        "dpdk_eal": f"-l {os.environ['EAL_LCORE']} -n 1 --no-huge --no-pci; net_pcap rx_pcap+tx_pcap",
    },
    "warmup": warmup,
    "trials": trials,
    "summary": {
        "median_packets_per_second": statistics.median(pps_values),
        "min_packets_per_second": min(pps_values),
        "max_packets_per_second": max(pps_values),
        "total_dropped_packets": sum(trial["dropped_packets"] for trial in trials),
        "p50_latency_seconds": None,
        "p99_latency_seconds": None,
        "latency_unavailable_reason": (
            "offline replay has no correlated ingress/egress packet timestamps; "
            "reporting process duration as packet latency would be misleading"
        ),
    },
    "comparisons": {
        "af_xdp": {
            "status": "BLOCKED",
            "reason": "requires AF_XDP/XDP privileges, a suitable interface, and sufficient RLIMIT_MEMLOCK",
        },
        "kernel_networking": {
            "status": "BLOCKED",
            "reason": "requires CAP_NET_ADMIN to create the isolated veth/nftables comparison topology",
        },
    },
}
with open(result_path, "w", encoding="utf-8") as stream:
    json.dump(result, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

{
  echo "benchmark=dpdk_net_pcap_offline_replay"
  echo "result=$OUTPUT_DIR/result.json"
  echo "trials=$OUTPUT_DIR/trials.csv"
  echo "engine=$ENGINE"
  echo "engine_sha256=$ENGINE_SHA"
  echo "input_pcap=$INPUT_PCAP"
  echo "input_pcap_sha256=$INPUT_SHA"
  echo "warmup_trials=$WARMUP_TRIALS"
  echo "measured_trials=$MEASURED_TRIALS"
  echo "packets_per_trial=$PACKETS"
  echo "eal_lcore=$EAL_LCORE"
} >"$OUTPUT_DIR/manifest.txt"

echo "result=$OUTPUT_DIR/result.json"
