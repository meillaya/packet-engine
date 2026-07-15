#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/dpdk-enabled-packet-engine" >&2
  exit 64
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/packet-engine-benchmark-test.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

PACKETS=32 WARMUP_TRIALS=1 MEASURED_TRIALS=5 \
  "$repo_root/bench/run_pcap_benchmark.sh" \
  --engine "$1" \
  --output-dir "$tmp_dir/results"

python3 - "$tmp_dir/results/result.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)

assert result["schema_version"] == 1
assert result["status"] == "PASS"
assert result["benchmark"] == "dpdk_net_pcap_offline_replay"
assert result["parameters"]["warmup_trials"] == 1
assert result["parameters"]["measured_trials"] == 5
assert len(result["warmup"]) == 1
assert len(result["trials"]) == 5
assert all(trial["input_packets"] == 32 for trial in result["trials"])
assert all(trial["output_packets"] == 32 for trial in result["trials"])
assert all(trial["dropped_packets"] == 0 for trial in result["trials"])
assert all(trial["packets_per_second"] > 0 for trial in result["trials"])
assert result["summary"]["p50_latency_seconds"] is None
assert result["summary"]["p99_latency_seconds"] is None
assert "offline replay" in result["summary"]["latency_unavailable_reason"]
assert result["comparisons"]["af_xdp"]["status"] == "BLOCKED"
assert result["comparisons"]["kernel_networking"]["status"] == "BLOCKED"
assert result["provenance"]["engine_sha256"]
assert result["provenance"]["input_pcap_sha256"]
PY

test -s "$tmp_dir/results/trials.csv"
test -s "$tmp_dir/results/manifest.txt"

echo "PASS: deterministic DPDK net_pcap benchmark emitted five truthful trials"
