# Benchmark harness

The default benchmark is a deterministic, unprivileged DPDK `net_pcap`
offline replay. It executes the real `packet-engine` binary six times: one
warmup and five measured trials. Every trial receives the same generated PCAP,
uses a unique DPDK file prefix/control socket/metrics port, terminates at the
known packet count, and validates output records byte-for-byte.

This benchmark is intentionally narrower than a NIC line-rate test. The PCAP
PMD and AF_PACKET PMD are copy-backed software paths. They exercise EAL,
ethdev, application ownership, parsing, policy, metrics, TX, and teardown, but
they do not prove PCI kernel bypass or zero-copy.

## Default benchmark

```sh
cmake -S . -B build-dpdk -G Ninja -DENABLE_DPDK=ON
cmake --build build-dpdk -j

bench/run_pcap_benchmark.sh --engine build-dpdk/packet-engine
```

Optional parameters:

```sh
PACKETS=100000 \
WARMUP_TRIALS=2 \
MEASURED_TRIALS=7 \
TIMEOUT_SECONDS=60 \
EAL_LCORE=2 \
bench/run_pcap_benchmark.sh \
  --engine build-dpdk/packet-engine \
  --output-dir bench/results/my-run
```

`MEASURED_TRIALS` cannot be lower than five. The script needs only Bash,
Python's standard library, `sha256sum`, GNU `timeout`, and a DPDK-enabled engine
with the `net_pcap` PMD installed. It does not use tcpreplay, tcpdump, root,
hugepages, PCI binding, or a persistent daemon.

## Workload

The script generates a deterministic little-endian Ethernet PCAP. Each record
contains a 60-byte Ethernet/IPv4/UDP frame with valid IPv4 checksum, stable
addresses/ports/payload, a varying IPv4 ID, and deterministic timestamps.
`net_pcap` reads the file into DPDK mbufs and writes accepted TX packets to a
new PCAP.

The timed region includes:

1. process creation;
2. DPDK EAL initialization;
3. software-vdev and queue setup;
4. RX, parser/rule, and TX processing;
5. PCAP TX flush;
6. port, mempool, and EAL teardown.

Throughput is `output_packets / elapsed_seconds` using `time.monotonic_ns`.
Drops are `input_packets - output_packets`. This is an end-to-end executable
baseline rather than a steady-state hot-loop microbenchmark.

Offline PCAP records do not provide a correlated ingress-to-egress timestamp
for each packet. Consequently `p50_latency_seconds` and
`p99_latency_seconds` are JSON `null`. Process duration is not relabeled as
packet latency.

## Outputs

`bench/results/dpdk-net-pcap/` contains:

| File | Meaning |
|---|---|
| `result.json` | Machine-readable result, parameters, provenance, warmup, measured trials, summary, and blocked comparisons |
| `trials.csv` | One row per warmup/measured trial |
| `manifest.txt` | Paths, SHA-256 digests, and trial parameters |
| `input.pcap` | Deterministic input corpus |
| `warmup-*.pcap`, `measured-*.pcap` | DPDK TX output for packet-count/record inspection |
| `*.stdout.log`, `*.stderr.log` | Engine and DPDK output per process |

Important `result.json` fields:

```text
schema_version
status
benchmark
measurement_scope
parameters.{packets_per_trial,warmup_trials,measured_trials,timeout_seconds,eal_lcore}
provenance.{engine_sha256,input_pcap_sha256,kernel,machine,clock,dpdk_eal}
warmup[]
trials[].{elapsed_seconds,input_packets,output_packets,dropped_packets,packets_per_second}
summary.{median_packets_per_second,min_packets_per_second,max_packets_per_second,total_dropped_packets}
summary.{p50_latency_seconds,p99_latency_seconds,latency_unavailable_reason}
comparisons.{af_xdp,kernel_networking}.{status,reason}
```

The engine binary and input corpus are hashed so a result cannot be detached
from the code artifact/workload that produced it. The result also records the
kernel, architecture, host, clock, and exact EAL/vdev shape. For a publishable
hardware benchmark, additionally record compiler/build flags, CPU model and
frequency policy, SMT, NIC/firmware/PCIe link, NUMA/queue/core mapping,
hugepages/IOMMU, offered load, frame-size distribution, flow cardinality,
independent generator/receiver counts, device counters, CPU utilization,
cycles/packet, and timestamp error.

## Result committed with this revision

The checked-in run processed 10,000 packets per trial using a DPDK-enabled
engine identified by SHA-256 in `result.json`:

| Path | Status | Measured trials | Median packets/s | Total drops | p50/p99 |
|---|---:|---:|---:|---:|---|
| DPDK `net_pcap` offline | PASS | 5 | 27,850.459 | 0 | N/A |
| AF_XDP live | BLOCKED | 0 | N/A | N/A | Privileges/interface/memlock unavailable |
| Kernel veth/nftables | BLOCKED | 0 | N/A | N/A | `CAP_NET_ADMIN` unavailable |

The measured DPDK trials ranged from 24,503.933 to 30,427.172 packets/s. That
wide range is retained rather than hidden. The median is machine-specific,
startup-inclusive, and unsuitable as a line-rate or native-NIC claim.

## Integration regression

```sh
tests/integration/test_dpdk_pcap_cli.sh build-dpdk/packet-engine
tests/integration/test_pcap_benchmark.sh build-dpdk/packet-engine
```

The first test compares one decoded output frame byte-for-byte with its input.
The second runs one warmup plus five small measured trials and validates the
JSON contract, output/drop counts, positive throughput, explicit unavailable
latency, blocked privileged comparisons, and provenance hashes.

## Privileged live comparisons

These scripts remain available for operators with the required capabilities:

| Script | Requirement | Output |
|---|---|---|
| `capture_baseline.sh` | tcpdump and a prepared interface; normally `CAP_NET_RAW` | PCAP |
| `run_engine_bench.sh` | AF_XDP-capable interface, BPF/network capabilities, memlock, tcpreplay | 1 Hz counter rates and histogram-derived bounds |
| `run_kernel_bench.sh` | veth/nftables or iptables setup, `CAP_NET_ADMIN`, tcpreplay | kernel counter deltas |
| `latency_probe.py` | a deliberately configured UDP echo path | application RTT samples |
| `compare.py` | legacy live-run CSVs | aggregate Markdown table |

Do not compare offline `net_pcap` process throughput numerically with a live
AF_XDP or kernel replay result. The topology, measurement boundary, and load
generator differ. A valid three-way comparison must use the same traffic
corpus, offered rate, interfaces, duration, CPU allocation, policy, and
measurement boundary, while reporting actual AF_XDP mode.

For AF_XDP, a successful bind is insufficient: only
`mode=zero-copy` reported from `XDP_OPTIONS_ZEROCOPY` supports a zero-copy-mode
claim. Veth normally exercises AF_XDP copy mode. For DPDK AF_PACKET, packet
sockets/PACKET_MMAP remain in the kernel and the PMD copies into mbufs. For a
native DPDK claim, use a supported PCI PMD and document driver binding,
IOMMU/IOVA, hugepages, queues, mempool socket, and hardware counters.

## Cleanup and failure behavior

Every bounded benchmark process receives `--max-packets` and
`--max-idle-ms`, and GNU `timeout` supplies an outer deadline. The default
script tracks the current `timeout` child and terminates/waits for it from
`EXIT`, `INT`, or `TERM`; its temporary control sockets are below a private
`mktemp` directory. Live replay scripts likewise track engine/tcpreplay
children, and the kernel script removes only the table/rules it created.

A failed engine run is not converted into zero throughput. The script prints
that trial's logs and exits nonzero. Unavailable AF_XDP and kernel comparisons
are represented as `BLOCKED` with reasons, never as fabricated measurements.
