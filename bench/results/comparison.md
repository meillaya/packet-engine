# Packet Engine Benchmark Comparison

These rows are not a matched three-way performance comparison. Only the
unprivileged DPDK PCAP path was executable on this host; privileged rows remain
explicitly blocked.

| Path | Status | Workload | Trials | Median packets/s | Drops | p50/p99 latency |
|---|---|---|---:|---:|---:|---|
| DPDK `net_pcap` | PASS | 10,000-record offline PCAP; startup through teardown | 1 warmup + 5 measured | 27,850.459 | 0 | N/A: no correlated packet timestamps |
| AF_XDP | BLOCKED | live interface | 0 | N/A | N/A | privileges/interface/memlock unavailable |
| Linux kernel | BLOCKED | veth/nftables | 0 | N/A | N/A | `CAP_NET_ADMIN` unavailable |

Machine-readable data and provenance are in
`bench/results/dpdk-net-pcap/result.json`. Do not rank the blocked paths or
compare this offline result with a future live replay without a matched
workload, topology, CPU allocation, and measurement boundary.
