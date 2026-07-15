// SPDX-License-Identifier: GPL-2.0
/*
 * af_xdp_kern.bpf.c - Minimal AF_XDP redirect XDP program.
 *
 * Lookup the RX queue index in the XSKMAP and, if an AF_XDP socket is bound,
 * redirect the packet into that socket. While this unpinned program remains
 * attached, packets are dropped when no socket is bound or redirect fails.
 * Process exit removes the link, so deployments must isolate the normal
 * kernel path or manage a pinned guard program outside this prototype.
 *
 * License MUST be "GPL" (or compatible) — bpf_redirect_map() is a GPL-only
 * helper; the kernel verifier rejects the program otherwise.
 *
 * Compatible with: libxdp >= 1.4.0, libbpf >= 1.4, Linux kernel >= 7.1.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * XSKMAP: maps an RX queue index to the FD of an AF_XDP socket bound to it.
 * The kernel consumes the FD via bpf_redirect_map() and demuxes packets to
 * the matching XSK ring.
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xsk_redirect_prog(struct xdp_md* ctx) {
    __u32 index = ctx->rx_queue_index;

    /* A full/missing XSK ring must not bypass policy. */
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, XDP_DROP);

    /* No socket bound for this queue: preserve the fail-closed boundary. */
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
