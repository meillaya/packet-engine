#!/usr/bin/env python3
# latency_probe.py — UDP echo latency probe for the packet-engine benchmark.
#
# This is a *two-process* tool:
#
#   1. The receiver binds a UDP port and echoes every datagram back to the
#      sender verbatim.  It is also the component that decodes the probe
#      payload (sequence number + send timestamp) and computes per-packet
#      one-way latency = recv_ts - send_ts, then reports p50/p99.
#
#   2. The sender sends a burst of UDP datagrams to a target address.
#      Each datagram's payload is fixed-size (default 64 B) and starts with
#      a 16-byte header: 8-byte monotonic ns timestamp (host-order u64) and
#      an 8-byte sequence number (host-order u64).  The remainder of the
#      payload is padding that the receiver echoes back unchanged.
#
# Two run modes are supported:
#
#   (a) "engine mode" — used by run_engine_bench.sh.  The probe is run as
#       both sender and receiver.  The engine is configured (via
#       /tmp/packet-engine.sock PUT /rules) to *reflect* UDP packets back
#       to the sender.  The receiver therefore runs on the same machine
#       as the sender; packets travel: sender -> veth1 -> engine -> veth0
#       -> sender.  The measured latency captures the engine's processing
#       delay.
#
#   (b) "kernel mode" — used by run_kernel_bench.sh.  Same wire path, but
#       the engine is NOT in the data plane.  The receiver is configured
#       via an nftables DNAT rule that loops packets back to the receiver
#       port.  No application-level echo is needed because the receiver
#       is also the sender's peer; the kernel NAT rewrites src/dst.
#       To keep the protocol symmetric across modes, the receiver in
#       kernel mode ALSO runs the python echo server; packets are NATed
#       to the receiver's local port, the python listener echoes them.
#
# Usage:
#
#   # Run as receiver (background):
#   python3 bench/latency_probe.py receive \
#       --bind 10.99.0.1 --port 53000 \
#       --duration 60 --out bench/results/latency_engine.csv
#
#   # Run as sender (foreground):
#   python3 bench/latency_probe.py send \
#       --target 10.99.0.1 --target-port 53000 \
#       --bind 10.99.0.2 --port 53001 \
#       --rate 1000 --count 6000 --payload 64
#
# Both modes exit cleanly when --duration seconds elapse, --count packets
# are processed, or SIGINT/SIGTERM is received.

from __future__ import annotations

import argparse
import csv
import os
import select
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

# Header layout (16 bytes, native byte order):
#   uint64 send_monotonic_ns
#   uint64 sequence
HEADER_FMT = "=QQ"
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 16


@dataclass
class Sample:
    seq: int
    send_ns: int
    recv_ns: int
    rtt_us: float

    @property
    def one_way_us(self) -> float:
        # One-way is half the RTT, which is the right approximation for
        # the symmetric round-trip we measure here.
        return self.rtt_us / 2.0


def percentile(values: List[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p * (len(s) - 1)))))
    return s[k]


def monotonic_ns() -> int:
    return time.monotonic_ns()


def build_payload(seq: int, payload_size: int) -> bytes:
    if payload_size < HEADER_LEN:
        raise ValueError("payload-size must be >= 16 (header)")
    send_ns = monotonic_ns()
    header = struct.pack(HEADER_FMT, send_ns, seq)
    return header + b"\x00" * (payload_size - HEADER_LEN)


def parse_payload(data: bytes) -> Optional[Tuple[int, int]]:
    if len(data) < HEADER_LEN:
        return None
    send_ns, seq = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
    return seq, send_ns


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------

def cmd_send(args: argparse.Namespace) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    if args.bind:
        sock.bind((args.bind, args.port))
    sock.setblocking(False)

    payload = build_payload(0, args.payload)
    interval_ns = 0 if args.rate <= 0 else int(1e9 / args.rate)
    deadline = time.monotonic() + args.duration

    sent = 0
    lost = 0
    next_send = time.monotonic_ns()

    print(
        f"[send] target={args.target}:{args.target_port} "
        f"bind={args.bind or '*'}:{args.port or '*'} "
        f"rate={args.rate}/s count={args.count} payload={args.payload}B "
        f"duration={args.duration}s",
        file=sys.stderr,
        flush=True,
    )

    while sent < args.count and time.monotonic() < deadline:
        now = time.monotonic_ns()
        if now < next_send:
            # Sleep to next slot; socket is non-blocking but we don't recv
            # here — keep the sender pure.
            time.sleep(min(0.001, (next_send - now) / 1e9))
            continue
        buf = build_payload(sent, args.payload)
        try:
            sock.sendto(buf, (args.target, args.target_port))
        except (BlockingIOError, OSError):
            lost += 1
        sent += 1
        next_send += interval_ns

    sock.close()
    print(
        f"[send] done: sent={sent} lost={lost}",
        file=sys.stderr,
        flush=True,
    )
    return 0


# ---------------------------------------------------------------------------
# Receiver
# ---------------------------------------------------------------------------

def cmd_receive(args: argparse.Namespace) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
    sock.bind((args.bind, args.port))
    sock.setblocking(False)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    out_fp = open(args.out, "w", newline="")
    writer = csv.writer(out_fp)
    writer.writerow(["seq", "send_ns", "recv_ns", "rtt_us", "one_way_us"])

    deadline = time.monotonic() + args.duration
    samples: List[float] = []
    received = 0
    echoed = 0
    lost_echoes = 0

    print(
        f"[recv] bind={args.bind}:{args.port} duration={args.duration}s "
        f"echo-to={args.echo_to or '<off>'} out={args.out}",
        file=sys.stderr,
        flush=True,
    )

    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    while running and time.monotonic() < deadline:
        readable, _, _ = select.select([sock], [], [], 0.1)
        if not readable:
            continue
        try:
            data, addr = sock.recvfrom(2048)
        except (BlockingIOError, OSError):
            continue
        recv_ns = monotonic_ns()
        parsed = parse_payload(data)
        if parsed is None:
            continue
        seq, send_ns = parsed
        rtt_us = (recv_ns - send_ns) / 1000.0
        one_way_us = rtt_us / 2.0
        samples.append(rtt_us)
        writer.writerow([seq, send_ns, recv_ns, f"{rtt_us:.3f}", f"{one_way_us:.3f}"])
        received += 1

        if args.echo_to:
            try:
                sock.sendto(data, (args.echo_to, args.echo_port))
                echoed += 1
            except OSError:
                lost_echoes += 1

    out_fp.flush()
    out_fp.close()
    sock.close()

    p50 = percentile(samples, 0.50)
    p90 = percentile(samples, 0.90)
    p99 = percentile(samples, 0.99)
    avg = sum(samples) / len(samples) if samples else float("nan")
    print(
        f"[recv] done: received={received} echoed={echoed} lost_echoes={lost_echoes}",
        file=sys.stderr,
        flush=True,
    )
    print(
        f"[recv] latency_us: avg={avg:.2f} p50={p50:.2f} p90={p90:.2f} p99={p99:.2f}",
        file=sys.stderr,
        flush=True,
    )
    return 0


# ---------------------------------------------------------------------------
# One-shot client mode: sender + receiver in one process, useful for ICMP-style
# loopback or when the engine reflects in-process.  Sends to args.target, the
# kernel returns the datagram to the local receiver (which is bound on
# args.bind:args.port) and we record the RTT.  This mode is used by the
# compare.py smoke test to validate the probe end-to-end without an engine.
# ---------------------------------------------------------------------------

def cmd_loopback(args: argparse.Namespace) -> int:
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    rx.bind(("127.0.0.1", args.port))
    rx.setblocking(False)

    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    out_fp = open(args.out, "w", newline="")
    writer = csv.writer(out_fp)
    writer.writerow(["seq", "send_ns", "recv_ns", "rtt_us", "one_way_us"])

    deadline = time.monotonic() + args.duration
    samples: List[float] = []
    next_send = time.monotonic_ns()
    interval_ns = 0 if args.rate <= 0 else int(1e9 / args.rate)
    sent = 0
    received = 0

    print(
        f"[loopback] target=127.0.0.1:{args.port} rate={args.rate} "
        f"duration={args.duration}s out={args.out}",
        file=sys.stderr,
        flush=True,
    )

    while time.monotonic() < deadline and sent < args.count:
        now = time.monotonic_ns()
        # Drain recv queue
        while True:
            readable, _, _ = select.select([rx], [], [], 0)
            if not readable:
                break
            data, _ = rx.recvfrom(2048)
            recv_ns = monotonic_ns()
            parsed = parse_payload(data)
            if parsed is None:
                continue
            seq, send_ns = parsed
            rtt_us = (recv_ns - send_ns) / 1000.0
            samples.append(rtt_us)
            writer.writerow([seq, send_ns, recv_ns, f"{rtt_us:.3f}", f"{rtt_us / 2.0:.3f}"])
            received += 1
        # Send
        if now >= next_send:
            buf = build_payload(sent, args.payload)
            tx.sendto(buf, ("127.0.0.1", args.port))
            sent += 1
            next_send += interval_ns
        else:
            time.sleep(min(0.001, (next_send - now) / 1e9))

    rx.close()
    tx.close()
    out_fp.flush()
    out_fp.close()

    p50 = percentile(samples, 0.50)
    p90 = percentile(samples, 0.90)
    p99 = percentile(samples, 0.99)
    avg = sum(samples) / len(samples) if samples else float("nan")
    print(
        f"[loopback] sent={sent} received={received}",
        file=sys.stderr,
        flush=True,
    )
    print(
        f"[loopback] latency_us: avg={avg:.2f} p50={p50:.2f} p90={p90:.2f} p99={p99:.2f}",
        file=sys.stderr,
        flush=True,
    )
    return 0


# ---------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="UDP echo latency probe for packet-engine benchmarking.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--duration", type=float, default=60.0,
                        help="probe duration in seconds (default: 60)")
    common.add_argument("--count", type=int, default=10_000_000,
                        help="max packets to send/process (default: unlimited)")
    common.add_argument("--payload", type=int, default=64,
                        help="payload size in bytes (>=16, default: 64)")

    s = sub.add_parser("send", parents=[common], help="send-only mode")
    s.add_argument("--target", required=True)
    s.add_argument("--target-port", type=int, required=True)
    s.add_argument("--bind", default="")
    s.add_argument("--port", type=int, default=0)
    s.add_argument("--rate", type=int, default=1000,
                   help="packets per second (0 = line rate, default: 1000)")
    s.set_defaults(func=cmd_send)

    r = sub.add_parser("receive", parents=[common], help="receive + echo mode")
    r.add_argument("--bind", required=True)
    r.add_argument("--port", type=int, required=True)
    r.add_argument("--out", required=True, help="CSV path for sample log")
    r.add_argument("--echo-to", default="",
                   help="optional: echo received packets to this address")
    r.add_argument("--echo-port", type=int, default=0)
    r.set_defaults(func=cmd_receive)

    l = sub.add_parser("loopback", parents=[common],
                       help="in-process send+receive via 127.0.0.1")
    l.add_argument("--port", type=int, required=True)
    l.add_argument("--out", required=True)
    l.add_argument("--rate", type=int, default=1000)
    l.set_defaults(func=cmd_loopback)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
