#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/packet-engine" >&2
  exit 64
fi

engine=$1
if [[ ! -x "$engine" ]]; then
  echo "packet-engine is not executable: $engine" >&2
  exit 66
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/packet-engine-pcap-cli.XXXXXX")
prefix="pe-cli-$$"
cleanup() {
  local root
  for root in "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/dpdk" /var/run/dpdk; do
    [[ -d $root ]] && rm -rf -- "${root:?}/${prefix:?}"
  done
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
input_pcap=$tmp_dir/input.pcap
output_pcap=$tmp_dir/output.pcap
stdout_log=$tmp_dir/stdout.log
stderr_log=$tmp_dir/stderr.log

python3 - "$input_pcap" <<'PY'
import struct
import sys

path = sys.argv[1]
payload = bytes(range(18))
ethernet = bytes.fromhex("00112233445566778899aabb0800")
ipv4_without_checksum = struct.pack(
    "!BBHHHBBH4s4s",
    0x45, 0, 20 + 8 + len(payload), 0x1234, 0, 64, 17, 0,
    bytes((192, 0, 2, 1)), bytes((198, 51, 100, 2)),
)
words = struct.unpack("!10H", ipv4_without_checksum)
checksum = sum(words)
checksum = (checksum & 0xFFFF) + (checksum >> 16)
checksum = (~checksum) & 0xFFFF
ipv4 = ipv4_without_checksum[:10] + struct.pack("!H", checksum) + ipv4_without_checksum[12:]
udp = struct.pack("!HHHH", 12345, 4321, 8 + len(payload), 0)
frame = ethernet + ipv4 + udp + payload
assert len(frame) == 60

with open(path, "wb") as stream:
    stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    stream.write(struct.pack("<IIII", 1_700_000_000, 123_456, len(frame), len(frame)))
    stream.write(frame)
PY

set +e
timeout 15s "$engine" \
  --backend=dpdk \
  --dpdk-port=net_pcap_pe_cli \
  --max-packets=1 \
  --default-action=allow \
  -- \
  -l 0 -n 1 --no-huge --no-pci \
  "--file-prefix=$prefix" \
  "--vdev=net_pcap_pe_cli,rx_pcap=$input_pcap,tx_pcap=$output_pcap" \
  >"$stdout_log" 2>"$stderr_log"
engine_status=$?
set -e

if [[ $engine_status -ne 0 ]]; then
  cat "$stdout_log" >&2
  cat "$stderr_log" >&2
  echo "packet-engine exited with status $engine_status" >&2
  exit 1
fi
if [[ ! -s "$output_pcap" ]]; then
  cat "$stdout_log" >&2
  cat "$stderr_log" >&2
  echo "packet-engine exited successfully but produced no net_pcap output" >&2
  exit 1
fi

python3 - "$input_pcap" "$output_pcap" <<'PY'
import struct
import sys

def first_packet(path: str) -> bytes:
    data = open(path, "rb").read()
    if len(data) < 40:
        raise AssertionError(f"{path}: truncated PCAP")
    magic = data[:4]
    if magic == bytes.fromhex("d4c3b2a1"):
        endian = "<"
    elif magic == bytes.fromhex("a1b2c3d4"):
        endian = ">"
    elif magic == bytes.fromhex("4d3cb2a1"):
        endian = "<"
    elif magic == bytes.fromhex("a1b23c4d"):
        endian = ">"
    else:
        raise AssertionError(f"{path}: unsupported PCAP magic {magic.hex()}")
    included = struct.unpack_from(endian + "I", data, 24 + 8)[0]
    packet = data[40:40 + included]
    if len(packet) != included:
        raise AssertionError(f"{path}: truncated packet record")
    return packet

source = first_packet(sys.argv[1])
result = first_packet(sys.argv[2])
if result != source:
    raise AssertionError("net_pcap output frame differs from input frame")
PY

echo "PASS: one byte-identical net_pcap record processed with bounded CLI runtime"
