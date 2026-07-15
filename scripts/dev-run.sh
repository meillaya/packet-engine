#!/usr/bin/env bash
set -euo pipefail

# Packet Engine veth-only development harness.
# This script deliberately avoids real NICs and never uses sudo internally.
# Run as root only when the surrounding environment requires it (veth/XDP).

VETH0="veth0"
VETH1="veth1"
IP0="10.99.0.1/24"
IP1="10.99.0.2/24"

ENGINE_PID=""
HARNESS_CREATED="false"

cleanup() {
    local rc=$?
    echo "[dev-run] cleanup triggered (exit code $rc)"

    if [[ -n "$ENGINE_PID" ]] && kill -0 "$ENGINE_PID" 2>/dev/null; then
        echo "[dev-run] stopping engine PID $ENGINE_PID"
        kill -TERM "$ENGINE_PID" 2>/dev/null || true
        sleep 0.5
        kill -KILL "$ENGINE_PID" 2>/dev/null || true
        wait "$ENGINE_PID" 2>/dev/null || true
    fi

    # Best-effort XDP unload (no sudo inside script).
    if [[ "$HARNESS_CREATED" == "true" ]] && ip link show "$VETH0" >/dev/null 2>&1; then
        echo "[dev-run] unloading XDP from $VETH0"
        ip link set dev "$VETH0" xdp off 2>/dev/null || true
    fi

    if [[ "$HARNESS_CREATED" == "true" ]]; then
        echo "[dev-run] removing veth pair $VETH0/$VETH1"
        ip link del "$VETH0" 2>/dev/null || true
    fi

    exit "$rc"
}
trap cleanup EXIT INT TERM

setup_veth() {
    if ip link show "$VETH0" >/dev/null 2>&1 || ip link show "$VETH1" >/dev/null 2>&1; then
        echo "[dev-run] refusing to replace pre-existing $VETH0 or $VETH1" >&2
        return 1
    fi

    ip link add "$VETH0" type veth peer name "$VETH1"
    HARNESS_CREATED="true"
    ip addr add "$IP0" dev "$VETH0"
    ip addr add "$IP1" dev "$VETH1"
    ip link set "$VETH0" up
    ip link set "$VETH1" up

    # GRO on veth1 is required for XDP_REDIRECT paths.
    ethtool -K "$VETH1" gro on 2>/dev/null || true

    echo "[dev-run] veth pair ready: $VETH0=$IP0 $VETH1=$IP1"
}

load_xdp() {
    # Placeholder: load a BPF XDP program on veth0 with DRV mode.
    # The actual program path will come from Task 3/4 build artifacts.
    local prog="${1:-}"
    if [[ -n "$prog" && -f "$prog" ]]; then
        echo "[dev-run] loading XDP program $prog on $VETH0"
        xdp-loader load -m drv "$VETH0" "$prog" || {
            echo "[dev-run] XDP load failed; continuing in passthrough mode"
        }
    else
        echo "[dev-run] no XDP program provided; skipping XDP load"
    fi
}

run_bench() {
    local engine=${1:-${ENGINE_BIN:-build-dpdk/packet-engine}}
    "$(dirname "$0")/../bench/run_pcap_benchmark.sh" --engine "$engine"
}

run_test() {
    ctest --test-dir "${BUILD_DIR:-build}" --output-on-failure
}

run_shell() {
    echo "[dev-run] entering harness shell.  Run 'exit' or press Ctrl-C to tear down."
    export VETH0 VETH1
    # Spawn an interactive shell so the user can inspect the harness.
    # The trap fires when this subshell exits or on Ctrl-C.
    bash --rcfile <(echo 'PS1="[packet-engine] $ "') -i
}

main() {
    local subcommand="${1:-shell}"
    shift || true

    case "$subcommand" in
        bench)
            run_bench "$@"
            ;;
        test)
            run_test
            ;;
        shell)
            setup_veth
            run_shell
            ;;
        *)
            echo "Usage: $0 {bench|test|shell}"
            exit 1
            ;;
    esac
}

main "$@"
