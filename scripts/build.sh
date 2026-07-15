#!/usr/bin/env bash
set -euo pipefail

# Build wrapper for the packet engine.
# Uses Ninja and exports compile_commands.json for clangd/LSP integration.
# On first run cmake generates compile_commands.json natively; subsequent runs
# use bear --append so incremental ninja builds keep the database fresh.

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

BUILD_DIR="build"

mkdir -p "$BUILD_DIR"

if [[ ! -f "$BUILD_DIR/compile_commands.json" ]]; then
    echo "[build] first build: cmake + ninja (generates compile_commands.json)"
    cmake -B "$BUILD_DIR" -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON "$@"
    bear --append -- cmake --build "$BUILD_DIR" -j
else
    echo "[build] incremental build: bear --append + ninja"
    cmake -B "$BUILD_DIR" -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON "$@"
    bear --append -- cmake --build "$BUILD_DIR" -j
fi

echo "[build] done: $BUILD_DIR/compile_commands.json"
