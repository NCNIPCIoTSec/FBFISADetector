#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${PYTHON:-}" ]]; then
    if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
        PYTHON="$ROOT_DIR/.venv/bin/python"
    else
        PYTHON=python3
    fi
fi
export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"
SAMPLES_DIR="${FBFISA_SAMPLES_DIR:-$ROOT_DIR/resources/samples}"
OUTPUT_DIR="${FBFISA_OUTPUT_DIR:-$ROOT_DIR/output}"

sample="$SAMPLES_DIR/arm/p2im_drone.elf"
"$PYTHON" -m detectisa -p -f "$sample" "$@"
binary=$("$PYTHON" -m elf2bin -f "$sample" -o "$OUTPUT_DIR/arm/bin" --print-path)
"$PYTHON" -m detectisa -p -f "$binary" "$@"
