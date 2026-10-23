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

binary=$("$PYTHON" -m elf2bin -f "$SAMPLES_DIR/arm/p2im_gateway.elf" \
    -o "$OUTPUT_DIR/arm/bin" --print-path)
"$PYTHON" -m emulator.unicorn_run -f "$binary" -a ARM:LE -b 0x08000000 -e 0x0800365c "$@"
