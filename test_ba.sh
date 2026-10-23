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

# Select one architecture with FBFISA_TEST_ARCH=arm (default: all four).
run_sample() {
    local arch="$1" sample="$2" variant="$3" manual="$4"
    if [[ "${FBFISA_TEST_ARCH:-all}" != all && "${FBFISA_TEST_ARCH}" != "$arch" ]]; then
        return
    fi
    shift 4
    local binary
    binary=$("$PYTHON" -m elf2bin -f "$SAMPLES_DIR/$arch/$sample" \
        -o "$OUTPUT_DIR/$arch/bin" --print-path)
    echo "[Base address] $arch: $binary"
    "$PYTHON" -m addrsolver.solvers -b "$binary" -v "$variant" -m "$manual" "$@"
}

case "${FBFISA_TEST_ARCH:-all}" in
    all|arm|tricore|powerpc|mips) ;;
    *) echo "FBFISA_TEST_ARCH must be all, arm, tricore, powerpc or mips" >&2; exit 2 ;;
esac

# Forward solver options, e.g. ./test_ba.sh --no-llm --workspace /tmp/ba.
run_sample arm p2im_gateway.elf ARM:LE:32:Cortex '(0x365c, 0x368f)' "$@"
run_sample tricore ASCLIN_Shell_UART_1_KIT_TC297_TFT.elf tricore:LE:32:default '(0, 0)' "$@"
run_sample powerpc 0a2818b49cc0d364dc897328cc0d6e38.elf PowerPC:BE:32:default '(0, 0)' "$@"
run_sample mips 0a890b8cfbfc4ec85d27cdb84e1924c5.elf MIPS:BE:32:default '(0, 0)' "$@"
