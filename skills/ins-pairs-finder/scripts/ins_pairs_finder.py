#!/usr/bin/env python3
"""Extract and verify characteristic instruction pairs from a binary.

Examples::

    python3 ins_pairs_finder.py -f firmware.bin -a ARM --endian LE
    python3 ins_pairs_finder.py -f firmware.elf -a MIPS > temp/pairs.json

The JSON schema is stable and intentionally contains the evidence (hits,
feature checks and optional decoder result), rather than only a final count.
This makes it suitable as input to another skill or to a human review.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .pair_engine import analyze_binary, load_configs
except ImportError:  # direct execution from the scripts directory
    from pair_engine import analyze_binary, load_configs


ALIASES = {
    "ARM32": "ARM", "ARM-CORTEX": "ARM", "ARM-CORTEX-M": "ARM",
    "MIPS32": "MIPS", "PPC": "POWERPC", "PPC32": "POWERPC",
    "RISC-V": "RISCV64", "RISCV": "RISCV64", "RISC-V64": "RISCV64",
    "TRI-CORE": "TRICORE", "TRICORE32": "TRICORE",
}


def _arch(value: str) -> str:
    key = value.strip().upper()
    return ALIASES.get(key, key)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract FBFISADetector block/inner instruction pairs from a binary."
    )
    parser.add_argument("-f", "--file", required=True, help="input .bin/.hex/.elf/.img file")
    parser.add_argument("-a", "--arch", action="append", help="architecture (repeatable; default: all configured architectures)")
    parser.add_argument("--endian", choices=["LE", "BE", "AUTO", "le", "be", "auto"], default="AUTO", help="instruction byte order")
    parser.add_argument("--config-dir", help="JSON architecture file or directory")
    parser.add_argument("--max-hits", type=int, default=0, help="cap hits per instruction (0 means unlimited)")
    parser.add_argument("--max-pairs", type=int, default=0, help="cap pairs per pair definition (0 means unlimited)")
    parser.add_argument("--verify", action="store_true", help="run optional Capstone/pypcode block verification")
    parser.add_argument("--variant", help="decoder variant, for example v7 or RV64GC")
    parser.add_argument("--output", "-o", help="write JSON to this path (prefer ./temp for transient output)")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    parser.add_argument("--text", action="store_true", help="print a concise human-readable report instead of JSON")
    return parser


def _read_input(path: Path, data: bytes | None = None) -> bytes:
    if data is None:
        data = path.read_bytes()
    # Intel HEX is text, unlike the other accepted formats.  Parse records
    # without requiring objcopy so a raw .hex upload remains useful.
    is_hex_text = path.suffix.lower() in {".hex", ".ihex"} or (
        data.startswith(b":") and b"\n" in data[:256]
    )
    if is_hex_text:
        image: dict[int, int] = {}
        base = 0
        for line_number, line in enumerate(data.decode("ascii", errors="strict").splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            if not line.startswith(":"):
                raise ValueError(f"invalid Intel HEX record at line {line_number}")
            raw = bytes.fromhex(line[1:])
            if len(raw) < 5 or raw[0] != len(raw) - 5:
                raise ValueError(f"invalid Intel HEX length at line {line_number}")
            if sum(raw) & 0xFF:
                raise ValueError(f"invalid Intel HEX checksum at line {line_number}")
            length, address, record_type = raw[0], int.from_bytes(raw[1:3], "big"), raw[3]
            payload = raw[4:4 + length]
            if record_type == 0x00:
                for index, value in enumerate(payload):
                    image[base + address + index] = value
            elif record_type == 0x01:
                break
            elif record_type == 0x02 and len(payload) == 2:
                base = int.from_bytes(payload, "big") << 4
            elif record_type == 0x04 and len(payload) == 2:
                base = int.from_bytes(payload, "big") << 16
        if not image:
            return b""
        low, high = min(image), max(image)
        result = bytearray([0xFF]) * (high - low + 1)
        for address, value in image.items():
            result[address - low] = value
        return bytes(result)
    return data


def _text_report(result: dict) -> str:
    lines = [f"input bytes: {result['bytes']}"]
    if not result.get("candidates"):
        return "\n".join(lines + ["no architecture configuration produced a result"])
    for item in result["candidates"]:
        lines.append(
            f"{item['architecture']}:{item['endian']} score={item['score']:.2f} "
            f"blocks={item['blocks']} inner_pairs={item['inner_pairs']} "
            f"verified={item['verified_blocks']}"
        )
    best = result.get("best")
    lines.append("best: " + (f"{best['architecture']}:{best['endian']}" if best else "unknown"))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        input_path = Path(args.file)
        if not input_path.is_file():
            raise FileNotFoundError(input_path)
        binary = _read_input(input_path)
        architectures = [_arch(value) for value in args.arch] if args.arch else None
        result = analyze_binary(
            binary,
            architectures=architectures,
            endian=args.endian,
            config=args.config_dir,
            max_hits=max(0, args.max_hits),
            max_pairs=max(0, args.max_pairs),
            verify=args.verify,
            variant=args.variant,
        )
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"ins-pairs-finder: {exc}", file=sys.stderr)
        return 2

    if args.text:
        output = _text_report(result)
    else:
        output = json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None, sort_keys=not args.pretty)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
