"""Configuration driven instruction-pair extraction.

The original FBFISADetector implementation lives in ``src`` and assumes that
all of its optional reverse-engineering dependencies are installed.  Skills
are often copied to a different workspace, so this module deliberately keeps
the extraction stage dependency free.  Capstone and pypcode are used only
when available for the optional verification stage.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


DEFAULT_CONFIGS: dict[str, dict[str, Any]] = {
    "ARM": {
        "INSTRUCTIONS": {
            "push": {"endian": "BE", "regex": [r"\xb5.", r"\xe9\x2d[\x40-\x5f]."], "format": [r"\xb5\x00", r"\xe9\x2d\x40\x00"], "mask": [r"\xff\x00", r"\xff\xff\xe0\x00"]},
            "pop": {"endian": "BE", "regex": [r"\xbd.", r"\xe8\xbd[\x80-\x9f\xc0-\xdf]."], "format": [r"\xbd\x00", r"\xe8\xbd\x80\x00"], "mask": [r"\xff\x00", r"\xff\xff\xa0\x00"]},
            "cmp": {"endian": "BE", "regex": [r"[\x28-\x2f].", r"[\xf1\xf5][\xb0-\xbf][\x0f\x1f\x2f\x3f\x4f\x5f\x6f\x7f].", r"\x42[\x80-\xbf]", r"\x45.", r"\xeb[\xb0-\xbf][\x0f\x1f\x2f\x3f\x4f\x5f\x6f\x7f]."], "format": [r"\x28\x00", r"\xf1\xb0\x0f\x00", r"\x42\x80", r"\x45\x00", r"\xeb\xb0\x0f\x00"], "mask": [r"\xf8\x00", r"\xfb\xf0\x8f\x00", r"\xff\xc0", r"\xff\x00", r"\xff\xf0\x8f\x00"]},
            "b-it": {"endian": "BE", "regex": [r"[\xd0-\xdf].", r"[\xf0-\xf7].[\x80-\x8f\xc0-\xcf]."], "format": [r"\xd0\x00", r"\xf0\x00\x80\x00"], "mask": [r"\xf0\x00", r"\xf8\x00\xd0\x00"]},
            "bl-func": {"endian": "BE", "regex": [r"[\xf0-\xf7].[\xf0-\xff\xd0-\xdf]."], "format": [r"\xf0\x00\xd0\x00"], "mask": [r"\xf8\x00\xd0\x00"]},
            "mov": {"endian": "BE", "regex": [r"[\x20-\x27].", r"[\xf0\xf4][\x4f\x5f][\x00-\x7f].", r"[\xf2\xf6][\x40-\x4f][\x00-\x7f].", r"\x46.", r"\x00[\x00-\x3f]", r"\xea[\x4f\x5f][\x00-\x0f][\x00-\x0f]"], "format": [r"\x20\x00", r"\xf0\x4f\x00\x00", r"\xf2\x40\x00\x00", r"\x46\x00", r"\x00\x00", r"\xea\x4f\x00\x00"], "mask": [r"\xf8\x00", r"\xfb\xef\x80\x00", r"\xfb\xf0\x80\x00", r"\xff\x00", r"\xff\xc0", r"\xff\xef\xf0\xf0"]},
            "str": {"endian": "BE", "regex": [r"[\x50-\x51].", r"\xf8[\x40-\x4f]..", r"[\x60-\x67].", r"[\x90-\x97].", r"\xf8[\xc0-\xcf]..", r"\xf8[\x40-\x4f].."], "format": [r"\x50\x00", r"\xf8\x40\x00\x00", r"\x60\x00", r"\x90\x00", r"\xf8\xc0\x00\x00", r"\xf8\x40\x08\x00"], "mask": [r"\xfe\x00", r"\xff\xf0\x0f\xc0", r"\xf8\x00", r"\xf8\x00", r"\xff\xf0\x00\x00", r"\xff\xf0\x08\x00"]},
        },
        "PAIRS": {
            "BLOCK_PAIRS": [{"ins": ["push", "pop"], "type": "ARGS_SAVE", "features": {"register": ["push", "pop", "BE", [[r"\x00\xff", r"\x00\x00\x1f\xff"], [r"\x00\xff", r"\x00\x00\x1f\xff"]]]}}],
            "INNER_BLOCK_PAIRS": [{"ins": ["cmp", "b-it"], "type": "IT", "features": {"distance": ["cmp", "b-it", 1]}}],
        },
        "OTHERS": {"MemoryArgs": {"address_length": 4, "reverse_unit_size": 2, "min_instr_length": 2, "max_instr_length": 4, "alignment_size": 2}, "SupportedEndian": "*"},
    },
    "MIPS": {
        "INSTRUCTIONS": {
            "sw-ra": {"endian": "BE", "regex": [r"[\xac-\xaf]..."], "format": [r"\xac\x1f\x00\x00"], "mask": [r"\xfc\x1f\x00\x00"]},
            "addiu-sp-sp-reduce": {"endian": "BE", "regex": [r"\x27\xbd[\x80-\xff]."], "format": [r"\x27\xbd\x80\x00"], "mask": [r"\xff\xff\x80\x00"]},
            "jr-ra": {"endian": "BE", "regex": [r"\x03\xe0\x00\x08"], "format": [r"\x03\xe0\x00\x08"], "mask": [r"\xff\xff\xff\xff"]},
            "bne": {"endian": "BE", "regex": [r"[\x14-\x17]..."], "format": [r"\x14\x00\x00\x00"], "mask": [r"\xfc\x00\x00\x00"]},
            "lw": {"endian": "BE", "regex": [r"[\x8c-\x8f]..."], "format": [r"\x8c\x00\x00\x00"], "mask": [r"\xfc\x00\x00\x00"]},
            "beq": {"endian": "BE", "regex": [r"[\x10-\x13]..."], "format": [r"\x10\x00\x00\x00"], "mask": [r"\xfc\x00\x00\x00"]},
        },
        "PAIRS": {
            "BLOCK_PAIRS": [{"ins": ["addiu-sp-sp-reduce", "jr-ra"], "type": "FUNC-BOUNDARY", "features": {}}],
            "INNER_BLOCK_PAIRS": [
                {"ins": ["lw", "bne"], "type": "IT", "features": {"register": ["lw", "bne", "BE", [[r"\x00\x1f\x00\x00"], [r"\x03\xe0\x00\x00"]]]}},
                {"ins": ["lw", "beq"], "type": "IT", "features": {"register": ["lw", "beq", "BE", [[r"\x00\x1f\x00\x00"], [r"\x03\xe0\x00\x00"]]]}},
            ],
        },
        "OTHERS": {"MemoryArgs": {"address_length": 4, "reverse_unit_size": 4, "min_instr_length": 4, "max_instr_length": 4, "alignment_size": 4}, "SupportedEndian": "*"},
    },
    "POWERPC": {
        "INSTRUCTIONS": {
            "stwu-sp-reduce": {"endian": "BE", "regex": [r"\x94\x21[\x80-\xff]."], "format": [r"\x94\x21\x80\x00"], "mask": [r"\xff\xff\x80\x00"]},
            "blr": {"endian": "BE", "regex": [r"\x4e\x80\x00\x20"], "format": [r"\x4e\x80\x00\x20"], "mask": [r"\xff\xff\xff\xff"]},
            "mfspr-lr": {"endian": "BE", "regex": [r"[\x7c-\x7f][\x08\x28\x48\x68\x88\xa8\xc8\xe8]\x02\xa6"], "format": [r"\x7c\x08\x02\xa6"], "mask": [r"\xfc\x1f\xff\xff"]},
            "mtspr-lr": {"endian": "BE", "regex": [r"[\x7c-\x7f][\x08\x28\x48\x68\x88\xa8\xc8\xe8]\x03\xa6"], "format": [r"\x7c\x08\x03\xa6"], "mask": [r"\xfc\x1f\xff\xff"]},
            "stmw": {"endian": "BE", "regex": [r"[\xbc-\xbf]..."], "format": [r"\xbc\x00\x00\x00"], "mask": [r"\xfc\x00\x00\x00"]},
            "lmw": {"endian": "BE", "regex": [r"[\xb8-\xbb]..."], "format": [r"\xb8\x00\x00\x00"], "mask": [r"\xfc\x00\x00\x00"]},
        },
        "PAIRS": {
            "BLOCK_PAIRS": [{"ins": ["stwu-sp-reduce", "blr"], "type": "FUNC-BOUNDARY", "features": {}}],
            "INNER_BLOCK_PAIRS": [
                {"ins": ["stmw", "lmw"], "type": "ARGS_SAVE", "features": {"register": ["stmw", "lmw", "BE", [[r"\x03\xff\xff\xff"], [r"\x03\xff\xff\xff"]]]}},
                {"ins": ["mfspr-lr", "mtspr-lr"], "type": "ARGS_SAVE", "features": {"register": ["mfspr", "mtspr", "BE", [[r"\x00\x1f\xf8\x00"], [r"\x00\x1f\xf8\x00"]]]}},
            ],
        },
        "OTHERS": {"MemoryArgs": {"address_length": 4, "reverse_unit_size": 4, "min_instr_length": 4, "max_instr_length": 4, "alignment_size": 4}, "SupportedEndian": "*"},
    },
    "RISCV64": {
        "INSTRUCTIONS": {
            "c.addi16sp-reduce": {"endian": "BE", "regex": [r"\x71[\x01\x21\x31\x41\x51\x61\x71\x05-\x0d\x15-\x1d\x25-\x2d\x35-\x3d\x45-\x4d\x55-\x5d\x65-\x6d\x75-\x7d]"], "format": [r"\x71\x01"], "mask": [r"\xff\x83"]},
            "ret": {"endian": "BE", "regex": [r"\x80\x82"], "format": [r"\x80\x82"], "mask": [r"\xff\xff"]},
            "c.li": {"endian": "BE", "regex": [r"[\x40-\x5f][\x01\x05-\x0d\x11\x15-\x1d\x21\x25-\x2d\x31\x35-\x3d\x41\x45-\x4d\x51\x55-\x5d\x61\x65-\x6d\x71\x75-\x7d\x81\x85-\x8d\x91\x95-\x9d\xa1\xa5-\xad\xb1\xb5-\xbd\xc1\xc5-\xcd\xd1\xd5-\xdd\xe1\xe5-\xed\xf1\xf5-\xfd]"], "format": [r"\x40\x01"], "mask": [r"\xe0\x03"]},
            "c.sdsp": {"endian": "BE", "regex": [r"[\xe0-\xff][\x02\x06-\x0e\x12\x16-\x1e\x22\x26-\x2e\x32\x36-\x3e\x42\x46-\x4e\x52\x56-\x5e\x62\x66-\x6e\x72\x76-\x7e\x82\x86-\x8e\x92\x96-\x9e\xa2\xa6-\xae\xb2\xb6-\xbe\xc2\xc6-\xce\xd2\xd6-\xde\xe2\xe6-\xee\xf2\xf6-\xfe]"], "format": [r"\xe0\x02"], "mask": [r"\xe0\x03"]},
            "c.ldsp": {"endian": "BE", "regex": [r"[\x60-\x7f][\x02\x06-\x0e\x12\x16-\x1e\x22\x26-\x2e\x32\x36-\x3e\x42\x46-\x4e\x52\x56-\x5e\x62\x66-\x6e\x72\x76-\x7e\x82\x86-\x8e\x92\x96-\x9e\xa2\xa6-\xae\xb2\xb6-\xbe\xc2\xc6-\xce\xd2\xd6-\xde\xe2\xe6-\xee\xf2\xf6-\xfe]"], "format": [r"\x60\x02"], "mask": [r"\xe0\x03"]},
        },
        "PAIRS": {"BLOCK_PAIRS": [{"ins": ["c.addi16sp-reduce", "ret"], "type": "FUNC-BOUNDARY", "features": {}}], "INNER_BLOCK_PAIRS": [{"ins": ["c.sdsp", "c.ldsp"], "type": "ARGS_SAVE", "features": {"register": ["c.sdsp", "c.ldsp", [[r"\x1f\x80"], [r"\x10\x7d"]]]}}]},
        "OTHERS": {"MemoryArgs": {"address_length": 8, "reverse_unit_size": 8, "min_instr_length": 2, "max_instr_length": 8, "alignment_size": 2}, "SupportedEndian": "LE"},
    },
    "TRICORE": {
        "INSTRUCTIONS": {
            "call-r-func": {"endian": "BE", "regex": [r"...\x6d", r".\x5c"], "format": [r"\x00\x00\x00\x6d", r"\x00\x5c"], "mask": [r"\x00\x00\x00\xff", r"\x00\xff"]},
            "ret": {"endian": "BE", "regex": [r"[\x90-\x9f]\x00"], "format": [r"\x90\x00"], "mask": [r"\xf0\xff"]},
            "rfe": {"endian": "BE", "regex": [r"\x80\x00"], "format": [r"\x80\x00"], "mask": [r"\xff\xff"]},
            "movh.a": {"endian": "BE", "regex": [r"...\x91"], "format": [r"\x00\x00\x00\x91"], "mask": [r"\x00\x00\x00\xff"]},
            "lea": {"endian": "BE", "regex": [r"...\xd9"], "format": [r"\x00\x00\x00\xd9"], "mask": [r"\x00\x00\x00\xff"]},
            "ld.x": {"endian": "BE", "regex": [r"...\x39", r"...\x19"], "format": [r"\x00\x00\x00\x39", r"\x00\x00\x00\x19"], "mask": [r"\x00\x00\x00\xff", r"\x00\x00\x00\xff"]},
            "st.x": {"endian": "BE", "regex": [r"...\xe9", r"...\x59"], "format": [r"\x00\x00\x00\xe9", r"\x00\x00\x00\x59"], "mask": [r"\x00\x00\x00\xff", r"\x00\x00\x00\xff"]},
            "mfcr": {"endian": "BE", "regex": [r"..[\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0]\x4d"], "format": [r"\x00\x00\x00\x4d"], "mask": [r"\x00\x00\x0f\xff"]},
            "sub.a-a10": {"endian": "BE", "regex": [r".\x20"], "format": [r"\x00\x20"], "mask": [r"\x00\xff"]},
            "mov.aa-ax-a4": {"endian": "BE", "regex": [r"[\x40-\x4f]\x40"], "format": [r"\x40\x40"], "mask": [r"\xf0\xff"]},
            "mov-dx-d4": {"endian": "BE", "regex": [r"[\x40-\x4f]\x02"], "format": [r"\x40\x02"], "mask": [r"\xf0\xff"]},
        },
        "PAIRS": {
            "BLOCK_PAIRS": [{"ins": ["mov.aa-ax-a4", "ret"], "type": "FUNC-ARG-PASS", "features": {}}, {"ins": ["mov-dx-d4", "ret"], "type": "FUNC-ARG-PASS", "features": {}}],
            "INNER_BLOCK_PAIRS": [{"ins": ["movh.a", "lea"], "type": "LONG_JMP_EA", "features": {"scope": ["movh.a", "lea", [1, 5]], "register": ["movh.a", "lea", "BE", [[r"\xf0\x00\x00\x00"], [r"\x00\x00\x0f\x00"]]]}}, {"ins": ["movh.a", "ld.x"], "type": "LOAD_DATA", "features": {"distance": ["movh.a", "ld.x", 1], "register": ["movh.a", "ld.x", [[r"\xf0\x00\x00\x00"], [r"\x00\x00\xf0\x00"]]]}}, {"ins": ["movh.a", "st.x"], "type": "STORE_DATA", "features": {"distance": ["movh.a", "st.x", 1], "register": ["movh.a", "st.x", [[r"\xf0\x00\x00\x00"], [r"\x00\x00\xf0\x00"]]]}}],
        },
        "OTHERS": {"MemoryArgs": {"address_length": 4, "reverse_unit_size": 4, "min_instr_length": 2, "max_instr_length": 4, "alignment_size": 2}, "SupportedEndian": "LE"},
    },
}

ARCHITECTURE_ALIASES = {
    "ARM32": "ARM", "ARM-CORTEX": "ARM", "ARM-CORTEX-M": "ARM",
    "MIPS32": "MIPS", "PPC": "POWERPC", "PPC32": "POWERPC",
    "RISCV": "RISCV64", "RISC-V": "RISCV64", "RISC-V64": "RISCV64",
    "TRI-CORE": "TRICORE", "TRICORE32": "TRICORE",
}


@dataclass(frozen=True)
class InstructionHit:
    instruction: str
    offset: int
    end: int
    data: bytes
    pattern_index: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "instruction": self.instruction,
            "offset": self.offset,
            "end": self.end,
            "length": self.end - self.offset,
            "bytes": self.data.hex(),
            "pattern_index": self.pattern_index,
        }


@dataclass
class PairHit:
    architecture: str
    endian: str
    pair_type: str
    head: InstructionHit
    tail: InstructionHit
    features: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)

    @property
    def distance(self) -> int:
        # This is the distance used by the paper/source configuration: an
        # adjacent instruction pair has distance one.
        return self.tail.offset - self.head.end + 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "endian": self.endian,
            "type": self.pair_type,
            "head": self.head.as_dict(),
            "tail": self.tail.as_dict(),
            "distance": self.distance,
            "features": self.features,
            "verification": self.verification,
        }


def _hex_string(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise TypeError(f"expected a byte string, got {type(value).__name__}")
    # Config files use strings such as ``\\xff\\x00``.  Also accept a plain
    # hexadecimal string because it is convenient in user supplied configs.
    if "\\x" in value:
        chunks = re.findall(r"\\x([0-9a-fA-F]{2})", value)
        remainder = re.sub(r"\\x[0-9a-fA-F]{2}", "", value).strip()
        if remainder:
            raise ValueError(f"invalid escaped byte string {value!r}")
        return bytes.fromhex("".join(chunks))
    compact = re.sub(r"\s+", "", value)
    if compact and re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
        return bytes.fromhex(compact)
    return value.encode("latin1")


def _tokenize_pattern(pattern: str) -> list[str]:
    """Tokenize the byte-oriented subset of Python regex used by the configs."""
    # A few legacy configuration files wrote byte values as ``\40`` or
    # ``\4f`` rather than ``\x40``/``\x4f``.  In this byte-pattern format a
    # two-digit hexadecimal escape is unambiguous and should not become a
    # regex backreference or an octal escape.
    pattern = re.sub(r"\\(?!x)([0-9a-fA-F]{2})", r"\\x\1", pattern)
    tokens: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 3 < len(pattern) and pattern[i + 1] == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", pattern[i + 2:i + 4]):
            tokens.append(pattern[i:i + 4]); i += 4; continue
        if c == "[":
            end = i + 1
            escaped = False
            while end < len(pattern):
                if pattern[end] == "]" and not escaped:
                    break
                escaped = pattern[end] == "\\" and not escaped
                if pattern[end] != "\\":
                    escaped = False
                end += 1
            if end >= len(pattern):
                raise ValueError(f"unterminated character class in {pattern!r}")
            tokens.append(pattern[i:end + 1]); i = end + 1; continue
        if c == ".":
            tokens.append("[\\x00-\\xff]"); i += 1; continue
        # A literal ASCII byte.  Configurations are byte patterns, not
        # arbitrary regular expressions; keeping anchors/quantifiers intact
        # would make reversal ambiguous, so reject them with a useful error.
        if c in "*+?{}()|^$":
            raise ValueError(f"unsupported regex operator {c!r} in byte pattern {pattern!r}")
        tokens.append(re.escape(c)); i += 1
    return tokens


def _reverse_pattern(pattern: str, unit: int) -> str:
    tokens = _tokenize_pattern(pattern)
    if not tokens:
        return pattern
    unit = min(max(1, unit), len(tokens))
    if len(tokens) % unit:
        # Match the source behaviour: malformed/non-aligned patterns are left
        # untouched instead of silently changing their length.
        return pattern.replace(".", "[\\x00-\\xff]")
    return "".join("".join(tokens[i:i + unit][::-1]) for i in range(0, len(tokens), unit))


def _pattern_bytes(pattern: str, reverse: bool, reverse_unit: int) -> re.Pattern[bytes]:
    text = _reverse_pattern(pattern, reverse_unit) if reverse else "".join(_tokenize_pattern(pattern))
    # Turn \xNN escapes into literal bytes while retaining classes and regex
    # syntax.  ``re`` accepts escaped non-ASCII bytes in a bytes pattern.
    raw = text.encode("latin1")
    while True:
        match = re.search(rb"\\x([0-9a-fA-F]{2})", raw)
        if not match:
            break
        byte = bytes([int(match.group(1), 16)])
        # A byte which is meaningful to the regular-expression parser must
        # remain a literal byte.  Backslash is especially easy to miss here:
        # TriCore's ``.\\x5c`` pattern is a real backslash byte, not the start
        # of another regex escape.
        regex_meta = b".*?+-|^$()[]{}\\\\"
        raw = raw[:match.start()] + (b"\\" + byte if byte in regex_meta else byte) + raw[match.end():]
    return re.compile(raw)


def _reverse_chunks(data: bytes, unit: int) -> bytes:
    if not data:
        return data
    unit = min(max(1, unit), len(data))
    if len(data) <= unit:
        return data[::-1]
    out = bytearray()
    for start in range(0, len(data), unit):
        chunk = data[start:start + unit]
        out.extend(chunk[::-1] if len(chunk) == unit else chunk)
    return bytes(out)


def _compile_instruction_variants(info: Mapping[str, Any], endian: str, reverse_unit: int) -> list[tuple[re.Pattern[bytes], bytes, bytes, int]]:
    regexes = info.get("regex", [])
    formats = info.get("format", [])
    masks = info.get("mask", [])
    if not (len(regexes) == len(formats) == len(masks)):
        raise ValueError("instruction regex/format/mask lists must have equal lengths")
    result = []
    source_endian = str(info.get("endian", "BE")).upper()
    reverse = source_endian != endian.upper()
    for index, (regex, fmt, mask) in enumerate(zip(regexes, formats, masks)):
        fmt_b, mask_b = _hex_string(fmt), _hex_string(mask)
        if reverse:
            fmt_b, mask_b = _reverse_chunks(fmt_b, reverse_unit), _reverse_chunks(mask_b, reverse_unit)
        result.append((_pattern_bytes(str(regex), reverse, reverse_unit), fmt_b, mask_b, index))
    return result


def _masked_equal(data: bytes, fmt: bytes, mask: bytes) -> bool:
    return len(data) == len(fmt) == len(mask) and bytes(a & b for a, b in zip(data, mask)) == fmt


def find_instruction_hits(binary: bytes, name: str, info: Mapping[str, Any], endian: str, reverse_unit: int, max_hits: int = 0) -> list[InstructionHit]:
    hits: dict[tuple[int, int, bytes], InstructionHit] = {}
    for regex, fmt, mask, pattern_index in _compile_instruction_variants(info, endian, reverse_unit):
        for match in regex.finditer(binary):
            # A broad regex can also match when started at an interior byte.
            # Check all such starts, as the reference implementation does.
            width = len(mask)
            for shift in range(width):
                start = match.start() + shift
                end = start + width
                if end > len(binary):
                    break
                data = binary[start:end]
                if regex.match(data) and _masked_equal(data, fmt, mask):
                    hit = InstructionHit(name, start, end, data, pattern_index)
                    hits[(start, end, data)] = hit
                    if max_hits and len(hits) >= max_hits:
                        return sorted(hits.values(), key=lambda x: (x.offset, x.end))
    return sorted(hits.values(), key=lambda x: (x.offset, x.end))


def _bit_value(data: bytes, mask: bytes) -> int:
    bits: list[str] = []
    # Same bit ordering as fbfisa.utils.bytes_op.get_register_num.
    for index in range(len(mask) * 8):
        byte_index = len(mask) - 1 - index // 8
        bit = index % 8
        if (mask[byte_index] >> bit) & 1:
            bits.append(str((data[byte_index] >> bit) & 1))
    return int("".join(bits), 2) if bits else 0


def _mask_sets(value: Any) -> list[list[bytes]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or len(value) < 2:
        return [[], []]
    result: list[list[bytes]] = []
    for group in value[:2]:
        if isinstance(group, (str, bytes)):
            group = [group]
        result.append([_hex_string(x) for x in group])
    return result


def _register_feature_ok(head: InstructionHit, tail: InstructionHit, feature: Sequence[Any], target_endian: str, reverse_unit: int) -> bool:
    if len(feature) < 3:
        return True
    mask_endian = target_endian.upper()
    masks_spec = feature[-1]
    if len(feature) >= 4 and isinstance(feature[-2], str):
        mask_endian = feature[-2].upper()
    mask_groups = _mask_sets(masks_spec)
    if len(mask_groups) < 2:
        return True
    for hmask in mask_groups[0] or [b""]:
        if len(hmask) != len(head.data):
            continue
        for tmask in mask_groups[1] or [b""]:
            if len(tmask) != len(tail.data):
                continue
            hdata, tdata = head.data, tail.data
            current_hmask, current_tmask = hmask, tmask
            if target_endian.upper() != mask_endian:
                # Normalize the value and mask to the mask's declared byte
                # order.  A BE mask applied to LE bytes requires reversing the
                # bytes; an LE mask applied to BE bytes requires reversing the
                # mask.  Reversing both would compare unrelated bit fields.
                if mask_endian == "BE":
                    hdata = _reverse_chunks(hdata, reverse_unit)
                    tdata = _reverse_chunks(tdata, reverse_unit)
                else:
                    current_hmask = _reverse_chunks(current_hmask, reverse_unit)
                    current_tmask = _reverse_chunks(current_tmask, reverse_unit)
            if _bit_value(hdata, current_hmask) == _bit_value(tdata, current_tmask):
                return True
    return False


def _feature_ok(head: InstructionHit, tail: InstructionHit, features: Mapping[str, Any], endian: str, reverse_unit: int) -> tuple[bool, dict[str, Any]]:
    details: dict[str, Any] = {}
    for key, feature in (features or {}).items():
        key_l = str(key).lower()
        if key_l == "register":
            ok = _register_feature_ok(head, tail, feature, endian, reverse_unit)
            details["register"] = ok
        elif key_l == "distance":
            expected = feature[-1] if isinstance(feature, Sequence) and feature else feature
            ok = tail.offset - head.end + 1 == int(expected)
            details["distance"] = {"expected": int(expected), "actual": tail.offset - head.end + 1, "ok": ok}
        elif key_l == "scope":
            scope = feature[-1] if isinstance(feature, Sequence) and feature else feature
            low, high = int(scope[0]), int(scope[1])
            actual = tail.offset - head.end + 1
            ok = low <= actual <= high
            details["scope"] = {"expected": [low, high], "actual": actual, "ok": ok}
        elif key_l in {"frequency", "count"}:
            # Frequency is a block-level relation and is checked by callers;
            # preserving it here makes custom configurations explainable.
            details[key_l] = {"configured": feature, "ok": True}
        else:
            details[key_l] = {"configured": feature, "ok": True, "note": "unknown feature ignored"}
        value = details[key_l]
        if isinstance(value, bool) and not value:
            return False, details
        if isinstance(value, Mapping) and value.get("ok") is False:
            return False, details
    return True, details


def create_pairs(heads: Sequence[InstructionHit], tails: Sequence[InstructionHit], *, architecture: str, endian: str, pair_type: str, features: Mapping[str, Any] | None, alignment: int, min_instruction_length: int, reverse_unit: int | None = None, max_pairs: int = 0) -> list[PairHit]:
    # The reference implementation groups hits by the effective instruction
    # alignment.  A configuration may provide an alignment smaller than its
    # minimum instruction length, so use the larger of the two values.
    alignment = max(1, int(alignment or 1), int(min_instruction_length or 1))
    by_residue: dict[int, list[tuple[InstructionHit, bool]]] = {}
    for hit in heads:
        by_residue.setdefault(hit.offset % alignment, []).append((hit, True))
    for hit in tails:
        by_residue.setdefault(hit.offset % alignment, []).append((hit, False))
    result: list[PairHit] = []
    seen: set[tuple[int, int, str]] = set()
    for entries in by_residue.values():
        entries.sort(key=lambda x: (x[0].offset, x[0].end, not x[1]))
        current_head: InstructionHit | None = None
        for hit, is_head in entries:
            if is_head:
                current_head = hit
                continue
            if current_head is None or hit.offset < current_head.end:
                continue
            key = (current_head.offset, hit.offset, pair_type)
            if key in seen:
                continue
            ok, feature_details = _feature_ok(current_head, hit, features or {}, endian, max(1, reverse_unit or min_instruction_length))
            if ok:
                result.append(PairHit(architecture, endian, pair_type, current_head, hit, feature_details))
                seen.add(key)
                if max_pairs and len(result) >= max_pairs:
                    return sorted(result, key=lambda x: (x.head.offset, x.tail.offset, x.pair_type))
            # A tail closes the current function-boundary candidate, even if a
            # feature rejected it, matching the source algorithm's one-to-one
            # pairing rule.
            current_head = None
    return sorted(result, key=lambda x: (x.head.offset, x.tail.offset, x.pair_type))


def _language_candidates(architecture: str, endian: str, variant: str | None = None) -> list[str]:
    arch = architecture.upper()
    if arch == "ARM":
        return [f"ARM:{endian}:32:{variant or 'v7'}"]
    if arch == "MIPS":
        return [f"MIPS:{endian}:32:{variant or 'default'}"]
    if arch == "POWERPC":
        return [f"PowerPC:{endian}:32:{variant or 'default'}"]
    if arch == "TRICORE":
        return [f"tricore:{endian}:32:{variant or 'default'}"]
    if arch in {"RISCV", "RISCV64", "RISC-V", "RISC-V64"}:
        return [f"RISCV:{endian}:64:{variant or 'RV64GC'}"]
    return []


def verify_bytes(code: bytes, architecture: str, endian: str, *, variant: str | None = None, base_address: int = 0) -> dict[str, Any]:
    """Try Capstone first and pypcode second, without making either required."""
    if not code:
        return {"status": "failed", "reason": "empty block", "decoded_bytes": 0, "instruction_count": 0}
    try:
        import capstone  # type: ignore
        arch = architecture.upper()
        if arch == "ARM":
            cs_arch, mode = capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB
        elif arch == "MIPS":
            cs_arch, mode = capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32
        elif arch == "POWERPC":
            cs_arch, mode = capstone.CS_ARCH_PPC, getattr(capstone, "CS_MODE_32", 4)
        elif arch == "TRICORE":
            cs_arch, mode = capstone.CS_ARCH_TRICORE, getattr(capstone, "CS_MODE_TRICORE_162", 0)
        elif arch in {"RISCV", "RISCV64", "RISC-V", "RISC-V64"}:
            cs_arch, mode = capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 | getattr(capstone, "CS_MODE_RISCVC", 0)
        else:
            raise ValueError("unsupported architecture")
        if endian.upper() == "BE":
            mode |= getattr(capstone, "CS_MODE_BIG_ENDIAN", 0)
        # ARM blocks can contain either Thumb or ARM-state instructions.  Try
        # Thumb first (the common Cortex-M case), then ARM state before falling
        # through to pypcode.
        modes = [mode]
        if arch == "ARM":
            arm_mode = getattr(capstone, "CS_MODE_ARM", 0)
            if endian.upper() == "BE":
                arm_mode |= getattr(capstone, "CS_MODE_BIG_ENDIAN", 0)
            modes.append(arm_mode)
        partial: dict[str, Any] | None = None
        for current_mode in modes:
            md = capstone.Cs(cs_arch, current_mode)
            decoded = list(md.disasm(code, base_address))
            covered = sum(int(ins.size) for ins in decoded)
            if decoded and covered == len(code):
                return {"status": "verified", "engine": "capstone", "mode": current_mode, "decoded_bytes": covered, "instruction_count": len(decoded), "instructions": [{"address": int(i.address), "size": int(i.size), "mnemonic": i.mnemonic, "op_str": i.op_str} for i in decoded[:64]]}
            if decoded and partial is None:
                partial = {"status": "partial", "engine": "capstone", "mode": current_mode, "decoded_bytes": covered, "instruction_count": len(decoded)}
        # Keep a partial Capstone result as a fallback, but still try pypcode:
        # pypcode understands some compressed/delay-slot forms that Capstone
        # may stop before covering completely.
    except Exception as exc:
        capstone_error = str(exc)
    else:
        capstone_error = ""
    try:
        import pypcode  # type: ignore
        for language in _language_candidates(architecture, endian, variant):
            try:
                disassembly = pypcode.Context(language).disassemble(code, base_address=base_address)
                instructions = list(disassembly.instructions)
                covered = sum(int(i.length) for i in instructions)
                if instructions and covered == len(code):
                    ir_info: dict[str, Any] = {"status": "unavailable", "op_count": 0}
                    try:
                        translation = pypcode.Context(language).translate(code, base_address=base_address)
                        ir_info = {"status": "verified" if translation.ops else "failed", "op_count": len(translation.ops)}
                    except Exception as exc:
                        ir_info = {"status": "failed", "op_count": 0, "reason": str(exc)}
                    return {"status": "verified", "engine": "pypcode", "language": language, "decoded_bytes": covered, "instruction_count": len(instructions), "ir": ir_info, "instructions": [{"address": int(i.addr.offset), "size": int(i.length), "mnemonic": i.mnem, "body": i.body} for i in instructions[:64]]}
                if instructions:
                    return {"status": "partial", "engine": "pypcode", "language": language, "decoded_bytes": covered, "instruction_count": len(instructions)}
            except Exception:
                continue
    except Exception:
        pass
    if partial is not None:
        return partial
    return {"status": "unavailable", "reason": locals().get("capstone_error", "no decoder installed"), "decoded_bytes": 0, "instruction_count": 0}


def _candidate_config_paths(config: str | Path | None) -> list[Path]:
    if config:
        path = Path(config)
        if path.is_dir():
            return sorted(path.glob("*.json"))
        return [path]
    here = Path(__file__).resolve()
    repo_root = here.parents[3] if len(here.parents) > 3 else None
    paths: list[Path] = []
    if repo_root:
        paths.extend(sorted((repo_root / "src/fbfisa/config/arch").glob("*.json")))
    return [p for p in paths if p.is_file()]


def load_configs(config: str | Path | None = None) -> dict[str, dict[str, Any]]:
    paths = _candidate_config_paths(config)
    if paths:
        loaded: dict[str, dict[str, Any]] = {}
        for path in paths:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                name = path.stem.upper()
                if name == "RISCV64":
                    name = "RISCV64"
                loaded[name] = data
            except (OSError, json.JSONDecodeError):
                continue
        if loaded:
            return loaded
    return json.loads(json.dumps(DEFAULT_CONFIGS))


def _supported_endians(config: Mapping[str, Any], requested: str | None) -> list[str]:
    if requested and requested.upper() != "AUTO":
        return [requested.upper()]
    value = str(config.get("OTHERS", {}).get("SupportedEndian", "*")).upper()
    return ["LE", "BE"] if value == "*" else [value]


def analyze_binary(binary: bytes, *, architectures: Iterable[str] | None = None, endian: str | None = None, config: str | Path | None = None, max_hits: int = 0, max_pairs: int = 0, verify: bool = False, variant: str | None = None) -> dict[str, Any]:
    configs = load_configs(config)
    selected = [ARCHITECTURE_ALIASES.get(str(a).strip().upper(), str(a).strip().upper()) for a in architectures] if architectures else list(configs)
    results: list[dict[str, Any]] = []
    for architecture in selected:
        cfg = configs.get(architecture)
        if not cfg:
            continue
        memory = cfg.get("OTHERS", {}).get("MemoryArgs", {})
        reverse_unit = int(memory.get("reverse_unit_size", 1) or 1)
        min_len = int(memory.get("min_instr_length", reverse_unit) or reverse_unit)
        alignment = int(memory.get("alignment_size", min_len) or min_len)
        for current_endian in _supported_endians(cfg, endian):
            instruction_hits: dict[str, list[InstructionHit]] = {}
            for name, info in cfg.get("INSTRUCTIONS", {}).items():
                try:
                    instruction_hits[name] = find_instruction_hits(binary, name, info, current_endian, reverse_unit, max_hits=max_hits)
                except (TypeError, ValueError, re.error) as exc:
                    instruction_hits[name] = []
            block_pairs: list[PairHit] = []
            for definition in cfg.get("PAIRS", {}).get("BLOCK_PAIRS", []):
                names = definition.get("ins", [])
                if len(names) != 2:
                    continue
                block_pairs.extend(create_pairs(instruction_hits.get(names[0], []), instruction_hits.get(names[1], []), architecture=architecture, endian=current_endian, pair_type=str(definition.get("type", "BLOCK")), features=definition.get("features", {}), alignment=alignment, min_instruction_length=min_len, reverse_unit=reverse_unit, max_pairs=max_pairs))
            inner_pairs: list[PairHit] = []
            for definition in cfg.get("PAIRS", {}).get("INNER_BLOCK_PAIRS", []):
                names = definition.get("ins", [])
                if len(names) != 2:
                    continue
                inner_pairs.extend(create_pairs(instruction_hits.get(names[0], []), instruction_hits.get(names[1], []), architecture=architecture, endian=current_endian, pair_type=str(definition.get("type", "INNER")), features=definition.get("features", {}), alignment=alignment, min_instruction_length=min_len, reverse_unit=reverse_unit, max_pairs=max_pairs))
            # The paper's second filter asks whether an inner pair occurs
            # *inside* a candidate block.  Keep all matches for evidence, but
            # calculate the block count only from contained matches.
            inner_by_block: dict[int, list[PairHit]] = {}
            for block_index, block in enumerate(block_pairs):
                contained = [p for p in inner_pairs if p.head.offset >= block.head.offset and p.tail.end <= block.tail.end]
                if contained:
                    inner_by_block[block_index] = contained
            if verify:
                for pair in block_pairs:
                    pair.verification = verify_bytes(binary[pair.head.offset:pair.tail.end], architecture, current_endian, variant=variant, base_address=pair.head.offset)
            verified = sum(1 for p in block_pairs if p.verification.get("status") == "verified")
            inner_pair_blocks = len(inner_by_block)
            structural = len(block_pairs) * 3 + inner_pair_blocks * 2
            score = float(structural + verified * 4)
            results.append({
                "architecture": architecture,
                "endian": current_endian,
                "score": score,
                "blocks": len(block_pairs),
                "inner_pairs": len(inner_pairs),
                "inner_pair_blocks": inner_pair_blocks,
                "verified_blocks": verified,
                "verification_rate": verified / len(block_pairs) if block_pairs else 0.0,
                "instruction_hits": {name: len(hits) for name, hits in instruction_hits.items() if hits},
                "pairs": [dict(p.as_dict(), inner_pairs=[q.as_dict() for q in inner_by_block.get(index, [])]) for index, p in enumerate(block_pairs)],
                "inner_pair_details": [p.as_dict() for p in inner_pairs],
                "config_source": "repository-or-bundled",
            })
    results.sort(key=lambda item: (-item["score"], -item["verified_blocks"], -item["inner_pairs"], item["architecture"], item["endian"]))
    best = results[0] if results and results[0]["score"] > 0 else None
    return {"schema_version": "1.0", "bytes": len(binary), "candidates": results, "best": best}
