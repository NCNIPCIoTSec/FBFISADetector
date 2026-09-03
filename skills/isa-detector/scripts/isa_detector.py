#!/usr/bin/env python3
"""Evidence-based ISA and firmware-type detection.

This is the executable companion to the ``isa-detector`` skill.  It keeps the
usual analyst workflow (binwalk -> ELF/tool metadata -> instruction-pair
analysis) deterministic and machine-readable.  A missing optional utility is
reported as evidence rather than treated as a fatal error.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

# ``isa-detector/scripts`` and ``ins-pairs-finder/scripts`` are sibling
# directories.  Import by path so both direct execution and copied skills work
# without requiring a package install.
_PAIR_SCRIPT_DIR = Path(__file__).resolve().parents[2] / "ins-pairs-finder" / "scripts"
if not _PAIR_SCRIPT_DIR.is_dir():
    _PAIR_SCRIPT_DIR = Path(__file__).resolve().parents[3] / "skills" / "ins-pairs-finder" / "scripts"
if str(_PAIR_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_PAIR_SCRIPT_DIR))
try:
    from pair_engine import analyze_binary  # type: ignore
    from ins_pairs_finder import _read_input  # type: ignore
except ImportError:  # pragma: no cover - only reached for a broken copy
    analyze_binary = None

    def _read_input(path: Path, data: bytes | None = None) -> bytes:
        return path.read_bytes() if data is None else data


ARCH_ALIASES = {
    "ARM32": "ARM", "ARM-CORTEX": "ARM", "ARM-CORTEX-M": "ARM",
    "AARCH64": "AARCH64", "ARM64": "AARCH64",
    "MIPS32": "MIPS", "MIPS64": "MIPS", "PPC": "POWERPC", "PPC32": "POWERPC", "PPC64": "POWERPC",
    "RISCV": "RISCV64", "RISC-V": "RISCV64", "RISC-V64": "RISCV64", "RISCV64": "RISCV64",
    "TRI-CORE": "TRICORE", "TRICORE32": "TRICORE",
}

# ELF e_machine values.  Keep unknown values in the raw metadata so adding an
# architecture later does not destroy useful information.
ELF_MACHINES = {
    3: "X86", 8: "MIPS", 10: "MIPS", 20: "POWERPC", 21: "POWERPC",
    40: "ARM", 43: "SPARC", 44: "TRICORE", 62: "X86_64", 183: "AARCH64",
    243: "RISCV64", 247: "BPF",
}
ELF_MACHINE_NAMES = {
    "EM_ARM": "ARM", "EM_AARCH64": "AARCH64", "EM_MIPS": "MIPS", "EM_MIPS_RS3_LE": "MIPS",
    "EM_PPC": "POWERPC", "EM_PPC64": "POWERPC", "EM_TRICORE": "TRICORE", "EM_RISCV": "RISCV64",
    "EM_386": "X86", "EM_X86_64": "X86_64", "EM_SPARC": "SPARC", "EM_BPF": "BPF",
}
PAIR_ARCHITECTURES = {"ARM", "MIPS", "POWERPC", "RISCV64", "TRICORE"}

# pyelftools exposes ``e_machine`` as a symbolic string on some releases and
# as an enum-like value on others.  Keep the numeric value available in the
# report regardless of which version is installed.
ELF_MACHINE_CODES = {
    "EM_NONE": 0,
    "EM_386": 3,
    "EM_MIPS": 8,
    "EM_MIPS_RS3_LE": 10,
    "EM_PPC": 20,
    "EM_PPC64": 21,
    "EM_ARM": 40,
    "EM_SPARC": 43,
    "EM_TRICORE": 44,
    "EM_X86_64": 62,
    "EM_AARCH64": 183,
    "EM_RISCV": 243,
    "EM_BPF": 247,
}

CONTAINER_SIGNATURES = (
    (b"\x1f\x8b", "gzip compressed data"),
    (b"BZh", "bzip2 compressed data"),
    (b"\xfd7zXZ\x00", "XZ compressed data"),
    (b"(\xb5/\xfd", "Zstandard compressed data"),
    (b"\x04\x22\x4d\x18", "LZ4 compressed data"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"UBI#", "UBI image"),
    (b"hsqs", "SquashFS filesystem"),
    (b"sqsh", "SquashFS filesystem"),
    (b"070701", "cpio archive"),
    (b"070702", "cpio archive"),
    (b"\xed\x26\xff\x3a", "Android sparse image"),
)

CONTAINER_FILE_MARKERS = (
    "compressed",
    "archive",
    "filesystem",
    "squashfs",
    "gzip",
    "bzip",
    "zip archive",
    "7-zip",
    "rar archive",
    "xz",
    "lzma",
    "zstandard",
    "lz4",
    "ubifs",
    "ubi image",
    "sparse image",
    "cpio",
    "tar archive",
)


def _canonical_arch(value: str | None) -> str | None:
    if value is None:
        return None
    key = str(value).strip().upper().replace(" ", "")
    return ARCH_ALIASES.get(key, key)


def _clip(text: str, limit: int = 12000) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"


def _run(command: list[str], *, timeout: float = 20.0, text: bool = True) -> dict[str, Any]:
    name = command[0] if command else ""
    if not command or shutil.which(name) is None:
        return {"command": command, "available": False, "returncode": None, "stdout": "", "stderr": f"{name or 'command'} not found"}
    try:
        completed = subprocess.run(command, capture_output=True, text=text, timeout=timeout, check=False)
        stdout = completed.stdout if isinstance(completed.stdout, str) else completed.stdout.decode("utf-8", "replace")
        stderr = completed.stderr if isinstance(completed.stderr, str) else completed.stderr.decode("utf-8", "replace")
        return {"command": command, "available": True, "returncode": completed.returncode, "stdout": _clip(stdout), "stderr": _clip(stderr)}
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        err = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
        return {"command": command, "available": True, "returncode": None, "timeout": timeout, "stdout": _clip(out), "stderr": _clip(err + "\ncommand timed out")}
    except OSError as exc:
        return {"command": command, "available": True, "returncode": None, "stdout": "", "stderr": str(exc)}


def _looks_like_elf(data: bytes) -> bool:
    return data.startswith(b"\x7fELF")


def _parse_elf_header_fallback(path: Path, error: Exception | None = None) -> dict[str, Any]:
    """Read the portable part of an ELF header without pyelftools.

    Section/segment details remain unavailable in this fallback, but the
    machine, class and byte order are still authoritative and preferable to a
    heuristic scan of the ELF container.
    """
    data = path.read_bytes()
    if not _looks_like_elf(data) or len(data) < 20:
        return {"is_elf": False, "architecture": None, "machine": None, "machine_code": None, "bits": None, "endian": None, "entry": None, "sections": [], "executable_sections": [], "segments": [], "symbols": {}, "error": str(error) if error else "invalid ELF header"}
    class_id, data_id = data[4], data[5]
    if class_id not in (1, 2) or data_id not in (1, 2):
        return {"is_elf": False, "architecture": None, "machine": None, "machine_code": None, "bits": None, "endian": None, "entry": None, "sections": [], "executable_sections": [], "segments": [], "symbols": {}, "error": "unsupported ELF class or data encoding"}
    byte_order = "<" if data_id == 1 else ">"
    machine_code = struct.unpack_from(byte_order + "H", data, 18)[0]
    machine_name = next((name for name, code in ELF_MACHINE_CODES.items() if code == machine_code), f"EM_{machine_code}")
    if class_id == 1:
        entry = struct.unpack_from(byte_order + "I", data, 24)[0] if len(data) >= 28 else 0
        flags_offset = 36
    else:
        entry = struct.unpack_from(byte_order + "Q", data, 24)[0] if len(data) >= 32 else 0
        flags_offset = 48
    flags = struct.unpack_from(byte_order + "I", data, flags_offset)[0] if len(data) >= flags_offset + 4 else 0
    result: dict[str, Any] = {
        "is_elf": True,
        "architecture": ELF_MACHINES.get(machine_code) or ELF_MACHINE_NAMES.get(machine_name),
        "machine": machine_name,
        "machine_code": machine_code,
        "bits": 32 if class_id == 1 else 64,
        "endian": "LE" if data_id == 1 else "BE",
        "entry": entry,
        "flags": flags,
        "os_abi": f"ELFOSABI_{data[7]}",
        "type": str(struct.unpack_from(byte_order + "H", data, 16)[0]) if len(data) >= 18 else "unknown",
        "sections": [],
        "executable_sections": [],
        "segments": [],
        "symbols": {},
        "parser": "header-fallback",
    }
    if error:
        result["parser_error"] = str(error)
    return result


def _parse_elf(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"is_elf": False, "architecture": None, "machine": None, "machine_code": None, "bits": None, "endian": None, "entry": None, "sections": [], "executable_sections": [], "segments": [], "symbols": {}}
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            machine_value = elf.header.get("e_machine", 0)
            machine_code = getattr(machine_value, "value", None)
            if machine_code is None:
                try:
                    machine_code = int(machine_value)
                except (TypeError, ValueError):
                    machine_code = ELF_MACHINE_CODES.get(str(machine_value))
            info.update({
                "is_elf": True,
                "machine": str(machine_value),
                "machine_code": machine_code,
                "bits": int(elf.elfclass),
                "endian": "LE" if elf.little_endian else "BE",
                "entry": int(elf.header.get("e_entry", 0)),
                "os_abi": str(elf.header.get("e_ident", {}).get("EI_OSABI", "unknown")),
                "type": str(elf.header.get("e_type", "unknown")),
                "flags": int(elf.header.get("e_flags", 0)),
                "parser": "pyelftools",
            })
            info["architecture"] = ELF_MACHINES.get(info["machine_code"]) or ELF_MACHINE_NAMES.get(str(machine_value))
            for section in elf.iter_sections():
                flags = int(section.header.get("sh_flags", 0))
                record = {"name": section.name, "type": str(section.header.get("sh_type")), "offset": int(section.header.get("sh_offset", 0)), "size": int(section.header.get("sh_size", 0)), "address": int(section.header.get("sh_addr", 0)), "flags": flags, "executable": bool(flags & 0x4)}
                info["sections"].append(record)
                if record["executable"] and record["size"]:
                    info["executable_sections"].append(record)
                if section.name in {".symtab", ".dynsym"}:
                    try:
                        counts = Counter(str(symbol.entry.get("st_info", {}).get("type", "UNKNOWN")) for symbol in section.iter_symbols() if symbol.name)
                        info["symbols"].update({key.lower(): int(value) for key, value in counts.items()})
                    except Exception:
                        continue
            for segment in elf.iter_segments():
                record = {"type": str(segment.header.get("p_type")), "offset": int(segment.header.get("p_offset", 0)), "filesz": int(segment.header.get("p_filesz", 0)), "memsz": int(segment.header.get("p_memsz", 0)), "vaddr": int(segment.header.get("p_vaddr", 0)), "flags": int(segment.header.get("p_flags", 0))}
                info["segments"].append(record)
    except Exception as exc:
        # Preserve the authoritative header when pyelftools is unavailable or
        # a damaged section table prevents a full parse.
        return _parse_elf_header_fallback(path, exc)
    return info


def _parse_readelf_header(output: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower().replace(" ", "_")
        result[key] = value.strip()
    return result


def _extract_tool_architecture(tool_outputs: dict[str, Any]) -> list[str]:
    text = "\n".join(str(item.get("stdout", "")) for item in tool_outputs.values())
    lowered = text.lower()
    found: list[str] = []
    patterns = [
        (r"\barm\s*(?:v?\d|cortex|thumb|aarch32)\b|\barm\b", "ARM"),
        (r"aarch64|arm64", "AARCH64"), (r"mips(?:el|64)?", "MIPS"),
        (r"powerpc|ppc", "POWERPC"), (r"risc[- ]?v|riscv", "RISCV64"),
        (r"tricore|tc1[0-9]+", "TRICORE"),
    ]
    for pattern, arch in patterns:
        if re.search(pattern, lowered) and arch not in found:
            found.append(arch)
    return found


def _firmware_class(*, file_type: str, strings: str, elf: dict[str, Any], tool_text: str) -> tuple[str, list[str]]:
    haystack = "\n".join((file_type, strings, tool_text, str(elf.get("os_abi", "")))).lower()
    evidence: list[str] = []
    if any(marker in file_type.lower() for marker in CONTAINER_FILE_MARKERS) and not elf.get("is_elf"):
        evidence.append("container signature takes precedence over payload strings")
        return "compressed/archive/container (payload not classified)", evidence
    # A bare ``kernel`` string is not Linux-specific: RTOS images commonly
    # contain phrases such as "RIOT kernel panic".  Require a Linux/runtime
    # marker that identifies the userland or the OS name instead.
    linux_markers = ["gnu/linux", "linux", "busybox", "glibc", "uclibc", "ld-uclibc", "/lib/ld", "/etc/", "/sbin/", "/bin/sh", "kernel.org", "linux kernel", "squashfs", "ext2", "ext3", "ext4", "initramfs"]
    rtos_markers = ["freertos", "free rtos", "riot-os", "riot kernel", "zephyr", "threadx", "nuttx", "vxworks", "rt-thread", "embos", "u cos", "rtos"]
    bare_markers = ["isr_vector", "reset_handler", "startup", "cortex-m", "stm32", "nrf52", "bare metal", "__libc_init_array"]
    linux_hits = [marker for marker in linux_markers if marker in haystack]
    rtos_hits = [marker for marker in rtos_markers if marker in haystack]
    bare_hits = [marker for marker in bare_markers if marker in haystack]
    if rtos_hits:
        evidence.extend(f"RTOS marker: {marker}" for marker in rtos_hits[:8])
        return "RTOS firmware", evidence
    if linux_hits:
        evidence.extend(f"linux marker: {marker}" for marker in linux_hits[:8])
        return "Linux firmware", evidence
    os_abi = str(elf.get("os_abi", "")).lower()
    if bare_hits or (elf.get("is_elf") and elf.get("executable_sections") and os_abi not in {"elfosabi_linux", "linux"}):
        evidence.extend(f"bare-metal marker: {marker}" for marker in bare_hits[:8])
        if elf.get("executable_sections"):
            evidence.append("ELF has executable sections without an explicit Linux marker")
        return "bare-metal firmware", evidence
    if elf.get("is_elf"):
        evidence.append("ELF executable/object without enough OS markers")
        return "firmware/embedded executable (OS unknown)", evidence
    return "unknown", evidence


def _file_type(path: Path, file_result: dict[str, Any], data: bytes) -> str:
    if path.suffix.lower() in {".hex", ".ihex"}:
        return "Intel HEX text"
    if data.startswith(b"\x7fELF"):
        description = str(file_result.get("stdout", "")).strip()
        return description or "ELF binary"
    if data.startswith(b":") and b"\n" in data[:256]:
        return "Intel HEX text"
    for magic, label in CONTAINER_SIGNATURES:
        if data.startswith(magic):
            return label
    # ``ustar`` is conventionally found at offset 257 in tar members.
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar archive"
    description = str(file_result.get("stdout", "")).strip()
    if description and description.lower() not in {"data", "application/octet-stream", "binary data"}:
        return description
    return "raw binary data"


def _is_top_level_container(*, file_type: str, data: bytes, binwalk_text: str = "") -> bool:
    """Return whether the input itself is a container rather than a firmware image.

    Binwalk may report compressed members embedded in an otherwise valid image;
    those do not make the complete input non-code.  Only signatures at offset
    zero (or the file utility's top-level description) suppress pair analysis.
    """
    lowered = file_type.lower()
    if any(marker in lowered for marker in CONTAINER_FILE_MARKERS):
        return True
    if any(data.startswith(magic) for magic, _ in CONTAINER_SIGNATURES):
        return True
    if len(data) >= 262 and data[257:262] == b"ustar":
        return True
    first_line = (binwalk_text or "").splitlines()
    for line in first_line:
        # Binwalk tables begin with a decimal offset.  A zero-offset hit is a
        # top-level signature; nonzero offsets are embedded members.
        if re.match(r"^\s*0\s+", line) and any(marker in line.lower() for marker in CONTAINER_FILE_MARKERS):
            return True
    return False


def _normalise_pair_result(pair_result: dict[str, Any], *, limit: int = 24) -> dict[str, Any]:
    result = {key: value for key, value in pair_result.items() if key not in {"candidates", "best"}}
    candidates: list[dict[str, Any]] = []
    for candidate in pair_result.get("candidates", []):
        copy = {key: value for key, value in candidate.items() if key not in {"pairs", "inner_pair_details"}}
        copy["pairs"] = candidate.get("pairs", [])[:limit]
        copy["inner_pair_details"] = candidate.get("inner_pair_details", [])[:limit]
        candidates.append(copy)
    result["candidates"] = candidates
    if pair_result.get("best"):
        best = {key: value for key, value in pair_result["best"].items() if key not in {"pairs", "inner_pair_details"}}
        best["pairs"] = pair_result["best"].get("pairs", [])[:limit]
        best["inner_pair_details"] = pair_result["best"].get("inner_pair_details", [])[:limit]
        result["best"] = best
    else:
        result["best"] = None
    return result


def _pair_confidence(candidate: dict[str, Any], *, rank: int, total: float) -> float:
    score = float(candidate.get("score", 0.0))
    blocks = int(candidate.get("blocks", 0))
    verified = int(candidate.get("verified_blocks", 0))
    inner_blocks = int(candidate.get("inner_pair_blocks", 0))
    if score <= 0 or blocks <= 0:
        return 0.0
    relative = score / total if total > 0 else 0.0
    volume = min(1.0, math.log1p(blocks) / math.log(101))
    verification = float(candidate.get("verification_rate", 0.0))
    confidence = 0.12 + 0.43 * min(1.0, relative * 2.0) + 0.22 * volume + 0.18 * verification + 0.05 * min(1.0, inner_blocks / max(1, blocks))
    if rank > 0:
        confidence *= 0.92 ** rank
    return max(0.0, min(0.92, confidence))


def _variant(architecture: str | None, *, elf: dict[str, Any], readelf_text: str, strings: str, endian: str | None) -> tuple[str | None, list[str]]:
    if not architecture:
        return None, []
    arch = architecture.upper()
    text = "\n".join((readelf_text, strings)).lower()
    evidence: list[str] = []
    if arch == "ARM":
        match = re.search(r"cortex[- _]?m(\d+)|cortex[- _]?r(\d+)|cortex[- _]?a(\d+)", text)
        if match:
            value = next(group for group in match.groups() if group)
            family = "M" if "cortex-m" in match.group(0).lower() else ("R" if "cortex-r" in match.group(0).lower() else "A")
            evidence.append(f"tool/string marker: {match.group(0)}")
            return f"Cortex-{family}{value}", evidence
        for marker, value in (("thumb-2", "ARMv7 Thumb-2"), ("armv8-m", "ARMv8-M"), ("v7e-m", "ARMv7E-M"), ("armv7", "ARMv7"), ("armv6", "ARMv6")):
            if marker in text:
                evidence.append(f"tool marker: {marker}")
                return value, evidence
        return "ARM (variant unknown)", evidence
    if arch == "RISCV64":
        flags = re.search(r"flags:\s*([^\n]+)", readelf_text, re.I)
        has_c = "rvc" in text or (flags and "c" in flags.group(1).lower())
        has_double_abi = "double-float" in text or "lp64d" in text
        has_single_abi = "single-float" in text or "lp64f" in text
        if has_c and has_double_abi:
            value = "RV64GC"
        elif has_c and has_single_abi:
            value = "RV64GC (RVC, single-float ABI)"
        elif has_c:
            value = "RV64C"
        elif has_double_abi:
            value = "RV64G (double-float ABI)"
        else:
            value = "RV64 (variant unknown)"
        evidence.append("ELF/tool metadata indicates 64-bit RISC-V")
        return value, evidence
    if arch == "MIPS":
        for marker, value in (("micromips", "MIPS microMIPS"), ("micro mips", "MIPS microMIPS")):
            if marker in text:
                evidence.append(f"tool marker: {marker}")
                return value, evidence
        match = re.search(r"\bmips32r([0-9]+)\b", text)
        if match:
            value = f"MIPS32R{match.group(1)}"
            evidence.append(f"tool marker: {match.group(0)}")
            return value, evidence
        for marker, value in (("mips64", "MIPS64"), ("mips32", "MIPS32")):
            if re.search(rf"\b{re.escape(marker)}\b", text):
                evidence.append(f"tool marker: {marker}")
                return value, evidence
        match = re.search(r"\bmips[- ]?(?:r)?([2345689][0-9]{2,3})\b", text)
        if match:
            value = f"MIPS R{match.group(1)}"
            evidence.append(f"tool marker: {match.group(0)}")
            return value, evidence
        match = re.search(r"\bmips([1-6])\b", text)
        if match:
            roman = {"1": "I", "2": "II", "3": "III", "4": "IV", "5": "V", "6": "VI"}[match.group(1)]
            value = f"MIPS-{roman}"
            evidence.append(f"tool marker: {match.group(0)}")
            return value, evidence
        match = re.search(r"\bmips[- ]?(ii|iii|iv|v)\b", text)
        if match:
            value = f"MIPS-{match.group(1).upper()}"
            evidence.append(f"tool marker: {match.group(0)}")
            return value, evidence
        return "MIPS (variant unknown)", evidence
    if arch == "POWERPC":
        if "64-bit" in text or elf.get("bits") == 64:
            return "PowerPC64", ["ELF class/tool output indicates 64-bit PowerPC"]
        return "PowerPC (variant unknown)", evidence
    if arch == "TRICORE":
        match = re.search(r"tc(1[0-9]{2,3}|2[0-9]{2})[a-z]*", text)
        if match:
            evidence.append(f"tool marker: {match.group(0)}")
            return match.group(0).upper(), evidence
        return "TriCore (variant unknown)", evidence
    if arch == "AARCH64":
        return "AArch64 (variant unknown)", evidence
    return None, evidence


def _candidate_segments(pair_result: dict[str, Any], *, file_size: int, direct_arch: str | None, executable_sections: list[dict[str, Any]], executable_load_segments: list[dict[str, Any]] | None = None, selected_pair: tuple[str, str | None] | None = None) -> list[dict[str, Any]]:
    if direct_arch and executable_sections:
        segments: list[dict[str, Any]] = []
        for section in executable_sections:
            if str(section.get("type", "")).upper() in {"SHT_NOBITS", "NOBITS"}:
                continue
            start = max(0, int(section.get("offset", 0)))
            end = min(file_size, start + max(0, int(section.get("size", 0))))
            if end <= start:
                continue
            name = str(section.get("name", ""))
            role = "primary firmware/control program"
            if name and name not in {".text", ".init", ".fini", ".vectors", ".isr_vector"}:
                role = f"executable section {name}"
            segments.append({
                "architecture": direct_arch,
                "start": start,
                "end": end,
                "section": name or None,
                "address": int(section.get("address", 0)),
                "flags": int(section.get("flags", 0)),
                "role": role,
                "basis": "ELF executable section",
            })
        if segments:
            return segments
    if direct_arch and executable_load_segments:
        segments = []
        for segment in executable_load_segments:
            start = max(0, int(segment.get("offset", 0)))
            end = min(file_size, start + max(0, int(segment.get("filesz", 0))))
            if end <= start:
                continue
            segments.append({
                "architecture": direct_arch,
                "start": start,
                "end": end,
                "address": int(segment.get("vaddr", 0)),
                "flags": int(segment.get("flags", 0)),
                "role": "primary firmware/control program",
                "basis": "ELF executable PT_LOAD segment",
            })
        if segments:
            return segments
    segments: list[dict[str, Any]] = []
    for candidate in pair_result.get("candidates", []):
        positions: list[int] = []
        for pair in candidate.get("pairs", []):
            for key in ("head", "tail"):
                if key in pair and isinstance(pair[key], dict):
                    positions.extend([int(pair[key].get("offset", 0)), int(pair[key].get("end", 0))])
        # Offsets are starts and ``end`` values are exclusive boundaries, so a
        # boundary equal to the file size is valid and must be retained.
        positions = sorted(set(p for p in positions if 0 <= p <= file_size))
        if not positions:
            continue
        start = positions[0]
        previous = positions[0]
        chunks: list[tuple[int, int, int]] = []
        cluster_positions: list[int] = [positions[0]]
        for position in positions[1:]:
            if position - previous > 0x4000:
                chunks.append((start, previous, len(cluster_positions)))
                start = position
                cluster_positions = [position]
            else:
                cluster_positions.append(position)
            previous = position
        chunks.append((start, previous, len(cluster_positions)))
        for chunk_start, chunk_end, count in chunks:
            if count < 2:
                continue
            candidate_key = (candidate.get("architecture"), candidate.get("endian"))
            is_best = selected_pair is not None and candidate_key == selected_pair
            if selected_pair is None:
                role = "candidate code region (inferred)"
            elif is_best and not any(s.get("role") == "primary firmware/control program" for s in segments):
                role = "primary firmware/control program"
            else:
                role = "auxiliary/co-processor code (inferred)"
            segments.append({"architecture": candidate["architecture"], "endian": candidate["endian"], "start": chunk_start, "end": min(file_size, chunk_end), "hit_count": count, "role": role, "basis": "clustered instruction-pair hits"})
    return segments


def detect(path: str | Path, *, architectures: Iterable[str] | None = None, config: str | Path | None = None, run_entropy: bool = True, verify_pairs: bool = True, max_hits: int = 2000, max_pairs: int = 300, variant: str | None = None) -> dict[str, Any]:
    input_path = Path(path)
    source_data = input_path.read_bytes()
    data = _read_input(input_path, source_data)
    elf = _parse_elf(input_path) if _looks_like_elf(data) else {"is_elf": False, "architecture": None, "executable_sections": [], "sections": [], "segments": []}
    file_result = _run(["file", "-b", str(input_path)])
    binwalk_result = _run(["binwalk", str(input_path)])
    entropy_result = _run(["binwalk", "-E", str(input_path)]) if run_entropy else {"available": False, "skipped": True, "stdout": "", "stderr": ""}
    strings_result = _run(["strings", "-a", "-n", "4", str(input_path)], timeout=20)
    readelf_result = _run(["readelf", "-h", str(input_path)]) if elf.get("is_elf") else {"available": False, "skipped": True, "stdout": "", "stderr": ""}
    readelf_attr_result = _run(["readelf", "-A", str(input_path)]) if elf.get("is_elf") else {"available": False, "skipped": True, "stdout": "", "stderr": ""}
    objdump_result = _run(["objdump", "-f", str(input_path)]) if elf.get("is_elf") else {"available": False, "skipped": True, "stdout": "", "stderr": ""}
    tools = {"file": file_result, "binwalk": binwalk_result, "entropy": entropy_result, "strings": strings_result, "readelf_header": readelf_result, "readelf_attributes": readelf_attr_result, "objdump": objdump_result}
    tool_text = "\n".join(str(item.get("stdout", "")) for item in tools.values())
    file_type = _file_type(input_path, file_result, source_data)
    firmware_class, firmware_evidence = _firmware_class(file_type=file_type, strings=strings_result.get("stdout", ""), elf=elf, tool_text=tool_text)
    direct_arch = _canonical_arch(elf.get("architecture"))
    requested = [_canonical_arch(value) for value in architectures] if architectures else None
    if direct_arch and requested and direct_arch not in requested:
        pair_architectures = requested
    elif direct_arch:
        pair_architectures = [direct_arch] if direct_arch in PAIR_ARCHITECTURES else []
    else:
        pair_architectures = requested
    pair_result: dict[str, Any] = {"schema_version": "1.0", "bytes": len(data), "candidates": [], "best": None}
    # ``None`` means all configured ISAs for a raw image; an empty list means
    # an authoritative ELF architecture outside the five pair configs (for
    # example x86/AArch64), so skip the pair engine only in the latter case.
    top_level_container = _is_top_level_container(file_type=file_type, data=data, binwalk_text=str(binwalk_result.get("stdout", "")))
    if analyze_binary is not None and pair_architectures != [] and not top_level_container:
        try:
            elf_endian = elf.get("endian") if direct_arch else None
            pair_result = analyze_binary(data, architectures=pair_architectures, endian=elf_endian, config=config, max_hits=max_hits, max_pairs=max_pairs, verify=verify_pairs, variant=variant)
        except Exception as exc:
            pair_result = {"schema_version": "1.0", "bytes": len(data), "candidates": [], "best": None, "error": str(exc)}
    normalised_pairs = _normalise_pair_result(pair_result)
    candidates: list[dict[str, Any]] = []
    pair_candidates = pair_result.get("candidates", [])
    total_pair_score = sum(float(item.get("score", 0.0)) for item in pair_candidates)
    for rank, item in enumerate(pair_candidates):
        architecture = _canonical_arch(item.get("architecture"))
        if architecture is None:
            continue
        confidence = _pair_confidence(item, rank=rank, total=total_pair_score)
        direct_match = bool(direct_arch and architecture == direct_arch and (not elf.get("endian") or item.get("endian") == elf.get("endian")))
        if direct_match:
            confidence = max(confidence, 0.82)
            confidence = min(0.995, confidence + 0.12)
        resolved_variant, variant_evidence = _variant(architecture, elf=elf, readelf_text=readelf_result.get("stdout", "") + "\n" + readelf_attr_result.get("stdout", "") + "\n" + file_result.get("stdout", "") + "\n" + objdump_result.get("stdout", ""), strings=strings_result.get("stdout", ""), endian=item.get("endian"))
        candidates.append({"architecture": architecture, "endian": item.get("endian"), "variant": variant or resolved_variant, "confidence": round(confidence, 4), "direct_elf_match": direct_match, "evidence": [f"instruction-pair score={item.get('score', 0):.2f}", f"blocks={item.get('blocks', 0)}", f"inner_pair_blocks={item.get('inner_pair_blocks', 0)}", f"verified_blocks={item.get('verified_blocks', 0)}"] + variant_evidence, "metrics": {key: item.get(key) for key in ("score", "blocks", "inner_pairs", "inner_pair_blocks", "verified_blocks", "verification_rate", "instruction_hits")}, "pair_details": {"pairs": item.get("pairs", [])[:24], "inner_pair_details": item.get("inner_pair_details", [])[:24]}})
    if direct_arch and not any(item["architecture"] == direct_arch for item in candidates):
        resolved_variant, variant_evidence = _variant(direct_arch, elf=elf, readelf_text=readelf_result.get("stdout", "") + "\n" + readelf_attr_result.get("stdout", "") + "\n" + file_result.get("stdout", "") + "\n" + objdump_result.get("stdout", ""), strings=strings_result.get("stdout", ""), endian=elf.get("endian"))
        candidates.insert(0, {"architecture": direct_arch, "endian": elf.get("endian"), "variant": variant or resolved_variant, "confidence": 0.92, "direct_elf_match": True, "evidence": [f"ELF e_machine={elf.get('machine')}"] + variant_evidence, "metrics": {}, "pair_details": {}})
    candidates.sort(key=lambda item: (-float(item["confidence"]), item["architecture"], str(item.get("endian"))))
    known_candidates = [item for item in candidates if float(item["confidence"]) > 0.0]
    # A raw image may contain overlapping code/data from more than one
    # processor.  When the leading pair scores are close, preserve the
    # candidate list and require corroboration instead of presenting a small
    # heuristic margin as a definitive architecture.
    raw_pair_ambiguous = False
    if not direct_arch:
        positive_pair_candidates = [item for item in pair_candidates if float(item.get("score", 0.0)) > 0]
        if len(positive_pair_candidates) > 1:
            ranked_scores = sorted((float(item.get("score", 0.0)) for item in positive_pair_candidates), reverse=True)
            if ranked_scores[0] > 0 and ranked_scores[1] / ranked_scores[0] >= 0.80:
                raw_pair_ambiguous = True
    # An ELF machine/data header is authoritative even when the caller asked
    # the pair engine to inspect a different architecture.  The explicit
    # architecture option limits heuristic analysis; it must not overturn a
    # contradictory container header.
    direct_authoritative = bool(direct_arch)
    direct_candidates = [item for item in known_candidates if item.get("direct_elf_match") and item.get("architecture") == direct_arch]
    if direct_authoritative and direct_candidates:
        best = direct_candidates[0]
    else:
        best = known_candidates[0] if known_candidates and (known_candidates[0]["direct_elf_match"] or known_candidates[0]["confidence"] >= 0.28) else None
        # Equal raw-byte scores do not identify an architecture.  Preserve the
        # candidates and evidence, but make the final result explicitly
        # unknown instead of turning a deterministic sort order into a vote.
        positive_pair_candidates = [item for item in pair_candidates if float(item.get("score", 0.0)) > 0]
        if best is not None and len(positive_pair_candidates) > 1:
            top_score = float(positive_pair_candidates[0].get("score", 0.0))
            tied = [item for item in positive_pair_candidates if abs(float(item.get("score", 0.0)) - top_score) <= 1e-9]
            if len(tied) > 1:
                best = None
        if raw_pair_ambiguous:
            best = None
    if best is None:
        result_architecture: Any = "unknown"
    else:
        result_architecture = best["architecture"]
    if best is not None and best.get("endian"):
        result_endian = best["endian"]
    else:
        result_endian = None
    executable_load_segments = [segment for segment in elf.get("segments", []) if str(segment.get("type", "")).upper() in {"PT_LOAD", "LOAD"} and int(segment.get("flags", 0)) & 0x1 and int(segment.get("filesz", 0)) > 0]
    selected_pair = (best["architecture"], best.get("endian")) if best is not None else None
    segments = _candidate_segments(pair_result, file_size=len(data), direct_arch=direct_arch if elf.get("is_elf") else None, executable_sections=elf.get("executable_sections", []), executable_load_segments=executable_load_segments, selected_pair=selected_pair)
    limitations = [
        "A raw binary has no authoritative ELF header; a low-score pair match is reported as unknown.",
        "Multiple ISA segments are inferred from clustered pair hits unless section metadata provides boundaries.",
        "Decoder verification is optional and depends on locally installed Capstone/pypcode.",
    ]
    if top_level_container:
        limitations.insert(0, "Top-level compressed/archive/filesystem container was not decoded; extract the payload before ISA analysis.")
    unavailable_tools = [name for name, tool in tools.items() if not tool.get("available", False) and not tool.get("skipped", False)]
    failed_tools = [name for name, tool in tools.items() if tool.get("available") and tool.get("returncode") not in (0, None)]
    if unavailable_tools:
        limitations.append("Unavailable tools: " + ", ".join(unavailable_tools) + ".")
    if failed_tools:
        limitations.append("Tools returned non-zero status: " + ", ".join(failed_tools) + ".")
    if not direct_authoritative:
        positive_pair_candidates = [item for item in pair_candidates if float(item.get("score", 0.0)) > 0]
        if len(positive_pair_candidates) > 1:
            top_score = float(positive_pair_candidates[0].get("score", 0.0))
            if sum(abs(float(item.get("score", 0.0)) - top_score) <= 1e-9 for item in positive_pair_candidates) > 1:
                limitations.append("Top raw instruction-pair scores are tied; architecture remains unknown until corroborated.")
        if raw_pair_ambiguous and not any("close" in note.lower() for note in limitations):
            limitations.append("Top raw instruction-pair scores are close; architecture remains unknown until corroborated.")
    if pair_result.get("error"):
        limitations.append("Instruction-pair analysis failed: " + str(pair_result["error"]))
    if elf.get("error"):
        limitations.append(f"ELF parser limitation: {elf['error']}")
    return {
        "schema_version": "1.0",
        "input": {"path": str(input_path), "size": len(data), "sha256": __import__("hashlib").sha256(data).hexdigest()},
        "file": {"type": file_type, "firmware_class": firmware_class, "firmware_class_evidence": firmware_evidence},
        "result": {"architecture": result_architecture, "endianness": result_endian, "variant": best.get("variant") if best else None, "confidence": best.get("confidence", 0.0) if best else 0.0, "candidates": candidates, "segments": segments},
        "elf": elf,
        "evidence": {"tools": tools, "tool_architecture_hints": _extract_tool_architecture(tools), "pair_analysis": normalised_pairs},
        "limitations": limitations,
    }


def _text_report(result: dict[str, Any]) -> str:
    file_info, detection = result["file"], result["result"]
    lines = [f"file: {file_info['type']}", f"firmware class: {file_info['firmware_class']}", f"ISA: {detection['architecture']}" + (f" ({detection['endianness']})" if detection.get("endianness") else "") + (f" / {detection['variant']}" if detection.get("variant") else ""), f"confidence: {float(detection.get('confidence', 0.0)):.3f}"]
    if detection.get("candidates"):
        lines.append("candidates:")
        lines.extend(f"  - {item['architecture']}:{item.get('endian') or '?'} confidence={float(item['confidence']):.3f} blocks={item.get('metrics', {}).get('blocks', 0)}" for item in detection["candidates"][:8])
    if detection.get("segments"):
        lines.append("segments:")
        lines.extend(f"  - {item['architecture']} {item['start']:#x}-{item['end']:#x}: {item['role']}" for item in detection["segments"][:12])
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect firmware ISA, endianness, variant and firmware class.")
    parser.add_argument("-f", "--file", required=True, help="input .bin/.hex/.elf/.img file")
    parser.add_argument("-a", "--arch", action="append", help="limit pair analysis to an architecture (repeatable)")
    parser.add_argument("--config-dir", help="architecture JSON file or directory")
    parser.add_argument("--no-entropy", action="store_true", help="skip binwalk entropy scan")
    parser.add_argument("--no-verify", action="store_true", help="skip Capstone/pypcode block verification")
    parser.add_argument("--max-hits", type=int, default=2000, help="cap hits per instruction")
    parser.add_argument("--max-pairs", type=int, default=300, help="cap pairs per pair definition")
    parser.add_argument("--variant", help="decoder variant override")
    parser.add_argument("--output", "-o", help="write JSON to this path (prefer ./temp for transient output)")
    parser.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    parser.add_argument("--text", action="store_true", help="print a concise report instead of JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        input_path = Path(args.file)
        if not input_path.is_file():
            raise FileNotFoundError(input_path)
        result = detect(input_path, architectures=args.arch, config=args.config_dir, run_entropy=not args.no_entropy, verify_pairs=not args.no_verify, max_hits=max(0, args.max_hits), max_pairs=max(0, args.max_pairs), variant=args.variant)
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"isa-detector: {exc}", file=sys.stderr)
        return 2
    output = _text_report(result) if args.text else json.dumps(result, ensure_ascii=False, indent=2 if args.pretty else None, sort_keys=not args.pretty)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
