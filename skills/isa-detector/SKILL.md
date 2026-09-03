---
name: isa-detector
description: Detect firmware ISA, endianness, variant, file type, and firmware class from ELF or raw binary images.
---

# Firmware ISA detection

Use this skill for `.bin`, `.hex`, `.elf`, `.exe`, `.img` and similar firmware
artifacts.  Return an evidence-backed result, not just a guessed architecture.
The executable implementation is
`scripts/isa_detector.py`; it combines tool metadata with the
`ins-pairs-finder` implementation and records every unavailable/ambiguous
step.

## Required workflow

Run the detector from the repository root:

```bash
python3 skills/isa-detector/scripts/isa_detector.py \
  --file firmware.bin --output temp/isa-result.json --pretty
```

Use `--arch ARM` (repeatable) to constrain pair analysis, `--no-entropy` when
the entropy scan is unnecessary, and `--no-verify` for a quick pass.  Keep
reports, extracted slices and temporary tool output in `./temp`.

### 1. Identify the container and obvious contents

The script runs `file`, `binwalk`, `strings`, and (for ELF) `readelf` and
`objdump`.  It also runs `binwalk -E` unless `--no-entropy` is supplied.  Use
binwalk signatures to identify archives/filesystems/compression.  Do not call a
compressed or encrypted payload an ISA: report the container type and explain
that the payload needs extraction/decryption.  Extraction is out of scope
unless the user requests it; if requested, use a directory below `./temp`.

### 2. Prefer authoritative ELF metadata

For an ELF, use `e_machine`, ELF class, data encoding, ABI/flags, entry point,
executable sections and load segments as the primary ISA/endianness evidence.
`readelf -A`, `strings`, and `objdump -f` refine the variant (for example
ARM Cortex/Thumb, MIPS32R6, or RISC-V extensions).  ELF metadata wins over a
low-scoring raw-byte pattern match.  Executable sections are translated to
file-offset ranges for segment reporting.

### 3. Apply instruction-pair evidence

For the five configured ISAs (ARM, MIPS, POWERPC, RISCV64 and TRICORE), run the
pair engine with the ELF endian when available.  It performs the paper's
sequence: block-pair segmentation -> inner-pair semantic filter -> optional
Capstone/pypcode decode verification.  Compare `score`, `blocks`,
`inner_pair_blocks`, and `verified_blocks`; inspect representative pair bytes
before accepting a raw-binary result.  A low score or a tie is `unknown`, not a
forced vote.  The detector automatically limits analysis to the ELF ISA when
the header names one of the configured architectures, avoiding false matches
from data bytes.

### 4. Resolve variant and firmware class

Variant resolution combines ELF attributes, tool/string markers and pair
results.  Preserve an explicit `variant` override when supplied.  Classify the
artifact as Linux, RTOS, bare-metal, embedded executable with OS unknown, or
unknown.  Linux markers include an interpreter, BusyBox/glibc/uClibc, `/etc`,
`/sbin`, SquashFS and kernel strings.  RTOS markers include FreeRTOS, Zephyr,
ThreadX, NuttX, VxWorks and RT-Thread.  Vector-table/startup/Cortex-M/MCU
markers plus executable sections support a bare-metal classification.  State
which markers were observed.

### 5. Handle multiple architectures

Do not collapse a multi-image into one label.  Return every credible
architecture/endianness candidate and `result.segments`.  ELF executable
sections are authoritative segment boundaries.  For raw images, clusters of
pair-hit offsets are reported as primary control code versus inferred
auxiliary/co-processor code; call this an inference and include the offsets.

## Result contract

The JSON result has these top-level fields:

- `result.architecture`, `result.endianness`, `result.variant` and
  `result.confidence` (0..1);
- `result.candidates`, each with metrics, evidence and pair details;
- `result.segments` with file offsets and a cautious functional role;
- `file.type`, `file.firmware_class` and marker evidence;
- `elf` metadata when applicable;
- `evidence.tools` containing command, availability, return code, stdout and
  stderr, plus `evidence.pair_analysis`;
- `limitations`, including missing tools or ambiguity.

`--text` prints a concise summary, but retain the JSON for auditability.  If no
candidate has authoritative metadata or a meaningful pair score, return
`unknown` and say why.  Put explanatory notes/knowledge records under
`./logs`; only modify files under `./skills` when developing this skill.

For field meanings and confidence guidance, read
[references/result-schema.md](references/result-schema.md).
