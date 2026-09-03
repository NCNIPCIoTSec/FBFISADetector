---
name: ins-pairs-finder
description: Extract, combine, and validate configuration-driven instruction pairs from firmware or executable binaries.
---

# Instruction-pair extraction

Use this skill when a binary needs code-region evidence for ISA detection or
another static-analysis task.  The method follows the FBFISADetector paper:
block instruction pairs first delimit likely function/code blocks; inner block
pairs then select blocks with richer semantics; optional decoder checks measure
whether the selected bytes are credible code.

## Run the implementation

The dependency-light implementation is in
`scripts/ins_pairs_finder.py`.  It accepts the repository JSON configurations
(`src/fbfisa/config/arch/*.json`) and also accepts a custom JSON file or
directory:

```bash
python3 skills/ins-pairs-finder/scripts/ins_pairs_finder.py \
  --file firmware.bin --arch ARM --endian LE --verify \
  --output temp/instruction-pairs.json --pretty
```

Use `--arch` more than once to compare architectures.  Omit it to evaluate all
available configurations.  `--endian AUTO` follows `OTHERS.SupportedEndian`;
for `*`, both LE and BE are evaluated.  `--max-hits` and `--max-pairs` are
sampling limits for very large images, not confidence thresholds.  Intel HEX
records are parsed into a contiguous image with `0xff` for sparse gaps.

The script is safe to import as well:

```python
from pair_engine import analyze_binary
report = analyze_binary(data, architectures=["ARM"], endian="LE", verify=True)
```

## Analysis rules

1. Load the architecture configuration instead of guessing opcodes.  An
   instruction entry contains equal-length `regex`, `format`, and `mask`
   lists.  A match is retained only when `(matched_byte & mask) == format`.
   Patterns are interpreted in the entry's declared endian and reversed in
   `MemoryArgs.reverse_unit_size` chunks when the requested endian differs.
2. For each `PAIRS.BLOCK_PAIRS` definition, sort head/tail hits by aligned
   offset and pair a head with the next tail in the same alignment residue.
   A tail closes the current head candidate, even if a feature rejects it;
   this prevents one noisy tail from pairing with several distant heads.
3. Apply configured relationships.  `register` compares masked operand fields,
   `distance` requires the exact paper/source distance
   `tail.offset - head.end + 1`, and `scope` accepts an inclusive range.
   Unknown feature names are preserved in the report and do not silently alter
   the pair.
4. Search `PAIRS.INNER_BLOCK_PAIRS` using the same matcher.  The report keeps
   all inner matches, but `inner_pair_blocks` counts only those wholly inside a
   block pair, which is the paper's semantic-block filter.
5. With `--verify`, try Capstone and then pypcode.  A decoder is optional: an
   unavailable decoder is reported as `unavailable`, never treated as proof
   that bytes are data.  A fully covered decode is `verified`; a partial decode
   is `partial`.

## Reading the JSON result

`candidates` contains one record per architecture/endianness.  Important
fields are:

- `instruction_hits`: count per configured instruction;
- `pairs`: block pairs, including head/tail byte offsets, feature checks,
  distance, verification and contained `inner_pairs`;
- `blocks`, `inner_pairs`, `inner_pair_blocks`, `verified_blocks` and
  `verification_rate`;
- `score` and `best`, which are ranking aids only.  A nonzero score is not an
  architectural guarantee; corroborate it with ELF/tool metadata.

Offsets are file offsets, not load addresses.  For an ELF, use section/segment
metadata from `isa-detector` to translate them to virtual addresses.  Keep
large reports and any derived byte slices under `./temp`; put explanatory
notes or experiment logs under `./logs`.  Do not modify source/configuration
files while running the skill.

For the configuration shape and feature examples, read
[references/configuration.md](references/configuration.md).
