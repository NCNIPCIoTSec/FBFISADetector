# ISA detector result notes

The detector intentionally separates evidence from the final vote:

```json
{
  "result": {
    "architecture": "ARM",
    "endianness": "LE",
    "variant": "Cortex-M4",
    "confidence": 0.94,
    "candidates": [],
    "segments": []
  },
  "file": {"type": "...", "firmware_class": "..."},
  "evidence": {"tools": {}, "pair_analysis": {}}
}
```

Confidence is deliberately conservative:

- `0.90+`: matching ELF `e_machine`/endianness or an equivalent authoritative
  header, optionally corroborated by pairs;
- `0.60–0.89`: strong pair/decoder evidence with useful tool corroboration;
- `0.28–0.59`: plausible raw-binary candidate requiring review;
- below `0.28` or tied candidates: report `unknown`.

Raw images have no authoritative header, so a small score margin is not enough
to choose an ISA.  If the second positive pair score is at least 80% of the
leading score, or if the leading scores are exactly tied, the detector keeps
the candidates and evidence but sets `result.architecture` to `unknown` until
another source corroborates the choice.  Because `max_pairs` is a sampling
limit, a very small value can change the ranking; use the default limit for a
bounded scan or `0` for an uncapped final pass.

`direct_elf_match` identifies an authoritative header match.  `metrics` retain
the pair-engine counts (`blocks`, `inner_pair_blocks`, `verified_blocks`,
`verification_rate`); they are not probabilities.  `pair_details` is capped in
the detector output to keep reports manageable, while the pair engine can emit
the complete report separately to `./temp`.

`segments.start` and `segments.end` are file offsets, with `end` exclusive.
For an ambiguous raw image, the role `candidate code region (inferred)` means
that no candidate was selected as primary.  Otherwise,
`auxiliary/co-processor code (inferred)` is a heuristic, not a proof of a
second processor.  When an ELF has multiple executable sections, preserve
each section and use its name/address as the stronger role evidence.
