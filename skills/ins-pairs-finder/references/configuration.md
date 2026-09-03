# Instruction-pair configuration

The repository configurations are JSON objects with three relevant sections:

```json
{
  "INSTRUCTIONS": {
    "push": {
      "endian": "BE",
      "regex": ["\\xb5."],
      "format": ["\\xb5\\x00"],
      "mask": ["\\xff\\x00"],
      "descriptions": ["push {registers}, lr"]
    }
  },
  "PAIRS": {
    "BLOCK_PAIRS": [
      {"ins": ["push", "pop"], "type": "ARGS_SAVE", "features": {}}
    ],
    "INNER_BLOCK_PAIRS": [
      {"ins": ["cmp", "b-it"], "type": "IT", "features": {"distance": ["cmp", "b-it", 1]}}
    ]
  },
  "OTHERS": {
    "MemoryArgs": {
      "reverse_unit_size": 2,
      "min_instr_length": 2,
      "max_instr_length": 4,
      "alignment_size": 2
    },
    "SupportedEndian": "*"
  }
}
```

`regex`, `format`, and `mask` list entries correspond by index.  `.` means any
byte; character classes and `\xNN` escapes use Python's byte-regex syntax.
`format` and `mask` may also be plain hexadecimal strings.  Masks must have the
same length as their format and matched instruction.

Feature forms:

- `{"distance": ["head", "tail", 1]}` uses the exact inclusive source
  distance described in the skill entrypoint;
- `{"scope": ["head", "tail", [1, 5]]}` uses an inclusive range;
- `{"register": ["head", "tail", "BE", [["\\x00\\xff"], ["\\x00\\xff"]]]}`
  compares masked register/operand fields.  The endian item is optional; if
  omitted, masks are treated as native target-endian masks.

When adding a configuration, keep instruction names stable and add a short
description for analysts.  Validate it on a small synthetic byte string before
using it on a multi-megabyte image.
