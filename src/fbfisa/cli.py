"""Command line interface for ISA detection."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Sequence

from fbfisa.settings import ARCH_INFO, CONFIG_DIR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detectisa",
        description="Identify the ISA and endianness of a raw firmware binary.",
    )
    parser.add_argument("-f", "--file", required=True, type=Path,
                        help="path to the target binary file")
    parser.add_argument("-a", "--arch", default=None,
                        help="test a specific ISA (for example ARM or MIPS)")
    parser.add_argument("-p", "--multiprocessing", action="store_true",
                        help="enable multiprocessing during analysis")
    return parser


def _configure_analyzer(multiprocessing: bool = False) -> None:
    # Import the heavy analysis stack only when a scan is requested. This
    # keeps help and package metadata inspection lightweight.
    from fbfisa.analysis.instruction_analysis import BinaryAnalyzer

    BinaryAnalyzer.updateSupportedArch(supported_arch_info=ARCH_INFO)
    BinaryAnalyzer.loadBrachCalculationExpressions(
        branch_calc_info_path=os.path.join(CONFIG_DIR, "call_branch.json")
    )
    if multiprocessing:
        BinaryAnalyzer.openMultiProcessing()


def main(argv: Sequence[str] | None = None) -> int:
    """Run the detector and return a process exit status."""

    args = build_parser().parse_args(argv)
    if not args.file.is_file():
        raise FileNotFoundError(f"binary file does not exist: {args.file}")

    _configure_analyzer(args.multiprocessing)
    from fbfisa.analysis.instruction_analysis import BinaryAnalyzer

    analyzer = BinaryAnalyzer(bin_file_path=str(args.file), display=True)
    result = (analyzer.analyzing() if args.arch is None
              else analyzer.specific_arch_analyzing(arch=args.arch))
    print("#" * 100)
    if args.arch is None:
        print(f"Predict Arch: {result}")
    else:
        print(f"TEST ARCH = {args.arch} | Result: {result}")
    variants = analyzer.possible_variants.get("ghidra", {}).get(result[0], [])
    print(f"Possible Variants: {variants}")
    print("#" * 100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
