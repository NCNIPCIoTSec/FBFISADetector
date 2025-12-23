import os
import argparse

from fbfisa.settings import CONFIG_DIR, ARCH_INFO
from fbfisa.analysis.instruction_analysis import BinaryAnalyzer


if __name__ == "__main__":
    # 设置参数
    parser = argparse.ArgumentParser(
        prog="DetectISA", description="Identify the ISA of target firmware", epilog='Have Fun!!!'
    )
    parser.add_argument('-f', '--file', help="storage path of target binary file", type=str)
    parser.add_argument('-a', '--arch', help="Test specific ISA", type=str, default=None)
    parser.add_argument('-p', '--multiprocessing', action="store_true", help="whether to open multiprocessing")
    args = parser.parse_args()

    # 初始化文件和分析器
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=ARCH_INFO)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=os.path.join(CONFIG_DIR, "call_branch.json"))
    if args.multiprocessing:
        BinaryAnalyzer.openMultiProcessing()

    # 分析器加载文件
    cur_analyzer = BinaryAnalyzer(bin_file_path=args.file, display=True)
    if args.arch is None:
        arch_info = cur_analyzer.analyzing()
        print("#" * 100)
        print(f"Predict Arch: {arch_info}")
        print(f"Possible Variants: {cur_analyzer.possible_variants['ghidra'][arch_info[0]]}")
    else:
        arch_res = cur_analyzer.specific_arch_analyzing(arch=args.arch)
        print("#" * 100)
        print(f"TEST ARCH = {args.arch} | Result: {arch_res}")
        print(f"Possible Variants: {cur_analyzer.possible_variants['ghidra'][arch_res[0]]}")
    print("#" * 100)
    