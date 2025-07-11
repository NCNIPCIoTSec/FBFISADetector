import os
import argparse

from settings import CONFIG_DIR, ARCH_INFO
from analysis.instruction_analysis import BinaryAnalyzer


if __name__ == "__main__":
    # 设置参数
    parser = argparse.ArgumentParser(
        prog="DetectISA", description="Identify the ISA of target firmware", epilog='Have Fun!!!'
    )
    parser.add_argument('-f', '--file', help="storage path of target binary file", type=str)
    parser.add_argument('-p', '--multiprocessing', action="store_true", help="whether to open multiprocessing")
    args = parser.parse_args()

    # 初始化文件和分析器
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=ARCH_INFO)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=CONFIG_DIR+"call_branch.json")
    if args.multiprocessing:
        BinaryAnalyzer.openMultiProcessing()

    # 分析器加载文件
    cur_analyzer = BinaryAnalyzer(bin_file_path=args.file, display=True)
    arch_info = cur_analyzer.analyzing()
    print(f"Predict Arch: {arch_info}")
    