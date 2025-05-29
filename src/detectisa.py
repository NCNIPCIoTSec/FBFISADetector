import os
import argparse

from analysis.instruction_analysis import BinaryAnalyzer

config_dir = '../resources/ISA/config/'
demo_dir = '../resources/samples/'

if __name__ == "__main__":
    # 设置参数
    parser = argparse.ArgumentParser(
        prog="DetectISA", description="Identify the ISA of target firmware", epilog='Have Fun!!!'
    )
    parser.add_argument('-f', '--file', help="storage path of target binary file", type=str)
    args = parser.parse_args()

    # 初始化文件和分析器
    arch_info = dict()
    for arch_file in os.listdir(config_dir+'arch/'):
        arch = arch_file.replace(".json", "")
        arch_info[arch] = config_dir+'arch/'+arch_file
    del arch
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=arch_info)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=config_dir+"call_branch.json")

    # 分析器加载文件
    cur_analyzer = BinaryAnalyzer(bin_file_path=args.file)
    cur_analyzer.analyzing()
    