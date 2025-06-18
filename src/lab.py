import os
import json

from analysis.instruction_analysis import BinaryAnalyzer
from settings import ARCH_INFO, CONFIG_DIR


def coverage_lab(bin_fpath: str):
    storage_path, bin_file = os.path.split(bin_fpath)
    arch = storage_path.split('/')[-2].upper()
    # 分析器
    analyzer = BinaryAnalyzer(bin_fpath)
    blk_filter = analyzer.archAnalysis(isa_arch=arch, endian='LE')
    # TODO: 分析过滤过程中的每个块
    print(blk_filter)


if __name__ == "__main__":
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=ARCH_INFO)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=CONFIG_DIR+"call_branch.json")

    sample_path = '/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/arm/bin/FreeRTOS_ThreadCreation_0x8000000.bin'
    coverage_lab(sample_path)

