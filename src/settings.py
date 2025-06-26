import os
from analysis.instruction_analysis import BinaryAnalyzer

# 路径配置
CONFIG_DIR = '../resources/ISA/config/'
SAMPLES_DIR = '../resources/samples/'
OUTPUT_DIR = '../output/'

# 获取所有架构的配置文件路径信息
ARCH_INFO = dict()
for arch_file in os.listdir(CONFIG_DIR+'arch/'):
    arch = arch_file.replace(".json", "")
    ARCH_INFO[arch] = CONFIG_DIR+'arch/'+arch_file

# 初始化分析器
BinaryAnalyzer.updateSupportedArch(supported_arch_info=ARCH_INFO)
BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=CONFIG_DIR+"call_branch.json")
