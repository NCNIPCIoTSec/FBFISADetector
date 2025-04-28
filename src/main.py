import os
import sys
import re

from evaluate.calc import calc_pair_rate
from utils.bytes_op import bytes_fmt_compare
from analysis.instruction_analysis import BinaryAnalyzer

config_dir = '../resources/ISA/config/'
demo_dir = '../resources/samples/'

# PPC32
regex_ppc_blr = br"\x4e\x80\x00\x20"

regex_ppc_mfspr = br"[\x7c\x7d\x7e\x7f].\x02\xa6"
ppc_mfspr_LR_fmt = b"\x7c\x08\x02\xa6"
ppc_mfspr_LR_mask = b"\xfc\x1f\xff\xff"

regex_ppc_b = br"[\x48\x49\x4a\x4b]..."


def powerPCAnalysis(path: str):
    binary_res = b''
    with open(file=path, mode='rb') as fread:
        binary_res = fread.read()

    search_mfspr_res = re.finditer(regex_ppc_mfspr, binary_res)
    search_blr_res = re.finditer(regex_ppc_blr, binary_res)
    # search_b_res = re.finditer(regex_ppc_b, binary_res)
    
    mfspr_result = [res.group().hex() for res in search_mfspr_res if bytes_fmt_compare(mask=ppc_mfspr_LR_mask, ins=res.group(), fmt_ins=ppc_mfspr_LR_fmt)]
    blr_result = [res.group().hex() for res in search_blr_res]
    print(f"Push stack: {len(mfspr_result)} | Pop Stack: {len(blr_result)} | Abs Rate = {calc_pair_rate(len(mfspr_result), len(blr_result)) * 100: .2f}%")

def main():
    # ARM分析
    arch_info = dict()
    for arch_file in os.listdir(config_dir+'arch/'):
        arch = arch_file.replace(".json", "")
        arch_info[arch] = config_dir+'arch/'+arch_file
    del arch
    
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=arch_info)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=config_dir+"call_branch.json")

    print("\n\n ======================== <ARM:FreeRTOS_ThreadCreation> ========================")
    ba = BinaryAnalyzer(bin_file_path=demo_dir + 'arm/bin/FreeRTOS_ThreadCreation_0x8000000.bin')
    ba.analyzing()
    print("\n\n ======================== <TRICORE:ADC_Background_Scan_1_KIT_TC297_TFT> ========================")
    ba = BinaryAnalyzer(bin_file_path=demo_dir + 'tricore/bin/ADC_Background_Scan_1_KIT_TC297_TFT_0x80000000.bin')
    ba.analyzing()

    # for arch in os.listdir(demo_dir):
    #     for demo in os.listdir(demo_dir+f'{arch}/bin/'):
    #         file_path = demo_dir+f'{arch}/bin/'+demo
    #         if not os.path.isfile(file_path):
    #             continue
    #         print(f"\n\n ======================== <{arch}:{demo}> ========================")
    #         ba = BinaryAnalyzer(bin_file_path=file_path)
    #         ba.analyzing()


if __name__ == "__main__":
    # # PowerPC分析
    # for ppc_demo in os.listdir(demo_dir+'ppc/'):
    #     print(f'==== {ppc_demo} ====')
    #     powerPCAnalysis(demo_dir+'ppc/'+ppc_demo)
    with open(file='../resources/records.log', mode='w') as fw:
        original_stdout = sys.stdout
        sys.stdout = fw
        main()
        sys.stdout = original_stdout


