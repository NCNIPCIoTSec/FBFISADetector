import os
import re

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
        

if __name__ == "__main__":
    # # PowerPC分析
    # for ppc_demo in os.listdir(demo_dir+'ppc/'):
    #     print(f'==== {ppc_demo} ====')
    #     powerPCAnalysis(demo_dir+'ppc/'+ppc_demo)
    # ARM分析
    arch_info = dict()
    for arch_file in os.listdir(config_dir+'arch/'):
        arch = arch_file.replace(".json", "")
        arch_info[arch] = config_dir+'arch/'+arch_file
    del arch
    
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=arch_info)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=config_dir+"call_branch.json")
    
    for arch in os.listdir(demo_dir):
        for demo in os.listdir(demo_dir+f'{arch}/bin/'):
            file_path = demo_dir+f'{arch}/bin/'+demo
            if not os.path.isfile(file_path):
                continue
            print(f" ======================== <{arch}:{demo}> ========================")
            ba = BinaryAnalyzer(bin_file_path=file_path)
            ba.analyzing()
