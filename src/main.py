import os
import sys

from settings import CONFIG_DIR, SAMPLES_DIR, ARCH_INFO
from analysis.instruction_analysis import BinaryAnalyzer


def main():
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=ARCH_INFO)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=CONFIG_DIR+"call_branch.json")

    # Demo Test
    # print("\n\n ======================== <ARM:FreeRTOS_ThreadCreation> ========================")
    # ba = BinaryAnalyzer(bin_file_path=SAMPLES_DIR + 'arm/bin/FreeRTOS_ThreadCreation_0x8000000.bin')
    # ba.analyzing()
    # print("\n\n ======================== <MIPS:busybox_0x0.bin> ========================")
    # ba = BinaryAnalyzer(bin_file_path=SAMPLES_DIR + 'mips/bin/busybox_0x0.bin')
    # ba.analyzing()
    # print("\n\n ======================== <TRICORE:ADC_Background_Scan_1_KIT_TC297_TFT> ========================")
    # ba = BinaryAnalyzer(bin_file_path=SAMPLES_DIR + 'tricore/bin/ADC_Background_Scan_1_KIT_TC297_TFT_0x80000000.bin')
    # ba.analyzing()
    
    # Real Firmware Test
    print("\n\n ======================== <TRICORE:TC1797_FLASH.bin> ========================")
    ba = BinaryAnalyzer(bin_file_path=SAMPLES_DIR + 'tricore/bin/TC1797_FLASH.bin')
    ba.analyzing()

    # All Demo Test
    # for arch in os.listdir(SAMPLES_DIR):
    #     for demo in os.listdir(SAMPLES_DIR+f'{arch}/bin/'):
    #         file_path = SAMPLES_DIR+f'{arch}/bin/'+demo
    #         if not os.path.isfile(file_path):
    #             continue
    #         print(f"\n\n ======================== <{arch}:{demo}> ========================")
    #         ba = BinaryAnalyzer(bin_file_path=file_path)
    #         ba.analyzing()


if __name__ == "__main__":
    # # PowerPC分析
    # for ppc_demo in os.listdir(SAMPLES_DIR+'ppc/'):
    #     print(f'==== {ppc_demo} ====')
    #     powerPCAnalysis(SAMPLES_DIR+'ppc/'+ppc_demo)
    with open(file='../resources/records.log', mode='w') as fw:
        original_stdout = sys.stdout
        sys.stdout = fw
        main()
        sys.stdout = original_stdout

