import os
import sys

from settings import OUTPUT_DIR, SAMPLES_DIR
from analysis.instruction_analysis import BinaryAnalyzer


def main():
    # Demo Test
    # print("\n\n ======================== <ARM:FreeRTOS_ThreadCreation> ========================")
    # ba = BinaryAnalyzer(bin_file_path=OUTPUT_DIR + 'arm/FreeRTOS_ThreadCreation_0x8000000.bin')
    # ba.analyzing()
    # print("\n\n ======================== <MIPS:busybox_0x0.bin> ========================")
    # ba = BinaryAnalyzer(bin_file_path=OUTPUT_DIR + 'mips/busybox_0x0.bin')
    # ba.analyzing()
    # print("\n\n ======================== <TRICORE:ADC_Background_Scan_1_KIT_TC297_TFT> ========================")
    # ba = BinaryAnalyzer(bin_file_path=OUTPUT_DIR + 'tricore/ADC_Background_Scan_1_KIT_TC297_TFT_0x80000000.bin')
    # ba.analyzing()
    
    # Real Firmware Test
    print("\n\n ======================== <TRICORE:TC1797_FLASH.bin> ========================")
    ba = BinaryAnalyzer(bin_file_path=SAMPLES_DIR + 'tricore/bin/TC1797_FLASH.bin')
    ba.analyzing()

    # All Demo Test
    for arch in os.listdir(OUTPUT_DIR):
        for demo in os.listdir(OUTPUT_DIR+f'{arch}/'):
            file_path = OUTPUT_DIR+f'{arch}/'+demo
            if not os.path.isfile(file_path) or not file_path.endswith('.bin'):
                continue
            print(f"\n\n ======================== <{arch}:{demo}> ========================")
            ba = BinaryAnalyzer(bin_file_path=file_path)
            ba.analyzing()


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

