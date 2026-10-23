import os

from fbfisa.settings import OUTPUT_DIR, CONFIG_DIR, ARCH_INFO
from fbfisa.analysis.instruction_analysis import BinaryAnalyzer


def main():
    BinaryAnalyzer.openMultiProcessing()
    # 初始化分析器
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=ARCH_INFO)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=os.path.join(CONFIG_DIR, "call_branch.json"))

    # All Demo Test
    for arch in os.listdir(OUTPUT_DIR):
        arch_dir = os.path.join(OUTPUT_DIR, arch)
        if not os.path.isdir(arch_dir):
            print(f'[SKIP FILE] {arch}')
            continue
        print(f"\n\n ======================== <{arch.upper()}> ========================")
        bin_dir = os.path.join(arch_dir, 'bin')
        if not os.path.isdir(bin_dir):
            print(f'[SKIP DIRECTORY] {bin_dir}')
            continue
        for demo in os.listdir(bin_dir):
            file_path = os.path.join(bin_dir, demo)
            if not os.path.isfile(file_path) or not file_path.endswith('.bin'):
                continue
            print(f'[RUN FILE] {demo}')
            ba = BinaryAnalyzer(bin_file_path=file_path)
            cur_arch, cur_data = ba.analyzing()
            print(f'\t[{arch.upper()}] ==> {cur_arch} | {cur_data}')

def test_partial():
    BinaryAnalyzer.openMultiProcessing()
    # 初始化分析器
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=ARCH_INFO)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=os.path.join(CONFIG_DIR, "call_branch.json"))

    # Demo Test
    print("======================== <ARM:FreeRTOS_ThreadCreation> ========================")
    ba = BinaryAnalyzer(bin_file_path=os.path.join(OUTPUT_DIR, 'arm', 'bin', 'FreeRTOS_ThreadCreation_0x8000000.bin'))
    cur_arch, cur_data = ba.analyzing()
    print(f'[ARM] ==> {cur_arch} | {cur_data}')

    print("\n======================== <MIPS:busybox_0x0.bin> ========================")
    ba = BinaryAnalyzer(bin_file_path=os.path.join(OUTPUT_DIR, 'mips', 'bin', 'busybox_0x0.bin'))
    cur_arch, cur_data = ba.analyzing()
    print(f'[MIPS] ==> {cur_arch} | {cur_data}')

    print("\n======================== <TRICORE:ADC_Background_Scan_1_KIT_TC297_TFT> ========================")
    ba = BinaryAnalyzer(bin_file_path=os.path.join(OUTPUT_DIR, 'tricore', 'bin', 'ADC_Background_Scan_1_KIT_TC297_TFT_0x60000000.bin'))
    cur_arch, cur_data = ba.analyzing()
    print(f'[TRICORE] ==> {cur_arch} | {cur_data}')

if __name__ == "__main__":
    # 批量测试
    # import sys
    # with open(file='../output/records.log', mode='w') as fw:
    #     original_stdout = sys.stdout
    #     sys.stdout = fw
    #     main()
    #     sys.stdout = original_stdout
    # demo测试
    test_partial()

