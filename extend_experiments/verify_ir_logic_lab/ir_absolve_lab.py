import os
import json

from fbfisa.analysis.instruction_analysis import BinaryAnalyzer


def find_specific_files(directory: str, file_type: str, default_null_suffix: str = 'elf') -> list:
    """
    递归搜索指定目录下的所有.xx文件
    
    参数:
        directory: 要搜索的目录路径
        file_type: 要搜索的文件后缀
        default_null_suffix: 无后缀文件默认的文件格式
    返回:
        包含所有.xx文件路径的列表
    """
    cur_files = []
    
    # 检查目录是否存在
    if not os.path.isdir(directory):
        print(f"Error: dir '{directory}' not exits or not a valid directory!")
        return cur_files
    
    # 遍历目录中的所有项
    file_type = file_type.lower()
    default_null_suffix = default_null_suffix.lower()
    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)
        
        # 如果是目录，则递归搜索
        suffix = f".{file_type}"
        suffix_mid = f".{file_type}@"
        if os.path.isdir(item_path):
            # 将子目录中找到的bin文件添加到结果列表
            cur_files.extend(find_specific_files(item_path, file_type, default_null_suffix))
        # 如果是文件且以.bin结尾或者是.bin@md5code形式
        elif os.path.isfile(item_path):
            if item.lower().endswith(suffix) or suffix_mid in item.lower():
                cur_files.append(item_path)
            elif file_type == default_null_suffix and '.' not in item:
                cur_files.append(item_path)
    
    return cur_files


def accuracy_lab(samples_dir: str, arch: str, record_fpath: str, files_type: str = "bin"):
    recorded_files = dict()
    if os.path.exists(record_fpath):
        with open(file=record_fpath, mode='r', encoding='utf-8') as fr:
            recorded_files = json.load(fp=fr)
    # bin files
    all_files = []
    all_files = find_specific_files(samples_dir, files_type)
    # 验证列表
    TT, TF = 0, 0
    echo, count = 0, 0
    for file_path in all_files:
        # 识别错误再重新检查
        if (cur_info := recorded_files.get(file_path)) is not None:
            if cur_info['proper']:
                TT += 1
                continue
            else:
                print("ERROR:", file_path, "==>", cur_info['predict_arch'])
                TF += 1
            continue
        fnm = file_path.split("/")[-1]
        # 分析与记录
        print(f'AnalysisRes[{echo}-{count}] {fnm}:{arch.upper()} ==> ', end="")
        ba = BinaryAnalyzer(bin_file_path=file_path)
        cur_arch, cur_data = ba.analyzing()
        judge_res = arch.upper() == cur_arch
        if judge_res:
            TT += 1
        else:
            TF += 1
        print(f'{cur_arch} | {cur_data} | Judge={judge_res}')
        # 记录
        recorded_files[file_path] = {"arch": arch.upper(), "predict_arch": cur_arch, "predict_arch_data": str(cur_data), "proper": judge_res}
        # 每N条，记录一次，避免崩溃导致数据丢失
        count += 1
        if count > 20:
            echo += 1
            with open(file=record_fpath, mode='w', encoding='utf-8') as fw:
                json.dump(obj=recorded_files, fp=fw)
            count = 0
    if (echo + count) > 0:
        with open(file=record_fpath, mode='w', encoding='utf-8') as fw:
            json.dump(obj=recorded_files, fp=fw)
    # 计算准确率
    if TF > 0 or TT > 0:
        print(f'RATE: {TT}/{TF+TT}={TT/(TT+TF)*100:.2f}%')
    else:
        print(f'RATE: 0.00%')
        

if __name__ == "__main__":
    from fbfisa.settings import CONFIG_DIR, ARCH_INFO

    BinaryAnalyzer.closeInnerBlockFilter()
    BinaryAnalyzer.openMultiProcessing()
    # 初始化分析器
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=ARCH_INFO)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=os.path.join(CONFIG_DIR, "call_branch.json"))
    
    print(" =>=>=> Analysis ARM Firmware <=<=<= ")
    accuracy_lab(
        samples_dir='../output/arm/bin', 
        arch='ARM:LE',
        record_fpath='../output/arm-cortex-m_no_inner_block_filter_accuracy_records.json'
    )
    print(" =>=>=> Analysis ARMHF-ELF <=<=<= ")
    accuracy_lab(
        samples_dir='../resources/data/firmwares/isadetect/armhf', 
        arch='ARM:LE',
        record_fpath='../output/armhf_no_inner_block_filter_accuracy_records.json',
        files_type='elf'
    )
    print(" =>=>=> Analysis RISCV64-ELF <=<=<= ")
    accuracy_lab(
        samples_dir='../resources/data/firmwares/isadetect/riscv64', 
        arch='RISCV64:LE',
        record_fpath='../output/riscv64_no_inner_block_filter_accuracy_records.json',
        files_type='elf'
    )
    print(" =>=>=> Analysis MIPS-ELF <=<=<= ")
    accuracy_lab(
        samples_dir='../resources/data/firmwares/isadetect/mips', 
        arch='MIPS:BE',
        record_fpath='../output/mips_no_inner_block_filter_accuracy_records.json',
        files_type='elf'
    )
    print(" =>=>=> Analysis PowerPC-ELF <=<=<= ")
    accuracy_lab(
        samples_dir='../resources/data/firmwares/isadetect/powerpc', 
        arch='PowerPC:BE',
        record_fpath='../output/powerpc_no_inner_block_filter_accuracy_records.json',
        files_type='elf'
    )
    print(" =>=>=> Analysis TriCore-ELF <=<=<= ")
    accuracy_lab(
        samples_dir='../resources/data/firmwares/AurixIDE/Aurix_TriCore', 
        arch='tricore:LE',
        record_fpath='../output/tricore_no_inner_block_filter_accuracy_records.json',
        files_type='elf'
    )
