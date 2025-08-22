import os
import re
import json

from analysis.instruction_analysis import BinaryBlock, BinaryAnalyzer
from evaluate.extractor import get_all_blocks
from evaluate.lab.coveragestudy import block_display


def coverage_lab(bin_fpath: str, elf_fpath: str, storage_space_path: str, arch: str, endian: str):
    '''
    覆盖率实验  
    - 输入：  
      - bin_fpath: str, 二进制bin文件的路径  
      - elf_fpath: str, 原始ELF文件的路径
      - storage_space_path: str, 存储路径  
    - 作用  
    '''

    def block_coverage_analysis(bin_blocks: list[tuple], svg_file_tail: str, file_type='bin', start_addr: int = 0x8000000, title: str = "二进制文件字节块分析"):
        '''
        展示代码块在整个二进制文件里的位置
        '''
        # 分析块指令对命中
        svg_data = block_display(
            entry_addr=start_addr, 
            whole_bin=BinaryBlock.complete_binary, 
            bin_blocks=bin_blocks,
            title=title
        )
        # 存储文件
        svg_file = os.path.split(bin_fpath)[-1]
        if file_type.lower() == 'elf':
            svg_file = os.path.split(elf_fpath)[-1]
        svg_file = svg_file.replace(f'.{file_type}', svg_file_tail)
        # 存储
        with open(file=storage_space_path+svg_file, mode='w', encoding='utf-8') as fw:
            fw.write(svg_data)

    # ================ 预处理 ================
    blocks_info = get_all_blocks(bin_fpath=bin_fpath, elf_fpath=elf_fpath, arch=arch, endian=endian.upper())
    entry_addr = blocks_info['others']['entry_address']

    # ================ RESULT DISPLAY ================
    block_coverage_analysis(bin_blocks=blocks_info['elf'], svg_file_tail='.svg', file_type='elf', start_addr=entry_addr)
    block_coverage_analysis(bin_blocks=blocks_info['blocks'], svg_file_tail='_blk_pair.svg', start_addr=entry_addr, title='A. 指令对切块结果')
    block_coverage_analysis(bin_blocks=blocks_info['blocks_with_inner_pairs'], svg_file_tail='_inner_pair.svg', start_addr=entry_addr, title="B. A+加入块内指令对的结果")
    block_coverage_analysis(bin_blocks=blocks_info['blocks_with_reversing'], svg_file_tail='_reverse_check.svg', start_addr=entry_addr, title="C. B+逆向算法验证")     


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
    import settings

    BinaryAnalyzer.openMultiProcessing()
    
    sample_path = '/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output/arm/FreeRTOS_ThreadCreation_0x8000000.bin'
    elf_path = '/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/arm/FreeRTOS_ThreadCreation.elf'
    # coverage_lab(bin_fpath=sample_path, elf_fpath=elf_path, storage_space_path='/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output/arm/')
    # print(ablation_study(settings.SAMPLES_DIR, settings.OUTPUT_DIR))
    print(" =>=>=> Analysis ARM Firmware <=<=<= ")
    accuracy_lab(
        samples_dir='../output/arm/bin', 
        arch='ARM:LE',
        record_fpath='../output/arm-cortex-m_accuracy_records.json'
    )
    print(" =>=>=> Analysis ARMHF-ELF <=<=<= ")
    accuracy_lab(
        samples_dir='../relative_works/workspace/ISADetect/new_new_dataset/ISAdetect_full_binaries/armhf', 
        arch='ARM:LE',
        record_fpath='../output/armhf_accuracy_records.json',
        files_type='elf'
    )
    print(" =>=>=> Analysis RISCV64-ELF <=<=<= ")
    accuracy_lab(
        samples_dir='../relative_works/workspace/ISADetect/new_new_dataset/ISAdetect_full_binaries/riscv64', 
        arch='RISCV64:LE',
        record_fpath='../output/riscv64_accuracy_records.json',
        files_type='elf'
    )
    print(" =>=>=> Analysis MIPS-ELF <=<=<= ")
    accuracy_lab(
        samples_dir='../relative_works/workspace/ISADetect/new_new_dataset/ISAdetect_full_binaries/mips', 
        arch='MIPS:BE',
        record_fpath='../output/mips_accuracy_records.json',
        files_type='elf'
    )
    print(" =>=>=> Analysis PowerPC-ELF <=<=<= ")
    accuracy_lab(
        samples_dir='../relative_works/workspace/ISADetect/new_new_dataset/ISAdetect_full_binaries/powerpc', 
        arch='PowerPC:BE',
        record_fpath='../output/powerpc_accuracy_records.json',
        files_type='elf'
    )
    print(" =>=>=> Analysis TriCore-ELF <=<=<= ")
    accuracy_lab(
        samples_dir='../resources/samples/tricore', 
        arch='tricore:LE',
        record_fpath='../output/tricore_accuracy_records.json',
        files_type='elf'
    )
