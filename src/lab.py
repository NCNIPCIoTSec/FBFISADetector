import os

from analysis.instruction_analysis import BinaryBlock
from evaluate.extractor import get_all_blocks
from evaluate.lab.coveragestudy import block_display
from evaluate.lab.ablationstudy import ablation_study


def coverage_lab(bin_fpath: str, elf_fpath: str, storage_space_path: str):
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
    blocks_info = get_all_blocks(bin_fpath=bin_fpath, elf_fpath=elf_fpath)
    entry_addr = blocks_info['others']['entry_address']

    # ================ RESULT DISPLAY ================
    block_coverage_analysis(bin_blocks=blocks_info['elf'], svg_file_tail='.svg', file_type='elf', start_addr=entry_addr)
    block_coverage_analysis(bin_blocks=blocks_info['blocks'], svg_file_tail='_blk_pair.svg', start_addr=entry_addr, title='A. 指令对切块结果')
    block_coverage_analysis(bin_blocks=blocks_info['blocks_with_inner_pairs'], svg_file_tail='_inner_pair.svg', start_addr=entry_addr, title="B. A+加入块内指令对的结果")
    block_coverage_analysis(bin_blocks=blocks_info['blocks_with_reversing'], svg_file_tail='_reverse_check.svg', start_addr=entry_addr, title="C. B+逆向算法验证")     


if __name__ == "__main__":
    import settings
    
    sample_path = '/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output/arm/FreeRTOS_ThreadCreation_0x8000000.bin'
    elf_path = '/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/arm/FreeRTOS_ThreadCreation.elf'
    # coverage_lab(bin_fpath=sample_path, elf_fpath=elf_path, storage_space_path='/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output/arm/')
    print(ablation_study(settings.SAMPLES_DIR, settings.OUTPUT_DIR))
