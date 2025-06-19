import os

from settings import ARCH_INFO, CONFIG_DIR
from analysis.instruction_analysis import BinaryAnalyzer, BinaryBlock
from evaluate.lab.coveragestudy import block_display


def coverage_lab(bin_fpath: str, storage_space_path: str):
    '''
    覆盖率实验  
    - 输入：  
      - bin_fpath: str, 二进制bin文件的路径  
      - storage_space_path: str, 存储路径  
    - 作用  
    '''
    def get_block_pos(block: BinaryBlock):
        head, tail = block.block_pair
        start_pos, end_pos = head[1], tail[2]  # structure: (instruction bytes, start offset, end offset, is head?)
        size = end_pos - start_pos
        return (start_pos, size)
    
    def block_coverage_analysis(blocks: list[BinaryBlock], svg_file_tail: str):
        bin_blocks = []
        for blk in blocks:
            bin_blocks.append(get_block_pos(block=blk))
        # 分析块指令对命中
        svg_data = block_display(entry_addr=0x8000000, whole_bin=BinaryBlock.complete_binary, bin_blocks=bin_blocks)
        svg_file = bin_file.replace('.bin', svg_file_tail)
        with open(file=storage_space_path+svg_file, mode='w', encoding='utf-8') as fw:
            fw.write(svg_data)

    storage_path, bin_file = os.path.split(bin_fpath)
    arch = storage_path.split('/')[-2].upper()
    # 分析器
    analyzer = BinaryAnalyzer(bin_fpath)
    blk_filter = analyzer.archAnalysis(isa_arch=arch, endian='LE')
    # 分析过滤过程中的每个块
    block_coverage_analysis(blocks=blk_filter.blocks, svg_file_tail='_blk_pair.svg')
    block_coverage_analysis(blocks=[blk_filter.blocks[ind] for ind in blk_filter.have_pairs_blocks], svg_file_tail='_inner_pair.svg')
    block_coverage_analysis(blocks=[blk_filter.blocks[ind] for ind in blk_filter.reversed_ht_valid_blocks], svg_file_tail='reverse_check.svg')     


if __name__ == "__main__":
    BinaryAnalyzer.updateSupportedArch(supported_arch_info=ARCH_INFO)
    BinaryAnalyzer.loadBrachCalculationExpressions(branch_calc_info_path=CONFIG_DIR+"call_branch.json")

    sample_path = '/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output/arm/FreeRTOS_ThreadCreation_0x8000000.bin'
    coverage_lab(sample_path, '/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output/arm/')

