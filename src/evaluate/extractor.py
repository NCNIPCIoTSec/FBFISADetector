import os

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from analysis.instruction_analysis import BinaryAnalyzer, BinaryBlock


def extract_code_block_from_elf(elf_fpath: str):
    '''
    从标准ELF文件中抽取出信息块（数据块、代码块）
    '''
    # 读取ELF文件，抽取关键信息
    min_addr, max_addr = 0xffffffffffffffff, 0
    with open(file=elf_fpath, mode='rb') as f:
        try:
            elf = ELFFile(f)
        except ELFError as e:
            print(f"[Error: {e}] ===> 文件<{elf_fpath}>不是ELF文件！！！")
            return 
        # 获取文件程序段中最小地址，作为文件基址；最大地址作为文件上界
        for segment in elf.iter_segments():
            physical_addr = segment["p_paddr"]
            upper_bound_addr = physical_addr + segment['p_memsz']
            if min_addr > physical_addr:
                min_addr = physical_addr
            if upper_bound_addr > max_addr:
                max_addr = upper_bound_addr
        # print(elf.get_section_by_name('.symtab'))
        # 筛选出所有的有意义的节（节中的symbol作为block）
        code_addr_record = {}
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    block_name: str = symbol.name
                    block_addr, block_size = symbol.entry.st_value, symbol.entry.st_size
                    if len(block_name) == 0:
                        continue
                    if block_addr < min_addr or block_addr >= max_addr:
                        continue
                    # print(f"BLOCK {block_name}: 0x{block_addr:x} 0x{block_size:x}")
                    if code_addr_record.get(block_addr) is None:
                        code_addr_record[block_addr] = {'all_name': [], 'size': 0}
                    code_addr_record[block_addr]['all_name'].append(block_name)
                    if code_addr_record[block_addr]['size'] == 0:
                        code_addr_record[block_addr]['size'] = block_size

    return min_addr, code_addr_record


def get_all_blocks(bin_fpath: str, elf_fpath: str, endian: str = 'LE'):
    '''
    获取指定文件所有的BLOCKS
    - 输入：  
      - bin_fpath: str, 二进制bin文件的路径  
      - elf_fpath: str, 原始ELF文件的路径
      - storage_space_path: str, 存储路径  
    - 返回：  
      - blocks_info: dict, 格式如{"elf": [(start_pos, size), ...], "blocks": [...], "blocks_with_inner_pairs": [...], "blocks_with_reversing": [...], "others": {"entry_address": int, ...}}  
    '''
    def get_block_pos(block: BinaryBlock):
        head, tail = block.block_pair
        start_pos, end_pos = head[1], tail[2]  # structure: (instruction bytes, start offset, end offset, is head?)
        size = end_pos - start_pos
        return (start_pos, size)

    # ================ 预处理 ================
    entry_addr, record = extract_code_block_from_elf(elf_fpath=elf_fpath)  # ELF处理
    storage_path, _ = os.path.split(bin_fpath)  # 获取bin文件路径信息
    arch = storage_path.split('/')[-1].upper()  # 获取架构信息
    ## 分析器初始化
    print(f'====> {bin_fpath} <====')
    analyzer = BinaryAnalyzer(bin_fpath)
    blk_filter = analyzer.archAnalysis(isa_arch=arch, endian=endian)

    # 获取ELF标准块
    elf_segments = [(addr - entry_addr, record[addr]['size']) for addr in record.keys() if record[addr]['size'] > 0]  # (start_pos, size)
    # 获取bin分析器所得的所有的blocks
    all_blocks = [get_block_pos(blk) for blk in blk_filter.blocks]
    blocks_with_inner_pairs = [get_block_pos(blk) for blk in [blk_filter.blocks[ind] for ind in blk_filter.have_pairs_blocks]]
    blocks_with_reversing = [get_block_pos(blk) for blk in [blk_filter.blocks[ind] for ind in blk_filter.reversed_ht_valid_blocks]]

    return {"others": {"entry_address": entry_addr}, "elf": elf_segments, "blocks": all_blocks, "blocks_with_inner_pairs": blocks_with_inner_pairs, "blocks_with_reversing": blocks_with_reversing}