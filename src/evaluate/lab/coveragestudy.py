import os
import re
import pprint

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def extract_code_block_from_elf(elf_fpath: str):
    # 读取ELF文件，抽取关键信息
    min_addr, max_addr = float('inf'), 0
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


def block_display(entry_addr: int, whole_bin: bytes, bin_blocks: list, width: int = 800, height: int = 120, margin: int = 50) -> str:
    """
    以可视化的方式展示出“有意义的字节块”在“整个二进制文件的字节内容”的位置区域  
    - 输入：  
      - whole_bin: bytes，整个二进制文件的二进制内容  
      - bin_blocks: list，格式为[(block offset, block size), ...]，一块二进制在其中的偏移量  
      - width: int, SVG尺寸宽度  
      - height: int, SVG尺寸高度  
      - margin: int, 图距离边界距离  
    - 输出：  
      - str: SVG格式的可视化图像  
    """
    # 确保块按偏移量排序
    bin_blocks.sort(key=lambda x: x[0])
    # 总字节数
    total_bytes = len(whole_bin)
    # 每个字节对应的像素宽度（考虑边距）
    usable_width = width - margin * 2  # 左右各留50像素边距
    bytes_per_pixel = (total_bytes / usable_width) if total_bytes > 0 else 1
    # 生成SVG内容
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">'
    ]
    # 添加背景
    svg.append('<rect width="100%" height="100%" fill="white" rx="5" ry="5"/>')
    # 添加标题
    svg.append(f'<text x="{width/2}" y="{height/2 - 30}" text-anchor="middle" font-family="Arial" font-size="14" font-weight="bold">二进制文件字节块可视化</text>')
    # 绘制整个二进制文件的背景条
    svg.append(f'<rect x="{margin}" y="{height/2}" width="{usable_width}" height="30" fill="#DCDCDC"/>')
    # 为每个块绘制白色矩形
    end_pos = width - margin
    for offset, size in bin_blocks:
        # print(hex(entry_addr + offset), hex(entry_addr + offset + size))
        # 计算块在SVG中的位置和宽度
        block_start = margin + (offset / bytes_per_pixel)
        block_width = (size / bytes_per_pixel) if bytes_per_pixel > 0 else 0
        # 确保块宽度至少为1像素
        if block_width < 1 and size > 0:
            block_width = 1
        # 添加块矩形（白色填充，黑色边框）
        svg.append(f'<rect x="{block_start}" y="{height/2}" width="{block_width}" height="30" fill="#F5F5F5"/>')
        if (block_end := block_start + block_width) > end_pos:
            end_pos = block_end
    # 添加刻度和必要标签
    # 起始刻度
    svg.append(f'<line x1="{margin}" y1="{height/2-5}" x2="{margin}" y2="{height/2+35}" stroke="#666" stroke-width="0.1"/>')  # 刻度线
    svg.append(f'<text x="{margin}" y="{height/2-8}" text-anchor="middle" font-family="Arial" font-size="10" fill="#666">{hex(entry_addr)}</text>')
    # 结束刻度
    svg.append(f'<line x1="{end_pos}" y1="{height/2-5}" x2="{end_pos}" y2="{height/2+35}" stroke="#666" stroke-width="0.1"/>')  # 刻度线
    svg.append(f'<text x="{end_pos}" y="{height/2-8}" text-anchor="middle" font-family="Arial" font-size="10" fill="#666">{hex(entry_addr + total_bytes)}</text>')
    # 添加总字节数信息
    svg.append(f'<text x="{width/2}" y="{height/2+50}" text-anchor="middle" font-family="Arial" font-size="12" fill="#333">总字节数: {total_bytes}</text>')
    # 完成SVG
    svg.append('</svg>')
    
    return ''.join(svg) 


if __name__ == "__main__":
    paths = [
        '/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/ppc/ppc_be_vxwork_os.elf',
        "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/arm/FreeRTOS_ThreadCreation.elf",
        "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/mips/busybox.elf",
        # "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/tricore/ADC_Background_Scan_1_KIT_TC297_TFT.elf"    
    ]
    out_dir = "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output"

    for elf_fpth in paths:
        print('==>', elf_fpth)
        # 获取文件夹路径、文件名
        dir_path, elf_file = os.path.split(elf_fpth)
        arch = dir_path.split('/')[-1]
        # 从ELF文件中抽取信息
        entry_addr, record = extract_code_block_from_elf(elf_fpath=elf_fpth)
        # bin文件路径
        bin_file_bytes = b""
        bin_file_path = dir_path + '/bin/' +  re.sub('.elf', f'_0x{entry_addr:x}.bin', elf_file)
        with open(file=bin_file_path, mode='rb') as fr:
            bin_file_bytes = fr.read()
        # 代码块的划分与展示
        # all_addr = sorted([(addr, addr + record[addr]['size']) for addr in record.keys() if record[addr]['size'] > 0], key=lambda x: x[1])
        # print([(hex(saddr), hex(eaddr)) for saddr, eaddr in all_addr])
        svg_text = block_display(
            entry_addr=entry_addr, 
            whole_bin=bin_file_bytes, 
            bin_blocks=[(addr - entry_addr, record[addr]['size']) for addr in record.keys() if record[addr]['size'] > 0]
        )
        svg_file = elf_file.replace('.elf', '.svg')
        with open(file=out_dir + f'/{arch}/{svg_file}', mode='w', encoding='utf-8') as fw:
            fw.write(svg_text)
