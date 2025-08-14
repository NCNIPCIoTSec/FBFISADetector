import os
import re
import bisect
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

from evaluate.extractor import get_all_blocks


def create_segmented_histogram(data: list[tuple], bin_num: int, bin_tags: list[str], segments: int, seg_tags: list[str], seg_colors: list[str], title="Piecewise Histogram", x_label="x axis", y_label="y axis", hist_hw_rate: float = 0.07, plane_height: int = 10):
    """
    创建分段直方图  
    参数:  
    - data: 输入数据，形如[(d1, d2, ...), ...]  
    - bin_num: 直方图的分箱数量  
    - bin_tags: 直方图分箱的标签
    - segments: 每个bin要分割的段数  
    - seg_colors: 每段使用的颜色列表  
    - title: 图表标题  
    - x_label: X轴标签  
    - y_label: Y轴标签  
    """
    # 确保颜色数量与段数匹配
    if len(seg_colors) != segments or len(data[0]) != segments:
        raise ValueError(f"Data or Color Number({len(seg_colors)}) must equal Segments Number({segments})")
    
    # 数值初始化
    highest_hist = max([sum(d) for d in data])
    edge_width = highest_hist * hist_hw_rate
    margin = edge_width * 0.1
    y_ax_len = plane_height  # 图纸高度
    x_ax_len = (bin_num * 1.1 + 0.1) * (y_ax_len / edge_width)  # 图纸宽度
    
    # ========= 创建直方图 =========
    fig, ax = plt.subplots(figsize=(x_ax_len, y_ax_len))  # 创建图形和坐标轴
    x_pos = margin
    all_x_pos = []
    for i in range(bin_num):  # 对于每个bin，创建分段直方图
        y_start = 0
        all_x_pos.append(x_pos + edge_width/2)
        # ax.text(x_pos, 0, bin_tags[i], fontsize=12, color='black')
        for j in range(segments):
            y_pos = y_start
            ax.add_patch(Rectangle((x_pos, y_pos), edge_width, data[i][j], facecolor=seg_colors[j], edgecolor='#888888', linewidth=0.5))
            y_start += data[i][j]
        x_pos += (edge_width + margin)
    
    # 设置坐标轴范围和标签
    ax.set_xlim(0, bin_num*(edge_width+margin)+margin)
    ax.set_ylim(0, highest_hist * 1.1)  # 留出一些空间
    plt.xticks(all_x_pos, bin_tags)

    # 添加文字标签
    ax.set_title(title)
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    
    # 创建图例
    handles = [Rectangle((0, 0), 1, 1, facecolor=seg_colors[i], edgecolor="#888888", linewidth=0.5) for i in range(segments)]
    # handles.extend([])
    # labels.extend(['A'+i for i in range(bin_num)])
    ax.legend(handles, seg_tags)
    
    plt.tight_layout()
    return fig, ax


def get_histogram_data(elf_file_path: str, bin_file_path: str, arch: str, endian: str):
    def shoot(blocks):
        '''
            输入：
            blocks - list[tuple]，格式为[(块A起始地址，块A大小), ...]，块起始地址有序不重复
            全局变量：
            standard_blocks - list[tuple]，格式为[(块A起始地址，块A大小), ...]，块起始地址有序不重复
        '''
        shoot_bingo = set()
        # 提取标准块的起始地址列表，用于二分查找
        std_starts = [sb[0] for sb in standard_blocks]
        m = len(standard_blocks)
        
        for blk in blocks:
            cur_start = blk[0]
            blk_size = blk[1]
            cur_end = cur_start + blk_size
            
            # 二分查找找到第一个起始地址 >= cur_end的标准块索引
            # 所有可能有交集的标准块都在这个索引之前
            right = bisect.bisect_left(std_starts, cur_end)
            
            # 只检查[0, right)范围内的标准块
            for i in range(right):
                sb = standard_blocks[i]
                sb_size, sb_start = sb[1], sb[0]
                sb_end = sb_start + sb_size
                
                # 标准块大小必须 >= 当前块大小
                if sb_size < blk_size:
                    continue
                
                # 标准块结束地址必须 > 当前块起始地址才可能有交集
                if sb_end <= cur_start:
                    continue
                
                # 计算交集大小（简化版）
                overlap_start = max(cur_start, sb_start)
                overlap_end = min(cur_end, sb_end)
                dis = overlap_end - overlap_start
                
                # 交集大小足够
                if dis >= 5:
                    shoot_bingo.add(blk)
                    break  # 找到一个符合条件的就可以停止检查
                
        return shoot_bingo

    blocks_info = get_all_blocks(elf_fpath=elf_file_path, bin_fpath=bin_file_path, arch=arch, endian=endian.upper())
    if blocks_info is None:
        return []
    standard_blocks, pairs_blocks, inner_pairs_blocks, reversing_blocks = set(blocks_info['elf']), set(blocks_info['blocks']), set(blocks_info['blocks_with_inner_pairs']), set(blocks_info['blocks_with_reversing'])
    standard_blocks = sorted(standard_blocks, key=lambda x: x[0])
    pairs_blocks = sorted(pairs_blocks, key=lambda x: x[0])
    
    bingo_blocks = shoot(pairs_blocks)
    inner_valid = set(inner_pairs_blocks).intersection(bingo_blocks)
    reverse_valid = set(reversing_blocks).intersection(bingo_blocks)

    # print(">> STD:\n", standard_blocks)
    # print(">> ORG:\n", pairs_blocks)
    # print(">> ORG-VALID:\n", bingo_blocks)
    # print(">> Final-VALID:\n", reverse_valid)
    print("[STANDARD SEG]", len(standard_blocks))
    print("[BLOCK NUM after ANALYZING]", len(bingo_blocks), '|', len(inner_valid), '|', len(reverse_valid))

    return [(len(standard_blocks), 0), 
            (len(bingo_blocks), len(pairs_blocks) - len(bingo_blocks)), 
            (len(inner_valid), len(inner_pairs_blocks) - len(inner_valid)), 
            (len(reverse_valid), len(reversing_blocks) - len(reverse_valid))]
    

def ablation_study(samples_workspace: str, output_workspace: str, test_arch: str = None):
    endian_table = {'arm': 'le', 'tricore': 'le', 'mips': 'be', "riscv64": "le", "powerpc": "be"}

    def __study_current_arch__(arch_workspace: str, arch_output_workspace: str, cur_arch: str):
        elf2bin_map = {re.sub(r'_0x.*?\.bin', '.elf', fnm):fnm for fnm in os.listdir(arch_output_workspace + "/bin/") if fnm.endswith('.bin')}
        for fnm in os.listdir(arch_workspace):
            # 仅处理ELF文件
            bin_file_name = elf2bin_map.get(fnm)
            if not fnm.endswith('.elf') or bin_file_name is None:
                continue
            elf_file_path = arch_workspace + '/' + fnm
            bin_file_path = output_workspace + cur_arch + '/bin/' + bin_file_name
            print("[ELF-FILE to BIN]", elf_file_path, '==>', bin_file_path)
            del bin_file_name
            # 验证
            tmp_result = get_histogram_data(elf_file_path=elf_file_path, bin_file_path=bin_file_path, arch=cur_arch.upper(), endian=endian_table.get(cur_arch))
            if len(tmp_result) == 0:
                continue
            for i, e in enumerate(tmp_result):
                total_result[i][0] += e[0]
                total_result[i][1] += e[1]

    # 分析
    total_result = [[0, 0], [0, 0], [0, 0], [0, 0]]
    if test_arch is not None:  # 单类架构分析
        test_arch = test_arch.lower()
        if test_arch in endian_table.keys():
            __study_current_arch__(arch_workspace=samples_workspace + test_arch, arch_output_workspace=output_workspace + test_arch, cur_arch=test_arch)
    else:  # 多架构分析
        for arch in os.listdir(samples_workspace):
            arch_workspace = samples_workspace + arch
            if not arch in endian_table.keys() or os.path.isfile(arch_workspace):
                continue
            __study_current_arch__(arch_workspace=arch_workspace, arch_output_workspace=output_workspace + arch, cur_arch=arch)

        
    
    # 百分比
    for cent in total_result:
        TT = cent[0]
        TF = cent[1]
        rate = (TT / (TT + TF))*100 if (TT > 0 and TF > 0) else 0
        print(f"{TT}/({TT}+{TF}) = {rate:.2f}%")

    return [tuple(ele) for ele in total_result]


if __name__ == "__main__":
    import settings

    samples = [
        (
            "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/arm/p2im_drone.elf", 
            "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output/arm/bin/p2im_drone_0x8000000.bin", 
            "ARM", "LE"
        ),
        (
            "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/tricore/ASCLIN_Shell_UART_1_KIT_TC297_TFT.elf", 
            "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output/tricore/bin/ASCLIN_Shell_UART_1_KIT_TC297_TFT_0x60000000.bin", 
            "TriCore", "LE"
        ),
        (
            "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/tricore/ASCLIN_LIN_Master_1_KIT_TC297_TFT.elf",
            "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output/tricore/bin/ASCLIN_LIN_Master_1_KIT_TC297_TFT_0x60000000.bin",
            "TriCore", "LE"
        ),
        (
            "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/resources/samples/mips/helloworld_be_mips_r3000.elf",
            "/home/yq/workspace/studies/MyProjects/FirmISAIdentify/output/mips/bin/helloworld_be_mips_r3000_0x0.bin",
            "MIPS", "BE"
        ),
    ]

    for felf, fbin, arch, endian in samples:
        print("=>" * 75)
        data = get_histogram_data(
            elf_file_path=felf, 
            bin_file_path=fbin, 
            arch=arch, 
            endian=endian
        )
        print(data)



