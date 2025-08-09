import os
import re
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


def get_histogram_data(elf_file_path: str, bin_file_path: str, endian: str):
    def shoot(blocks):
        sorted_blocks = sorted(blocks, key=lambda x: x[0])
        shoot_bingo = set()
        for blk in sorted_blocks:
            cur_scope = (blk[0], blk[0] + blk[1])
            for sb in standard_blocks:
                std_scope = (sb[0], sb[0] + sb[1])
                if (std_scope[0] > cur_scope[1]) or (std_scope[1] < cur_scope[0]):
                    continue
                if sb[1] > blk[1]:
                    continue
                
                dis = 0
                if cur_scope[0] < std_scope[0]:
                    if cur_scope[1] > std_scope[1]:
                        dis = std_scope[1] - std_scope[0]
                    else:
                        dis = cur_scope[1] - std_scope[0]
                else:
                    if cur_scope[1] > std_scope[1]:
                        dis = std_scope[1] - cur_scope[0]
                    else:
                        dis = cur_scope[1] - cur_scope[0]
                if dis < 5:
                    continue
                
                # print(std_scope, cur_scope)
                shoot_bingo.add(blk)
                break

        # i, j = 0, 0
        # std_num, blk_num = len(standard_blocks), len(blocks)
        # while i < std_num and j < blk_num:
        #     std_scope = (standard_blocks[i][0], standard_blocks[i][0] + standard_blocks[i][1])
        #     cur_scope = (sorted_blocks[j][0], sorted_blocks[j][0] + sorted_blocks[j][1])
        #     # print(std_scope, cur_scope)
        #     if (std_scope[0] < cur_scope[0] < std_scope[1]) or (std_scope[0] < cur_scope[1] < std_scope[1]):
        #         shoot_bingo.add(sorted_blocks[j])
        #     elif std_scope[1] < cur_scope[0]:
        #         i += 1
        #         continue
        #     j += 1

        return shoot_bingo

    blocks_info = get_all_blocks(elf_fpath=elf_file_path, bin_fpath=bin_file_path, endian=endian.upper())
    if blocks_info is None:
        return []
    standard_blocks, pairs_blocks, inner_pairs_blocks, reversing_blocks = set(blocks_info['elf']), set(blocks_info['blocks']), set(blocks_info['blocks_with_inner_pairs']), set(blocks_info['blocks_with_reversing'])
    standard_blocks = sorted(standard_blocks, key=lambda x: x[0])

    print(standard_blocks)
    print(reversing_blocks)
    print("STANDARD BLOCK NUM:", len(standard_blocks))
    print("BLOCK NUM after ANALYZING:", len(pairs_blocks), '->', len(inner_pairs_blocks), '->', len(reversing_blocks))

    bingo_blocks = shoot(pairs_blocks)
    inner_valid = set(inner_pairs_blocks).intersection(bingo_blocks)
    reverse_valid = set(reversing_blocks).intersection(bingo_blocks)

    print(bingo_blocks, inner_valid, reverse_valid)
    print(len(bingo_blocks), len(inner_valid), len(reverse_valid))

    return [(len(standard_blocks), 0), 
            (len(bingo_blocks), len(pairs_blocks) - len(bingo_blocks)), 
            (len(inner_valid), len(inner_pairs_blocks) - len(inner_valid)), 
            (len(reverse_valid), len(reversing_blocks) - len(reverse_valid))]
    

def ablation_study(samples_workspace: str, output_workspace: str):
    endian_table = {'arm': 'le', 'tricore': 'le', 'mips': 'be'}

    total_result = [[0, 0], [0, 0], [0, 0], [0, 0]]
    for arch in os.listdir(samples_workspace):
        arch_workspace = samples_workspace + arch
        if not arch in endian_table.keys() or os.path.isfile(arch_workspace):
            continue
        elf2bin_map = {re.sub(r'_0x.*?\.bin', '.elf', fnm):fnm for fnm in os.listdir(output_workspace + arch) if fnm.endswith('.bin')}
        for fnm in os.listdir(arch_workspace):
            # 仅处理ELF文件
            bin_file_name = elf2bin_map.get(fnm)
            if not fnm.endswith('.elf') or bin_file_name is None:
                continue
            elf_file_path = arch_workspace + '/' + fnm
            bin_file_path = output_workspace + arch + '/' + bin_file_name
            del bin_file_name
            tmp_result = get_histogram_data(elf_file_path=elf_file_path, bin_file_path=bin_file_path, endian=endian_table.get(arch))
            if len(tmp_result) == 0:
                continue
            for i, e in enumerate(tmp_result):
                total_result[i][0] += e[0]
                total_result[i][1] += e[1]
    
    # 百分比
    for cent in total_result:
        TT = cent[0]
        TF = cent[1]
        rate = TT / (TT + TF)
        print(f"{TT}/({TT}+{TF}) = {rate*100:.2f}%")

    return [tuple(ele) for ele in total_result]

