import os
import re
import json

from eval.calc import *
from utils.bytes_op import bytes_fmt_compare
from utils.config_processor import features_configure_init
from analysis.instruction_analysis import BinaryBlock, create_block_pair, ins_pair_identify, call_instructions_rebuild

config_dir = '../resources/ISA/config/'
demo_dir = '../resources/samples/'

# PPC32
regex_ppc_blr = br"\x4e\x80\x00\x20"

regex_ppc_mfspr = br"[\x7c\x7d\x7e\x7f].\x02\xa6"
ppc_mfspr_LR_fmt = b"\x7c\x08\x02\xa6"
ppc_mfspr_LR_mask = b"\xfc\x1f\xff\xff"

regex_ppc_b = br"[\x48\x49\x4a\x4b]..."


def powerPCAnalysis(path: str):
    binary_res = b''
    with open(file=path, mode='rb') as fread:
        binary_res = fread.read()

    search_mfspr_res = re.finditer(regex_ppc_mfspr, binary_res)
    search_blr_res = re.finditer(regex_ppc_blr, binary_res)
    # search_b_res = re.finditer(regex_ppc_b, binary_res)
    
    mfspr_result = [res.group().hex() for res in search_mfspr_res if bytes_fmt_compare(mask=ppc_mfspr_LR_mask, ins=res.group(), fmt_ins=ppc_mfspr_LR_fmt)]
    blr_result = [res.group().hex() for res in search_blr_res]
    print(f"Push stack: {len(mfspr_result)} | Pop Stack: {len(blr_result)} | Abs Rate = {calc_pair_rate(len(mfspr_result), len(blr_result)) * 100: .2f}%")


def archAnalysis(isa_arch: str, path: str, ins_pair_fp: str, branch_calc_fp: str, endian: str):
    # 必要文件获取
    isa_arch = isa_arch.upper()
    binary_res = b''
    ins_pair_dict = dict()
    branch_calc_info = dict()

    with open(file=path, mode='rb') as fr:
        binary_res = fr.read()
    with open(file=ins_pair_fp, mode='r', encoding='utf-8') as fr:
        ins_pair_dict = json.load(fp=fr)
    with open(file=branch_calc_fp, mode='r', encoding='utf-8') as fr:
        branch_calc_info = json.load(fp=fr).get(isa_arch.lower())
    
    # 其他设置
    # BRANCH
    arch_info = {"arch": "triCore", "ins_tag": "call-r-func", "endian": "le", "reverse_unit": 4, "address_length": 4} if isa_arch == "TRICORE" else {}
    BinaryBlock.load_configure_info(
        arch=isa_arch, 
        inner_pairs_dict=ins_pair_dict['PAIRS']['INNER_BLOCK_PAIRS'], 
        instructions_info=ins_pair_dict['INSTRUCTIONS']
    )
    
    # 从BLOCK中识别
    for k, pair_ls in ins_pair_dict['PAIRS']['BLOCK_PAIRS'].items():
        print(f"PROCESS BLOCK TYPE - {k}")
        for bp in pair_ls:
            # 获取信息
            head_ins, tail_ins = bp['ins']
            features = features_configure_init(head_ins, tail_ins, bp['features'])
            reverse_unit = ins_pair_dict['OTHERS']['MemoryArgs']['reverse_unit_size']
            min_instr_length = ins_pair_dict['OTHERS']['MemoryArgs']['min_instr_length']
            alignment_bytes_size = ins_pair_dict['OTHERS']['MemoryArgs']['alignment_size']
            
            # ======================================== <抽取指令对儿> ========================================
            possible_block_head, possible_block_tail = ins_pair_identify(
                ins1=head_ins, ins2=tail_ins, 
                endian=endian, binary=binary_res, 
                ins_dict={head_ins: ins_pair_dict['INSTRUCTIONS'][head_ins], tail_ins: ins_pair_dict['INSTRUCTIONS'][tail_ins]}, 
                reverse_unit=reverse_unit
            )
            print(f"{head_ins.upper()}: {len(possible_block_head)} | {tail_ins.upper()}: {len(possible_block_tail)}")
            print(f"      PAIR_RATE = {calc_pair_rate(len(possible_block_head), len(possible_block_tail)) * 100: .2f}%")
            print(f"HEAD BYTES_RATE = {calc_InsBytesBinaryFile_rate(possible_block_head, len(binary_res))*100: .5f}%")
            print(f"TAIL BYTES_RATE = {calc_InsBytesBinaryFile_rate(possible_block_tail, len(binary_res))*100: .5f}%")
            # 指令对儿组合
            print("POSSIBLE CALL INS NUMBERS:", len(possible_block_head))

            # ======================================== <指令对儿组合> ========================================
            # print([instr.hex() for instr, _, _ in possible_block_head])
            if k == 'BRANCH':
                possible_block_head = call_instructions_rebuild(
                    arch_info=arch_info,
                    calc_info=branch_calc_info,
                    call_instructions=possible_block_head,
                    org_binary=binary_res
                )
            block_pairs = create_block_pair(
                arch = isa_arch,
                endian = endian,
                ins_collection1 = possible_block_head,
                ins_collection2 = possible_block_tail,
                reverse_unit = reverse_unit,
                min_ins_length = min_instr_length,
                alignment_bytes=alignment_bytes_size,
                features=features
            )

            # ======================================== <BLOCK的创建于内部分析> ========================================
            count = 0
            valid_blocks, it_blocks = [], []
            for block_pair in block_pairs:
                block_bytes = binary_res[block_pair[0][1]: block_pair[1][2]]
                # print(f"{block_pair}\n{block_bytes}")
                cur_block = BinaryBlock(endian=endian, block_stack_pair=block_pair, binary=block_bytes)
                if len(cur_block.getInnerBlockPairs()) > 0:
                    it_blocks.append(cur_block)
                    if cur_block.isReversedResultValid(head_ins=head_ins, tail_ins=tail_ins):
                        valid_blocks.append(cur_block)
                    count += 1
                else:
                    count -= 0.5
            # 评估
            calc_BlockRates(blocks=len(block_pairs), blocks_with_pair=len(it_blocks), blocks_valid_reverse=len(valid_blocks))
            


if __name__ == "__main__":
    # # PowerPC分析
    # for ppc_demo in os.listdir(demo_dir+'ppc/'):
    #     print(f'==== {ppc_demo} ====')
    #     powerPCAnalysis(demo_dir+'ppc/'+ppc_demo)
    # ARM分析
    for arh in ['arm', 'tricore', 'ppc', 'mips', 'x86']:
    # for arh in ['tricore']:
        for demo in os.listdir(demo_dir+f'{arh}/bin/'):
            if not os.path.isfile(demo_dir+f'{arh}/bin/'+demo):
                continue
            print(f'\n-------------------- {arh.upper()}:{demo} --------------------')
            print("=> Thumb")
            archAnalysis('arm', demo_dir+f'{arh}/bin/'+demo, config_dir+'arm.json', config_dir+"call_branch.json", endian="LE")
            print("=> TriCore")
            archAnalysis('tricore', demo_dir+f'{arh}/bin/'+demo, config_dir+'tricore.json', config_dir+"call_branch.json", endian="LE")
        #     break
        # break
