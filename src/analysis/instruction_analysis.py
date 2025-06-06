import re
import json
import pypcode
import capstone as cps
from multiprocessing import Pool, cpu_count

from evaluate.calc import calc_BlockRates, calc_BlockPairInstrRates
from utils.config_processor import features_configure_init
from utils.translator import hexString2bytes, string2bytes_regex
from utils.bytes_op import bytes_reverse, get_register_num, bytes_fmt_compare
from analysis.branch_analysis import get_branch_addr_multiprocessing


CAPSTONE_PROCESSOR_ARCHITECTURES = {
    "ARM": {
        "ARCH": cps.CS_ARCH_ARM,
        "MODES": [cps.CS_MODE_THUMB, cps.CS_MODE_ARM]
    },
    "TRICORE": {
        "ARCH": cps.CS_ARCH_TRICORE,
        "MODES": [cps.CS_MODE_TRICORE_180]
    },
    "MIPS": {
        "ARCH": cps.CS_ARCH_MIPS,
        "MODES": [
            cps.CS_MODE_MIPS16, 
            cps.CS_MODE_MIPS32,
            cps.CS_MODE_MIPS64,
            cps.CS_MODE_MIPS32R6, 
            cps.CS_MODE_MIPS64R6, 
            cps.CS_MODE_NANOMIPS
        ]
    }
}


GHIDRA_PROCESSOR_ARCHITECTURES = {
    "ARM": {
        "GHIDRA_ARCH_NAME": "ARM",
        "SPACE_SIZE": 32,
        "VARIANTS": [
            "Cortex", "v4", "v4t", "v5", "v5t", "v6", "v7", "v8", "v8-m", "v8T"
        ]
    },
    "TRICORE": {
        "GHIDRA_ARCH_NAME": "tricore",
        "SPACE_SIZE": 32,
        "VARIANTS": [
            "default", "tc172x", "tc176x", "tc29x"
        ]
    },
    "MIPS": {
        "GHIDRA_ARCH_NAME": "MIPS",
        "SPACE_SIZE": 32,
        "VARIANTS": [
            "default", "R6", "micro"
        ]
    }
}


class BinaryBlock:
    '''
    - 代码块内分析：  
      - FUNC-1. 获取指令对关系：获取所有块内指令对；  
    '''
    arch: str = None
    inner_pairs_list: list = None
    instructions_info: dict = {}
    complete_binary = b''

    @classmethod
    def loadConfigureInfo(cls, arch: str, inner_pairs_list: dict, instructions_info: dict):
        """
        获取类的相关配置信息
        """
        cls.arch = arch.upper()
        cls.inner_pairs_list = inner_pairs_list
        cls.instructions_info = instructions_info
        # TODO:其他参数，建议读取配置文件信息实现配置
        cls.reverse_unit = 2  # 字节序反转，按多少字节反转
        cls.min_ins_length = 2  # 指令字最短的指令占多少字节长度
        cls.max_ins_length = 4
        cls.alignment_bytes = 2  # 指令对齐字节长度
        cls.address_length = 4  # 地址空间位数（4*8=32位）
        if arch == 'ARM':
            pass
        elif arch == "MIPS":
            cls.min_ins_length = 4
            cls.reverse_unit = 4
            cls.alignment_bytes = 4
        elif arch == 'TRICORE':
            cls.reverse_unit = 4

    @ classmethod
    def loadCompleteBinary(cls, binary: bytes):
        cls.complete_binary = binary

    def __init__(self, endian: str, block_pair_instr: tuple[str, str], block_pair_data: tuple[tuple, tuple]):
        # 要求先初始化类信息
        if self.arch is None:
            print("[BinaryBlock Class Exception] Please Load Class Configuration information first, and then initialize this object...")
            raise Exception
        # 创建对象，配置其信息
        self.endian = endian.upper()
        self.head_instr, self.tail_instr = self.instr_preprocess(block_pair_instr[0]), self.instr_preprocess(block_pair_instr[1])
        self.block_pair = block_pair_data
        # 输出结果记录
        self.high_frequency_instr: list = []
        self.is_valid_block: bool = None  # record final judgement result - Boolean
        self.inner_pairs: list = []  # record pairs found by func-get_inner_block_pairs
        self.disassemble_record: dict = {"capstone_arch": None, "capstone_mode": None, "offset": None}  # record disassemble args result from capstone

    def instr_preprocess(self, instr: str) -> set[str]:
            '''
            添加一些预处理操作，处理call指令跳转和指令名称的问题
            '''
            instr_class = set()
            # 获取指令信息
            if instr.lower().endswith("-func"):
                instr_class.add("*")
            else:
                all_descriptions: list[str] = self.instructions_info[instr].get("descriptions")
                if all_descriptions is None:
                    print(f"[ERROR] <ARCH={self.arch}> Configure File with instruction '{instr}' has no descriptions information!")
                    raise Exception
                for des in all_descriptions:
                    original_ins = des.split('-')[0].strip()
                    for eins in original_ins.split(";"):
                        instr_class.add(eins.strip().lower())

            return instr_class
    
    def isCapstoneReversedPairsValid(self) -> bool:
        """
        Capstone 线性扫描逆向分析算法来分析“可能”为函数块
        """
        # 如果是CAPSTONE不支持的架构，不做过滤
        if CAPSTONE_PROCESSOR_ARCHITECTURES.get(self.arch) is None:
            return True
        # 如果指令长度固定，不做处理
        if self.min_ins_length == self.max_ins_length:
            return True

        # print(self.binary.hex())
        # 根据架构初始化
        offset = 0x10000
        capstone_arguments = CAPSTONE_PROCESSOR_ARCHITECTURES[self.arch]
        if self.arch == 'ARM':
            offset = 0x08000000
        elif self.arch == 'TRICORE':
            offset = 0x80000000
        block_offset = offset + self.block_pair[0][1]
        
        # For Inner Pairs Check
        inner_pairs_addr = {}
        for pair_info in self.inner_pairs:
            ins1, ins2 = pair_info["ins"]
            for pair in pair_info["details"]:
                inner_pairs_addr[block_offset + pair[0][1]] = self.instr_preprocess(ins1)
                inner_pairs_addr[block_offset + pair[1][1]] = self.instr_preprocess(ins2)
        # print(inner_pairs_addr)

        # 反汇编分析：线性扫描算法
        flag = False
        for cs_mode in capstone_arguments['MODES']:
            cs_mode_with_endian = cs_mode | cps.CS_MODE_BIG_ENDIAN if self.endian == 'BE' else cs_mode | cps.CS_MODE_LITTLE_ENDIAN
            md = cps.Cs(arch=capstone_arguments['ARCH'], mode=cs_mode_with_endian)
            reverse_res = []
            for ins in md.disasm(code=self.complete_binary[self.block_pair[0][1]: self.block_pair[1][2]], offset=block_offset):
                ins_addr, ins_bytes, ins_mnemonic, ins_op_str = ins.address, ins.bytes, ins.mnemonic.lower(), ins.op_str.lower()
                if (inner_instr_set := inner_pairs_addr.get(ins_addr)) is not None and ins_mnemonic not in inner_instr_set:
                    # print(f"0x{ins_addr:x}\t0x{bytes(ins_bytes).hex():8s}\t{ins_mnemonic}  {ins_op_str} | Exception is ({inner_instr_set})...")
                    reverse_res.clear()
                    break
                reverse_res.append((ins_addr, ins_bytes, ins_mnemonic, ins_op_str))
            # 首尾指令检测
            if len(reverse_res) > 0 and ("*" in self.head_instr or reverse_res[0][2] in self.head_instr ) and ("*" in self.tail_instr or reverse_res[-1][2] in self.tail_instr):
                self.disassemble_record["capstone_arch"] = capstone_arguments['ARCH']
                self.disassemble_record["capstone_mode"] = cs_mode_with_endian
                self.disassemble_record["offset"] = block_offset
                # 标记flag
                flag = True
                break
        return flag
    
    def isGhidraReversedPairsValid(self) -> bool:
        '''
        使用Ghidra的P-Code进行分析
        '''
        # 如果指令长度固定，不做处理
        if self.min_ins_length == self.max_ins_length:
            return True

        # 根据架构初始化
        offset = 0x10000
        if self.arch == 'ARM':
            offset = 0x08000000
        elif self.arch == 'TRICORE':
            offset = 0x80000000
        block_offset = offset + self.block_pair[0][1]

        # 块内指令对检测
        inner_pairs_addr = {}
        for pair_info in self.inner_pairs:
            ins1, ins2 = pair_info["ins"]
            for pair in pair_info["details"]:
                inner_pairs_addr[block_offset + pair[0][1]] = self.instr_preprocess(ins1)
                inner_pairs_addr[block_offset + pair[1][1]] = self.instr_preprocess(ins2)

        # 当前指令集架构的所有变体
        ghidra_arch_name = GHIDRA_PROCESSOR_ARCHITECTURES[self.arch]["GHIDRA_ARCH_NAME"]
        arch_space_size = GHIDRA_PROCESSOR_ARCHITECTURES[self.arch]["SPACE_SIZE"]
        isa_variants = [
            f"{ghidra_arch_name}:{self.endian}:{arch_space_size}:{var}"
            for var in GHIDRA_PROCESSOR_ARCHITECTURES[self.arch]["VARIANTS"]
        ]
        
        # 分析当前架构的所有变体，检测是否存在变体可以正确地反汇编
        flag = False
        analyzing_bytes = self.complete_binary[self.block_pair[0][1]: self.block_pair[1][2]]
        for isa_var in isa_variants:
            ctx= pypcode.Context(isa_var)
            # 反汇编分析：线性扫描算法
            disasm_result = ctx.disassemble(analyzing_bytes, block_offset)
            # 逆向结果分析
            reverse_res = []
            for instr in disasm_result.instructions:
                instr_addr, instr_mnemonic, instr_op_str = instr.addr, instr.mnem, instr.body
                # 如果“块内指令对”的位置处找到了不合理的指令反汇编，则认为反汇编无意义，跳过
                if (inner_instr_set := inner_pairs_addr.get(instr_addr)) is not None and instr_mnemonic not in inner_instr_set:
                    reverse_res.clear()
                    break
                reverse_res.append((instr_addr, instr_mnemonic, instr_op_str))
            if len(reverse_res) > 0 and ("*" in self.head_instr or reverse_res[0][1] in self.head_instr ) and ("*" in self.tail_instr or reverse_res[-1][1] in self.tail_instr):
                flag = True
                break

        return flag

    def getInnerBlockPairs(self): 
        """
        识别所有指令对儿；
        """
        # print(f'=== FUNC: {self.block_pair} ===')
        # 识别
        for cur_type_pair in self.inner_pairs_list:
            ins1, ins2 = cur_type_pair["ins"]
            possible_ins1, possible_ins2 = ins_pair_identify(
                ins1=ins1, 
                ins2=ins2, 
                endian=self.endian, 
                binary=self.complete_binary[self.block_pair[0][1]: self.block_pair[1][2]], 
                ins_dict={ins1: self.instructions_info[ins1], ins2: self.instructions_info[ins2]}, 
                reverse_unit=self.reverse_unit
            )
            # 筛掉不合理的指令，如起始地址为奇数的
            possible_ins1 = [match_ins for match_ins in possible_ins1 if match_ins[1] % 2 == 0]
            possible_ins2 = [match_ins for match_ins in possible_ins2 if match_ins[1] % 2 == 0]
            # 若为空，则认为不存在本指令对儿
            if len(possible_ins1) == 0 or len(possible_ins2) == 0:
                continue
            # 特征识别 + 组对儿
            cur_pairs = create_block_pair(
                ins_collection1=possible_ins1, 
                ins_collection2=possible_ins2, 
                features=features_configure_init(head_instr=ins1, tail_instr=ins2, features=cur_type_pair["features"]), 
                endian=self.endian, 
                reverse_unit=self.reverse_unit, 
                min_ins_length=self.min_ins_length,
                alignment_bytes=self.alignment_bytes
            )
            if len(cur_pairs) == 0:
                continue
            # 记录
            if self.inner_pairs is None:
                self.inner_pairs = []
            content = {"ins": (ins1, ins2), "type": cur_type_pair["type"], "details": cur_pairs}
            self.inner_pairs.append(content)
        
        return self.inner_pairs
    
    def getBelongedFunctionBlock(self):
        '''
        当但当前程序可以正常线性扫描反汇编时，尝试寻找其所属的函数体的完整汇编代码；
        '''
        # 如果当前的块未进行反汇编    
        if self.disassemble_record["capstone_arch"] is None and self.disassemble_record["capstone_mode"] is None:
            if not self.isCapstoneReversedPairsValid():  # 如果当前块反汇编后的与预估的指令对不对应，抛弃可能的不合理块
                print("[Error] Block cannot be successfully reversed!")
                return
        disassembler = cps.Cs(arch=self.disassemble_record["capstone_arch"], 
                              mode=self.disassemble_record["capstone_mode"])

        start, end = self.block_pair[0][1], self.block_pair[1][2]
        disasm_iter = disassembler.disasm(code=self.complete_binary[start:end], offset=self.disassemble_record["offset"])
        print("==> REVERSing: ")
        for ins in disasm_iter:
            addr, ins_bytes, mnemonic, op_str = ins.address, ins.bytes, ins.mnemonic.lower(), ins.op_str.lower()
            print(f"0x{addr:x}\t0x{bytes(ins_bytes).hex():8s}\t{mnemonic}  {op_str}")
    

class BlocksFilter:
    '''
    得到的二进制块进行过滤分析；
    '''
    def __init__(self, blocks: list[BinaryBlock]):
        self.blocks = blocks
        self.have_pairs_blocks = []
        self.reversed_ht_valid_blocks = []

    def filterBlocksByInnerPairs(self) -> list[BinaryBlock]:
        self.have_pairs_blocks = [i for i, block in enumerate(self.blocks) if len(block.getInnerBlockPairs()) > 0]
        return self.have_pairs_blocks
    
    def filterBlocksByHeadTailCheck(self) -> list[BinaryBlock]:
        self.reversed_ht_valid_blocks = [j for j in self.have_pairs_blocks if self.blocks[j].isGhidraReversedPairsValid()]
        return self.reversed_ht_valid_blocks


class BinaryAnalyzer:
    supported_arch = dict()
    branch_calc_info = dict()

    @classmethod
    def updateSupportedArch(cls, supported_arch_info: dict):
        '''
        - 输入：
          - arch_info: dict, 支持的架构以及架构配置文件的存储路径  
            形式如：{"ARM": "../resources/ISA/config/arm.json", "TriCore": "../resources/ISA/config/tricore.json"}  
        '''
        cls.supported_arch = dict()
        for k in supported_arch_info.keys():
            cls.supported_arch[k.upper()] = supported_arch_info[k]

    @classmethod
    def loadBrachCalculationExpressions(cls, branch_calc_info_path: str = "../resources/ISA/config/call_branch.json"):
        with open(file=branch_calc_info_path, mode='r', encoding='utf-8') as fr:
            cls.branch_calc_info = json.load(fp=fr)

    def __init__(self, bin_file_path: str):
        # 读取二进制文件内容
        self.binary_res = b''
        with open(file=bin_file_path, mode='rb') as fr:
            self.binary_res = fr.read()

    def archAnalysis(self, isa_arch: str, endian: str, ins_pair_dict: dict):
        '''
        指定特定架构和特定
        '''
        # 设置
        branch_calc_certain_arch = self.branch_calc_info.get(isa_arch.lower())
        BinaryBlock.loadCompleteBinary(binary=self.binary_res)
        BinaryBlock.loadConfigureInfo(
            arch=isa_arch, 
            inner_pairs_list=ins_pair_dict['PAIRS']['INNER_BLOCK_PAIRS'], 
            instructions_info=ins_pair_dict['INSTRUCTIONS']
        )
        
        # 从BLOCK中识别
        for bp in ins_pair_dict['PAIRS']['BLOCK_PAIRS']:
            k = bp["type"]
            print(f"PROCESS BLOCK TYPE - {k}")
            address_length = ins_pair_dict['OTHERS']['MemoryArgs']['address_length']
            reverse_unit = ins_pair_dict['OTHERS']['MemoryArgs']['reverse_unit_size']
            min_instr_length = ins_pair_dict['OTHERS']['MemoryArgs']['min_instr_length']
            alignment_bytes_size = ins_pair_dict['OTHERS']['MemoryArgs']['alignment_size']
            # 获取信息
            head_ins, tail_ins = bp['ins']
            features = features_configure_init(head_ins, tail_ins, bp['features'])
            # ======================================== <抽取指令对儿> ========================================
            possible_block_head, possible_block_tail = ins_pair_identify(
                ins1=head_ins, ins2=tail_ins, 
                endian=endian, binary=self.binary_res, 
                ins_dict={head_ins: ins_pair_dict['INSTRUCTIONS'][head_ins], tail_ins: ins_pair_dict['INSTRUCTIONS'][tail_ins]}, 
                reverse_unit=reverse_unit
            )
            # 评估
            calc_BlockPairInstrRates((head_ins, tail_ins), [possible_block_head, possible_block_tail], len(self.binary_res))
            # ======================================== <指令对儿组合> ========================================
            # print([instr.hex() for instr, _, _ in possible_block_head])
            if k == 'BRANCH':
                if branch_calc_certain_arch is None:
                    print(f"[BRACH-{head_ins}:{tail_ins}] Not Have Calculation-Expressions Recorded in Configuration-File...")
                    continue
                possible_block_head = call_instructions_rebuild(
                    arch_info={
                        "arch": isa_arch,
                        "ins_tag": head_ins,
                        "endian": endian,
                        "reverse_unit": reverse_unit,
                        "address_length": address_length
                    },
                    calc_info=branch_calc_certain_arch,
                    call_instructions=possible_block_head,
                    org_binary=self.binary_res
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
            blocks = []
            for block_pair in block_pairs:
                blocks.append(
                    BinaryBlock(endian=endian, block_pair_instr=(head_ins, tail_ins), block_pair_data=block_pair)
                )
            del block_pairs
            blk_filter = BlocksFilter(blocks=blocks)
            del blocks
            # 评估
            calc_BlockRates(blocks=len(blk_filter.blocks), blocks_with_pair=len(blk_filter.filterBlocksByInnerPairs()), blocks_valid_reverse=len(blk_filter.filterBlocksByHeadTailCheck()))
            # ======================================== <数据流分析> ========================================
            # for blk_index in blk_filter.reversed_ht_valid_blocks:
            #     blk_filter.blocks[blk_index].getBelongedFunctionBlock()

    def analyzing(self):
        for arch in self.supported_arch.keys():
            arch = arch.upper()
            print(f'\n=> {arch}')
            # 获取本架构支持的字节序
            ins_pair_dict = dict()
            with open(file=self.supported_arch.get(arch), mode='r', encoding='utf-8') as fr:
                ins_pair_dict = json.load(fp=fr)
            # 配置文件信息不完善，PASS
            if ins_pair_dict.get("INSTRUCTIONS") is None or ins_pair_dict.get("PAIRS") is None or ins_pair_dict.get("OTHERS") is None:
                continue
            supported_endian = ins_pair_dict['OTHERS']['SupportedEndian'].upper()
            # pprint.pprint(ins_pair_dict)
            # 分析
            if supported_endian == '*':
                print(f'-------------------- {arch}:LE --------------------')
                self.archAnalysis(isa_arch=arch, endian='LE', ins_pair_dict=ins_pair_dict)
                print(f'-------------------- {arch}:BE --------------------')
                self.archAnalysis(isa_arch=arch, endian='BE', ins_pair_dict=ins_pair_dict)
            else:
                print(f'-------------------- {arch}:{supported_endian} --------------------')
                self.archAnalysis(isa_arch=arch, endian=supported_endian, ins_pair_dict=ins_pair_dict)


############################# 指令搜索算法 #############################
def search_ins_by_regex(regex: re.Match[bytes], format: bytes, mask: bytes, binary: bytes) -> list[tuple]:
    """
    通过正则表达式搜寻可能的指令；  
    """
    final_res, lbin = [], len(binary)
    cur_ins_len = len(mask)

    # print(re.findall(regex, binary))
    # print([binascii.hexlify(match).decode() for match in re.findall(regex, binary)])
    # print([res for res in  re.finditer(regex, binary)])
    for res in re.finditer(regex, binary):
        start, end = res.start(), res.end()
        # 防止匹配的字节串中，存在以交叉字节为起始，符合正则表达式的“字节串”
        for i in range(cur_ins_len):
            # 异常条件
            if (end + i) > lbin:
                break
            # 获取交叉字节为起始的字节串
            ins_bin = binary[start + i: end + i]
            cur_res = re.match(regex, ins_bin) 
            if cur_res is None:
                continue
            # 检验合理性
            # print(cur_res.group().hex())
            if bytes_fmt_compare(ins=ins_bin, fmt_ins=format, mask=mask):
                final_res.append((cur_res.group(), start + i, end + i))

    return final_res


def single_ins_analysis(ins: str, endian: str, binary: bytes, ins_dict: dict, reverse_unit: int) -> list[tuple]:
    '''
    单条指令数量统计
    '''
    # 大小端转换
    def endian_transfer(ins_format: bytes, ins_mask: bytes):
        return bytes_reverse(ins_format, reverse_unit), bytes_reverse(ins_mask, reverse_unit)

    all_possible_res = []
    for i, regex in enumerate(ins_dict[ins]['regex']):
        # dict中获取信息
        ins_fmt, ins_msk = hexString2bytes(ins_dict[ins]['format'][i]), hexString2bytes(ins_dict[ins]['mask'][i])
        # 大小端是否变化
        is_endian_reverse = not (ins_dict[ins]['endian'].lower() == endian.lower())
        ins_regex = string2bytes_regex(regex_exp=regex, reverse=is_endian_reverse, reverse_unit=reverse_unit)
        # print(f"[string2bytes_regex func] <{regex}> is transformed to <{ins_regex}>!")
        if is_endian_reverse:
            ins_fmt, ins_msk = endian_transfer(ins_format=ins_fmt, ins_mask=ins_msk)
        # print(ins_fmt.hex(), ins_msk.hex())
        # 分析
        search_res = search_ins_by_regex(regex=ins_regex, binary=binary, format=ins_fmt, mask=ins_msk)
        # 统计
        all_possible_res.extend(search_res)

    return all_possible_res


def ins_pair_identify(ins1: str, ins2: str, endian: str, binary: bytes, ins_dict: dict, reverse_unit: int) -> tuple[list[tuple], list[tuple]]:
    '''
    指令对儿识别  
    '''

    ins1_result = single_ins_analysis(ins=ins1.lower(), endian=endian, binary=binary, ins_dict=ins_dict, reverse_unit=reverse_unit)
    ins2_result = single_ins_analysis(ins=ins2.lower(), endian=endian, binary=binary, ins_dict=ins_dict, reverse_unit=reverse_unit)

    return ins1_result, ins2_result


############################# 跳转指令预处理 #############################
def call_instructions_rebuild(arch_info: dict, calc_info: dict, call_instructions: list[tuple], org_binary: bytes) -> list[tuple]:
    """
    - 输入：
      - arch_info: dict, 记录了架构相关信息，架构、当前处理的指令、字节序、对齐字节、地址大小范围（4字节=32位/8字节=64位），形式如{"arch": "arm"(str), "ins_tag": "bl-r-func"(str),"endian": "le"(str), "reverse_unit": 2(int), "address_length": 4(int)}  
      - calc_info: dict, 形式如{"bits_map": dict(), "expressions": list[list/tuple]}
      - call_instructions: list[tuple], 形式如[(ins_bytes, ins_start_pos, ins_end_pos), ...]  
    - 输出：  
      - list[tuple]，1. 目的地址位置；2. 指令使用len(call_instr) * b"\\xff"替代
    """
    # 记录返回结果
    target_addr_instr = []
    
    # print("ORIGINAL BINARY SIZE: ", len(org_binary), "Bytes")
    endian = arch_info['endian']  # 指令字节序
    reverse_unit = arch_info['reverse_unit']  # 指令对齐（用于处理字节序变换）
    address_bytes = arch_info["address_length"]  # 用于返回地址长度大小（32/64位）
    args_records = []
    for i, call_ins in enumerate(call_instructions):
        call_bytes, ins_start = bytes(call_ins[0]), int(call_ins[1])
        # print(f" ===> NUM{i}-CALL-INS:{call_bytes.hex()} <===")
        expr_tag = arch_info['ins_tag'] + f'-{len(call_bytes)*8}'
        if calc_info.get(expr_tag) is not None:
            # 从存储变量中获取函数参数
            bits_map = calc_info[expr_tag]["bits_map"]  # 二进制比特串“位置n - 位置x”代表的什么？设置变量
            expressions = [tuple(l) for l in calc_info[expr_tag]["expressions"]]  # 通过变量表达式来求解目的地址

            args_records.append({'pc': ins_start,'instruction': call_bytes,'endian': endian,'reverse_unit': reverse_unit,'var_map': bits_map,'calc_method': expressions,'address_bytes': address_bytes})
    
    # 使用进程池计算
    target_address_res = []
    with Pool(processes=cpu_count()) as pool:
        # 目标地址 
        # target_address = call_instruction_branch_addr(
        #             pc=ins_start, call_ins=call_bytes, 
        #             endian=endian, reverse_unit=reverse_unit, address_bytes=address_bytes,
        #             var_map=bits_map, calc_method=expressions
        # )
        target_address_res = pool.map(get_branch_addr_multiprocessing, args_records)

    # 目标地址的筛选
    for i, target_address in enumerate(target_address_res):
        if target_address is None:
            continue
        call_bytes = args_records[i]['instruction']
        # 目的地址的筛选
        if 0 <= target_address < len(org_binary) - len(call_bytes):
            # print(f"[NUM{i}] (CALL ADDR)", ins_start, "=", f"{ins_start.to_bytes(length=arch_info["address_length"], byteorder='big').hex()}==>{target_address.hex()}", "=", tg_addr, "(TARGET ADDR)")
            # 目标地址后的二进制内容分析：
            end_tg_addr = target_address + len(call_bytes)
            target_addr_instr.append((len(call_bytes)*b'\xff', target_address, end_tg_addr))
            # if test_codes != b'':
            #     print(f"[NUM{i}] TARGET ADDR INSTRUCTIONS(12bytes):", test_codes.hex())
    return target_addr_instr


############################# 二进制块分割算法 #############################
# TODO: 持续更新此算法
def create_block_pair(ins_collection1: list, ins_collection2: list, endian: str, reverse_unit: int, arch: str = None, features: dict = None, min_ins_length: int = None, alignment_bytes = 1) -> list[tuple]:
    '''
    根据分析得到的指令，组成可以对二进制内容进行切片的指令对儿；  
    切块指令对儿特征要求：一对儿指令具有一定距离，且此片段指令不会重复出现此指令对儿中的任何一条指令；如PUSH，POP    
    - 输入：
        - ins_collection1: list, 指令类1列表
        - ins_collection2: list, 指令类2列表
        - reverse_unit: int, 指令反转长度单位（?bytes）
        - arch: str, 架构类型
        - endian: str, 大小端
        - features: dict, 指令对之间的特征关系
        - min_ins_length: int, 最小指令长度。默认为None，此时其值和对齐字节长度一致
    - 输出：
        - list[tuple], 指令对儿列表
    '''
    # 函数对儿记录
    block_pairs = []
    
    # 对齐字节不合理
    if reverse_unit <= 0 and reverse_unit % 2:
        return block_pairs
    
    # 最小指令长度，为None时，默认和对齐字节长度一致
    if min_ins_length is None:
        min_ins_length = reverse_unit

    # 按指令的初始地址排序（从小到大）
    sorted_ins = [(h[0], h[1], h[2], True) for h in ins_collection1]
    sorted_ins.extend([(t[0], t[1], t[2], False) for t in ins_collection2])
    sorted_ins = sorted(sorted_ins, key=lambda match_item: match_item[1])
    del ins_collection1, ins_collection2

    # 如果对齐字节长度大于最小指令字节长度，证明存在nop等填充/对齐指令
    if alignment_bytes > min_ins_length:
        min_ins_length = alignment_bytes

    # 余数列表
    remain_results = dict()
    for i in range(min_ins_length):
        remain_results[i] = []

    # 重新分配到各个余数列表内
    for ins in sorted_ins:
        r = ins[1] % min_ins_length
        remain_results[r].append(ins)
    del sorted_ins
    
    # 初步组对儿：按照 (addr=0 | head_ins --> addr=alignment*n | tail_ins)间，无重复指令的规律；
    for k in remain_results.keys():
        curls = remain_results[k]
        p, len_curls = 0, len(curls)
        head, tail = None, None
        while p < len_curls: # 从余数列表中获取对儿 [..., head-i, head-j, tail-n, ...] => (head-j, tail-n)
            if curls[p][-1]:
                head = curls[p]
                p += 1
                continue
            if head is not None:
                tail = curls[p]
                block_pairs.append((head, tail))
                head = None
            p += 1 
    # print(f"[BLOCK PAIRS WITHOUT FEATURES] {len(block_pairs)}")

    # 特征筛查
    if features is not None:
        # 寄存器关系特征
        if (reg_feature := features.get("register")) is not None and len(reg_feature) == 4:
            block_pairs = filter_pairs_with_register(
                instr_pairs=block_pairs, 
                endian=endian,
                reverse_unit=reverse_unit, 
                mask_endian=reg_feature[-2], register_mask=reg_feature[-1]
            )
            # print(f"[BLOCK PAIRS WITH REGISTER FEATURE] {len(block_pairs)}")
        # 距离特征
        if (dis_feature := features.get("distance")) is not None and len(dis_feature) == 3:
            block_pairs = filter_pairs_with_distance(instr_pairs=block_pairs, distance=dis_feature[-1])
            # print(f"[BLOCK PAIRS WITH DISTANCE FEATURE] {len(block_pairs)}")
        # 指令距离范围特征
        if (scope_feature := features.get("scope")) is not None and len(scope_feature) == 3:
            block_pairs = filter_pairs_with_scope(instr_pairs=block_pairs, scope=scope_feature[-1])
    #         print(f"[BLOCK PAIRS WITH SCOPE FEATURE] {len(block_pairs)}")
    # print(f"[BLOCK PAIRS WITH FEATURES] {len(block_pairs)}")

    return block_pairs


############################# 按照指令特征对指令对进行筛选 #############################
def filter_pairs_with_register(instr_pairs: list[tuple], endian: str, reverse_unit: int, mask_endian: str, register_mask: list[list[bytes]]) -> list[tuple]:
    """
    分析两个指令蕴含的寄存求编码是否一致；  
    - 输入：
      - instr_pairs: list[tuple], 已获取的“指令对儿”；
      - reverse_unit: int, 对齐字节长度；
      - mask_endian: str, 掩码的字节序；
      - register_mask: list[list[bytes]], 寄存器编号掩码；
    - 输出：
      - list[tuple]，筛选出寄存器编号一致的指令对儿
    """
    # 按指令长度，设置掩码规则
    h_mask_dict, t_mask_dict = {}, {}
    for reg_msk in register_mask[0]:
        if mask_endian.upper() != endian.upper():
            reg_msk = bytes_reverse(curb=reg_msk, reverse_unit=reverse_unit)
        h_mask_dict[len(reg_msk)] = reg_msk
    for reg_msk in register_mask[1]:
        if mask_endian.upper() != endian.upper():
            reg_msk = bytes_reverse(curb=reg_msk, reverse_unit=reverse_unit)
        t_mask_dict[len(reg_msk)] = reg_msk
    # 筛选
    new_pairs = []
    for i, p in enumerate(instr_pairs):
        h, t = p[0][0], p[1][0]
        # print(get_register_num(h, h_mask_dict[len(h)]), get_register_num(t, t_mask_dict[len(t)]))
        if get_register_num(h, h_mask_dict[len(h)]) == get_register_num(t, t_mask_dict[len(t)]):
            new_pairs.append(p)
    
    return new_pairs


def filter_pairs_with_distance(instr_pairs: list[tuple], distance: int) -> list[tuple]:
    """
    按照指令距离进行筛选指令对儿；  
    - 输入：
      - instr_pairs: list[tuple], 已获取的“指令对儿”；  
      - distance: int, 两个指令之间的距离
    - 输出：
      - list[tuple]，筛选出来的指令对儿；  
    """
    return [p for p in instr_pairs if (p[1][1] - p[0][2] + 1) == distance]


def filter_pairs_with_scope(instr_pairs: list[tuple], scope: list[int]) -> list[tuple]:
    '''
    通过指令距离的范围分辨指令对儿, 距离dis = ins2.start() - ins1.end() + 1，min(scope) <= dis <= max(scope)；
    - 输入：
      - instr_pairs: list[tuple], 已获取的“指令对儿”；  
      - scope: list[int]，两个指令的距离所属范围
    - 输出：
      - list[tuple]，筛选出来的指令对儿 
    '''
    return [p for p in instr_pairs if scope[0] <= (p[1][1] - p[0][2] + 1) <= scope[1]]



if __name__ == "__main__":
    # "6D 00 15 0C" / "6D 00 BE 0A" / "6D 00 0E 00" / "6D 00 F1 00"
    ori_hex = "00 90 0D 00 00 03 6D 00 15 0C 02 24 6D 00 BE 0A 91 00 00 46 D9 44 00 00 6D 00 0E 00 91 00 00 46 D9 44 00 00 82 14 6D 00 F1 00 3C 01 3C 00 82 12 3C 01 00 90 4D C0 E1 FF D7 10 21 0F 49 40 40 08"
    ori_bytes = bytes.fromhex(ori_hex.replace(" ", ""))
    print("\\x" + ori_hex.replace(" ", "\\x"), "\n", "==>", ori_bytes)
    print([a.hex() for a, s, e in search_ins_by_regex(regex=re.compile(rb"\x6d[\x00-\xff][\x00-\xff][\x00-\xff]"), mask=b'\xff\x00\x00\x00', format=b'\x6d\x00\x00\x00', binary=ori_bytes)])

