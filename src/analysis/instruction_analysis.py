import os
import re
import capstone as cps

from analysis.branch_analysis import call_instruction_branch_addr as get_branch_addr
from utils.translator import hexString2bytes, string2bytes_regex
from utils.bytes_op import bytes_reverse, get_register_num, bytes_fmt_compare
from utils.config_processor import features_configure_init


PROCESSOR_ARCHITECTURES = {
    "ARM": {
        "ARCH": cps.CS_ARCH_ARM,
        "MODES": [cps.CS_MODE_THUMB, cps.CS_MODE_ARM, cps.CS_MODE_V8]
    },
    "AMR64": {
        "ARCH": cps.CS_ARCH_AARCH64,
        "MODES": [cps.CS_MODE_V9]
    }
}


class BinaryAnalyzer:
    isa_config_arch_path = set()

    @classmethod
    def update_supported_ISAArch(cls, isa_config_dir: str = "./resources/ISA/config/"):
        for file_name in os.listdir(isa_config_dir):
            cls.isa_config_arch_path.add(isa_config_dir + file_name)

    def __init__(self, bin_file_path: str):
        # 读取二进制文件内容
        self.binary_res = b''
        with open(file=bin_file_path, mode='rb') as fr:
            self.binary_res = fr.read()
        # 初始化指令对儿统计记录
        self.ins_pair_calc_record = dict()
        if len(self.isa_config_arch_path) > 0:
            for path in self.isa_config_arch_path:
                arch_type = os.path.split(path)[-1].strip('.json').upper()
                self.ins_pair_calc_record[arch_type] = {'BE': [], 'LE': []}

    # 输入：指令集架构、大小端、指令1（指令与指令数量）、指令2（指令与指令数量）
    def update_ins_pair_clac_result(self, arch: str, endian: str, ins1: tuple[str, int], ins2: tuple[str, int]):
        # 查询架构内容是否记录
        arch = arch.upper()
        if self.ins_pair_calc_record.get(arch) is None:
            self.ins_pair_calc_record[arch] = {'BE': [], 'LE': []}
        # 记录指令对儿内容
        self.ins_pair_calc_record[arch][f"{ins1[0].upper()/ins2[0].upper()}"][endian.upper()] = [ins1[1], ins2[1]]


class BinaryBlock:
    '''
    - 代码块内分析：  
      - FUNC-1. 获取指令对关系：获取所有块内指令对；  
    '''
    arch = None
    pairs_dict = {}
    others_dict = {}

    def __init__(self, endian: str, binary: bytes, block_stack_pair: tuple):
        # 要求先初始化类信息
        if self.arch is None:
            print("[BinaryBlock Class Exception] Please Load Class Configuration information first, and then initialize this object...")
            raise Exception
        # 创建对象，配置其信息
        self.endian = endian.upper()
        self.binary = binary
        self.block_pair = block_stack_pair
        # 输出结果记录
        self.high_frequency_instr: list = []
        self.is_valid_block: bool = None  # record final judgement result - Boolean
        self.other_pairs = dict()  # record pairs found by func-get_inner_block_pairs
    
    @classmethod
    def load_configure_info(cls, arch: str, pairs_dict: dict, others_dict: dict):
        """
        获取类的相关配置信息
        """
        cls.arch = arch.upper()
        cls.pairs_dict = pairs_dict
        cls.others_dict = others_dict
        # 其他参数
        cls.reverse_unit = 2  # 字节序反转，按多少字节反转
        cls.min_ins_length = 2  # 指令字最短的指令占多少字节长度
        cls.alignment_bytes = 2  # 指令对齐字节长度
        if arch == 'ARM':
            pass
        elif arch == "POWERPC":
            cls.min_ins_length = 4
            cls.reverse_unit = 4
            cls.alignment_bytes = 4
        elif arch == 'TRICORE':
            cls.reverse_unit = 4
    
    def isReversedResultValid(self, head_ins: str, tail_ins: str) -> bool:
        """
        线性扫描逆向分析算法来分析“可能”为函数块
        """
        # 如果是CAPSTONE不支持的架构，不做过滤
        if PROCESSOR_ARCHITECTURES.get(self.arch) is None:
            return True

        # print(self.binary.hex())
        head_ins, tail_ins = head_ins.lower(), tail_ins.lower()
        # 根据架构初始化
        offset = 0x1000
        capstone_arguments = PROCESSOR_ARCHITECTURES[self.arch]
        if self.arch == 'ARM':
            offset = 0x08000000
        # 反汇编分析：线性扫描算法
        flag = False
        for cs_mode in capstone_arguments['MODES']:
            cs_mode_with_endian = cs_mode | cps.CS_MODE_BIG_ENDIAN if self.endian == 'BE' else cs_mode | cps.CS_MODE_LITTLE_ENDIAN
            md = cps.Cs(arch=capstone_arguments['ARCH'], mode=cs_mode_with_endian)
            reverse_res = [(ins.address, ins.bytes, ins.mnemonic.lower(), ins.op_str.lower()) for ins in md.disasm(code=self.binary, offset=offset)]
            # print(f'=== {self.arch}:{cs_mode} ===')
            # for i, ins in enumerate(reverse_res):
            #     print(f"{i} 0x{ins[0]:x}\t0x{bytes(ins[1]).hex():8s}\t{ins[2]}  {ins[3]}")
            if len(reverse_res) > 0 and reverse_res[0][2] == head_ins and reverse_res[-1][2] == tail_ins:
                flag = True
                break
        return flag
    
    def getInnerBlockPairs(self): 
        """
        识别所有指令对儿；
        """
        # print(f'=== FUNC: {self.block_pair} ===')
        # 识别
        for key in self.pairs_dict.keys():
            for one_dict in self.pairs_dict[key]:
                ins1, ins2 = one_dict["ins"].keys()
                possible_ins1, possible_ins2 = ins_pair_identify(
                    ins1=ins1, ins2=ins2, endian=self.endian, binary=self.binary, ins_dict=one_dict["ins"], reverse_unit=self.reverse_unit
                )
                # 筛掉不合理的指令，如起始地址为奇数的
                possible_ins1 = [match_ins for match_ins in possible_ins1 if match_ins[1] % 2 == 0]
                possible_ins2 = [match_ins for match_ins in possible_ins2 if match_ins[1] % 2 == 0]
                # 若为空，则认为不存在本指令对儿
                if len(possible_ins1) == 0 or len(possible_ins2) == 0:
                    continue
                # 特征识别 + 组对儿
                cur_pairs = create_block_pair(
                    ins_collection1=possible_ins1, ins_collection2=possible_ins2, features=features_configure_init(head_instr=ins1, tail_instr=ins2, features=one_dict["features"]), 
                    endian=self.endian, reverse_unit=self.reverse_unit, min_ins_length=self.min_ins_length,
                    alignment_bytes=self.alignment_bytes
                )
                if len(cur_pairs) == 0:
                    continue
                # 记录
                if self.other_pairs.get(key) is None:
                    self.other_pairs[key] = []
                content = {"ins": (ins1, ins2), "details": cur_pairs}
                self.other_pairs[key].append(content)
        
        return self.other_pairs

    def analyzeHighUsageInstruction(self):
        """
        分析指定架构的高频指令在块内的出现频率；
        """
        # 获取指令
        high_usage_dict: dict = self.others_dict.get('HighUsage')
        if high_usage_dict is None:
            print("[BinaryBlock-func-analyzeHighUsageInstruction] You have not set the HighUsage Instructions!")
            return False
        # 筛查
        for instr in high_usage_dict.keys():
            instr_ls = single_ins_analysis(
                ins=instr,
                endian=self.endian,
                binary=self.binary,
                ins_dict=high_usage_dict,
                reverse_unit=self.reverse_unit
            )
            self.high_frequency_instr.extend([e for e in instr_ls if (e[1] % self.min_ins_length) == 0])

        return self.high_frequency_instr
    

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
    for i, call_ins in enumerate(call_instructions):
        call_bytes, ins_start = bytes(call_ins[0]), int(call_ins[1])
        # print(f" ===> NUM{i}-CALL-INS:{call_bytes.hex()} <===")
        expr_tag = arch_info['ins_tag'] + f'-{len(call_bytes)*8}'
        if calc_info.get(expr_tag) is not None:
            # 从存储变量中获取函数参数
            bits_map = calc_info[expr_tag]["bits_map"]  # 二进制比特串“位置n - 位置x”代表的什么？设置变量
            expressions = [tuple(l) for l in calc_info[expr_tag]["expressions"]]  # 通过变量表达式来求解目的地址
            # 目标地址
            try:
                target_address = get_branch_addr(
                    pc=ins_start, call_ins=call_bytes, 
                    endian=endian, reverse_unit=reverse_unit, address_bytes=address_bytes,
                    var_map=bits_map, calc_method=expressions
                )
            except ValueError as e:
                # print(f"[NUM{i}-ERROR] <pc={hex(ins_start)} | ins={call_bytes.hex()}> - Invalid Offset Value!")
                continue
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
        len_curls = len(curls)
        for i, ins in enumerate(curls):  # 从余数列表中获取对儿 [..., head-i, head-j, tail-n, ...] => (head-j, tail-n)
            if ((i + 1) < len_curls):
                next_ins = curls[i + 1]
                if (ins[-1] and not next_ins[-1]) and ((next_ins[1] - ins[1]) % alignment_bytes == 0):  
                        block_pairs.append((ins, next_ins)) 
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
# TODO: 持续更新，寄存器特征策略
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

