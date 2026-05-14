from math import e
import re
import os
import struct
import pyghidra
from pyghidra.launcher import HeadlessPyGhidraLauncher

from agents.abs_agent import LLMAgent

# 启动 Ghidra，启动后才可以加载 ghidra 模块
WORKSAPCE_DIR = "/home/yq/NIPC/firmwares/identification/FBFISADetector"
FILE_DIR = f"{WORKSAPCE_DIR}/output"
TEMP_GHIDRA_DIR = f"{WORKSAPCE_DIR}/temp/ghidra_workspace"
launcher = HeadlessPyGhidraLauncher(verbose=True, install_dir=f"{WORKSAPCE_DIR}/requirements/ghidra")
launcher.java_home = "/home/yq/workspace/tools/compilers/jdk-21.0.10+7"
launcher.start()
pyghidra._launcher = launcher
from ghidra.util.task import TaskMonitor
from ghidra.pcodeCPort.opcodes import OpCode
from ghidra.program.model.lang import LanguageID
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.block import BasicBlockModel
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.listing import Program, Function
from ghidra.program.model.address import Address, AddressSet


# 程序入口地址分析器
class ProgramEPAnalyzer:
    def __init__(self, current_program: Program):
        self.current_program = current_program
        self.listing = self.current_program.getListing()
        self.depth_memo = {}
        self.visiting = set()
        self.called_map = {}
        self.calling_map = {}
        self.possible_ep = None
        self.all_ep_info = {}

    def calc_depth(self, f):
        """
            计算函数的深度，即递归调用的最大深度
            
            :param f: 函数对象
            :return: 函数的深度
        """
        if f in self.depth_memo:
            return self.depth_memo[f]
        if f in self.visiting:
            return 0
        self.visiting.add(f)

        max_child = 0
        for callee in self.called_map.get(f, ()):
            d = self.calc_depth(callee)
            if d > max_child:
                max_child = d

        self.visiting.remove(f)
        depth = 0 if len(self.called_map.get(f, ())) == 0 else (1 + max_child)
        self.depth_memo[f] = depth
        return depth

    def analyzing(self) -> int:
        """
            分析程序入口地址
        """
        fm = self.current_program.getFunctionManager()
        rm = self.current_program.getReferenceManager()

        # 建：entrypoint -> function
        funcs = list(fm.getFunctions(True))
        ep_to_func = { f.getEntryPoint(): f for f in funcs }

        self.called_map = { f: set() for f in funcs }   # f -> callees
        self.calling_map = { f: set() for f in funcs }  # f -> callers

        # 遍历每个函数的 body 中的引用，抓 CALL 类型引用
        for caller in funcs:
            body = caller.getBody()
            it = body.getAddresses(True)
            while it.hasNext():
                addr = it.next()
                refs = rm.getReferencesFrom(addr)
                for r in refs:
                    if r is None or not r.getReferenceType().isCall():
                        continue
                    to_addr = r.getToAddress()
                    callee = fm.getFunctionAt(to_addr)
                    if callee is None:
                        # 有时 call 到 thunk / 外部符号 / 未识别函数
                        continue
                    self.called_map[caller].add(callee)
                    self.calling_map[callee].add(caller)

        # 获取
        max_depth = -1
        for f in funcs:
            in_num = len(self.calling_map[f])
            ep = f.getEntryPoint().getUnsignedOffset()
            if in_num == 0 and max_depth < self.calc_depth(f):
                max_depth = self.calc_depth(f)
                self.possible_ep = ep
                self.all_ep_info[ep] = {
                    "in_num": in_num,
                    "out_num": len(self.called_map[f]),
                    "depth": self.calc_depth(f),
                    "name": f.getName()
                }
            # print("Func_EP: 0x%X  in=%d  out=%d  depth=%d  name=%s" %
            #     (ep, in_num, len(self.called_map[f]), self.calc_depth(f), f.getName()))

        return self.possible_ep


# 基地址分析器
class BaseAddressAnalyzer:
    def __init__(self, current_program: Program):
        self.current_program = current_program
        self.listing = self.current_program.getListing()
        self.memory = self.current_program.getMemory()
        self.arch = str(self.current_program.getLanguage())
        self.bits_width = int(self.arch.split("/")[2])
        self.endian = "BE" if current_program.getLanguage().isBigEndian() else "LE"
        self.file_bytes = self.memory.getAllFileBytes()[0]
        self.data_reversed_bytes = self.bits_width//8
        self.instr_reversed_bytes = self.data_reversed_bytes//2 if self.arch.startswith("ARM") else self.data_reversed_bytes
        self.ADDR_THRESHOLD = 0x1000  # 相差 4096 字节认为是不同的基地址
        self.FILE_SIZE = self.current_program.getMaxAddress().getUnsignedOffset()
        # 初始化 Agent
        self.llm_agent = LLMAgent()
        # 偏移地址
        self.string_offsets = []
        self.func_entry_points = []
        self.branch_offsets = []
        # 地址+偏移
        self.vector_abs_addresses = {}
        self.func_abs_addresses = {}
        self.data_abs_addresses = {}
        self.mixed_abs_addresses = {}
        # 候选基地址
        self.left_candidate_base_addresses = {}
        self.candidate_base_addresses = {}

    def analyzing(self):
        print("==== 利用 FirmXray 算法分析获取候选的基地址 ====")
        self.firmxray_algorithms()
        # 位移值分析策略
        # 处理位移值（里面包含了基地址）
        if self.left_candidate_base_addresses:
            classified_base_addresses = self.llm_agent.classify_base_addresses(self.left_candidate_base_addresses, self.arch, self.bits_width, self.endian)
            for str_candidate, tag in list(classified_base_addresses.items()):
                candidate = int(str_candidate, 16)
                if candidate < 0 or candidate > 0xffffffff:
                    continue
                if tag == "flash":
                    print(f"flash candidate = 0x{candidate:x}")
                    if candidate not in self.candidate_base_addresses:
                        self.candidate_base_addresses[candidate] = 0
                    self.candidate_base_addresses[candidate] += self.left_candidate_base_addresses[candidate]
                else:
                    print(f"{tag} = 0x{candidate:x}")
        # 打印绝对地址，10个为一行
        # print("==== 绝对地址 ====")
        # cnt = 0
        # ba_iter = sorted(self.func_abs_addresses.items(), key=lambda item: item[0])
        # for addr, abs in ba_iter:
        #     print(f"[0x{addr:x} -> 0x{abs:x}]", end=" | ")
        #     cnt += 1
        #     if cnt % 10 == 0:
        #         print("\n"+"+"*50)
        # 按照绝对地址排序打印，打印前10个
        print("==== RAM操作偏移位置的4字节值 ====")
        cnt = 0
        candidates_iter = sorted(self.candidate_base_addresses.items(), key=lambda item: item[1], reverse=True)
        for addr, count in candidates_iter:
            print(f"[count(0x{addr:x})={count}]", end=" | ")
            cnt += 1
            if cnt % 10 == 0:
                print("\n"+"+"*50)
        print()
        return candidates_iter[0][0] if candidates_iter else None
        
    # 复现并整改 FirmXray 的基地址求解算法，使其满足多架构需求
    def firmxray_algorithms(self):
        # 获取函数入口点，分析含地址操作相关的指令
        for func in self.listing.getFunctions(True):
            self.search_imm(func)
        self.func_entry_points = sorted(self.func_entry_points) 
        self.classify_absolute_addresses_by_Agent()
        
        # 约束计算1：获取各个绝对地址的推理地址范围
        base_addr_ranges = self.get_ranges()
        
        # 约束计算2：依靠函数入口点和绝对地址，计算候选基地址
        for abs_int in set(self.func_abs_addresses.values()):
            if abs_int > 0xffffffff:
                continue
            if abs_int % 2:
                abs_int -= 1
            for func_offset in self.func_entry_points:
                candidate = abs_int - func_offset
                if candidate < 0 or candidate > 0xffffffff:
                    continue
                if self.candidate_base_addresses.get(candidate) is None:
                    self.candidate_base_addresses[candidate] = 0
                self.candidate_base_addresses[candidate] += 1
                # print(f"TraceCandidateAddr: 0x{candidate:x}=0x{abs_int:x}-0x{func_offset:x}")
        
        # 约束计算3：字符串表约束获取字符串表内的字符串地址
        self.string_tables_record()
        for abs_int in set(self.data_abs_addresses.values()):
            if abs_int > 0xffffffff:
                continue
            if abs_int % 2:
                abs_int -= 1
            for string_offset in self.string_offsets:
                candidate = abs_int - string_offset
                if candidate < 0 or candidate > 0xffffffff:
                    continue
                if self.candidate_base_addresses.get(candidate) is None:
                    self.candidate_base_addresses[candidate] = 0
                self.candidate_base_addresses[candidate] += 1
                # print(f"TraceCandidateAddr: 0x{candidate:x}=0x{abs_int:x}-0x{string_offset:x}")

        # 约束计算4：向量表约束
        self.record_possible_vectors()
        for vector in set(self.vector_abs_addresses.values()):
            for branch_offset in self.branch_offsets:
                candidate = vector - branch_offset
                if candidate < 0 or candidate > 0xffffffff:
                    continue
                if self.candidate_base_addresses.get(candidate) is None:
                    self.candidate_base_addresses[candidate] = 0
                self.candidate_base_addresses[candidate] += 1
                # print(f"TraceCandidateAddr: 0x{candidate:x}=0x{vector:x}-0x{branch_offset:x}")

        # 基于range进行约束过滤 
        base, lower, upper = None, None, None
        for candidate in list(self.candidate_base_addresses.keys()):
            if candidate < 0 or candidate > 0xffffffff:
                self.candidate_base_addresses.pop(candidate)
                continue
            constraint_index = self.check_constraints(candidate, base_addr_ranges)
            if constraint_index == 0:
                self.candidate_base_addresses.pop(candidate)
                continue
            base = candidate
            score = self.candidate_base_addresses[candidate]
            lower = base_addr_ranges[constraint_index-1][0]
            upper = base_addr_ranges[constraint_index-1][1]
            # print(f"High Possible Base Address: 0x{base:x}=0x{lower:x}-0x{upper:x} (Score: {score})")
        
    # 寻找所有的立即数：主要是间接寻址，注意区分是寻（函数）地址、寻（数据）地址
    def search_imm(self, func: Function):
        """
            在函数中寻找与“有效地址（EA）”相关的“立即数地址”
        """
        # 函数体地址范围
        # addresses = func.getBody().getAddresses(True)
        min_address = func.getBody().getMinAddress().getUnsignedOffset()
        max_address = func.getBody().getMaxAddress().getUnsignedOffset()
        func_address = func.getEntryPoint()
        self.func_entry_points.append(func_address.getUnsignedOffset())
        # 迭代分析
        # print(f"==== FuncName:{func.getName()}|FuncEP:0x{func_address} ====")
        # print(f">> Address Range: [0x{min_address}, 0x{max_address}]")
        # # 按照控制流图遍历指令，采用深度优先搜索（函数则跳过，参数寄存器的数据模糊化处理）
        # self.cfg_walk(func_address)
        self.p_codes_sequence_walk(func)

    def cfg_walk(self, func_entry: Address):
        '''
        按照控制流图遍历指令，记录每条路径下的指令集合
        '''
        # @category CFG
        # DFS traversal of a function's control flow graph
        model = BasicBlockModel(self.current_program)
        monitor = TaskMonitor.DUMMY
        
        blocks = model.getCodeBlocksContaining(func_entry, monitor)
        start = next(iter(blocks))
        
        visited = set()
        stack = [(start, 0)]  # (block, depth)

        while stack:
            block, depth = stack.pop()
            key = block.getMinAddress()

            if key in visited:
                continue
            visited.add(key)

            indent = "  " * depth
            print(f"{indent}[Block {key} - {block.getMaxAddress()}]")

            # Print instructions in this block
            for addr_range in block:
                for instr in self.listing.getInstructions(addr_range, True):
                    print(f"{indent}  {instr.getAddress()}: {instr}")

            # Push successors onto stack (reversed to maintain left-to-right DFS order)
            successors = []
            dest_iter = block.getDestinations(monitor)
            while dest_iter.hasNext():
                ref = dest_iter.next()
                dest = ref.getDestinationBlock()
                flow = ref.getFlowType()
                print(f"{indent}  -> {ref.getDestinationAddress()} [{flow}]")
                if dest and dest.getMinAddress() not in visited:
                    successors.append((dest, depth + 1))

            # Reverse so first successor is processed first
            for successor in reversed(successors):
                stack.append(successor)

    # 由于无脑抓取大量的绝对地址，这导致稀释掉了很多候选基地址，需要优化 ==> 直接交给 LLM 筛选
    def p_codes_sequence_walk(self, func: Function):
        """
            顺序遍历函数体内的所有指令，并分析PCode内容，记录每条路径下的指令集合
        """
        register_copy_imm, register_int_add_imm = {}, {}
        func_addrs = [addr for addr in func.getBody().getAddresses(True)]
        for c_index, addr in enumerate(func_addrs):
            instr = self.listing.getInstructionAt(addr)
            if instr is None:
                continue
            op_list = []
            unique_copy_imm, unique_int_add_imm = {}, {}
            # 绝对地址的寻找与记录
            for p_code_op in instr.getPcode():
                # 记录指令
                op_list.append(str(p_code_op))
                # 基本块内进行寄存器计算，遇到跳转指令，则不处理，立即清空寄存器立即数
                jump_match = re.findall(r"(CALL|BRANCH)", str(p_code_op))
                if len(jump_match) > 0:
                    # 如果含有ram，则记录到向量表
                    ram_match = re.findall(r"\(ram, (0x[0-9a-fA-F]+), \d+\)", str(p_code_op))
                    if len(ram_match) > 0:
                        self.vector_abs_addresses[addr.getUnsignedOffset()] = int(ram_match[0], 16)
                    # 清空寄存器立即数，因为跳转指令会导致寄存器立即数的计算结果无效
                    register_copy_imm, register_int_add_imm = {}, {}
                    continue
                
                # ============================================ 寄存器间接寻址（LOAD / COPY RAM） ============================================
                match = re.findall(r"\(register, (0x[0-9a-fA-F]+), \d+\) (?:LOAD|COPY) \(ram, (0x[0-9a-fA-F]+), \d+\)", str(p_code_op))
                if len(match) > 0:
                    # 寄存器间接寻址，找到偏移量并计算偏移位置的值
                    # print(match)
                    reg_name, ram_imm = match[0]
                    self.indirect_absolute_address_calc(offset=ram_imm)  # 保存绝对地址
                    register_int_add_imm[reg_name] = None
                    continue

                # ============================================ LOAD 寄存器间接寻址 ============================================
                match = re.findall(r"\(register, (0x[0-9a-fA-F]+), \d+\) LOAD \(const, (0x[0-9a-fA-F]+), \d+\) , \(unique, (0x[0-9a-fA-F]+), \d+\)", str(p_code_op))
                if len(match) > 0:
                    # 寄存器间接寻址，找到偏移量并计算偏移位置的值
                    reg_name, _, unique_name = match[0]
                    riai = unique_int_add_imm.get(unique_name, None)
                    if riai is not None:  # base_address + offset => load ram[base_address + offset]
                        # print(f"| ** Register[{reg_name}] = LOAD RAM({riai})")
                        content = self.indirect_absolute_address_calc(offset=riai)
                        if content is not None:
                            data, _ = content  # 保存绝对地址
                            register_int_add_imm[reg_name] = data.hex()
                    continue
                
                # ============================================ 【COPY 操作】处理一些计算相关操作 ============================================
                unique_copy_match = re.findall(r"\(unique, (0x[0-9a-fA-F]+), \d+\) COPY \(const, (0x[0-9a-fA-F]+), \d+\)", str(p_code_op))
                if len(unique_copy_match) > 0:
                    unique_name, const_name = unique_copy_match[0]
                    unique_copy_imm[unique_name] = const_name
                    continue
                unique_copy_reg_match = re.findall(r"\(unique, (0x[0-9a-fA-F]+), \d+\) COPY \(register, (0x[0-9a-fA-F]+), \d+\)", str(p_code_op))
                if len(unique_copy_reg_match) > 0:
                    unique_name, reg_name = unique_copy_reg_match[0]
                    unique_copy_imm[unique_name] = register_copy_imm.get(reg_name, None)
                    unique_int_add_imm[unique_name] = register_int_add_imm.get(reg_name, None)
                    continue
                reg_copy_match = re.findall(r"\(register, (0x[0-9a-fA-F]+), \d+\) COPY \(unique, (0x[0-9a-fA-F]+), \d+\)", str(p_code_op))
                if len(reg_copy_match) > 0:
                    reg_name, unique_name = reg_copy_match[0]
                    temp_const = unique_int_add_imm.get(unique_name, None)
                    if temp_const is not None:
                        register_int_add_imm[reg_name] = temp_const
                    else:
                        register_copy_imm[reg_name] = unique_copy_imm.get(unique_name, None)
                    continue
                
                # 区分于寻址操作，此类操作一般直接获取可能的候选基址地址
                # ============================================ INT_ADD 操作 ============================================
                match = re.findall(r" INT_ADD \(register, 0x[0-9a-fA-F]+, \d+\) , \((?:unique|const), 0x[0-9a-fA-F]+, \d+\)", str(p_code_op))
                if len(match) > 0:
                    reg_name = re.findall(r"\(register, (0x[0-9a-fA-F]+), \d+\) INT_ADD", str(p_code_op))
                    unique_name = re.findall(r"\(unique, (0x[0-9a-fA-F]+), \d+\) INT_ADD", str(p_code_op))
                    const_name = re.findall(r"\(const, (0x[0-9a-fA-F]+), \d+\)", str(p_code_op))
                    # 记录寄存器相关的立即数
                    temp_const = None
                    if len(const_name) > 0:
                        temp_const = const_name[0]
                    else:
                        temp_const = unique_copy_imm.get(re.findall(r" , \(unique, (0x[0-9a-fA-F]+), \d+\)", str(p_code_op))[0], None)
                    # 寻找寄存器名称
                    if temp_const is not None:
                        if len(reg_name) > 0:
                            register_int_add_imm[reg_name[0]] = temp_const
                        else:
                            unique_int_add_imm[unique_name[0]] = temp_const
                    continue

                # ============================================ 基地址候选（含段基址，需要筛选） ============================================
                # INT_LEFT 操作；左移x位，计算地址的可能性较高（EA = BA + offset）
                match = re.findall(r"INT_LEFT \((?:register|unique|const), 0x[0-9a-fA-F]+, \d+\) , \(const, 0x[0-9a-fA-F]+, \d+\)", str(p_code_op))
                if len(match) > 0:
                    des_var_name = re.findall(r"(\(.*?\))", str(p_code_op))[0]
                    des_var_name = des_var_name.strip()
                    if len(op_list) > 1:
                        p_code_op = self.p_codes_extend(des_var_name, op_list)
                    if len(re.findall(des_var_name, str(p_code_op))) < 2 and len(re.findall(r"\((?:register|unique), 0x[0-9a-fA-F]+, \d+\)", str(p_code_op).replace(des_var_name, ""))) == 0:
                        left_shift_pcode = self.p_code_left_int_simplify(str(p_code_op))
                        # print("| ** INT-LEFT IMM:", left_shift_pcode)
                        left_shift_addr = re.findall(r"\(const, (0x[0-9a-fA-F]+), \d+\)", left_shift_pcode)[0]
                        # possible address
                        pos_address = int(left_shift_addr, 16)
                        if self.left_candidate_base_addresses.get(pos_address) is None:
                            self.left_candidate_base_addresses[pos_address] = 0
                        self.left_candidate_base_addresses[pos_address] += 1
                    continue

                # ============================================ 寄存器值被覆盖 ============================================
                # 变量值被覆盖，清空记录
                reg_int_match = re.findall(rf"\(register, (0x[0-9a-fA-F]+), \d+\) [A-Z_]+ ", str(p_code_op))
                if len(reg_int_match) > 0:
                    register_copy_imm[reg_int_match[0]] = None
                    register_int_add_imm[reg_int_match[0]] = None
                unique_int_match = re.findall(rf"\(unique, (0x[0-9a-fA-F]+), \d+\) [A-Z_]+ ", str(p_code_op))
                if len(unique_int_match) > 0:
                    unique_copy_imm[unique_int_match[0]] = None
                    unique_int_add_imm[unique_int_match[0]] = None
    
    def get_ranges(self) -> list[tuple]:
        """
            获取各个向量进行推理的上下界范围
        """
        boundaries = []
        low = high = 0
        
        ram_pointer_sorted = sorted(self.func_abs_addresses.values())
        for i in range(len(ram_pointer_sorted)-1):
            diff = ram_pointer_sorted[i+1] - ram_pointer_sorted[i]
            if diff > self.ADDR_THRESHOLD:  # 抗数据段干扰
                low = ram_pointer_sorted[i] - self.FILE_SIZE
                if low < 0:
                    low = 0
                if ( -1 < high < 0xffffffff and -1 < low < 0xffffffff ):
                    boundaries.append((low, high))
                high = ram_pointer_sorted[i+1]
        
        return boundaries

    def check_constraints(self, candidate: int, boundaries: list[tuple]):
        """
            检查约束条件
        """
        size = len(boundaries)
        for i in range(size):
            low, high = boundaries[i]
            if low <= candidate <= high:
                return i+1
        return 0

    def string_tables_record(self):
        """
        记录字符串表内的字符串地址
        """
        self.string_offsets = [data.getAddress().getUnsignedOffset() for data in self.listing.getDefinedData(True) if str(data.getDataType()) == "string"]

    def record_possible_vectors(self):
        """
        记录向量表内的多个4字节值
        """
        def get_neararest_func_offset(vt_offset):
            """
            获取最近的函数入口点偏移量
            """
            last_ep = 0
            for ep in self.func_entry_points:
                if last_ep <= vt_offset < ep:
                    return ep
            return self.FILE_SIZE

        vector_table_offset = 0x0
        if self.arch.startswith("ARM"):
            vector_table_offset = 0x00000000

        # 从地址 vector_table_offset 开始读取 4 字节，直到 4字节内容 为 0x00000000 或者 0xffffffff 亦或者落入最近的函数内
        near_func_offset = get_neararest_func_offset(vector_table_offset)
        while vector_table_offset < near_func_offset:
            # 获取字节内容
            vector = bytearray()
            try:
                for i in range(self.data_reversed_bytes):
                    vector.append(self.file_bytes.getOriginalByte(vector_table_offset + i) & 0xFF)
            except Exception as e:
                print(f"| Error: read failed @ 0x{vector_table_offset:X}: {e}")
                vector_table_offset += self.data_reversed_bytes
                continue
            # 将vector字节解析为整数
            if self.endian == "LE":
                vector = int.from_bytes(vector, byteorder="little")
            else:
                vector = int.from_bytes(vector, byteorder="big", signed=False)
            # 边界条件
            if vector == 0x00000000 or vector == 0xffffffff:
                break
            if self.vector_abs_addresses.get(vector_table_offset) is None:
                self.vector_abs_addresses[vector_table_offset] = None
            self.vector_abs_addresses[vector_table_offset] = vector
            print(f"offset: {vector_table_offset:x}, vector: {vector:x}")
            vector_table_offset += self.data_reversed_bytes

    def indirect_absolute_address_calc(self, offset: str, base_offset: int = 0) -> tuple[bytearray, bytearray]:
        """
        从文件偏移读取 4 字节，解析为 uint32，
        最终以“大端字节序”形式返回字节数据。
        
        :param offset: 文件偏移（0x开头字符串）
        :param base_offset: 基址偏移，可用于相对地址计算 pc+offset（默认 0）
        :param endian: 读取时解释的字节序（LE / BE）
        :param reversed_bytes: 分块翻转字节数
        :return: big_endian_value
        """

        # 1️⃣ 解析 offset 为整数
        try:
            off = int(offset, 16) + base_offset
        except Exception as e:
            print(f"| Error: invalid offset '{offset}': {e}")
            return None

        if off < 0:
            print(f"| Error: offset is negative")
            return None

        # 2️⃣ 读取文件 4 字节
        data = bytearray()
        try:
            for i in range(4):
                data.append(self.file_bytes.getOriginalByte(off + i) & 0xFF)
        except Exception as e:
            print(f"| Error: read failed @ 0x{off:X}: {e}")
            return None

        # 3️⃣ 如果是小端序存储，分块翻转
        big_data = data.copy()
        reversed_bytes = self.data_reversed_bytes
        if self.endian == "LE" and reversed_bytes and reversed_bytes > 1:
            if 4 % reversed_bytes == 0:
                chunks = [big_data[i:i+reversed_bytes] for i in range(0, 4, reversed_bytes)]
                big_data = bytearray(b for chunk in chunks for b in reversed(chunk))
            else:
                print(f"| Warn: reversed_bytes={reversed_bytes} invalid for 4-byte value")
        
        # 4️⃣ 检查值是否有效
        big_value = int.from_bytes(big_data, byteorder="big", signed=False)
        if big_value >= 0xF0000000:
            return None
        
        # 5️⃣ FIXME: 存储，但要区分是寻（函数）地址、寻（数据）地址
        if self.mixed_abs_addresses.get(off) is None:
            self.mixed_abs_addresses[off] = None
        self.mixed_abs_addresses[off] = big_value

        # print(f"| ** INDIRECT ABS @ 0x{off:X}")
        # print(f"|    raw_bytes        : {data.hex()}")
        # print(f"|    big_endian_store : {big_data.hex()}")
        # print(f"|    big_value        : 0x{big_value:X}")

        return data, big_data

    # 需要分类时调用，结果直接写回自身属性
    def classify_absolute_addresses_by_Agent(self):
        func, data, unknown = self.llm_agent.classify_addresses(
            candidates = self.mixed_abs_addresses,
            arch       = self.arch,
            bits_width = self.bits_width,
            endian     = self.endian,
            file_bytes = self.file_bytes,
            file_size  = self.FILE_SIZE,
        )
        self.func_abs_addresses.update(func)
        self.data_abs_addresses.update(data)
        self.mixed_abs_addresses = unknown

    def p_codes_extend(self, des_var_name: str, pcode_ops: list) -> str:
        """
            扩展 pcode 指令，将变量进行展开
            :param des_op: 需要处理的核心算式
            :param pcode_ops: pcode 指令列表
            :return: 扩展后的字符串表示
        """
        def replace_var(var: str) -> str:
            return vars_storage[var] if var in vars_storage.keys() else var

        vars_storage = {}
        for pcode in pcode_ops:
            # 获取被赋值的变量名
            var_name = None
            all_vars = []
            # print(">> CUREENT P-CODE:", pcode)
            if pcode.startswith("(unique"):
                all_vars = re.findall(r"(\(unique, 0x[0-9a-fA-F]+, \d+\)) ", pcode)
                var_name = all_vars[0]
            elif pcode.startswith("(register"):
                all_vars = re.findall(r"(\(register, 0x[0-9a-fA-F]+, \d+\)) ", pcode)
                var_name = all_vars[0]
            else:  # 其他非赋值操作，pass
                continue
            # 指令扩展
            exp = pcode[len(var_name):]
            if exp.startswith("COPY"):  # 赋值
                new_var = exp.replace("COPY", "").strip()
                vars_storage[var_name] = replace_var(new_var)
            else:  # 操作扩展
                cur_vars = re.findall(r"(\(.*?\))", exp)
                for cur_var in cur_vars:
                    rep_var = replace_var(cur_var)
                    # print(">> Extend:", cur_var, end="")
                    # print(" ==> ", rep_var)
                    exp = exp.replace(cur_var, rep_var).strip()
                vars_storage[var_name] = f"({exp})"
        
        return des_var_name + " = " + vars_storage.get(des_var_name)

    def p_code_left_int_simplify(self, input_str: str) -> str:
        """
            简化 pcode 指令，将常量处理掉
            :param input_str: 需要处理的核心算式
            :return: 简化后的字符串表示

            样例：
            - 输入格式：
                (register, 0xffb0, 4) = (INT_LEFT (COPY (const, 0xf003, 4)) , (const, 0x10, 4))
                或
                (register, 0xffb0, 4) = INT_LEFT (const, 0xf003, 4) , (const, 0x10, 4)
            
            - 输出格式：
                (register, 0xffb0, 4) COPY (const, 0xf0030000, 4)
        """
        # 提取目标寄存器部分
        target_match = re.search(r'^\((register, 0x[0-9a-fA-F]+, \d+)\)', input_str)
        if not target_match:
            return input_str
        target_part = target_match.group(1)
        
        # 提取左操作数（值）和右操作数（位移量）
        # 匹配 (const, 0x..., 4) 格式
        const_pattern = r'\(const, 0x([0-9a-fA-F]+), (\d+)\)'
        const_matches = re.findall(const_pattern, input_str)
        
        if len(const_matches) < 2:
            return input_str
        
        # 获取值和位移量
        value_hex, value_size = const_matches[0]
        shift_hex, shift_size = const_matches[1]
        
        # 计算左移后的值
        value = int(value_hex, 16)
        shift = int(shift_hex, 16)
        shifted_value = value << shift
        shifted_value_hex = hex(shifted_value)[2:].lower()
        
        # 构建输出字符串
        output = f"(register, {target_part.split(', ')[1]}, {value_size}) COPY (const, 0x{shifted_value_hex}, {value_size})"
        
        return output


def _run_disassemble(prog, monitor, start, restrict, follow_flow, label="") -> bool:
    """
    Runs DisassembleCommand and prints a summary.

    Returns True if the command reports success.
    """
    cmd = DisassembleCommand(start, restrict, follow_flow)
    ok  = cmd.applyTo(prog, monitor)

    status = "(no status)"
    try:
        status = cmd.getStatusMsg() or "(empty)"
    except Exception:
        pass

    tag = f"[{label}] " if label else ""
    print(f"[*] {tag}DisassembleCommand → ok={ok}, status='{status}'")
    return ok


def disassemble_at(
    flat_api,
    start_offset: int,
    end_offset: int = None,
    follow_flow: bool = True,
    clear_len: int = 0x200,
    try_thumb: bool = False,
) -> bool:
    """
    Force disassembly at a file-offset address, optionally up to end_offset.

    Args:
        flat_api    : FlatProgramAPI instance (usually `this` in a script)
        start_offset: file offset of the start address
        end_offset  : file offset of the end address (inclusive), or None to use clear_len
        follow_flow : whether the disassembler should follow branches
        clear_len   : fallback byte range to clear when end_offset is not given
        try_thumb   : retry with TMode=1 on failure (ARM Thumb mode)

    Returns:
        True on success, False on any failure.
    """
    prog    = flat_api.getCurrentProgram()
    mem     = prog.getMemory()
    listing = prog.getListing()
    monitor = flat_api.getMonitor()

    # ── 1. Resolve file offset → program address ──────────────────────────────
    candidates = mem.locateAddressesForFileOffset(start_offset)
    if not candidates:
        print(f"[-] No address found for file offset 0x{start_offset:x}")
        return False

    start = candidates[0]
    print(f"[*] Resolved file offset 0x{start_offset:x} → {start}")

    # ── 2. Sanity-check: address must be in a mapped, executable block ─────────
    if not mem.contains(start):
        print(f"[-] Address {start} is not mapped in memory")
        return False

    mem_block = mem.getBlock(start)
    if mem_block is None or not mem_block.isExecute():
        print(f"[!] Warning: memory block at {start} is not marked executable "
              f"(block={mem_block}). Proceeding anyway.")

    # ── 3. Peek at raw bytes (diagnostic) ─────────────────────────────────────
    try:
        preview = bytearray(16)
        n_read  = mem.getBytes(start, preview)
        print(f"[*] Raw bytes at {start} ({n_read} bytes read): "
              f"{preview[:n_read].hex(' ')}")
    except Exception as e:
        print(f"[-] Cannot read bytes at {start}: {e}")
        return False

    # ── 4. Build address range ─────────────────────────────────────────────────
    if end_offset is not None:
        end      = flat_api.toAddr(end_offset)
        restrict = AddressSet(start, end)          # inclusive on both ends
        clear_end = end
    else:
        end      = None
        restrict = None                            # let follow_flow decide range
        clear_end = start.add(clear_len - 1)

    # ── 5. Clear existing code units so the disassembler gets a clean slate ───
    print(f"[*] Clearing code units from {start} to {clear_end}")
    listing.clearCodeUnits(start, clear_end, True)

    # ── 6. First disassembly attempt ───────────────────────────────────────────
    success = _run_disassemble(prog, monitor, start, restrict, follow_flow,
                               label="attempt 1")
    if success:
        return True

    # ── 7. Optional ARM Thumb retry ───────────────────────────────────────────
    if not try_thumb:
        return False

    ctx   = prog.getProgramContext()
    tmode = ctx.getRegister("TMode")
    if tmode is None:
        print("[-] TMode register not found — not an ARM program?")
        return False

    thumb_end = start.add(clear_len - 1)
    print(f"[*] Setting TMode=1 (Thumb) from {start} to {thumb_end}")
    ctx.setValue(tmode, start, thumb_end, 1)

    # Clear again after context change to remove any partial ARM decoding
    listing.clearCodeUnits(start, clear_end, True)

    success = _run_disassemble(prog, monitor, start, restrict, follow_flow,
                               label="Thumb retry")
    return success


# 运行 Ghidra 分析器
def run_ghidra_base_address_solver(bin_file: str, variant: str, ghidra_workspace_dir: str, reversed_bytes: int = 4, manually_disassemble: tuple[int] = (0, 0)):
    with pyghidra.open_program(binary_path=bin_file, language=LanguageID(variant).getIdAsString(), project_location=ghidra_workspace_dir) as flat_api:
        print("###"*25)
        print("### 成功启动 Ghidra 并加载二进制文件")
        print(f"### 二进制文件路径：{bin_file}")
        print(f"### 架构变体：{variant}")
        print("###"*25)
        ok = disassemble_at(
            flat_api=flat_api, 
            start_offset=manually_disassemble[0], 
            end_offset=manually_disassemble[1], 
            follow_flow=True,
            try_thumb=True if variant.upper().startswith("ARM") else False
        )
        print("disassemble ok:", ok)
        print("###"*25)
        # 在这里使用 flat_api 进行操作
        # 基地址分析
        print("\n[开始分析固件基地址]")
        baa = BaseAddressAnalyzer(flat_api.getCurrentProgram())
        base_addr = baa.analyzing()
        print("###"*25)
        if base_addr is None:
            print("[-] 无法分析固件基地址")
        else:
            print(f"### 基地址：0x{base_addr:x}")
        print("###"*25)
        del baa
        # 分析程序入口地址
        print("\n[开始分析程序入口地址]")
        pea = ProgramEPAnalyzer(flat_api.getCurrentProgram())
        ep = pea.analyzing()
        print("###"*25)
        print("### 成功分析程序入口地址")
        print(f"### 入口地址：0x{ep:x}")
        print(f"### 入口地址信息：{pea.all_ep_info[ep]}")
        print("###"*25)
        del pea
        print("[分析完成]\n")

if __name__ == "__main__":
    # 调试
    # samples = [
    #     (f"{FILE_DIR}/arm/bin/p2im_gateway_0x8000000.bin", "ARM:LE:32:Cortex", 4, (0x365c, 0x368f)),
    #     (f"{FILE_DIR}/powerpc/bin/0a2818b49cc0d364dc897328cc0d6e38_0x0.bin", "PowerPC:BE:32:default", 4, (0x0, 0x0)),
    #     (f"{FILE_DIR}/mips/bin/0a890b8cfbfc4ec85d27cdb84e1924c5_0x0.bin", "MIPS:BE:32:default", 4, (0x0, 0x0)),
    #     (f"{FILE_DIR}/tricore/bin/ASCLIN_Shell_UART_1_KIT_TC297_TFT_0x60000000.bin", "tricore:LE:32:default", 4, (0x0, 0x0)),
    # ]

    import argparse
    parser = argparse.ArgumentParser(description="Run Ghidra base address solver")
    parser.add_argument("--bin_file", "-b", type=str, required=True, help="Path to the binary file")
    parser.add_argument("--variant", "-v", type=str, required=True, help="Architecture variant")
    parser.add_argument("--reversed_bytes", "-r", type=int, default=4, help="Number of reversed bytes")
    parser.add_argument("--manually_disassemble", "-m", type=str, default="(0, 0)", help="Manually disassemble range (start, end)")
    args = parser.parse_args()

    run_ghidra_base_address_solver(
        bin_file=args.bin_file, 
        variant=args.variant, 
        reversed_bytes=args.reversed_bytes, 
        manually_disassemble=eval(args.manually_disassemble),
        ghidra_workspace_dir=TEMP_GHIDRA_DIR
    )

