import re
import struct
import pyghidra

# 启动 Ghidra，启动后才可以加载 ghidra 模块
pyghidra.start(install_dir="/home/yq/workspace/studies/MyProjects/FBFISADetector/requirements/ghidra", verbose=True)
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.lang import LanguageID
from ghidra.program.model.listing import Program, Function
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.program.model.address import AddressSet
import java.math.BigInteger as BigInteger


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
            print("Func_EP: 0x%X  in=%d  out=%d  depth=%d  name=%s" %
                (ep, in_num, len(self.called_map[f]), self.calc_depth(f), f.getName()))

        return self.possible_ep


# 基地址分析器
class BaseAddressAnalyzer:
    def __init__(self, current_program: Program, reversed_bytes: int = 4):
        self.current_program = current_program
        self.listing = self.current_program.getListing()
        self.memory = self.current_program.getMemory()
        self.reversed_bytes = reversed_bytes
        self.endian = "BE" if current_program.getLanguage().isBigEndian() else "LE"
        self.file_bytes = self.memory.getAllFileBytes()[0]
        self.ADDR_THRESHOLD = 0x40  # 相差 64 字节（8*8，即，最少8条指令）认为是不同的基地址
        self.FILE_SIZE = self.current_program.getMaxAddress().getUnsignedOffset()
        # 偏移地址
        self.string_addresses = []
        self.func_entry_points = []
        # 地址+偏移
        self.abs_addresses = {}
        # 候选基地址
        self.candidate_base_addresses = {}

    def analyzing(self):
        print("==== 利用 FirmXray 算法分析获取候选的基地址 ====")
        self.firmxray_algorithms()
        # 打印绝对地址
        print("==== 绝对地址 ====")
        for addr, abs in sorted(self.abs_addresses.items(), key=lambda item: item[0]):
            print(f"0x{addr:x} -> 0x{abs:x}")
        # 按照绝对地址排序打印
        print("==== RAM操作偏移位置的4字节值 ====")
        for addr, count in sorted(self.candidate_base_addresses.items(), key=lambda item: item[1], reverse=True):
            print(f"BASE_ADDR:0x{addr:x} | count:{count}")

    # TODO: 复现并整改 FirmXray 的基地址求解算法，使其满足多架构需求
    def firmxray_algorithms(self):
        # 获取函数入口点，分析含地址操作相关的指令
        for func in self.listing.getFunctions(True):
            self.search_imm(func)
        # 提取字符串地址
        for data in self.listing.getDefinedData(True):
            if data.getDataType().toString() == "string":
                self.string_addresses.append(data.getAddress().getUnsignedOffset())
        # 约束计算1：获取各个绝对地址的推理地址范围
        base_addr_ranges = self.get_ranges()
        # 约束计算2：依靠函数
        print(f"==== 函数入口点 ====")
        for fep in self.func_entry_points:
            print(f"0x{0x08000000+fep:x}")
        for addr, abs in sorted(self.abs_addresses.items(), key=lambda item: item[1]):
            print(f"0x{addr:x} -> 0x{abs:x}")

        # self.func_entry_points = sorted(self.func_entry_points) 
        # for _, abs_int in self.abs_addresses.items():
        #     if abs_int > 0xffffffff:
        #         continue
        #     if abs_int % 2:
        #         abs_int -= 1
        #     for func_offset in self.func_entry_points:
        #         candidate = abs_int - func_offset
        #         if candidate < 0 or candidate > 0xffffffff:
        #             continue
        #         if self.candidate_base_addresses.get(candidate) is None:
        #             self.candidate_base_addresses[candidate] = 0
        #         self.candidate_base_addresses[candidate] += 1
    
    # FIXME: 间接寻址修复
    def search_imm(self, func: Function):
        """
            在函数中寻找与“有效地址（EA）”相关的“立即数地址”
        """
        # 函数体地址范围
        addresses = func.getBody().getAddresses(True)
        min_address = func.getBody().getMinAddress().getUnsignedOffset()
        max_address = func.getBody().getMaxAddress().getUnsignedOffset()
        func_address = func.getEntryPoint()
        self.func_entry_points.append(func_address.getUnsignedOffset())
        # 迭代分析
        print(f"==== FuncName:{func.getName()}|FuncEP:0x{func_address} ====")
        print(f">> Address Range: [0x{min_address}, 0x{max_address}]")
        register_copy_imm = {}  
        register_int_add_imm = {}  # 记录寄存器相关的立即数
        for addr in addresses:
            ins = self.listing.getInstructionAt(addr)
            if ins is None:
                continue
            print(ins)
            op_list = []
            unique_copy_imm = {}
            unique_int_add_imm = {}
            print("-"*100)
            for pcode_op in ins.getPcode():
                print("| >>", pcode_op)
                op_list.append(str(pcode_op))
                # ============================================ 间接寻址 ============================================
                # 简化为取址或者计算地址的指令
                match = re.findall(r"\(ram, (0x[0-9a-fA-F]+), \d+\)", str(pcode_op))
                if len(match) > 0:
                    # 过滤出 CALL 或 BRANCH 指令
                    jump_match = jump_match = re.findall(r"(CALL|BRANCH)", str(pcode_op))
                    if len(jump_match) == 0:
                        self.indirect_absolute_address_calc(match[0], self.endian, self.reversed_bytes)  # 保存绝对地址
                    continue
                # ============================================ 寄存器间接寻址 ============================================
                # COPY 操作
                unique_copy_match = re.findall(r"\(unique, (0x[0-9a-fA-F]+), \d+\) COPY \(const, (0x[0-9a-fA-F]+), \d+\)", str(pcode_op))
                if len(unique_copy_match) > 0:
                    unique_name, const_name = unique_copy_match[0]
                    unique_copy_imm[unique_name] = const_name
                    continue
                unique_copy_reg_match = re.findall(r"\(unique, (0x[0-9a-fA-F]+), \d+\) COPY \(register, (0x[0-9a-fA-F]+), \d+\)", str(pcode_op))
                if len(unique_copy_reg_match) > 0:
                    unique_name, reg_name = unique_copy_reg_match[0]
                    unique_copy_imm[unique_name] = register_copy_imm.get(reg_name, None)
                    unique_int_add_imm[unique_name] = register_int_add_imm.get(reg_name, None)
                    continue
                reg_copy_match = re.findall(r"\(register, (0x[0-9a-fA-F]+), \d+\) COPY \(unique, (0x[0-9a-fA-F]+), \d+\)", str(pcode_op))
                if len(reg_copy_match) > 0:
                    reg_name, unique_name = reg_copy_match[0]
                    temp_const = unique_int_add_imm.get(unique_name, None)
                    if temp_const is not None:
                        register_int_add_imm[reg_name] = temp_const
                        print(f"| ** INT_ADD: Register[{reg_name}] = Unique[{unique_name}] = {register_int_add_imm[reg_name]}")
                    else:
                        register_copy_imm[reg_name] = unique_copy_imm.get(unique_name, None)
                        print(f"| ** COPY: Register[{reg_name}] = Unique[{unique_name}] = {register_copy_imm[reg_name]}")
                    continue
                # LOAD 寄存器间接寻址
                match = re.findall(r"\(register, (0x[0-9a-fA-F]+), \d+\) LOAD \(const, (0x[0-9a-fA-F]+), \d+\) , \(unique, (0x[0-9a-fA-F]+), \d+\)", str(pcode_op))
                if len(match) > 0:
                    # 寄存器间接寻址，找到偏移量并计算偏移位置的值
                    reg_name, _, unique_name = match[0]
                    riai = unique_int_add_imm.get(unique_name, None)
                    if riai is not None:  # base_address + offset => load ram[base_address + offset]
                        print(f"| ** Register[{reg_name}] = LOAD RAM({riai})")
                        self.indirect_absolute_address_calc(riai, self.endian, self.reversed_bytes)  # 保存绝对地址
                        register_int_add_imm[reg_name] = None
                    continue
                # INT_ADD 操作 
                match = re.findall(r" INT_ADD \(register, 0x[0-9a-fA-F]+, \d+\) , \((?:unique|const), 0x[0-9a-fA-F]+, \d+\)", str(pcode_op))
                if len(match) > 0:
                    reg_name = re.findall(r"\(register, (0x[0-9a-fA-F]+), \d+\) INT_ADD", str(pcode_op))
                    unique_name = re.findall(r"\(unique, (0x[0-9a-fA-F]+), \d+\) INT_ADD", str(pcode_op))
                    const_name = re.findall(r"\(const, (0x[0-9a-fA-F]+), \d+\)", str(pcode_op))
                    # 记录寄存器相关的立即数
                    temp_const = None
                    if len(const_name) > 0:
                        temp_const = const_name[0]
                    else:
                        temp_const = unique_copy_imm.get(re.findall(r" , \(unique, (0x[0-9a-fA-F]+), \d+\)", str(pcode_op))[0], None)
                    # 寻找寄存器名称
                    if temp_const is not None:
                        if len(reg_name) > 0:
                            register_int_add_imm[reg_name[0]] = temp_const
                        else:
                            unique_int_add_imm[unique_name[0]] = temp_const
                    continue
                # ============================================ 基地址候选（含段基址，需要筛选） ============================================
                # INT_LEFT 操作；左移x位，计算地址的可能性较高（EA = BA + offset）
                match = re.findall(r"INT_LEFT \((?:register|unique|const), 0x[0-9a-fA-F]+, \d+\) , \(const, 0x[0-9a-fA-F]+, \d+\)", str(pcode_op))
                if len(match) > 0:
                    des_var_name = re.findall(r"(\(.*?\))", str(pcode_op))[0]
                    des_var_name = des_var_name.strip()
                    if len(op_list) > 1:
                        pcode_op = self.p_codes_extend(des_var_name, op_list)
                    if len(re.findall(des_var_name, str(pcode_op))) < 2 and len(re.findall(r"\((?:register|unique), 0x[0-9a-fA-F]+, \d+\)", str(pcode_op).replace(des_var_name, ""))) == 0:
                        left_shift_pcode = self.p_code_left_int_simplify(str(pcode_op))
                        print("| ** INT-LEFT IMM:", left_shift_pcode)
                        left_shift_addr = re.findall(r"\(const, (0x[0-9a-fA-F]+), \d+\)", left_shift_pcode)[0]
                        # possible address
                        pos_address = int(left_shift_addr, 16)
                        if self.candidate_base_addresses.get(pos_address) is None:
                            self.candidate_base_addresses[pos_address] = 0
                        self.candidate_base_addresses[pos_address] += 1
                    continue
                # ============================================ 寄存器值被覆盖 ============================================
                # 变量值被覆盖，清空记录
                reg_int_match = re.findall(rf"\(register, (0x[0-9a-fA-F]+), \d+\) [A-Z_]+ ", str(pcode_op))
                if len(reg_int_match) > 0:
                    register_int_add_imm[reg_int_match[0]] = None
                unique_int_match = re.findall(rf"\(unique, (0x[0-9a-fA-F]+), \d+\) [A-Z_]+ ", str(pcode_op))
                if len(unique_int_match) > 0:
                    unique_copy_imm[unique_int_match[0]] = None
                    unique_int_add_imm[unique_int_match[0]] = None
            print("-"*100)

    def indirect_absolute_address_calc(self, offset: str, base_offset: int = 0, endian: str = "LE", reversed_bytes: int = 4):
        """
        从文件偏移读取 4 字节，解析为 uint32，
        最终以“大端字节序”形式返回字节数据。
        @[由 GPT-5.2 生成]
        
        :param offset: 文件偏移（0x开头字符串）
        :param base_offset: 基址偏移，可用于相对地址计算 pc+offset（默认 0）
        :param endian: 读取时解释的字节序（LE / BE）
        :param reversed_bytes: 分块翻转字节数
        :return: (uint32_value, big_endian_bytes)
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

        # 3️⃣ 分块翻转（例如 reversed_bytes=2 用于 ARM 半字翻转）
        if reversed_bytes and reversed_bytes > 1:
            if 4 % reversed_bytes == 0:
                chunks = [data[i:i+reversed_bytes] for i in range(0, 4, reversed_bytes)]
                data = bytearray(b for chunk in chunks for b in reversed(chunk))
            else:
                print(f"| Warn: reversed_bytes={reversed_bytes} invalid for 4-byte value")

        # 4️⃣ 按指定 endian 解析
        endian = endian.upper()
        fmt = "<I" if endian == "LE" else ">I"
        value = struct.unpack(fmt, bytes(data))[0]

        # 5️⃣ 强制转成“大端字节序”
        big_endian_bytes = struct.pack(">I", value)

        # 6️⃣ 存储
        if not hasattr(self, "abs_addresses"):
            self.abs_addresses = {}
        
        # 7️⃣ 检查值是否有效
        big_value = int.from_bytes(big_endian_bytes, byteorder="big")
        if big_value >= 0xF0000000:
            return None
        self.abs_addresses[off] = big_value

        print(f"| ** INDIRECT ABS @ 0x{off:X}")
        print(f"|    raw_bytes        : {data.hex()}")
        print(f"|    parsed_value     : 0x{value:08X}")
        print(f"|    big_endian_store : {big_endian_bytes.hex()}")

        return value, big_endian_bytes

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

    def get_ranges(self) -> list[tuple]:
        """
            获取各个向量进行推理的上下界范围
        """
        boundaries = []
        low = high = 0
        
        ram_pointer_sorted = sorted(self.abs_addresses.items(), key=lambda item: item[1])
        for i in range(len(ram_pointer_sorted)-1):
            diff = ram_pointer_sorted[i+1][1] - ram_pointer_sorted[i][1]
            if diff > self.ADDR_THRESHOLD:  # 抗数据段干扰
                low = ram_pointer_sorted[i][1] - self.FILE_SIZE
                if low < 0:
                    low = 0
                if ( -1 < high < 0xffffffff and -1 < low < 0xffffffff ):
                    boundaries.append((low, high))
                high = ram_pointer_sorted[i+1][1]
        
        return boundaries
                    

def disassemble_like_D(flat_api: FlatProgramAPI, start_addr_int: int, end_addr_int: int=None, follow_flow: bool=True, clear_len: int=0x200, try_thumb: bool=False):
    prog = flat_api.getCurrentProgram()
    mem  = prog.getMemory()
    listing = prog.getListing()
    
    start = mem.locateAddressesForFileOffset(start_addr_int)
    if len(start) == 0:
        print("[-] not found addr @%s" % start_addr_int)
        return False
    start = start[0]

    # 1) 地址/字节检查
    if not mem.contains(start):
        print("[-] not in memory:", start)
        return False

    try:
        b = bytearray(16)
        rb = mem.getBytes(start, b)
        print("[*] read %s bytes" % hex(rb))
        print("[*] bytes @%s: %s" % (start, b.hex()))
    except Exception as e:
        print("[-] cannot read bytes at %s, err: %s" % (start, e))
        return False

    # 2) restrict（注意：AddressSet(start,end) 是包含 end 的，end 应该是最后一个字节）
    restrict = None
    end = None
    if end_addr_int:
        end = flat_api.toAddr(end_addr_int)
        restrict = AddressSet(start, end)

    # 3) 强力清理（比 clearListing 更“硬”）
    clear_end = end if end else start.add(clear_len)
    listing.clearCodeUnits(start, clear_end, True)  # True: clear context/refs where possible

    # 4) 第一次尝试
    cmd = DisassembleCommand(start, restrict, follow_flow)
    ok = cmd.applyTo(prog, flat_api.getMonitor())
    print("[*] disasm ok:", ok)
    try:
        print("[*] status:", cmd.getStatusMsg())
    except:
        pass

    if ok:
        return True

    # 5) 如果失败且是 ARM/Thumb 场景：尝试设置 TMode=1 再来一次
    if try_thumb:
        ctx = prog.getProgramContext()
        tmode = ctx.getRegister("TMode")
        if tmode is not None:
            # 在一小段范围内设置 Thumb 上下文
            thumb_end = start.add(clear_len)
            ctx.setValue(tmode, start, thumb_end, BigInteger.ONE)
            print("[*] retry with TMode=1 (Thumb)")

            # 再清一次，避免上下文切换后仍有残留
            listing.clearCodeUnits(start, clear_end, True)

            cmd2 = DisassembleCommand(start, restrict, follow_flow)
            ok2 = cmd2.applyTo(prog, flat_api.getMonitor())
            print("[*] thumb retry ok:", ok2)
            try:
                print("[*] status2:", cmd2.getStatusMsg())
            except:
                pass
            return ok2

    return False


# 运行 Ghidra 分析器
def run_ghidra_base_address_solver(bin_file: str, variant: str, ghidra_workspace_dir: str, reversed_bytes: int = 4, manually_disassemble: tuple[int] = (0, 0)):
    with pyghidra.open_program(binary_path=bin_file, language=LanguageID(variant).getIdAsString(), project_location=ghidra_workspace_dir) as flat_api:
        print("###"*25)
        print("### 成功启动 Ghidra 并加载二进制文件")
        print(f"### 二进制文件路径：{bin_file}")
        print(f"### 架构变体：{variant}")
        print("###"*25)
        ok = disassemble_like_D(
            flat_api=flat_api, 
            start_addr_int=manually_disassemble[0], 
            end_addr_int=manually_disassemble[1], 
            follow_flow=True,
            try_thumb=True if variant.upper().startswith("ARM") else False
        )
        print("disassemble ok:", ok)
        # 在这里使用 flat_api 进行操作
        # 基地址分析
        # baa = BaseAddressAnalyzer(flat_api.getCurrentProgram(), reversed_bytes)
        # baa.analyzing()
        # del baa
        # 分析程序入口地址
        pea = ProgramEPAnalyzer(flat_api.getCurrentProgram())
        ep = pea.analyzing()
        print("###"*25)
        print("### 成功分析程序入口地址")
        print(f"### 入口地址：0x{ep:x}")
        print(f"### 入口地址信息：{pea.all_ep_info[ep]}")
        print("###"*25)
        del pea

if __name__ == "__main__":
    workspace_dir = "/home/yq/workspace/studies/MyProjects/FBFISADetector/output"
    temp_ghidra_dir = "/home/yq/workspace/studies/MyProjects/FBFISADetector/temp/ghidra_workspace"
    
    # 调试
    samples = [
        (f"{workspace_dir}/arm/bin/p2im_gateway_0x8000000.bin", "ARM:LE:32:Cortex", 2, (0x365c, 0x368f)),
        # (f"{workspace_dir}/powerpc/bin/0a2818b49cc0d364dc897328cc0d6e38_0x0.bin", "PowerPC:BE:32:default", 4, (0x0, 0x0)),
        # (f"{workspace_dir}/mips/bin/0a890b8cfbfc4ec85d27cdb84e1924c5_0x0.bin", "MIPS:BE:32:default", 4, (0x0, 0x0)),
        # (f"{workspace_dir}/tricore/bin/ASCLIN_Shell_UART_1_KIT_TC297_TFT_0x60000000.bin", "tricore:LE:32:default", 4, (0x0, 0x0)),
    ]
    for s, v, r, m in samples:
        run_ghidra_base_address_solver(bin_file=s, variant=v, ghidra_workspace_dir=temp_ghidra_dir, reversed_bytes=r, manually_disassemble=m)

