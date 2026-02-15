import re
import struct
import shutil
import tempfile
import pyghidra

# 启动 Ghidra，启动后才可以加载 ghidra 模块
pyghidra.start(install_dir="/home/yq/workspace/studies/MyProjects/FBFISADetector/requirements/ghidra", verbose=True)
from ghidra.program.model.lang import LanguageID
from ghidra.program.model.listing import Program, Function


# 基地址分析器
class BaseAddressAnalyzer:
    def __init__(self, current_program: Program):
        self.current_program = current_program
        self.listing = self.current_program.getListing()
        self.memory = self.current_program.getMemory()

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

    def search_imm(self, func: Function):
        addresses = func.getBody().getAddresses(True)
        # 函数序言约束*
        min_address = func.getBody().getMinAddress()
        max_address = func.getBody().getMaxAddress()
        print(f"Address Range: [0x{min_address}, 0x{max_address}]")
        for addr in addresses:
            ins = self.listing.getInstructionAt(addr)
            if ins is None:
                continue
            print(ins)
            op_list = []
            for pcode_op in ins.getPcode():
                op_list.append(str(pcode_op))
                # 简化为取址或者计算地址的指令
                match = re.findall(r"\(ram, (0x[0-9a-fA-F]+), \d+\)", str(pcode_op))
                if len(match) > 0:
                    # 过滤出 CALL 或 BRANCH 指令
                    jump_match = re.findall(r"(CALL|BRANCH)", str(pcode_op))
                    if len(jump_match) == 0:
                        ram_data = self.memory.getInt(self.current_program.getAddressFactory().getAddress(match[0]))
                        # Convert signed int to unsigned int before packing
                        ram_hex_data = struct.pack(">I", ram_data & 0xFFFFFFFF).hex()
                        print(">> RAM IMM:", str(pcode_op), f"=> {ram_hex_data}")
                    continue
                # 左移x位，计算地址的可能性较高（EA = BA + offset）
                match = re.findall(r"INT_LEFT \((?:register|unique|const), 0x[0-9a-fA-F]+, \d+\) , \(const, 0x[0-9a-fA-F]+, \d+\)", str(pcode_op))
                if len(match) > 0:
                    des_var_name = re.findall(r"(\(.*?\))", str(pcode_op))[0]
                    if len(op_list) > 1:
                        pcode_op = self.p_codes_extend(des_var_name, op_list)
                    if len(re.findall(r"\((?:register|unique), 0x[0-9a-fA-F]+, \d+\)", str(pcode_op).replace(des_var_name, ""))) == 0:
                        print(">> ADDRESS CALC IMM:", self.p_code_left_int_simplify(str(pcode_op)))
                    continue
                

    def analyzing(self):
        for func in self.listing.getFunctions(True):
            func_address = func.getEntryPoint()
            print(f"=== <FuncName={func.getName()}:FuncEP=0x{func_address}> ===")
            self.search_imm(func)


# 运行 Ghidra，进行基址求解
def run_ghidra_base_address_solver(bin_file: str, variant: str, ghidra_workspace_dir: str):
    with pyghidra.open_program(binary_path=bin_file, language=LanguageID(variant).getIdAsString(), project_location=ghidra_workspace_dir) as flat_api:
        print("###"*50)
        print("### 成功启动 Ghidra 并加载二进制文件")
        print(f"### 二进制文件路径：{bin_file}")
        print(f"### 架构变体：{variant}")
        print("###"*50)
        # 在这里使用 flat_api 进行操作
        baa = BaseAddressAnalyzer(flat_api.getCurrentProgram())
        baa.analyzing()

if __name__ == "__main__":
    workspace_dir = "/home/yq/workspace/studies/MyProjects/FBFISADetector/output"
    temp_ghidra_dir = "/home/yq/workspace/studies/MyProjects/FBFISADetector/temp/ghidra_workspace"
    
    # 调试
    samples = [
        # (f"{workspace_dir}/arm/bin/p2im_gateway_0x8000000.bin", "ARM:LE:32:Cortex"),
        # (f"{workspace_dir}/powerpc/bin/0a2818b49cc0d364dc897328cc0d6e38_0x0.bin", "PowerPC:BE:32:default"),
        (f"{workspace_dir}/mips/bin/0a890b8cfbfc4ec85d27cdb84e1924c5_0x0.bin", "MIPS:BE:32:default"),
        # (f"{workspace_dir}/tricore/bin/ASCLIN_Shell_UART_1_KIT_TC297_TFT_0x60000000.bin", "tricore:LE:32:default"),
    ]
    for s, v in samples:
        run_ghidra_base_address_solver(bin_file=s, variant=v, ghidra_workspace_dir=temp_ghidra_dir)

