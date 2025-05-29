import re
import sympy as sp

from utils.bytes_op import bytes_reverse, bit_string2bytes, bytes2bit_string


def get_branch_addr_multiprocessing(instr_info: dict):
    '''
    多进程计算分支地址
    - 输入：
      - instr_info: dict, 包含函数调用指令信息的字典，形如：
        {
            'pc': Any,  # 函数调用指令的地址，要求int类型/bytes类型
            'instruction': bytes,  # 函数调用指令
            'endian': str,  # 指令的字节序
            'reverse_unit': int,  # 对齐字节数
            'var_map': dict,  # 变量字典，形如{var_name: [bit_start, bit_end]}
            'calc_method': list[tuple],  # 计算分支地址方法，形如[('a', 'offset = imm32 + 4')]
            'address_bytes': int  # 输出地址字节长度。当pc为bytes时，默认长度等于len(pc)；当pc为int时，默认位8字节（64位）
        }
    - 输出：
      - bytes, 分支函数的起始地址
    '''
    try:
        res = call_instruction_branch_addr(
            pc=instr_info['pc'], 
            call_ins=instr_info['instruction'], 
            endian=instr_info['endian'], 
            reverse_unit=instr_info['reverse_unit'], 
            var_map=instr_info['var_map'], 
            calc_method=instr_info['calc_method'],
            address_bytes=instr_info['address_bytes']
        )
    except ValueError as e:
        return None
    finally:
        return res


def call_instruction_branch_addr(pc: any, call_ins: bytes, endian: str, reverse_unit: int, var_map: dict, calc_method: list[tuple], address_bytes: int = 8):
    '''
    根据函数调用指令中的绝对/相对地址，计算分支函数的起始地址；  
    - 输入：  
      - pc: Any, 函数调用指令的地址，要求int类型/bytes类型
      - call_ins: bytes, 函数调用指令  
      - endian: str, 指令的字节序  
      - reverse_unit: int, 对齐字节数  
      - var_map: dict, 变量字典，形如{var_name: [bit_start, bit_end]}
      - calc_method: str, 计算分支地址方法
      - address_bytes: int, 输出地址字节长度。当pc为bytes时，默认长度等于len(pc)；当pc为int时，默认位8字节（64位）
    - 输出：
      - bytes, 分支函数的起始地址
    - Samples:  
    ```python
    # ARM分支地址计算 - BL指令
    arm_expressions = [
        ("b", "i1 = ~((j1 & ~s) | (~j1 & s))"),  # 单个位逻辑运算
        ("b", "i2 = ~((j2 & ~s) | (~j2 & s))"), 
        ("c", "imm25 = s || i1 || i2 || imm10 || imm11 || 0"),  # 二进制串拼接
        ("e", "imm32 = LS(imm25, 7)"),  # 左侧扩展，带符号
        ("a", "imm32"),  # 补码转换，固定格式：imm(num)(tag)
        ("d", "offset = imm32 + 4")  # 实数运算
    ]
    arm_var_map = {
        's': [5, 6],
        'imm10': [6, 16],
        'j1': [18, 19],
        'j2': [20, 21],
        'imm11': [21, 32]
    }
    arm_test = [
        (b"\\x08\\x00\\x6f\\xf8", b"\\x00\\xf0\\x02\\xf8"),  # 0x08007000
        (b"\\x08\\x00\\x71\\x66", b"\\x00\\xf0\\x85\\xfe"),  # 0x08007e74
        (b"\\x08\\x00\\x71\\x00", b"\\x00\\xf0\\xb8\\xfe"),  # 0x08007e74
    ]
    
    for cur_addr, bl_ins in arm_test:
        target_addr = call_instruction_branch_addr(pc=cur_addr, call_ins=bl_ins, endian='LE', reverse_unit=2, var_map=arm_var_map, calc_method=arm_expressions)
        print(f"起始地址：{cur_addr.hex()} | 跳转指令：{bl_ins.hex()} | 跳转地址：{target_addr.hex()}")
    ```
    '''
    # PC转字节
    if type(pc) == type(int()):
        pc = int(pc).to_bytes(length=address_bytes, byteorder='big')  # 默认64位
    elif type(pc) != type(bytes()):
        print(f"非法程序计数器输入，PC的格式要求是INT类型或BYTES类型, 输入类型为{type(pc)}")
        raise ValueError
    # 指令若是小端字节序，将小端转大端
    if endian.upper() == 'LE':
        call_ins = bytes_reverse(curb=call_ins, reverse_unit=reverse_unit)
    call_ins_bits = bytes2bit_string(call_ins)
    # print(call_ins_bits)
    variables = {k: call_ins_bits[span[0]: span[1]] for k, span in var_map.items()}
    offset = calculate_offset(variables, calc_method)
    # print(f"偏移量: {offset}")
    if offset == 0:
        # print("计算偏移量错误！")
        return None
    # 计算分支地址
    return int(int.from_bytes(pc, byteorder='big') + offset)
    

def calculate_offset(variables: dict, expressions: list[tuple]):
    """
    计算偏移量；  
    - 输入：  
      variables: dict, 变量字典
      expressions: list, 表达式列表
    - 输出：  
      int, 偏移量
    """
    # 替换变量值并计算偏移量结果
    # print(variables)
    resolved_vars = {
        sp.symbols(var): int(value, 2)
        for var, value in variables.items()
    }

    # 计算表达式
    for expr_type, expr in expressions:
        # print([(k, bin(v)) for k, v in resolved_vars.items()])
        result = None
        # 补码转换
        if expr_type == 'a':  
            int2binary = str(bin(resolved_vars[sp.symbols(expr.strip())]))[2:].zfill(int(re.search(r"\d+", expr.strip()).group()))
            result = bit_string2bytes(int2binary, is_unsigned=False)
            positive = False if result[0] == '-' else True
            result = int(result[2:], 16) if positive else -int(result[3:], 16)
        else:
            # 获取表达式左右两侧的变量和表达式
            expr_var, expression = expr.split('=')
            expr_var = sp.symbols(expr_var.strip())
            expression = expression.strip()
            # 计算表达式的值
            if expr_type == 'b':  # 单个位逻辑运算
                result = 1 if sp.logic.simplify_logic(expression).subs(resolved_vars) else 0
            elif expr_type == 'c':  # 二进制串拼接
                result = ''
                for tv in expression.replace(' ', '').split('||'):
                    tv = tv.strip()
                    if tv.startswith('imm'):  # 比特长度大于1的变量
                        result += str(bin(resolved_vars[sp.symbols(tv)]))[2:].zfill(int(re.search(r"\d+", tv).group()))
                    elif tv[0] in ['0', '1']:  # 比特字符串
                        result += tv
                    else:  # 比特长度为1的变量
                        result += str(bin(resolved_vars[sp.symbols(tv)]))[2:]
                result = int(result, 2)
            elif expr_type == 'd':  # 实数运算
                result = sp.sympify(expression).subs(resolved_vars)
            elif expr_type == 'e':  # 扩展
                # 获取原变量名和扩展长度
                org_var, mv_len = [item.strip() for item in re.search(r"\(.*?\)", expression).group()[1:-1].split(',')]
                mv_len = int(mv_len)
                # print(org_var, mv_len)
                value = str(bin(resolved_vars[sp.symbols(org_var)]))[2:].zfill(int(re.search(r"\d+", org_var).group()))
                padding = value[0] * mv_len
                # 左侧添加扩展位
                if expression.startswith('L'):
                    result = int('0' * mv_len + value, 2)
                    if expression.startswith('LS'):  # 左侧添加扩展位，带符号
                        result = int(padding + value, 2)
                elif expression.startswith('R'):  # 右侧添加扩展位
                    result = int(value + '0' * mv_len, 2)
                    if expression.startswith('RS'):  # 右侧添加扩展位，带符号
                        result = int(value + padding, 2)
            else:   
                print(f"未知的表达式类型: {expr_type}")
                return 0
        
        resolved_vars[expr_var] = result

    # 将表达式解析为 sympy 表达式
    return resolved_vars[sp.symbols('offset')]


if __name__ == '__main__':
    # 测试DEMO
    def demo(test, var_map, expressions, endian, reverse_unit):
        for cur_addr, bl_ins in test:
            target_addr = call_instruction_branch_addr(pc=cur_addr, call_ins=bl_ins, endian=endian, reverse_unit=reverse_unit, var_map=var_map, calc_method=expressions).to_bytes(len(cur_addr), byteorder='big')
            print(f"起始地址：{cur_addr.hex()} | 跳转指令：{bl_ins.hex()} | 跳转地址：{target_addr.hex()}")

    # Thumb分支地址计算 - BL指令
    print("Thumb分支地址计算 - BL指令")
    thumb_var_map = {
        's': [5, 6],
        'imm10': [6, 16],
        'j1': [18, 19],
        'j2': [20, 21],
        'imm11': [21, 32]
    }
    thumb_expressions = [
        ("b", "i1 = ~((j1 & ~s) | (~j1 & s))"),  # 单个位逻辑运算
        ("b", "i2 = ~((j2 & ~s) | (~j2 & s))"), 
        ("c", "imm25 = s || i1 || i2 || imm10 || imm11 || 0"),  # 二进制串拼接
        ("e", "imm32 = LS(imm25, 7)"),  # 左侧扩展，带符号
        ("a", "imm32"),  # 补码转换，固定格式：imm(num)(tag)
        ("d", "offset = imm32 + 4")  # 实数运算
    ]
    thumb_test = [
        (b"\x08\x00\x6f\xf8", b"\x00\xf0\x02\xf8"),  # 0x08007000
        (b"\x08\x00\x71\x66", b"\x00\xf0\x85\xfe"),  # 0x08007e74
        (b"\x08\x00\x71\x00", b"\x00\xf0\xb8\xfe"),  # 0x08007e74
    ]
    demo(thumb_test, thumb_var_map, thumb_expressions, 'LE', 2)
      
    # PowerPC分支地址计算 - BL指令
    print("PowerPC分支地址计算 - BL指令")
    ppc_var_map = {
        'imm24': [6, 30],
        'AA': [30, 31],
        'LK': [31, 32]
    }
    ppc_expressions = [
        ("c", "imm26 = imm24 || 00"),  # 二进制串拼接
        ("e", "imm32 = LS(imm26, 6)"),  # 左侧扩展，带符号
        ("a", "imm32"),  # 补码转换，固定格式：imm(num)(tag)
        ("d", "offset = imm32")  # 实数运算
    ]
    ppc_test = [
        (b"\x00\x01\x10\x00", b"\x48\x3a\xc1\xad"),  # 0x003bd1ac
        (b"\x00\x01\x10\x34", b"\x4b\xff\xff\x05"),  # 0x00010f38
    ]
    demo(ppc_test, ppc_var_map, ppc_expressions, 'BE', 4)

    # TriCore分支地址计算 - CALL指令
    print("TriCore分支地址计算 - CALL指令")
    triCore_var_map = {
        "imm16": [0, 16],
        "imm8": [16, 24],
    }
    triCore_expressions = [
        ("c", "imm24 = imm8 || imm16"),  # 二进制串拼接
        ("d", "imm25 = imm24 * 2"),
        ("e", "imm32 = LS(imm25, 7)"),  # 左侧扩展，带符号
        ("a", "imm32"),  # 补码转换，固定格式：imm(num)(tag)
        ("d", "offset = imm32")  # 实数运算
    ]
    triCore_test = [
        (b"\x80\x00\x28\x1a", b"\x6d\x00\x53\x00"),  # 0x800028c0
        (b"\x80\x00\x03\x0c", b"\x6d\x00\xbe\x0a"),  # 0x80001888
    ]
    demo(triCore_test, triCore_var_map, triCore_expressions, 'LE', 4)

    