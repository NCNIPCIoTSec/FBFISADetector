import re
import sympy


# P-Code 翻译器
class PcodeTranslator:
    def __init__(self):
        pass

    def explain2python(self, pcode_exp):
        def explain_bool_expression():
            pass
        def explain_arithmetic_expression():
            pass
        pass

    def pcode2python(self, pcode_ir):
        pcode_ir: list[str] = [cexp for cexp in pcode_ir.split("\n") if len(cexp.strip()) > 0]
        for pcode_exp in pcode_ir:
            python_exp = self.explain2python(pcode_exp)


# P-Code IR 分析器
class PcodeIR:
    pointer_operator = ["*[ram]", "*[register]", "*"]
    neg_operator = ["!", "-", "~"]
    mid_operator = [
        "||",  "&&", "<<", ">>", "^^", "&", "|", "+", "-", "*", "/", "%", "^", "<", "<=", "==", "!=", 
        "s>>", "s/", "s%", "s<", "s<=", 
        "f+", "f-", "f*", "f/", "f<", "f<=", "f==", "f!=",  
    ]
    weak_syntax_char = [
        "(", ")", "{", "}", "[", "]", ","
    ]

    def __init__(self, ir: str, general_registers: list = []) -> None:
        # 清洗IR
        ir = re.sub(r'IMARK ram\[([0-9a-fA-F:]+)\]\n', r'', ir)
        ir = re.sub(r'= SUBPIECE ([\[\]:\w]+), 0x(\d+)', r"= SUBPIECE(\1,0x\2)", ir)
        # 变量分析
        self.ir = ir
        self.gen_reg = general_registers
        self.format_ir = []
        self.var_expand_chain = {}
        self.var_undeclare_chain = {}

    # TODO: 分析可能的参数寄存器
    def get_arguments_from_chain(self):
        args = {}
        context_save_addr = {}
        
        # 记录可能得保存上下文的地址
        def record_pos_context_addr(cur_var: str, all_reg: set):
            if len(all_reg) > 1 and cur_var.startswith('ram'):
                if context_save_addr.get(cur_var) is None:
                    context_save_addr[cur_var] = set()
                context_save_addr[cur_var] = context_save_addr[cur_var].union(all_reg)

        if len(self.var_undeclare_chain) == 0:
            self.expression_analysis(extend=False, trace=True)
        
        # 统计未声明变量，为分析“参数传递寄存器”的可能做准备
        for cvar, chain in self.var_undeclare_chain.items():
            pre_reg = set()
            for unv_set in chain:
                if unv_set == "const":
                    record_pos_context_addr(cur_var=cvar, all_reg=pre_reg)
                    pre_reg.clear()
                    continue
                pre_reg = pre_reg.union(unv_set)
                # 分析寄存器集合内的寄存器，并记录
                for unv in unv_set:
                    if unv in self.gen_reg:
                        if args.get(unv) is None:
                            args[unv] = 0
                        args[unv] += 1
            record_pos_context_addr(cur_var=cvar, all_reg=pre_reg)

        # 筛选
        # 若“保存上下文的地址区域内的寄存器”出现未声明的情况，则认为矛盾
        pos_ram = []
        for ram, reg in context_save_addr.items():
            special_reg = set([r for r in reg if r not in self.gen_reg])
            if len(special_reg) == 0:
                continue
            save_gen_reg = reg - special_reg
            error_reg = set([r for r in save_gen_reg if args.get(r) is None or args[r] > 1])
            if len(error_reg) > 0:
                continue
            pos_ram.append(ram)
        del args, context_save_addr
        
        print(pos_ram)

    # 内存/寄存器（指针）处理
    def get_var_from_pointer(self, variable: str) -> tuple[str, bool]:
        if variable.startswith("*"):
            # 前缀标签
            tag = tt[0] if len(tt := re.findall(r'\*\[(.*?)\]', variable)) > 0 else "*"
            pre_len = 1
            if len(tag) > pre_len:
                pre_len = 3 + len(tag)
            addr_info = variable[pre_len:].strip()
            # 格式变换
            if (exp_chain := self.var_expand_chain.get(addr_info)) is not None:  # 扩展
                exp_chain[-1] = exp_chain[-1].replace(" ", "")
                return f"{tag}[{exp_chain[-1]}]", True
            else:  # 不扩展
                return f"{tag}[{addr_info}]", True
        return variable, False

    # 清洗变量前缀运算符（否定运算符）
    def get_var_from_neg(self, variable: str):
        for op in self.neg_operator:
            if variable.startswith(op):
                return op, variable[len(op):].strip()
        return "", variable

    # 展开的表达式进行格式化表示
    def format_print_expression(self, exp_list: list[str]):
        final_exp = ""
        for e in exp_list:
            e = e.strip()
            if len(e) == 0:
                continue
            if e in self.mid_operator:
                final_exp += (" " + e + " ")
                continue
            final_exp += e
        # print(exp, "==>", final_exp)
        return final_exp.strip()

    # 清洗表达式
    def clean_expression(self, whole_exp: str):
        whole_exp = whole_exp.replace("\n", "").strip()
        whole_exp = re.sub(r"(\w+)\((.*?),(.*?)\)", r"\1( \2 , \3 )", whole_exp)
        whole_exp = re.sub(r"(\w+)\((.*?)\)", r"\1( \2 )", whole_exp)
        # 拆分等式
        if (match_eq := re.search("=", whole_exp)) is not None:
            # 表达式为赋值表达式
            cur_var = whole_exp[:match_eq.start()].strip()
            cur_exp = whole_exp[match_eq.end():].strip()
            # 清洗变量名
            _, cur_var = self.get_var_from_neg(self.get_var_from_pointer(cur_var)[0])
            return cur_var, cur_exp
        return "", whole_exp

    # 等式表达式扩展
    def equal_exp_analysis(self, cvar: str, cexp: str, extend: bool, trace: bool):
        # 表达式扩展记录
        if extend and self.var_expand_chain.get(cvar) is None:
            self.var_expand_chain[cvar] = [cexp]
        # 追踪未声明变量
        if trace and self.var_undeclare_chain.get(cvar) is None:
            self.var_undeclare_chain[cvar] = []
        
        # =========== 分析阶段 ===========
        new_exp = ""
        undeclare_variable = set()
        for ve in cexp.split(" "):
            ve = ve.strip()
            # 运算符/其他非变量以及常量符号，PASS
            if len(ve) == 0 or ve in self.mid_operator:
                new_exp += (ve + " ")
                continue
            # 前缀运算符处理
            ve, isp = self.get_var_from_pointer(ve)
            pre_op, ve = self.get_var_from_neg(ve)
            new_exp += pre_op
            # 未声明变量追踪
            if trace:
                trace_ve = ve
                if isp:  # 如果是指针变量，追溯地址存放变量
                    trace_ve = re.findall(r'[ramgister\*]+\[(.*?)\]$', ve)[0]
                if (tch := self.var_undeclare_chain.get(trace_ve)) is not None and len(tch) > 0:
                    if tch[-1] != 'const':
                        undeclare_variable.union(tch[-1])
                elif not (trace_ve in self.weak_syntax_char or trace_ve.startswith('0x') or trace_ve.endswith("(")):
                    undeclare_variable.add(trace_ve)
                del trace_ve
            # 表达式展开
            if extend and self.var_expand_chain.get(ve) is not None:
                new_exp += f"( {self.var_expand_chain[ve][-1]} )"
            else:
                new_exp += ve
            new_exp += " "
        
        # 若扩展，记录算式
        new_exp = new_exp.strip()
        new_exp = new_exp if new_exp != "" else cexp
        if extend:
            self.var_expand_chain[cvar].append(new_exp)
        if trace:
            if len(undeclare_variable) > 0:
                self.var_undeclare_chain[cvar].append(undeclare_variable)
            else:
                self.var_undeclare_chain[cvar].append('const')

        return (cvar, self.format_print_expression(new_exp.split(" ")))
    
    # 跳转相关操作
    def branch_func_analysis(self, cexp, extend: bool) -> tuple:
        final_res = (cexp, "")
        if extend:
            # 跳转类型表达式展开
            pattern, rep_str = r"", ""
            if cexp.startswith("if "):  # if-else 语句
                pattern = r"if \((.*?)\) ?goto"
                rep_str = "if (@#@) goto"
            elif cexp.startswith("return "):  # return 语句
                pattern = r"return (.*?)$"
                rep_str = "return (@#@)"
            else:
                return final_res
            # 展开并记录
            expand_cond_var = re.findall(pattern, cexp)[0].strip()
            std_exp = self.var_expand_chain.get(expand_cond_var)
            expand_exp = expand_cond_var if std_exp is None else std_exp[-1]
            final_res = (re.sub(pattern, rep_str.replace("@#@", self.format_print_expression(expand_exp.split(" "))), cexp), "")
        return final_res
    
    # 表达式分析
    def expression_analysis(self, extend: bool = False, trace: bool = False):
        # 分析
        for exp in self.ir.split('\n'):
            cvar, cexp = self.clean_expression(exp)
            if len(cvar) > 0:
                # 等式表达式扩展？追踪？并记录
                self.format_ir.append(self.equal_exp_analysis(cvar, cexp, extend, trace))
            else:
                # 跳转语句扩展？追踪？并记录 / 其他
                self.format_ir.append(self.branch_func_analysis(cexp, extend))
        return self.format_ir


if __name__ == "__main__":
    def test_pcode_analysis(ir: str):
        trans = PcodeTranslator()
        trans.pcode2python(pcode_ir=ir)

    def ir_analysis(ir: str, args_reg: list):
        import pprint

        my_pcode = PcodeIR(ir, args_reg)
        print('==== <P-Code IR> ====')
        for cvar, cexp in my_pcode.expression_analysis(trace=True):
            expression = f"{cvar} = {cexp}" if cexp != "" else cvar
            print(expression)
        # pprint.pprint(my_pcode.var_expand_chain)
        print('==== <Undeclared Variables Chain> ====')
        print(my_pcode.var_undeclare_chain)
        print('==== <Possible Arguments> ====')
        my_pcode.get_arguments_from_chain()


    def arch_pcode_main(arch_info: str, bytes_info: list):
        import pypcode
        
        suffix = ''
        if arch_info.startswith('MIPS:'):
            suffix = ' 00 00 00 00 '

        ctx = pypcode.Context(arch_info)
        for sample in bytes_info[0]:
            print('='*50 + f'[RIGHT INTERMEDIATE REPRESENTATION - {arch_info}]' + '='*50)
            cb = bytes.fromhex(sample+suffix)
            # print('==== <ASSEMBLE CODE> ====')
            # disasm = ctx.disassemble(cb)
            # print(disasm)
            pcode = ctx.translate(cb)
            ir_analysis(str(pcode), bytes_info[1])

    wrong_irs = [
    '''
        IMARK ram[81f2a00:2]
        mult_addr = sp
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = lr
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = r4
        sp = mult_addr
        IMARK ram[81f2a02:2]
        tmpCY = 0x20 <= r4
        tmpOV = sborrow(r4, 0x20)
        unique[97e80:4] = r4 - 0x20
        tmpNG = unique[97e80:4] s< 0x0
        tmpZR = unique[97e80:4] == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[81f2a04:2]
        unique[85680:1] = NG == OV
        if (unique[85680:1]) goto ram[81f2b06:4]
        IMARK ram[81f2a06:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[81f29ee:4]
        IMARK ram[81f2a08:2]
        mult_addr = sp
        r4 = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        sp = mult_addr
        IMARK ram[81f2a0a:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[81f2a0c:4]
        IMARK ram[81f2a0c:2]
        mult_addr = sp
        r4 = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        pc = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        sp = mult_addr
        unique[0:4] = pc & 0x1
        ISAModeSwitch = unique[0:4] != 0x0
        TB = ISAModeSwitch
        pc = pc & 0xfffffffe
        return pc
    ''',
    '''
        IMARK ram[18063c1e:2]
        mult_addr = sp
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = lr
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = r7
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = r6
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = r5
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = r4
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = r3
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = r2
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = r1
        mult_addr = mult_addr - 0x4
        *[ram]mult_addr = r0
        sp = mult_addr
        IMARK ram[18063c20:2]
        r5 = 0xb7
        tmpNG = r5 s< 0x0
        tmpZR = r5 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c22:2]
        unique[9df00:4] = 0x17
        unique[9d980:4] = unique[9df00:4] - 0x1
        unique[9da00:4] = r2 >> unique[9d980:4]
        unique[9db00:4] = unique[9da00:4] & 0x1
        unique[9db80:1] = unique[9df00:4] == 0x0
        unique[9dc00:1] = unique[9db80:1] && CY
        unique[9dc80:1] = unique[9df00:4] != 0x0
        unique[9dd00:1] = unique[9db00:4] != 0x0
        unique[9dd80:1] = unique[9dc80:1] && unique[9dd00:1]
        tmpCY = unique[9dc00:1] || unique[9dd80:1]
        r0 = r2 >> 0x17
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c24:2]
        r3 = r10
        IMARK ram[18063c26:2]
        tmpCY = 0xf <= r0
        tmpOV = sborrow(r0, 0xf)
        unique[97e80:4] = r0 - 0xf
        tmpNG = unique[97e80:4] s< 0x0
        tmpZR = unique[97e80:4] == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c28:2]
        unique[93c80:4] = sp + 0x3c
        *[ram]unique[93c80:4] = r1
        IMARK ram[18063c2a:2]
        r0 = r2
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c2c:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063c2a:4]
        IMARK ram[18063c2e:2]
        unique[93c80:4] = sp + 0x3fc
        r2 = *[ram]unique[93c80:4]
        IMARK ram[18063c30:2]
        tmpCY = 0x77 <= r0
        tmpOV = sborrow(r0, 0x77)
        unique[97e80:4] = r0 - 0x77
        tmpNG = unique[97e80:4] s< 0x0
        tmpZR = unique[97e80:4] == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c32:2]
        tmpCY = carry(r0, 0x4)
        tmpOV = scarry(r0, 0x4)
        r0 = r0 + 0x4
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c34:2]
        unique[85080:1] = NG == 0x0
        if (unique[85080:1]) goto ram[18063c38:4]
        IMARK ram[18063c36:2]
        unique[93c80:4] = sp + 0xf0
        *[ram]unique[93c80:4] = r1
        IMARK ram[18063c38:2]
        r0 = r2
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c3a:2]
        unique[93900:4] = r7 + 0x16
        unique[c4180:2] = SUBPIECE r5, 0x0
        *[ram]unique[93900:4] = unique[c4180:2]
        IMARK ram[18063c3c:2]
        unique[93900:4] = r1 + 0x10
        unique[c4180:2] = SUBPIECE r7, 0x0
        *[ram]unique[93900:4] = unique[c4180:2]
        IMARK ram[18063c3e:2]
        unique[93c80:4] = sp + 0x8
        *[ram]unique[93c80:4] = r1
        IMARK ram[18063c40:2]
        r0 = r2
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c42:2]
        unique[93900:4] = r5 + 0x10
        unique[c4180:2] = SUBPIECE r5, 0x0
        *[ram]unique[93900:4] = unique[c4180:2]
        IMARK ram[18063c44:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063c4a:4]
        IMARK ram[18063c46:2]
        tmpCY = 0xff <= r0
        tmpOV = sborrow(r0, 0xff)
        unique[97e80:4] = r0 - 0xff
        tmpNG = unique[97e80:4] s< 0x0
        tmpZR = unique[97e80:4] == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c48:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063cac:4]
        IMARK ram[18063c4a:2]
        tmpCY = r0 <= r4
        tmpOV = sborrow(r4, r0)
        r2 = r4 - r0
        tmpNG = r2 s< 0x0
        tmpZR = r2 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c4c:2]
        unique[93900:4] = r0 + 0xa
        unique[98d00:2] = *[ram]unique[93900:4]
        r4 = zext(unique[98d00:2])
        IMARK ram[18063c4e:2]
        tmpCY = carry(r7, 0x3)
        tmpOV = scarry(r7, 0x3)
        r7 = r7 + 0x3
        tmpNG = r7 s< 0x0
        tmpZR = r7 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c50:2]
        unique[93900:4] = r1 + 0x10
        unique[c4180:2] = SUBPIECE r0, 0x0
        *[ram]unique[93900:4] = unique[c4180:2]
        IMARK ram[18063c52:2]
        unique[93900:4] = r1 + 0x18
        unique[98d00:2] = *[ram]unique[93900:4]
        r7 = zext(unique[98d00:2])
        IMARK ram[18063c54:2]
        r1 = r2
        tmpNG = r1 s< 0x0
        tmpZR = r1 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c56:2]
        tmpCY = carry(r7, 0x0)
        tmpOV = scarry(r7, 0x0)
        r7 = r7 + 0x0
        tmpNG = r7 s< 0x0
        tmpZR = r7 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c58:2]
        unique[93900:4] = r3 + 0x0
        unique[98d00:2] = *[ram]unique[93900:4]
        r7 = zext(unique[98d00:2])
        IMARK ram[18063c5a:2]
        unique[9d280:4] = 0xb - 0x1
        unique[9d300:4] = r6 << unique[9d280:4]
        unique[9d400:4] = unique[9d300:4] & 0x80000000
        unique[9d480:1] = 0xb == 0x0
        unique[9d500:1] = unique[9d480:1] && CY
        unique[9d580:1] = 0xb != 0x0
        unique[9d600:1] = unique[9d400:4] != 0x0
        unique[9d680:1] = unique[9d580:1] && unique[9d600:1]
        tmpCY = unique[9d500:1] || unique[9d680:1]
        r0 = r6 << 0xb
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c5c:2]
        unique[95480:1] = 0x20 - 0x1
        unique[95500:4] = r0 s>> unique[95480:1]
        unique[95600:4] = unique[95500:4] & 0x1
        unique[95680:1] = 0x20 == 0x0
        unique[95700:1] = unique[95680:1] && CY
        unique[95780:1] = 0x20 != 0x0
        unique[95800:1] = unique[95600:4] != 0x0
        unique[95880:1] = unique[95780:1] && unique[95800:1]
        tmpCY = unique[95700:1] || unique[95880:1]
        r1 = r0 s>> 0x20
        tmpNG = r1 s< 0x0
        tmpZR = r1 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c5e:2]
        tmpCY = carry(r7, 0x2f)
        tmpOV = scarry(r7, 0x2f)
        r7 = r7 + 0x2f
        tmpNG = r7 s< 0x0
        tmpZR = r7 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c60:2]
        unique[93800:4] = r0 + 0x0
        r0 = *[ram]unique[93800:4]
        IMARK ram[18063c62:2]
        unique[88480:4] = sp + 0x3c0
        r0 = unique[88480:4]
        IMARK ram[18063c64:2]
        unique[86c80:1] = ZR != 0x0
        IMARK ram[18063c66:4]
        unique[86500:1] = !CY
        unique[86600:1] = unique[86500:1] || ZR
        if (unique[86600:1]) goto ram[17f93268:4]
        IMARK ram[18063c6a:2]
        unique[93c80:4] = sp + 0x7c
        *[ram]unique[93c80:4] = r1
        IMARK ram[18063c6c:2]
        r0 = r2
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c6e:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063c6c:4]
        IMARK ram[18063c70:2]
        unique[9d280:4] = 0x13 - 0x1
        unique[9d300:4] = r7 << unique[9d280:4]
        unique[9d400:4] = unique[9d300:4] & 0x80000000
        unique[9d480:1] = 0x13 == 0x0
        unique[9d500:1] = unique[9d480:1] && CY
        unique[9d580:1] = 0x13 != 0x0
        unique[9d600:1] = unique[9d400:4] != 0x0
        unique[9d680:1] = unique[9d580:1] && unique[9d600:1]
        tmpCY = unique[9d500:1] || unique[9d680:1]
        r7 = r7 << 0x13
        tmpNG = r7 s< 0x0
        tmpZR = r7 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c72:2]
        tmpCY = 0x40 <= r0
        tmpOV = sborrow(r0, 0x40)
        unique[97e80:4] = r0 - 0x40
        tmpNG = unique[97e80:4] s< 0x0
        tmpZR = unique[97e80:4] == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c74:2]
        tmpCY = 0x0 <= r3
        tmpOV = sborrow(r3, 0x0)
        r3 = r3 - 0x0
        tmpNG = r3 s< 0x0
        tmpZR = r3 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c76:2]
        unique[9df00:4] = 0x1f
        unique[9d980:4] = unique[9df00:4] - 0x1
        unique[9da00:4] = r6 >> unique[9d980:4]
        unique[9db00:4] = unique[9da00:4] & 0x1
        unique[9db80:1] = unique[9df00:4] == 0x0
        unique[9dc00:1] = unique[9db80:1] && CY
        unique[9dc80:1] = unique[9df00:4] != 0x0
        unique[9dd00:1] = unique[9db00:4] != 0x0
        unique[9dd80:1] = unique[9dc80:1] && unique[9dd00:1]
        tmpCY = unique[9dc00:1] || unique[9dd80:1]
        r0 = r6 >> 0x1f
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c78:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063c7c:4]
        IMARK ram[18063c7a:2]
        unique[9df00:4] = 0x10
        unique[9d980:4] = unique[9df00:4] - 0x1
        unique[9da00:4] = r5 >> unique[9d980:4]
        unique[9db00:4] = unique[9da00:4] & 0x1
        unique[9db80:1] = unique[9df00:4] == 0x0
        unique[9dc00:1] = unique[9db80:1] && CY
        unique[9dc80:1] = unique[9df00:4] != 0x0
        unique[9dd00:1] = unique[9db00:4] != 0x0
        unique[9dd80:1] = unique[9dc80:1] && unique[9dd00:1]
        tmpCY = unique[9dc00:1] || unique[9dd80:1]
        r7 = r5 >> 0x10
        tmpNG = r7 s< 0x0
        tmpZR = r7 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c7c:2]
        unique[88480:4] = sp + 0x0
        r0 = unique[88480:4]
        IMARK ram[18063c7e:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063c86:4]
        IMARK ram[18063c80:2]
        unique[9df00:4] = 0x18
        unique[9d980:4] = unique[9df00:4] - 0x1
        unique[9da00:4] = r5 >> unique[9d980:4]
        unique[9db00:4] = unique[9da00:4] & 0x1
        unique[9db80:1] = unique[9df00:4] == 0x0
        unique[9dc00:1] = unique[9db80:1] && CY
        unique[9dc80:1] = unique[9df00:4] != 0x0
        unique[9dd00:1] = unique[9db00:4] != 0x0
        unique[9dd80:1] = unique[9dc80:1] && unique[9dd00:1]
        tmpCY = unique[9dc00:1] || unique[9dd80:1]
        r7 = r5 >> 0x18
        tmpNG = r7 s< 0x0
        tmpZR = r7 == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c82:2]
        tmpCY = 0x0 <= r0
        tmpOV = sborrow(r0, 0x0)
        unique[97e80:4] = r0 - 0x0
        tmpNG = unique[97e80:4] s< 0x0
        tmpZR = unique[97e80:4] == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c84:2]
        unique[93c80:4] = sp + 0x8
        *[ram]unique[93c80:4] = r1
        IMARK ram[18063c86:2]
        r0 = r2
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c88:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063c86:4]
        IMARK ram[18063c8a:2]
        unique[93c80:4] = sp + 0x3fc
        r4 = *[ram]unique[93c80:4]
        IMARK ram[18063c8c:2]
        unique[88480:4] = sp + 0x25c
        r0 = unique[88480:4]
        IMARK ram[18063c8e:2]
        unique[93c80:4] = sp + 0x8
        *[ram]unique[93c80:4] = r1
        IMARK ram[18063c90:2]
        r0 = r2
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c92:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063c90:4]
        IMARK ram[18063c94:2]
        unique[93c80:4] = sp + 0x3fc
        *[ram]unique[93c80:4] = r4
        IMARK ram[18063c96:2]
        tmpCY = 0x67 <= r0
        tmpOV = sborrow(r0, 0x67)
        unique[97e80:4] = r0 - 0x67
        tmpNG = unique[97e80:4] s< 0x0
        tmpZR = unique[97e80:4] == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063c98:2]
        unique[93900:4] = r1 + 0x10
        unique[c4180:2] = SUBPIECE r7, 0x0
        *[ram]unique[93900:4] = unique[c4180:2]
        IMARK ram[18063c9a:2]
        unique[93c80:4] = sp + 0x3c
        *[ram]unique[93c80:4] = r1
        IMARK ram[18063c9c:2]
        r0 = r2
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063c9e:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063c9c:4]
        IMARK ram[18063ca0:2]
        unique[aba80:4] = r7 & 0xff
        unique[abb00:4] = r7 >> 0x8
        unique[abc00:4] = unique[abb00:4] & 0xff
        unique[abc80:4] = unique[aba80:4] << 0x8
        unique[abd80:4] = unique[abc80:4] | unique[abc00:4]
        unique[abe00:2] = SUBPIECE unique[abd80:4], 0x0
        r7 = sext(unique[abe00:2])
        IMARK ram[18063ca2:2]
        tmpCY = 0x57 <= r0
        tmpOV = sborrow(r0, 0x57)
        unique[97e80:4] = r0 - 0x57
        tmpNG = unique[97e80:4] s< 0x0
        tmpZR = unique[97e80:4] == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063ca4:2]
        unique[93c80:4] = sp + 0x8
        *[ram]unique[93c80:4] = r1
        IMARK ram[18063ca6:2]
        r0 = r2
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063ca8:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063ca6:4]
        IMARK ram[18063caa:2]
        unique[97400:1] = r7 != 0x0
        if (unique[97400:1]) goto ram[18063d2c:4]
        IMARK ram[18063cac:2]
        tmpCY = 0x57 <= r0
        tmpOV = sborrow(r0, 0x57)
        unique[97e80:4] = r0 - 0x57
        tmpNG = unique[97e80:4] s< 0x0
        tmpZR = unique[97e80:4] == 0x0
        CY = tmpCY
        ZR = tmpZR
        NG = tmpNG
        OV = tmpOV
        IMARK ram[18063cae:2]
        unique[93c80:4] = sp + 0x8
        *[ram]unique[93c80:4] = r1
        IMARK ram[18063cb0:2]
        r0 = r2
        tmpNG = r0 s< 0x0
        tmpZR = r0 == 0x0
        ZR = tmpZR
        NG = tmpNG
        IMARK ram[18063cb2:2]
        unique[85480:1] = !CY
        unique[85580:1] = unique[85480:1] || ZR
        if (unique[85580:1]) goto ram[18063cb0:4]
        IMARK ram[18063cb4:2]
        mult_addr = sp
        r0 = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        r1 = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        r2 = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        r3 = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        r4 = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        r5 = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        r6 = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        r7 = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        pc = *[ram]mult_addr
        mult_addr = mult_addr + 0x4
        sp = mult_addr
        unique[0:4] = pc & 0x1
        ISAModeSwitch = unique[0:4] != 0x0
        TB = ISAModeSwitch
        pc = pc & 0xfffffffe
        return pc
    ''',
    ]
    
    bytes_info = {
        "tricore:LE:32:tc29x": [
            [
                "4d c0 e1 ff 16 07 3c 01 91 30 00 ff d9 ff 00 46 53 cf 20 f0 10 ff 54 ff 2e 1b 8f 24 20 f0 96 01 54 f0 37 00 70 08 8f 00 21 00 a6 0f 74 ff 8f 24 20 f0 96 02 54 f0 37 00 70 08 8f 00 21 00 a6 0f 74 ff 3c 01 54 ff 16 01 df 1f fe 7f 08 4f 96 08 2c f4 54 ff 2e 1b 8f 24 20 f0 96 01 54 f0 37 00 70 08 8f 00 21 00 a6 0f 74 ff 86 24 8f 34 40 f1 54 f0 37 00 70 08 8f 00 21 00 a6 0f 74 ff 3c 01 54 ff 6f 0f ff 7f 00 90",
                "20 38 49 a4 00 0a 91 00 00 56 d9 55 08 00 6d 00 fa 11 da 00 2c a4 da 00 2c a5 da 01 89 af 31 08 da 01 89 af 24 08 da 01 89 af 28 08 91 00 00 46 d9 44 2c 00 49 a5 00 0a 6d 00 f3 0f 00 90",
                "53 84 20 f0 91 00 00 f6 d9 ff 0c 00 10 ff c8 12 09 22 84 09 08 1f 53 4f 20 f0 10 2f 19 ff 00 a0 3c 01 3c 01 37 0f 68 0c 6f 70 ec 7f 37 0f 70 20 3c 01 00 90"
            ],
            ["a2", "a3", "a4", "a5", "a6", "a7", "a12", "a13", "a14", "a15", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15"]
        ],
        "MIPS:BE:32:default": [
            [
                "27 bd ff d8 af bf 00 24 af b1 00 20 af b0 00 1c af bc 00 10 3c 11 00 45 10 00 00 04 3c 10 00 45 0c 10 99 cf 00 00 00 00 8f bc 00 10 8e 22 6c e8 8e 03 6c ec 00 00 00 00 00 43 10 2a 14 40 ff f8 00 00 20 21 8f bf 00 24 8f b1 00 20 8f b0 00 1c 03 e0 00 08",
                "3c 1c 00 46 27 bd ff e0 27 9c 9c 80 af bf 00 1c af b0 00 18 af bc 00 10 3c 02 00 45 8c 43 6c f0 3c 02 00 45 8c 42 6c e8 00 80 80 21 00 62 18 21 90 64 00 00 00 00 00 00 14 80 00 02 00 00 00 00 24 04 00 20 8f 82 82 80 00 00 00 00 8c 45 00 00 00 00 00 00 8c a2 00 48 00 00 00 00 10 40 00 0d 00 00 00 00 8c a3 00 10 8c a2 00 1c 00 00 00 00 00 62 10 2b 10 40 00 04 24 62 00 01 a0 64 00 00 10 00 00 09 ac a2 00 10 8f 99 84 b0 10 00 00 03 00 00 00 00 8f 99 83 94 00 00 00 00 03 20 f8 09 00 00 00 00 8f bc 00 10 3c 04 00 45 8c 82 6c dc 3c 03 00 45 8c 63 19 90 24 42 00 01 ac 82 6c dc 00 43 10 2a 14 40 00 3b 3c 03 00 45 8c 62 6c e0 ac 80 6c dc 24 42 00 01 16 00 00 02 ac 62 6c e0 24 10 00 20 8f 82 82 80 00 00 00 00 8c 45 00 00 00 00 00 00 8c a2 00 48 00 00 00 00 10 40 00 0d 00 00 00 00 8c a3 00 10 8c a2 00 1c 00 00 00 00 00 62 10 2b 10 40 00 04 24 62 00 01 a0 70 00 00 10 00 00 0a ac a2 00 10 8f 99 84 b0 10 00 00 03 00 00 00 00 8f 99 83 94 00 00 00 00 03 20 f8 09 02 00 20 21 8f bc 00 10 00 00 00 00 8f 82 82 80 00 00 00 00 8c 45 00 00 00 00 00 00 8c a2 00 48 00 00 00 00 10 40 00 0e 00 00 00 00 8c a4 00 10 8c a2 00 1c 00 00 00 00 00 82 10 2b 10 40 00 05 24 83 00 01 24 02 00 08 a0 82 00 00 10 00 00 09 ac a3 00 10 8f 99 84 b0 10 00 00 03 00 00 00 00 8f 99 83 94 00 00 00 00 03 20 f8 09 24 04 00 08 8f bc 00 10 3c 03 00 45 8c 62 6c e8 8f bf 00 1c 8f b0 00 18 24 42 00 01 ac 62 6c e8 03 e0 00 08",
            ],
            ["v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"]
        ],
        "ARM:LE:32:Cortex":[
            [
                "b0 b5 8a b0 00 af 00 f0 59 fa 00 f0 99 f8 00 20 00 f0 9a f9 01 20 00 f0 97 f9 12 4b 07 f1 14 04 1d 46 0f cd 0f c4 2b 68 23 60 0f 4b 3c 46 1d 46 0f cd 0f c4 2b 68 23 60 07 f1 14 03 00 21 18 46 01 f0 d1 fc 03 46 09 4a 13 60 3b 46 00 21 18 46 01 f0 c9 fc 03 46 06 4a 13 60 01 f0 ad fc 00 bf fd e7",
                "80 b5 00 af ff f7 e3 ff 03 46 00 2b 03 d0 00 f0 40 fd 03 46 02 e0 00 f0 2c fd 03 46 18 46 80 bd",
                "f0 b5 87 b0 02 af 78 60 39 60 7b 68 5c 68 7b 68 1d 68 7b 68 1b 69 9e b2 7b 68 b3 f9 08 30 18 46 ff f7 ad ff 02 46 07 f1 0c 03 01 93 00 92 3b 68 32 46 29 46 20 46 00 f0 0c f9 03 46 01 2b 01 d0 00 23 00 e0 fb 68 18 46 14 37 bd 46 f0 bd",
            ], 
            ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"]
        ]
    }

    for key, value in bytes_info.items():
        arch_pcode_main(key, value)
    
    # 记录“负样本”
    for ir in wrong_irs:
        print('='*50 + '[WRONG INTERMEDIATE REPRESENTATION]' + '='*50)
        ir_analysis(ir, ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"])


