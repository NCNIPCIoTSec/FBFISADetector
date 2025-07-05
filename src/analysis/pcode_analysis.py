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

    def __init__(self, ir: str) -> None:
        # 清洗IR
        ir = re.sub(r'IMARK ram\[([0-9a-fA-F:]+)\]\n', r'', ir)
        ir = re.sub(r'= SUBPIECE ([\[\]:\w]+), 0x(\d+)', r"= SUBPIECE(\1,0x\2)", ir)
        # 变量分析
        self.ir = ir
        self.var_expand_chain = {}
        self.var_undeclare_chain = {}

    # 内存/寄存器（指针）处理
    def get_var_from_pointer(self, variable: str):
        for p in self.pointer_operator:
            if variable.startswith(p):
                addr_info = variable[len(p):].strip()
                if (exp_chain := self.var_expand_chain.get(addr_info)) is not None:
                    exp_chain[-1] = exp_chain[-1].replace(" ", "")
                    return f"ram[{exp_chain[-1]}]"
        return variable

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
            _, cur_var = self.get_var_from_neg(self.get_var_from_pointer(cur_var))
            return cur_var, cur_exp
        return "", whole_exp

    def extract_expression_variables(self, cur_exp):
        pass

    # 表达式分析
    def expression_analysis(self):
        # 跳转相关操作
        def branch_func_trace(cexp) -> tuple:
            # 跳转类型表达式展开
            pattern, rep_str = r"", ""
            if cexp.startswith("if "):
                pattern = r"if \((.*?)\) ?goto"
                rep_str = "if (@#@) goto"
            elif cexp.startswith("return "):
                pattern = r"return (.*?)$"
                rep_str = "return (@#@)"
            else:
                return (cexp, "")
            # 展开并记录
            expand_cond_var = re.findall(pattern, cexp)[0].strip()
            std_exp = self.var_expand_chain.get(expand_cond_var)
            expand_exp = expand_cond_var if std_exp is None else std_exp[-1]
            return (re.sub(pattern, rep_str.replace("@#@", self.format_print_expression(expand_exp.split(" "))), cexp), "")

        # 等式表达式扩展
        def equal_exp_trace(cvar: str, cexp: str):
            if self.var_expand_chain.get(cvar) is None:
                self.var_expand_chain[cvar] = [cexp]
            if self.var_undeclare_chain.get(cvar) is None:
                self.var_undeclare_chain[cvar] = set()
            new_exp = ""
            for ve in cexp.split(" "):
                ve = ve.strip()
                # 运算符/其他非变量以及常量符号，PASS
                if len(ve) == 0 or ve in self.mid_operator:
                    new_exp += (ve + " ")
                    continue
                # 前缀运算符处理
                ve = self.get_var_from_pointer(ve)
                pre_op, ve = self.get_var_from_neg(ve)
                new_exp += pre_op
                # 未声明变量追踪
                if self.var_undeclare_chain.get(ve) is not None:
                    self.var_undeclare_chain[cvar].union(self.var_undeclare_chain[ve])
                elif not (ve in self.weak_syntax_char or ve.startswith('0x') or ve.endswith("(")):
                    self.var_undeclare_chain[cvar].add(ve)
                # 表达式展开
                if self.var_expand_chain.get(ve) is not None:
                    new_exp += f"( {self.var_expand_chain[ve][-1]} )"
                else:
                    new_exp += ve
                new_exp += " "
            # 简化算式
            new_exp = new_exp.strip()
            new_exp = new_exp if new_exp != "" else cexp
            self.var_expand_chain[cvar].append(new_exp)
            return (cvar, self.format_print_expression(new_exp.split(" ")))

        # 分析
        full_expressions = []
        for exp in self.ir.split('\n'):
            cvar, cexp = self.clean_expression(exp)
            if len(cvar) > 0:
                # 等式表达式扩展并记录
                full_expressions.append(equal_exp_trace(cvar, cexp))
            else:
                # 跳转语句扩展并记录 / 其他
                full_expressions.append(branch_func_trace(cexp))
        return full_expressions
    

def test_pcode_analysis(ir: str):
    # my_pcode = PcodeIR(ir)
    # for cvar, cexp in my_pcode.expression_analysis():
    #     expression = f"{cvar} = {cexp}" if cexp != "" else cvar
    #     print(expression)
    # print(my_pcode.var_expand_chain)
    # print(my_pcode.var_undeclare_chain)
    trans = PcodeTranslator()
    trans.pcode2python(pcode_ir=ir)


if __name__ == "__main__":
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
    right_irs = [
        '''
            IMARK ram[80000228:4]
            isync()
            IMARK ram[8000022c:4]
            dsync()
            IMARK ram[80000230:2]
            unique[77f80:1] = 0x0
            unique[77f80:1] = unique[77f80:1]
            IMARK ram[80000232:2]
            unique[77f80:1] = 0x0
            unique[77f80:1] = unique[77f80:1]
            IMARK ram[80000234:4]
            unique[f180:4] = 0xfe00
            d0 = *[register]unique[f180:4]
            IMARK ram[80000238:4]
            isync()
            IMARK ram[8000023c:4]
            unique[f180:4] = 0xfff0
            d1 = unique[f180:4] << 0x10
            IMARK ram[80000240:2]
            d0 = d0 & d1
            IMARK ram[80000242:4]
            unique[f180:4] = 0xfe00
            *[register]unique[f180:4] = d0
            IMARK ram[80000246:4]
            isync()
            IMARK ram[8000024a:4]
            unique[f180:4] = 0xd000
            d0 = unique[f180:4] << 0x10
            IMARK ram[8000024e:4]
            unique[f100:4] = 0x40
            d0 = d0 + unique[f100:4]
            unique[4680:4] = PSW & 0xbfffffff
            unique[4500:4] = d0 >> 0x1f
            unique[4580:1] = SUBPIECE unique[4500:4], 0x0
            unique[4600:1] = unique[4580:1] & 0x1
            unique[4700:4] = zext(unique[4600:1])
            unique[4780:4] = unique[4700:4] << 0x1e
            PSW = unique[4680:4] | unique[4780:4]
            unique[4b80:4] = PSW & 0xdfffffff
            unique[4800:4] = PSW >> 0x1e
            unique[4880:1] = SUBPIECE unique[4800:4], 0x0
            unique[4900:1] = unique[4880:1] & 0x1
            unique[4980:4] = PSW >> 0x1d
            unique[4a00:1] = SUBPIECE unique[4980:4], 0x0
            unique[4a80:1] = unique[4a00:1] & 0x1
            unique[4b00:1] = unique[4900:1] | unique[4a80:1]
            unique[4c00:4] = zext(unique[4b00:1])
            unique[4c80:4] = unique[4c00:4] << 0x1d
            PSW = unique[4b80:4] | unique[4c80:4]
            unique[5080:4] = PSW & 0xefffffff
            unique[4d00:4] = d0 >> 0x1f
            unique[4d80:1] = SUBPIECE unique[4d00:4], 0x0
            unique[4e00:1] = unique[4d80:1] & 0x1
            unique[4e80:4] = d0 >> 0x1e
            unique[4f00:1] = SUBPIECE unique[4e80:4], 0x0
            unique[4f80:1] = unique[4f00:1] & 0x1
            unique[5000:1] = unique[4e00:1] ^ unique[4f80:1]
            unique[5100:4] = zext(unique[5000:1])
            unique[5180:4] = unique[5100:4] << 0x1c
            PSW = unique[5080:4] | unique[5180:4]
            unique[5580:4] = PSW & 0xf7ffffff
            unique[5200:4] = PSW >> 0x1c
            unique[5280:1] = SUBPIECE unique[5200:4], 0x0
            unique[5300:1] = unique[5280:1] & 0x1
            unique[5380:4] = PSW >> 0x1b
            unique[5400:1] = SUBPIECE unique[5380:4], 0x0
            unique[5480:1] = unique[5400:1] & 0x1
            unique[5500:1] = unique[5300:1] | unique[5480:1]
            unique[5600:4] = zext(unique[5500:1])
            unique[5680:4] = unique[5600:4] << 0x1b
            PSW = unique[5580:4] | unique[5680:4]
            IMARK ram[80000252:4]
            unique[f180:4] = 0xd000
            d2 = unique[f180:4] << 0x10
            IMARK ram[80000256:4]
            unique[f100:4] = 0x83f
            d2 = d2 + unique[f100:4]
            unique[4680:4] = PSW & 0xbfffffff
            unique[4500:4] = d2 >> 0x1f
            unique[4580:1] = SUBPIECE unique[4500:4], 0x0
            unique[4600:1] = unique[4580:1] & 0x1
            unique[4700:4] = zext(unique[4600:1])
            unique[4780:4] = unique[4700:4] << 0x1e
            PSW = unique[4680:4] | unique[4780:4]
            unique[4b80:4] = PSW & 0xdfffffff
            unique[4800:4] = PSW >> 0x1e
            unique[4880:1] = SUBPIECE unique[4800:4], 0x0
            unique[4900:1] = unique[4880:1] & 0x1
            unique[4980:4] = PSW >> 0x1d
            unique[4a00:1] = SUBPIECE unique[4980:4], 0x0
            unique[4a80:1] = unique[4a00:1] & 0x1
            unique[4b00:1] = unique[4900:1] | unique[4a80:1]
            unique[4c00:4] = zext(unique[4b00:1])
            unique[4c80:4] = unique[4c00:4] << 0x1d
            PSW = unique[4b80:4] | unique[4c80:4]
            unique[5080:4] = PSW & 0xefffffff
            unique[4d00:4] = d2 >> 0x1f
            unique[4d80:1] = SUBPIECE unique[4d00:4], 0x0
            unique[4e00:1] = unique[4d80:1] & 0x1
            unique[4e80:4] = d2 >> 0x1e
            unique[4f00:1] = SUBPIECE unique[4e80:4], 0x0
            unique[4f80:1] = unique[4f00:1] & 0x1
            unique[5000:1] = unique[4e00:1] ^ unique[4f80:1]
            unique[5100:4] = zext(unique[5000:1])
            unique[5180:4] = unique[5100:4] << 0x1c
            PSW = unique[5080:4] | unique[5180:4]
            unique[5580:4] = PSW & 0xf7ffffff
            unique[5200:4] = PSW >> 0x1c
            unique[5280:1] = SUBPIECE unique[5200:4], 0x0
            unique[5300:1] = unique[5280:1] & 0x1
            unique[5380:4] = PSW >> 0x1b
            unique[5400:1] = SUBPIECE unique[5380:4], 0x0
            unique[5480:1] = unique[5400:1] & 0x1
            unique[5500:1] = unique[5300:1] | unique[5480:1]
            unique[5600:4] = zext(unique[5500:1])
            unique[5680:4] = unique[5600:4] << 0x1b
            PSW = unique[5580:4] | unique[5680:4]
            IMARK ram[8000025a:4]
            unique[f100:4] = 0x1
            d2 = d2 + unique[f100:4]
            unique[4680:4] = PSW & 0xbfffffff
            unique[4500:4] = d2 >> 0x1f
            unique[4580:1] = SUBPIECE unique[4500:4], 0x0
            unique[4600:1] = unique[4580:1] & 0x1
            unique[4700:4] = zext(unique[4600:1])
            unique[4780:4] = unique[4700:4] << 0x1e
            PSW = unique[4680:4] | unique[4780:4]
            unique[4b80:4] = PSW & 0xdfffffff
            unique[4800:4] = PSW >> 0x1e
            unique[4880:1] = SUBPIECE unique[4800:4], 0x0
            unique[4900:1] = unique[4880:1] & 0x1
            unique[4980:4] = PSW >> 0x1d
            unique[4a00:1] = SUBPIECE unique[4980:4], 0x0
            unique[4a80:1] = unique[4a00:1] & 0x1
            unique[4b00:1] = unique[4900:1] | unique[4a80:1]
            unique[4c00:4] = zext(unique[4b00:1])
            unique[4c80:4] = unique[4c00:4] << 0x1d
            PSW = unique[4b80:4] | unique[4c80:4]
            unique[5080:4] = PSW & 0xefffffff
            unique[4d00:4] = d2 >> 0x1f
            unique[4d80:1] = SUBPIECE unique[4d00:4], 0x0
            unique[4e00:1] = unique[4d80:1] & 0x1
            unique[4e80:4] = d2 >> 0x1e
            unique[4f00:1] = SUBPIECE unique[4e80:4], 0x0
            unique[4f80:1] = unique[4f00:1] & 0x1
            unique[5000:1] = unique[4e00:1] ^ unique[4f80:1]
            unique[5100:4] = zext(unique[5000:1])
            unique[5180:4] = unique[5100:4] << 0x1c
            PSW = unique[5080:4] | unique[5180:4]
            unique[5580:4] = PSW & 0xf7ffffff
            unique[5200:4] = PSW >> 0x1c
            unique[5280:1] = SUBPIECE unique[5200:4], 0x0
            unique[5300:1] = unique[5280:1] & 0x1
            unique[5380:4] = PSW >> 0x1b
            unique[5400:1] = SUBPIECE unique[5380:4], 0x0
            unique[5480:1] = unique[5400:1] & 0x1
            unique[5500:1] = unique[5300:1] | unique[5480:1]
            unique[5600:4] = zext(unique[5500:1])
            unique[5680:4] = unique[5600:4] << 0x1b
            PSW = unique[5580:4] | unique[5680:4]
            IMARK ram[8000025e:2]
            d2 = d2 - d0
            unique[4680:4] = PSW & 0xbfffffff
            unique[4500:4] = d2 >> 0x1f
            unique[4580:1] = SUBPIECE unique[4500:4], 0x0
            unique[4600:1] = unique[4580:1] & 0x1
            unique[4700:4] = zext(unique[4600:1])
            unique[4780:4] = unique[4700:4] << 0x1e
            PSW = unique[4680:4] | unique[4780:4]
            unique[4b80:4] = PSW & 0xdfffffff
            unique[4800:4] = PSW >> 0x1e
            unique[4880:1] = SUBPIECE unique[4800:4], 0x0
            unique[4900:1] = unique[4880:1] & 0x1
            unique[4980:4] = PSW >> 0x1d
            unique[4a00:1] = SUBPIECE unique[4980:4], 0x0
            unique[4a80:1] = unique[4a00:1] & 0x1
            unique[4b00:1] = unique[4900:1] | unique[4a80:1]
            unique[4c00:4] = zext(unique[4b00:1])
            unique[4c80:4] = unique[4c00:4] << 0x1d
            PSW = unique[4b80:4] | unique[4c80:4]
            unique[5080:4] = PSW & 0xefffffff
            unique[4d00:4] = d2 >> 0x1f
            unique[4d80:1] = SUBPIECE unique[4d00:4], 0x0
            unique[4e00:1] = unique[4d80:1] & 0x1
            unique[4e80:4] = d2 >> 0x1e
            unique[4f00:1] = SUBPIECE unique[4e80:4], 0x0
            unique[4f80:1] = unique[4f00:1] & 0x1
            unique[5000:1] = unique[4e00:1] ^ unique[4f80:1]
            unique[5100:4] = zext(unique[5000:1])
            unique[5180:4] = unique[5100:4] << 0x1c
            PSW = unique[5080:4] | unique[5180:4]
            unique[5580:4] = PSW & 0xf7ffffff
            unique[5200:4] = PSW >> 0x1c
            unique[5280:1] = SUBPIECE unique[5200:4], 0x0
            unique[5300:1] = unique[5280:1] & 0x1
            unique[5380:4] = PSW >> 0x1b
            unique[5400:1] = SUBPIECE unique[5380:4], 0x0
            unique[5480:1] = unique[5400:1] & 0x1
            unique[5500:1] = unique[5300:1] | unique[5480:1]
            unique[5600:4] = zext(unique[5500:1])
            unique[5680:4] = unique[5600:4] << 0x1b
            PSW = unique[5580:4] | unique[5680:4]
            IMARK ram[80000260:2]
            unique[ee00:4] = 0xfffffffa
            unique[83a00:4] = -unique[ee00:4]
            d2 = d2 >> unique[83a00:4]
            IMARK ram[80000262:2]
            a3 = d0
            IMARK ram[80000264:4]
            unique[f280:4] = 0x4
            unique[f300:4] = 0x1c
            unique[2b280:4] = d0 >> unique[f300:4]
            unique[2b300:4] = 0x1 << unique[f280:4]
            unique[2b400:4] = unique[2b300:4] - 0x1
            d0 = unique[2b280:4] & unique[2b400:4]
            IMARK ram[80000268:4]
            unique[f000:4] = 0x10
            unique[84400:1] = SUBPIECE unique[f000:4], 0x0
            unique[84480:1] = unique[84400:1] & 0x3f
            d0 = d0 << unique[84480:1]
            IMARK ram[8000026c:2]
            unique[ee80:4] = 0x0
            a4 = unique[ee80:4]
            IMARK ram[8000026e:2]
            unique[f900:4] = a3
            *[ram]unique[f900:4] = a4
            IMARK ram[80000270:2]
            a4 = a3
            IMARK ram[80000272:4]
            unique[e580:4] = 0x40
            unique[f880:4] = a3 + unique[e580:4]
            a3 = unique[f880:4]
            IMARK ram[80000276:2]
            d1 = a3
            IMARK ram[80000278:4]
            unique[f280:4] = 0x10
            unique[f300:4] = 0x6
            unique[2b280:4] = d1 >> unique[f300:4]
            unique[2b300:4] = 0x1 << unique[f280:4]
            unique[2b400:4] = unique[2b300:4] - 0x1
            d1 = unique[2b280:4] & unique[2b400:4]
            IMARK ram[8000027c:2]
            d1 = d1 | d0
            IMARK ram[8000027e:4]
            unique[f180:4] = 0xfe3c
            *[register]unique[f180:4] = d1
            IMARK ram[80000282:4]
            isync()
            IMARK ram[80000286:2]
            unique[ee00:4] = 0xfffffffe
            d2 = d2 + unique[ee00:4]
            unique[4680:4] = PSW & 0xbfffffff
            unique[4500:4] = d2 >> 0x1f
            unique[4580:1] = SUBPIECE unique[4500:4], 0x0
            unique[4600:1] = unique[4580:1] & 0x1
            unique[4700:4] = zext(unique[4600:1])
            unique[4780:4] = unique[4700:4] << 0x1e
            PSW = unique[4680:4] | unique[4780:4]
            unique[4b80:4] = PSW & 0xdfffffff
            unique[4800:4] = PSW >> 0x1e
            unique[4880:1] = SUBPIECE unique[4800:4], 0x0
            unique[4900:1] = unique[4880:1] & 0x1
            unique[4980:4] = PSW >> 0x1d
            unique[4a00:1] = SUBPIECE unique[4980:4], 0x0
            unique[4a80:1] = unique[4a00:1] & 0x1
            unique[4b00:1] = unique[4900:1] | unique[4a80:1]
            unique[4c00:4] = zext(unique[4b00:1])
            unique[4c80:4] = unique[4c00:4] << 0x1d
            PSW = unique[4b80:4] | unique[4c80:4]
            unique[5080:4] = PSW & 0xefffffff
            unique[4d00:4] = d2 >> 0x1f
            unique[4d80:1] = SUBPIECE unique[4d00:4], 0x0
            unique[4e00:1] = unique[4d80:1] & 0x1
            unique[4e80:4] = d2 >> 0x1e
            unique[4f00:1] = SUBPIECE unique[4e80:4], 0x0
            unique[4f80:1] = unique[4f00:1] & 0x1
            unique[5000:1] = unique[4e00:1] ^ unique[4f80:1]
            unique[5100:4] = zext(unique[5000:1])
            unique[5180:4] = unique[5100:4] << 0x1c
            PSW = unique[5080:4] | unique[5180:4]
            unique[5580:4] = PSW & 0xf7ffffff
            unique[5200:4] = PSW >> 0x1c
            unique[5280:1] = SUBPIECE unique[5200:4], 0x0
            unique[5300:1] = unique[5280:1] & 0x1
            unique[5380:4] = PSW >> 0x1b
            unique[5400:1] = SUBPIECE unique[5380:4], 0x0
            unique[5480:1] = unique[5400:1] & 0x1
            unique[5500:1] = unique[5300:1] | unique[5480:1]
            unique[5600:4] = zext(unique[5500:1])
            unique[5680:4] = unique[5600:4] << 0x1b
            PSW = unique[5580:4] | unique[5680:4]
            IMARK ram[80000288:2]
            a5 = d2
            IMARK ram[8000028a:2]
            d1 = a4
            IMARK ram[8000028c:4]
            unique[f280:4] = 0x10
            unique[f300:4] = 0x6
            unique[2b280:4] = d1 >> unique[f300:4]
            unique[2b300:4] = 0x1 << unique[f280:4]
            unique[2b400:4] = unique[2b300:4] - 0x1
            d1 = unique[2b280:4] & unique[2b400:4]
            IMARK ram[80000290:2]
            d1 = d1 | d0
            IMARK ram[80000292:2]
            unique[f900:4] = a3
            *[ram]unique[f900:4] = d1
            IMARK ram[80000294:2]
            a4 = a3
            IMARK ram[80000296:4]
            unique[e580:4] = 0x40
            unique[f880:4] = a3 + unique[e580:4]
            a3 = unique[f880:4]
            IMARK ram[8000029a:2]
            unique[39d00:4] = a5
            a5 = a5 - 0x1
            unique[39e00:1] = unique[39d00:4] != 0x0
            if (unique[39e00:1]) goto ram[8000028a:4]
            IMARK ram[8000029c:2]
            d1 = a4
            IMARK ram[8000029e:4]
            unique[f280:4] = 0x10
            unique[f300:4] = 0x6
            unique[2b280:4] = d1 >> unique[f300:4]
            unique[2b300:4] = 0x1 << unique[f280:4]
            unique[2b400:4] = unique[2b300:4] - 0x1
            d1 = unique[2b280:4] & unique[2b400:4]
            IMARK ram[800002a2:2]
            d1 = d1 | d0
            IMARK ram[800002a4:4]
            unique[f180:4] = 0xfe38
            *[register]unique[f180:4] = d1
            IMARK ram[800002a8:4]
            isync()
            IMARK ram[800002ac:4]
            unique[f180:4] = 0xd000
            a10 = unique[f180:4] << 0x10
            IMARK ram[800002b0:4]
            unique[e580:4] = 0xac0
            unique[f880:4] = a10 + unique[e580:4]
            a10 = unique[f880:4]
            IMARK ram[800002b4:4]
            unique[f180:4] = 0xd000
            a0 = unique[f180:4] << 0x10
            IMARK ram[800002b8:4]
            unique[e580:4] = 0x7508
            unique[f880:4] = a0 + unique[e580:4]
            a0 = unique[f880:4]
            IMARK ram[800002bc:4]
            goto ram[800002c2:4]
            IMARK ram[800002c0:2]
            unique[81e00:4] = a11 & 0xfffffffe
            restoreCallerState(FCX, LCX, PCXI)
            return unique[81e00:4]
        '''
    ]
    # 记录“负样本”
    for ir in wrong_irs:
        print('='*50 + '[WRONG INTERMEDIATE REPRESENTATION]' + '='*50)
        test_pcode_analysis(ir)
    # 记录“正样本”
    # for ir in right_irs:
    #     print('='*50 + '[RIGHT INTERMEDIATE REPRESENTATION]' + '='*50)
    #     main(ir)

