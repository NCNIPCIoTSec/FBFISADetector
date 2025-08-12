import re


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
    status_mark_var = ['PSW', 'NG', 'CY', 'ZR', 'OV', 'tmpNG', 'tmpCY', 'tmpZR', 'tmpNG', 'tmpOV', 'TB', 'shift_carry']

    def __init__(self, ir: str, registers: dict, debug_mode: bool = False) -> None:
        # 清洗IR
        ir = re.sub(r'^[ \t]+|[ \t]+$', '', ir)
        ir = re.sub(r'= SUBPIECE ([\[\]:\w]+), 0x(\d+)', r"= SUBPIECE(\1,0x\2)", ir)
        # 变量分析
        self.ir = ir
        self.spec_reg = registers['special']
        self.gen_reg = tuple(set(registers['general']))
        self.arg_passing_reg = set(registers['calling-convention']['argument-passing'])
        self.ret_value_reg = set(registers['calling-convention']['return-values'])
        self.stack_frame_saved_reg = set(registers['calling-convention']['saved'])
        self.registers = set(registers['general']).union(self.get_special_registers())
        # 变量记录
        self.addr2ir_pos = {}
        self.format_ir = []
        self.unique_var_life_zone = {}  # 变量"值"的生存区间
        self.var_expand_chain = {}  # 变量每个阶段的扩展结果
        self.var_undeclare_chain = []  # 未声明变量的记录 [path1_dict, path2_dict]
        self.context_storage_reg = {}
        # 函数相关寄存器（消去一部分后剩余）
        self.func_ret_reg = set()
        self.func_args_reg = set()
        self.sub_func_args_send_reg = {}
        self.sub_func_args_recv_reg = {}
        # 跳转表达式位置：跳转地址
        self.addr_goto = {}
        self.addr_if_goto = {}
        self.addr_call_func = {}
        self.cover_address = set()
        self.uncover_address = set()
        self.unknown_address = {'if-goto': [], 'goto': []}
        # 其他
        self.debug = debug_mode
        # 格式化运行
        self.expression_analysis(extend=False)

    # 获取特殊寄存器内容（寄存器编号+寄存器名称）
    def get_special_registers(self) -> set:
        spec_reg_mix = set()
        for key, value in self.spec_reg.items():
            spec_reg_mix.add(key)
            spec_reg_mix.add(value)
        return spec_reg_mix
    
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

    # 递归形式仿真运行p-code代码，追踪未声明变量并记录（if-goto/goto ram[imm]）相关位置
    def __run_expressions_simulation(self, row: int, cur_path_var_status: dict, last_func_pos = -1):
        # 边界条件1: row最大到最低端算式
        # 边界条件2: 一条路径中，每个节点只允许走过一次（防止while-loop导致死循环）
        # print(f"{row} / {cur_path_var_status}}")
        # 限制成局部变量
        cur_path_var_status = cur_path_var_status.copy()
        for cr in range(row, len(self.format_ir)):
            # 如果处理过，不做处理
            if cr in self.cover_address:
                self.var_undeclare_chain.append(cur_path_var_status)
                break

            # 当前表达式分析
            if cr in self.uncover_address:
                self.uncover_address.remove(cr)
            _, exp_info = self.format_ir[cr]
            # print(exp_info)
            p_var, p_exp, p_inner_var = exp_info
            p_inner_var = p_inner_var.copy()
            self.cover_address.add(cr) 

            # 追踪每个变量值的状态
            und_var_deliver = set()
            if len(p_inner_var) > 0:
                for sub_var in p_inner_var:
                    if re.search(r'ram\[[0-9a-fA-F]+:[0-9]+\]', sub_var) is not None:  # ram[imm:size]为指定地址位置，不当变量处理
                        continue
                    all_status = cur_path_var_status.get(sub_var)
                    if all_status is None:
                        und_var_deliver.add(sub_var)
                        # 将寄存器分类 -> a. 子函数接收参数寄存器；b. 主函数参数寄存器
                        if sub_var in self.gen_reg:
                            if (last_func_pos > -1) and (sub_var in self.ret_value_reg):
                                if self.sub_func_args_recv_reg.get(sub_var) is None:
                                    self.sub_func_args_recv_reg[sub_var] = set()
                                self.sub_func_args_recv_reg[sub_var].add((cr, last_func_pos))
                            else:
                                self.func_args_reg.add(sub_var)
                        continue
                    newest_status = all_status[-1][1]
                    if newest_status == 'const':
                        continue
                    und_var_deliver = und_var_deliver.union(newest_status)
            if len(und_var_deliver) == 0:
                und_var_deliver = 'const'
            # 更新变量值的传递状态
            if cur_path_var_status.get(p_var) is None:
                cur_path_var_status[p_var] = []
            cur_path_var_status[p_var].append((cr, und_var_deliver))  # (current_var_ir_index, "const" or {undeclared_reg_rx, undeclared_reg_ry})
                
            # 处理跳转
            if p_exp == '':
                if p_var.startswith('goto '):  # JUMP
                    # 计算跳转位置
                    target_addr = p_inner_var.pop()
                    target_addr = re.sub(r':[0-9]+\]', ']', target_addr)
                    ir_pos = self.addr2ir_pos.get(target_addr)
                    if ir_pos is None:
                        ir_pos = -1
                        self.unknown_address['goto'].append(cr)
                        if self.debug:
                            print(f'>> [CLASS PcodeIR] GotoSyntaxWarning: P-Code has "goto branch", but out of current block range - {target_addr}!!!')
                    self.addr_goto[cr] = ir_pos
                    # 直接跳转
                    # 如果跳转位置不在当前块内地址，当成函数来处理
                    if ir_pos != -1:
                        return self.__run_expressions_simulation(row=ir_pos, cur_path_var_status=cur_path_var_status, last_func_pos=last_func_pos)
                elif p_var.startswith('if '):  # IF-THEN
                    # 计算跳转位置
                    ir_pos = -1
                    target_addr = [iv for iv in p_inner_var if iv.startswith('ram')]
                    if len(target_addr) == 0:  # 转跳地址为常数/变量（非块内） —— 异常
                        if self.debug:
                            print(f'>> [CLASS PcodeIR] If-ThenSyntaxWarning: P-Code has "if-then goto branch", but out of current block range - {p_var}!!!')
                    else: 
                        target_addr = re.sub(r':[0-9]+\]', ']', target_addr[0])
                        ir_pos = self.addr2ir_pos.get(target_addr)
                        if ir_pos is None:
                            ir_pos = -1
                            self.unknown_address['if-goto'].append(cr)
                            if self.debug:
                                print(f'>> [CLASS PcodeIR] If-ThenSyntaxWarning: P-Code has "if-then goto branch", but out of current block range - {target_addr}!!!')
                    self.addr_if_goto[cr] = ir_pos
                    if ir_pos == -1:  # FIXME: 异常跳转（有可能是不完整的字节块导致的），不阻塞路径
                        continue
                    # 转跳
                    self.__run_expressions_simulation(row=ir_pos, cur_path_var_status=cur_path_var_status, last_func_pos=last_func_pos)
                elif p_var.startswith('call'):
                    if self.addr_call_func.get(cr) is None:
                        self.addr_call_func[cr] = exp_info
                    last_func_pos = cr
                elif p_var.startswith("return "):
                    if self.addr_call_func.get(cr) is None:
                        self.addr_call_func[cr] = exp_info
                    self.var_undeclare_chain.append(cur_path_var_status)
    
    # FIXME: 持续检测是否存在逻辑问题
    # 未声明变量追踪 & 跳转解析 & 生命区间重组
    def __format_unique_var_life_zone(self):
        # 跳转解析，重组运行路径
        if self.debug:
            print('>> [CLASS PcodeIR] SIMULATE IR-RUNNING...')
        self.__run_expressions_simulation(row=0, cur_path_var_status={})
        if self.debug:
            print(">> [CLASS PcodeIR] SIMULATE IR DONE!!!")
        # 记录所有（if-then）goto的位置以及跳转位置
        it_goto_info = self.addr_if_goto
        goto_info = self.addr_goto
        # 遍历每个变量的所有生命区间
        if self.debug:
            print('>> [CLASS PcodeIR] REMAKE ZONES...')
        sorted_goto = list(goto_info.keys())
        sorted_goto.extend(list(it_goto_info.keys()))
        sorted_goto = sorted(sorted_goto)
        lir = len(self.format_ir)
        for cvar, cur_info in self.unique_var_life_zone.items():
            var_repeat, zones = cur_info['repeat'], sorted(cur_info['zones'])
            # 处理过的不处理
            if type(zones[0]) == type(tuple()):
                continue
            # 遍历每个指定变量的位置，两两组区间
            p = 0
            gp = sorted_goto[p] if len(sorted_goto) > 0 else lir
            new_zones = []
            for zid in range(var_repeat):
                s = zones[zid]
                e = zones[zid+1] if (zid+1) < var_repeat else lir-1
                # 区间内无goto语句，直接记录
                if gp < s:
                    while p < len(sorted_goto) and (gp := sorted_goto[p]) < s:
                        p += 1
                if e < gp:
                    new_zones.append([(s, e+1)])
                    continue
                # 区间内有goto语句，分析
                ns, ne, tp = s, e, p
                sub_zones = []
                while tp < len(sorted_goto):
                    tgp = sorted_goto[tp]
                    # 更新sorted_goto总指针
                    if gp < e < tgp:
                        p = tp
                        gp = sorted_goto[p]
                    # 获取跳转目标
                    tg = goto_info.get(tgp)
                    if tg is None:  # 如果不是goto，就是if-then
                        tg = it_goto_info.get(tgp)
                        sub_zones.append((s, e))  # 添加if True区间
                    # goto跳转到非块内地址，假设是函数；
                    if tg == -1:  
                        tp += 1
                        continue
                    # 区间记录与更新
                    sub_zones.append((ns, tgp+1))
                    ns = tg
                    # 向后跳
                    ne = lir - 1
                    if ns > s:
                        next_end_ind = zid + 1
                        while next_end_ind < var_repeat and zones[next_end_ind] < ns:
                            next_end_ind += 1
                        ne = zones[next_end_ind] if next_end_ind < var_repeat else lir-1
                    else: # 向前跳
                        last_end_ind = zid - 1
                        while 0 <= last_end_ind and zones[last_end_ind] > ns:
                            last_end_ind -= 1
                        ne = zones[last_end_ind+1]
                    # 下一条goto
                    tp += 1
                sub_zones.append((ns, ne+1))
                new_zones.append(sub_zones)
            self.unique_var_life_zone[cvar]['zones'] = new_zones
        if self.debug:
            print('>> [CLASS PcodeIR] REMAKE ZONES DONE!!!')

    # 分析可能的参数寄存器
    def __undeclared_variables_analysis(self):   
        # 获取 SP/PC/LR/RA 的全部名称
        sp_reg = set()
        pc_reg = set()
        for k, n in self.spec_reg.items():   
            if n == "sp":
                sp_reg.add(k)
                sp_reg.add(n)
                continue
            if n in {"pc", "ra", "lr"}:
                pc_reg.add(k)
                pc_reg.add(n)
        stack_frame_reg: set = self.stack_frame_saved_reg.union(pc_reg).union(sp_reg)

        # 记录可能得保存上下文的地址
        def record_pos_context_addr(ram_addr: str, all_reg: set, record_addr: dict, continuous: bool = True):
            if not ram_addr.startswith('ram'):
                return record_addr
            # 记录
            if record_addr.get(ram_addr) is None:
                record_addr[ram_addr] = [set()]
            # 是否是连续压栈/出栈存储
            if not continuous:
                if len(record_addr[ram_addr][-1]) > 0:
                    record_addr[ram_addr].append(set())
            record_addr[ram_addr][-1] = record_addr[ram_addr][-1].union(all_reg)
            return record_addr

        # 分析未声明变量
        def undeclared_var_analysis(chain_path: dict, results: dict) -> dict:
            for cvar, chain in chain_path.items():
                pre_reg = set()
                for ir_ind, unv_set in chain:
                    # ===================> 内存分析
                    if cvar.startswith('ram'):
                        #  ------------------ 分析是否为常量 
                        if unv_set == "const":
                            if results.get(cvar) and len(pre_reg) > 0 and pre_reg not in results[cvar]:
                                results[cvar][-1] = results[cvar][-1].union(pre_reg)  # 记录某地址之前连续存储的寄存器
                            pre_reg.clear()  # 当中间出现常量，认为是上下文保存的地址的概率较低，清除记录
                            continue
                        # ------------------- 记录栈帧中的值
                        if results.get(cvar) is None:
                            results = record_pos_context_addr(ram_addr=cvar, all_reg=set(), record_addr=results, continuous=False)
                        if len(unv_set - stack_frame_reg) > 0:  # 若存储了非上下文保存寄存器，记录并另开一块新区域
                            if len(pre_reg) > 0 and pre_reg not in results[cvar]:
                                results[cvar][-1] = results[cvar][-1].union(pre_reg)  
                            pre_reg.clear()
                            results = record_pos_context_addr(ram_addr=cvar, all_reg=set(), record_addr=results, continuous=False)
                        # 更新未声明变量
                        pre_reg = pre_reg.union(unv_set)
                    # ===================>  分析寄存器集合内的寄存器，并记录
                    for unv in unv_set:
                        if unv in self.gen_reg:
                            # 记录当前寄存器未声明位置
                            if und_args_freq.get(unv) is None:
                                und_args_freq[unv] = set()
                            und_args_freq[unv].add(ir_ind)
                # 如果存放未声明变量，记录
                if results.get(cvar) and len(pre_reg) > 0 and pre_reg not in results[cvar]:
                    results[cvar][-1] = results[cvar][-1].union(pre_reg)  

            return results

        # print('b. get all undeclared variables...')
        # 1. 记录可能的“上下文保存地址”
        # 2. 记录可能的“函数传参寄存器”
        # 统计未声明变量，为分析“参数传递寄存器”的可能做准备
        lir = len(self.format_ir)-1
        und_args_freq = {}  # “寄存器”：“未声明次数”
        context_save_addr = {}  # “地址”：“存储的未声明寄存器”
        context_load_addr = {}  # “地址”：“从此地址出栈到寄存器但未使用”
        processed_addr = set()
        for chain_path in self.var_undeclare_chain:
            context_save_addr = undeclared_var_analysis(chain_path=chain_path, results=context_save_addr)
        del processed_addr
            
        # 统计未使用变量，是否存在连续的未使用变量，存储到相同地址
        for reg, pos_set in self.sub_func_args_send_reg.items():
            for pos in pos_set:
                declare_pos, call_pos, is_used = pos
                if call_pos == lir:
                    if not is_used:  # ir->ret 区间内一直未使用，记录
                        self.func_ret_reg.add(reg)
                    _, exp_info = self.format_ir[declare_pos]
                    exp = exp_info[1].strip()
                    if not exp.startswith('ram'):
                        continue
                    if context_load_addr.get(exp) is None:
                        context_load_addr = record_pos_context_addr(ram_addr=exp, all_reg=set(), record_addr=context_load_addr, continuous=False)
                    context_load_addr = record_pos_context_addr(ram_addr=exp, all_reg={reg}, record_addr=context_load_addr)

        # print('c. analyze undeclared variables...')
        # 是否存在上下文保存区域，分析并筛选掉一部分用于上下文保存的未声明变量
        # 压栈内容分析
        all_spec_reg = self.get_special_registers()
        record_save_reg = set()
        for ram, push_reg_zones in context_save_addr.items():
            pop_reg = context_load_addr.get(ram)
            if pop_reg is None:
                pop_reg = set()
                for item in context_load_addr.items(): 
                    if len(item[1]) > 0:
                        pop_reg = pop_reg.union(item[1][0])
            else:
                pop_reg = pop_reg[0]
            max_intersection, proper_push_reg = 0, set()
            for push_reg in push_reg_zones:
                if len(push_reg) == 0:
                    continue
                # 被上下文保存的寄存器存在以下特点：
                # a. 存储了特殊寄存器 = PC/LR/RA/SP；b. 有压栈信息，也有出栈信息，且压栈和出栈内容一致；
                cur_pc_reg = None
                cur_sp_reg = None
                for r in push_reg:
                    if r in pc_reg:
                        cur_pc_reg = r
                    elif r in sp_reg:
                        cur_sp_reg = r
                # 没有返回地址、栈指针保存，pass
                if cur_pc_reg is None or cur_sp_reg is None:
                    continue
                # 压栈、出栈的寄存器内容不一致，pass
                temp_push_reg = push_reg.intersection(pop_reg)
                temp_intersection = len(temp_push_reg)
                if temp_intersection > max_intersection:
                    max_intersection = temp_intersection
                    proper_push_reg = temp_push_reg
            # 上下文存储
            if max_intersection > 0:
                if self.context_storage_reg.get(ram) is None:
                    self.context_storage_reg[ram] = set()
                self.context_storage_reg[ram] = proper_push_reg
                record_save_reg = record_save_reg.union(proper_push_reg - all_spec_reg)
        # 记录函数相关寄存器
        self.func_args_reg = self.func_args_reg - record_save_reg
        self.func_ret_reg = self.func_ret_reg.intersection(self.ret_value_reg)
        
        # Display
        if self.debug:
            print("*" * 150)
            print("√ CALLING CONVENTION - Argument Passing:", self.arg_passing_reg)
            print("√ CALLING CONVENTION - Return Values:", self.ret_value_reg)
            print("√ The Position where Registers are Undeclared at: ", und_args_freq)
            print("-" * 100)
            print("√ CONTEXT-STORE-ADDR:", context_save_addr)
            print("√ CONTEXT-LOAD-ADDR:", context_load_addr)
            print("√ Upper Context Storage:", self.context_storage_reg)
            print("√ The Possible Function Arguments:", self.func_args_reg)
            print("√ The Possible Return-arguments:", self.func_ret_reg)
            print("-" * 100)
            # print("√ The Position of UNKNOWN Goto:", self.unknown_address['goto'])
            print("√ The Position of Call / Ret:", self.addr_call_func)
            print("√ The Possible Sub-Function Receive Arguments:", self.sub_func_args_recv_reg)
            print("*" * 150)
        del context_load_addr, context_save_addr
        
        # 有问题的寄存器反馈
        # A. 压入栈帧的存储寄存器，未声明次数仅限一次
        error_reg = set()
        for r in record_save_reg:  
            if len(und_args_freq.get(r)) > 1:
                error_reg.add(r)

        # 检查调用约定中：
        # B. 未声明变量中存在非参数传递寄存器，存在，则记录异常
        if len(self.func_args_reg) > 0:
            error_reg = error_reg.union(self.func_args_reg - self.arg_passing_reg)

        return error_reg
    
    # 变量值生命区间内使用情况分析
    def __variables_life_zone_analysis(self) -> dict:
        all_valid_exp = {}
        for cvar, cur_info in self.unique_var_life_zone.items():
            pos_reg_name = self.spec_reg.get(cvar)
            pos_reg_name = cvar if pos_reg_name is None else pos_reg_name
            # 当前寄存器为状态标识变量（寄存器）
            if cvar in self.status_mark_var:
                continue
            # 数据保存至指定地址（数据表）？pass
            if cvar.startswith('ram'):
                continue
            # 上下文保存、变量地址空间分配会变化sp指针
            if pos_reg_name in ['sp', 'gp']:  
                continue
            # ============> 值生命区间分析 <============
            var_repeat, zones = cur_info['repeat'], cur_info['zones']
            # print('=>'*25 + f' {self.format_ir[zones[0][0][0]][1][0]} ' + '<='*25 )
            for ind in range(var_repeat):
                zone_tag = f'{cvar}-z{ind}'
                all_valid_exp[zone_tag] = []
                # print('>> ', end= '')
                start_addr = zones[ind][0][0]
                call_func_addr = set()
                # print('+' * 150)
                record_passed_node = set()
                for zone in zones[ind]:
                    s, e = zone
                    # 在区间内进行分析
                    for ir_ind, ir_info in enumerate(self.format_ir[s:e]):
                        ir_ind = s + ir_ind
                        if ir_ind in record_passed_node:
                            continue
                        record_passed_node.add(ir_ind)
                        _, exp_info = ir_info
                        if cvar in exp_info[-1]:  # 如果当前变量在区间内出现过，认为合规；
                            all_valid_exp[zone_tag].append("BE-USED")
                            continue
                        # 如果区间内有函数调用、函数返回，疑似参数传递寄存器
                        if exp_info[0].startswith('call') or exp_info[0].startswith('return') or (ir_ind in self.unknown_address['goto']): 
                            if cvar in self.gen_reg:
                                call_func_addr.add(ir_ind)
                                all_valid_exp[zone_tag].append("FUNC-ARGS-REG")
                            elif pos_reg_name in ['pc', 'lr', 'ra', 'ISAModeSwitch']:
                                all_valid_exp[zone_tag].append("FUNC-ARGS-REG")
                    # 未被使用，检查是否跨指令，若是一条指令内的，认为是p-code翻译机制的问题，pass
                    if len(all_valid_exp[zone_tag]) == 0:
                        if self.format_ir[s][0] == self.format_ir[e-1][0]:
                            all_valid_exp[zone_tag].append('PCode-Translate-Warning')
                if len(all_valid_exp[zone_tag]) == 0:
                    if not (cvar.startswith('unique') or cvar.startswith('ram') or cvar in self.registers):  # 忽略翻译导致的问题（生成的临时变量但未被使用）
                        all_valid_exp[zone_tag].append('PCode-Translate-Warning')
                    # else:
                    #     print(f"√ Register({cvar} | {self.format_ir[start_addr][1]}) is highly possible not used!")
                # 函数距离分析与记录
                if "FUNC-ARGS-REG" in all_valid_exp[zone_tag]:
                    dis = len(self.format_ir)
                    temp_call_ind = -1
                    for ir_ind in call_func_addr:
                        if 0 < (new_id := (ir_ind - start_addr)) < dis:
                            dis = new_id
                            temp_call_ind = ir_ind
                    if temp_call_ind >= 0:
                        is_used = "BE-USED" in all_valid_exp[zone_tag]
                        if self.sub_func_args_send_reg.get(cvar) is None:
                            self.sub_func_args_send_reg[cvar] = set()
                        # print(f"{start_addr} | SEND-DATA: {self.format_ir[start_addr]}")
                        # print(f"{temp_call_ind} | CALL/RET: {self.format_ir[temp_call_ind]}")
                        self.sub_func_args_send_reg[cvar].add((start_addr, temp_call_ind, is_used))

        return all_valid_exp
    
    # FIXME: 分析当前P-CODE IR的逻辑正确性
    def logic_analysis(self) -> bool:
        res = True
        # =============== 未覆盖区域
        # print(self.ir)
        if len(self.uncover_address) > 0:
            if self.debug:
                print('>> [CLASS PcodeIR] PATH Logic Analysis ==> WOOPS!! EXITS UNCOVER-IR-ROW:', self.uncover_address)
            res = False
        else:
            if self.debug:
                print('>> [CLASS PcodeIR] PATH Logic Analysis ==> Congratulation!! UNCOVER_IR_ROW VALID!!!')
        
        if not self.debug and not res:
            return res
        
        # =============== 变量声明，未使用
        vlz = self.__variables_life_zone_analysis()
        for zv_tag, all_zones_stat in vlz.items():
            if len(all_zones_stat) == 0:
                if self.debug:
                    print('>> [CLASS PcodeIR] Var-Use Logic Analysis ==> WOOPS!! UNUSED-DECLARED-VAR:', zv_tag)
                res = False  
                    
        if res and self.debug:
            print('>> [CLASS PcodeIR] Var-Use Logic Analysis ==> Congratulation!! UNUSED-DECLARED-VAR VALID!!!')
        
        if not self.debug and not res:
            return res

        # =============== 变量未声明，但被使用
        error_reg = self.__undeclared_variables_analysis()
        if len(error_reg) > 0:
            if self.debug:
                print(">> [CLASS PcodeIR] UND-Var Logic Analysis ==> WOOPS!! GET-KNOW-ERROR-REG:", error_reg)
            res = False
        else:
            if self.debug:
                print(f'>> [CLASS PcodeIR] UND-Var Logic Analysis ==> Congratulation!! UNDEClARED-VAR VALID!!!')
        
        return res

    # 等式表达式拆解与记录
    def equal_exp_analysis(self, cvar: str, cexp: str, extend: bool, ir_ind: int = 0):
        # 表达式扩展记录
        if extend and self.var_expand_chain.get(cvar) is None:
            self.var_expand_chain[cvar] = [cexp]
        # 记录变量值
        if self.unique_var_life_zone.get(cvar) is None:
            self.unique_var_life_zone[cvar] = {'repeat': 0, 'zones': []}
        self.unique_var_life_zone[cvar]['repeat'] += 1
        
        # =========== 分析阶段 ===========
        exp_var = set()
        new_exp = ""
        # 等式前式可能出现变量，一般是指针位置
        for pos_var in re.findall(r'ram\[(unique\[.*?\]|[a-zA-Z_]+)\]', cvar):
            exp_var.add(pos_var)
        # 等式后式变量分析
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
            # 变量区分与记录
            trace_ve = ve
            if isp:  # 如果是指针变量，追溯地址存放变量
                trace_ve = re.findall(r'[ramgister\*]+\[(.*?)\]$', ve)[0]
            # 如果是变量，就记录
            if self.unique_var_life_zone.get(trace_ve) is not None or not (trace_ve in self.weak_syntax_char or trace_ve.startswith('0x') or trace_ve.endswith("(")):
                exp_var.add(trace_ve)
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
        
        # 是否扩展
        if extend:
            self.var_expand_chain[cvar].append(new_exp)
        # 记录变量值的生命区间
        self.unique_var_life_zone[cvar]['zones'].append(ir_ind)

        return (cvar, self.format_print_expression(new_exp.split(" ")), exp_var)
    
    # 跳转、复杂指令相关操作（拆解与记录）
    def branch_func_analysis(self, cexp, extend: bool) -> tuple:
        exp_var = set()

        # 跳转类型表达式展开
        pattern, rep_str = r"", ""
        if cexp.startswith("if "):  # if-else 语句
            pattern = r"if \((.*?)\) goto (.*?)$"
            rep_str = "if (@#0@) goto (@#1@)"
        elif cexp.startswith("return "):  # return 语句
            pattern = r"return (.*?)$"
            rep_str = "return (@#0@)"
        elif cexp.startswith("goto "):
            pattern = r"goto (.*?)$"
            rep_str = "goto (@#0@)"
        elif cexp.startswith("call "):
            pattern = r"call (.*?)$"
            rep_str = "call (@#0@)"
        else: # 其他函数
            pattern = r"\((.*?)\)$"
            func_args = re.findall(pattern, cexp)
            func_args = [arg.strip() for arg in func_args[0].split(',') if not arg.strip().startswith('0x')] if len(func_args) > 0 else []
            exp_var.union(set(func_args))
            return (cexp, "", exp_var)

        # 展开并记录
        new_exp = cexp
        all_vars = re.findall(pattern, cexp)[0]
        if type(all_vars) == type(""):
            all_vars = (all_vars,)
        for i, expand_cond_var in enumerate(all_vars):
            expand_cond_var = re.sub(r"^ *\[(.*?)\] *$", r"\1", expand_cond_var)  # 清洗取值符[]
            expand_cond_var = expand_cond_var.strip()
            if not expand_cond_var.startswith("0x"):  # 常量，0x??不管
                exp_var.add(expand_cond_var)
            if extend:
                std_exp = self.var_expand_chain.get(expand_cond_var)
                expand_exp = expand_cond_var if std_exp is None else std_exp[-1]
                repl_exp = self.format_print_expression(expand_exp.split(" "))
                new_exp = rep_str.replace(f"@#{i}@", repl_exp)
                rep_str = new_exp

        return (new_exp, "", exp_var)
    
    # 表达式分析
    def expression_analysis(self, extend: bool = False):
        # 分析
        format_ir_row = 0
        cur_ram_id = ""
        # 表达式解析与记录
        if self.debug:
            print('>> [CLASS PcodeIR] get "format_ir"...')
        for exp in self.ir.split('\n'):
            if exp.startswith('IMARK'):
                cur_ram_id = exp[5:].strip()
                # 记录物理地址 -> format ir起始行数
                for addr in cur_ram_id.split(","):
                    addr = re.sub(r':[0-9]+\]', ']',addr.strip())
                    self.addr2ir_pos[addr] = format_ir_row
                continue
            cvar, cexp = self.clean_expression(exp)
            if len(cvar) > 0:
                # 等式表达式扩展？追踪？并记录
                self.format_ir.append((cur_ram_id, self.equal_exp_analysis(cvar, cexp, extend, format_ir_row)))
            else:
                # 跳转语句扩展？追踪？并记录 / 其他
                self.format_ir.append((cur_ram_id, self.branch_func_analysis(cexp, extend)))
            self.uncover_address.add(format_ir_row)
            format_ir_row += 1
        
        # 格式化以及深度分析
        if self.debug:
            print('>> [CLASS PcodeIR] deep analyzing...')
        self.__format_unique_var_life_zone()


if __name__ == "__main__":
    def ir_analysis(ir: str, args_reg: dict):
        my_pcode = PcodeIR(ir, args_reg, True)
        print('==>==> P-Code IR Analysis <==<==')
        # print(ir)
        for addr, data in my_pcode.format_ir:
            cvar, cexp, inner_var = data
            expression = f"{addr}: "
            expression += f"{cvar} = {cexp}" if cexp != "" else cvar
            expression += f" | {inner_var}"
            print(expression)
        print(my_pcode.logic_analysis())


    def arch_pcode_main(arch_info: str, bytes_info: list):
        import pypcode
        
        # FIXME: delay slots
        suffix = ''
        if arch_info.startswith('MIPS:'):
            suffix = ' 00 00 00 00 '

        ctx = pypcode.Context(arch_info)
        for sample in bytes_info[0]:
            print('='*50 + f'[RIGHT INTERMEDIATE REPRESENTATION - {arch_info}]' + '='*50)
            cb = bytes.fromhex(sample+suffix)
            print('==== <ASSEMBLE CODE> ====')
            disasm = ctx.disassemble(cb)
            print(disasm)
            pcode = ctx.translate(cb)
            ir_analysis(str(pcode), bytes_info[1])

    bytes_info = {
        "tricore:LE:32:tc29x": [
            [
                "4d c0 e1 ff 16 07 3c 01 91 30 00 ff d9 ff 00 46 53 cf 20 f0 10 ff 54 ff 2e 1b 8f 24 20 f0 96 01 54 f0 37 00 70 08 8f 00 21 00 a6 0f 74 ff 8f 24 20 f0 96 02 54 f0 37 00 70 08 8f 00 21 00 a6 0f 74 ff 3c 01 54 ff 16 01 df 1f fe 7f 08 4f 96 08 2c f4 54 ff 2e 1b 8f 24 20 f0 96 01 54 f0 37 00 70 08 8f 00 21 00 a6 0f 74 ff 86 24 8f 34 40 f1 54 f0 37 00 70 08 8f 00 21 00 a6 0f 74 ff 3c 01 54 ff 6f 0f ff 7f 00 90",
                "20 38 49 a4 00 0a 91 00 00 56 d9 55 08 00 6d 00 fa 11 da 00 2c a4 da 00 2c a5 da 01 89 af 31 08 da 01 89 af 24 08 da 01 89 af 28 08 91 00 00 46 d9 44 2c 00 49 a5 00 0a 6d 00 f3 0f 00 90",
                "53 84 20 f0 91 00 00 f6 d9 ff 0c 00 10 ff c8 12 09 22 84 09 08 1f 53 4f 20 f0 10 2f 19 ff 00 a0 3c 01 3c 01 37 0f 68 0c 6f 70 ec 7f 37 0f 70 20 3c 01 00 90",
                "40 4f da 01 40 f4 6d ff d6 ff 26 2f 40 f4 6d ff 28 ff f6 26 82 14 40 f4 6d ff 71 ff 26 2f 02 f2 3c 01 00 90",
            ],
            {
                "special": {"a0": "gp", "a1": "gp", "a8": "gp", "a9": "gp", "a10": "sp", "a11": "ra"},
                "general": ["a2", "a3", "a4", "a5", "a6", "a7", "a12", "a13", "a14", "a15", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15"],
                "calling-convention": {
                    "argument-passing": ["a4", "a5", "a6", "a7", "a4", "d4", "d5", "d6", "d7"],
                    "return-values": ["d2", "a2"]
                }
            }
        ],
        "MIPS:BE:32:default": [
            [
                "27 bd ff d0 af bf 00 2c af b3 00 28 af b2 00 24 af b1 00 20 af b0 00 1c af bc 00 10 80 a3 00 0e 00 a0 88 21 10 60 00 0b 00 80 98 21 80 a2 00 0d 00 00 00 00 10 40 00 04 24 42 ff ff a0 a2 00 0d 10 00 00 23 24 10 00 8a a0 a0 00 0e 10 00 00 1d 00 60 80 21 0c 10 98 6b 00 00 00 00 00 40 80 21 24 02 00 0a 8f bc 00 10 16 02 00 16 24 02 00 01 a2 22 00 0d 10 00 00 05 24 12 00 0a 92 22 00 0d 00 00 00 00 24 42 00 01 a2 22 00 0d 0c 10 98 6b 02 60 20 21 8f bc 00 10 10 52 ff f8 00 00 00 00 14 40 00 03 a2 22 00 0e 10 00 00 09 00 00 80 21 92 22 00 0d 00 00 00 00 24 42 ff ff 10 00 00 03 a2 22 00 0d 12 00 00 02 00 00 00 00 36 10 00 80 8f bf 00 2c 02 00 10 21 8f b3 00 28 8f b2 00 24 8f b1 00 20 8f b0 00 1c 03 e0 00 08",
                "3c 1c 00 46 27 bd ff d8 27 9c 9c 80 af bf 00 24 af b1 00 20 af b0 00 1c af bc 00 10 8f 99 81 fc 00 80 88 21 24 05 00 02 24 04 00 02 03 20 f8 09 00 00 30 21 8f bc 00 10 00 40 20 21 02 20 28 21 8f 99 86 d0 24 06 00 10 03 20 f8 09 00 40 80 21 8f bc 00 10 04 41 00 0c 02 00 10 21 8f 99 82 bc 8e 24 00 04 03 20 f8 09 00 00 00 00 8f bc 00 10 3c 04 00 44 24 84 01 40 8f 99 84 9c 00 00 00 00 03 20 f8 09 00 40 28 21 8f bf 00 24 8f b1 00 20 8f b0 00 1c 03 e0 00 08 27 bd 00 28",
                "27 bd ff d8 af bf 00 24 af b1 00 20 af b0 00 1c af bc 00 10 3c 11 00 45 10 00 00 04 3c 10 00 45 0c 10 99 cf 00 00 00 00 8f bc 00 10 8e 22 6c e8 8e 03 6c ec 00 00 00 00 00 43 10 2a 14 40 ff f8 00 00 20 21 8f bf 00 24 8f b1 00 20 8f b0 00 1c 03 e0 00 08",
                "3c 1c 00 46 27 bd ff e0 27 9c 9c 80 af bf 00 1c af b0 00 18 af bc 00 10 3c 02 00 45 8c 43 6c f0 3c 02 00 45 8c 42 6c e8 00 80 80 21 00 62 18 21 90 64 00 00 00 00 00 00 14 80 00 02 00 00 00 00 24 04 00 20 8f 82 82 80 00 00 00 00 8c 45 00 00 00 00 00 00 8c a2 00 48 00 00 00 00 10 40 00 0d 00 00 00 00 8c a3 00 10 8c a2 00 1c 00 00 00 00 00 62 10 2b 10 40 00 04 24 62 00 01 a0 64 00 00 10 00 00 09 ac a2 00 10 8f 99 84 b0 10 00 00 03 00 00 00 00 8f 99 83 94 00 00 00 00 03 20 f8 09 00 00 00 00 8f bc 00 10 3c 04 00 45 8c 82 6c dc 3c 03 00 45 8c 63 19 90 24 42 00 01 ac 82 6c dc 00 43 10 2a 14 40 00 3b 3c 03 00 45 8c 62 6c e0 ac 80 6c dc 24 42 00 01 16 00 00 02 ac 62 6c e0 24 10 00 20 8f 82 82 80 00 00 00 00 8c 45 00 00 00 00 00 00 8c a2 00 48 00 00 00 00 10 40 00 0d 00 00 00 00 8c a3 00 10 8c a2 00 1c 00 00 00 00 00 62 10 2b 10 40 00 04 24 62 00 01 a0 70 00 00 10 00 00 0a ac a2 00 10 8f 99 84 b0 10 00 00 03 00 00 00 00 8f 99 83 94 00 00 00 00 03 20 f8 09 02 00 20 21 8f bc 00 10 00 00 00 00 8f 82 82 80 00 00 00 00 8c 45 00 00 00 00 00 00 8c a2 00 48 00 00 00 00 10 40 00 0e 00 00 00 00 8c a4 00 10 8c a2 00 1c 00 00 00 00 00 82 10 2b 10 40 00 05 24 83 00 01 24 02 00 08 a0 82 00 00 10 00 00 09 ac a3 00 10 8f 99 84 b0 10 00 00 03 00 00 00 00 8f 99 83 94 00 00 00 00 03 20 f8 09 24 04 00 08 8f bc 00 10 3c 03 00 45 8c 62 6c e8 8f bf 00 1c 8f b0 00 18 24 42 00 01 ac 62 6c e8 03 e0 00 08",
                "3c 1c 00 46 27 bd ff b8 27 9c 9c 80 af bf 00 44 af b5 00 40 af b4 00 3c af b3 00 38 af b2 00 34 af b1 00 30 af b0 00 2c af bc 00 18 8f 99 85 f4 24 02 00 4f af a2 00 20 00 00 20 21 27 a5 00 20 03 20 f8 09 00 00 30 21 8f bc 00 18 8f a2 00 20 3c 04 00 44 8f 99 80 c0 24 42 ff ff af a2 00 20 03 20 f8 09 24 84 df a0 3c 02 00 44 24 55 df d8 3c 02 00 44 24 54 df c4 3c 02 00 44 8f bc 00 18 10 00 00 45 24 53 df ec 8e 22 00 14 8e 32 00 28 8e 25 00 00 26 26 00 04 8f 99 80 e4 14 40 00 05 26 27 00 0d 03 20 f8 09 02 80 20 21 10 00 00 06 00 40 18 21 af a7 00 10 02 a0 20 21 03 20 f8 09 00 40 38 21 00 40 18 21 8f a2 00 20 8f bc 00 18 12 40 00 17 00 43 80 23 82 42 00 00 00 00 00 00 10 40 00 14 2a 02 00 02 8f 99 87 5c 00 00 00 00 03 20 f8 09 02 40 20 21 00 10 18 27 00 03 1f c3 02 03 18 24 00 62 10 2b 8f bc 00 18 10 40 00 02 02 43 10 21 a0 40 00 00 8f 99 80 c0 00 00 00 00 03 20 f8 09 02 40 20 21 10 00 00 13 00 00 00 00 2a 02 00 02 10 40 00 02 26 32 00 2c 24 10 00 02 8f 99 87 5c 00 00 00 00 03 20 f8 09 02 40 20 21 26 03 ff fe 00 62 10 2b 8f bc 00 18 10 40 00 02 02 30 10 21 a0 40 00 2a 8f 99 80 e4 02 40 28 21 03 20 f8 09 02 60 20 21 8f bc 00 18 8e 24 00 28 8f 99 81 30 00 00 00 00 03 20 f8 09 00 00 00 00 8f bc 00 18 00 00 00 00 8f 99 85 84 00 00 00 00 03 20 f8 09 24 04 00 01 8f bc 00 18 14 40 ff b6 00 40 88 21 8f bf 00 44 8f b5 00 40 8f b4 00 3c 8f b3 00 38 8f b2 00 34 8f b1 00 30 8f b0 00 2c 03 e0 00 08",
            ],
            {
                "special": {"r0": "zero", "r1": "at",  "r26": "k0", "r27": "k1", "r28": "gp", "r29": "sp", "r30": "fp", "r31": "ra"},
                "general": ["v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"],
                "calling-convention": {
                    "argument-passing": ["a0", "a1", "a2", "a3"],
                    "return-values": ["v0", "v1"]
                }
            }
        ],
        "ARM:LE:32:Cortex":[
            [
                "80 b5 88 b0 00 af f8 60 b9 60 7a 60 3b 60 3b 6b 18 6b 7b 68 9b 00 1a 46 a5 21 01 f0 60 fa 3b 6b 1a 6b 7b 68 03 f1 80 43 01 3b 9b 00 13 44 bb 61 bb 69 23 f0 07 03 bb 61 bb 69 03 f0 07 03 00 2b 0b d0 4f f0 50 03 83 f3 11 88 bf f3 6f 8f bf f3 4f 8f 7b 61 00 bf 00 bf fd e7 bb 68 00 2b 1f d0 00 23 fb 61 12 e0 ba 68 fb 69 13 44 19 78 3a 6b fb 69 13 44 34 33 0a 46 1a 70 ba 68 fb 69 13 44 1b 78 00 2b 06 d0 fb 69 01 33 fb 61 fb 69 0f 2b e9 d9 00 e0 00 bf 3b 6b 00 22 83 f8 43 20 03 e0 3b 6b 00 22 83 f8 34 20 bb 6a 06 2b 01 d9 06 23 bb 62 3b 6b ba 6a da 62 3b 6b ba 6a da 64 3b 6b 00 22 1a 65 3b 6b 04 33 18 46 ff f7 c4 fe 3b 6b 18 33 18 46 ff f7 bf fe 3b 6b 3a 6b 1a 61 bb 6a c3 f1 07 02 3b 6b 9a 61 3b 6b 3a 6b 5a 62 3b 6b 00 22 5a 65 3b 6b 00 22 83 f8 58 20 3a 68 f9 68 b8 69 00 f0 9c ff 02 46 3b 6b 1a 60 fb 6a 00 2b 02 d0 fb 6a 3a 6b 1a 60 00 bf 20 37 bd 46 80 bd",  # 多参数
                "80 b5 00 af ff f7 e3 ff 03 46 00 2b 03 d0 00 f0 40 fd 03 46 02 e0 00 f0 2c fd 03 46 18 46 80 bd",
                "f0 b5 87 b0 02 af 78 60 39 60 7b 68 5c 68 7b 68 1d 68 7b 68 1b 69 9e b2 7b 68 b3 f9 08 30 18 46 ff f7 ad ff 02 46 07 f1 0c 03 01 93 00 92 3b 68 32 46 29 46 20 46 00 f0 0c f9 03 46 01 2b 01 d0 00 23 00 e0 fb 68 18 46 14 37 bd 46 f0 bd",
                "80 b5 82 b0 00 af 78 60 ff f7 7e ff 03 46 00 2b 0e d0 78 68 00 f0 64 fb 03 46 01 2b 0b d1 08 4b 4f f0 80 52 1a 60 bf f3 4f 8f bf f3 6f 8f 02 e0 78 68 00 f0 f7 fa 00 23 18 46 08 37 bd 46 80 bd",
            ], 
            {
                "special": {"r15": "pc", "r14": "lr", "r13": "sp"},
                "general": ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"],
                "calling-convention": {
                    "argument-passing": ["r0", "r1", "r2", "r3"],
                    "return-values": ["r0", "r1", "r2", "r3"]
                }
            }
        ]
    }

    for key, value in bytes_info.items():
        arch_pcode_main(key, value)


