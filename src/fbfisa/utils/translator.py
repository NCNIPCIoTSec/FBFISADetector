import re


# 将二进制分析所用正则表达式进行大小端反转
def regex_reverse(regex_exp: str, reverse_unit: int = 1) -> str:
    # 转化成便于分析的表 -> @num1#@num2#.... | [0: num1, 1: num2, ....]
    sp, count, scope_map = 0, 0, []
    rep_regex = ''
    while sp < len(regex_exp):
        if regex_exp[sp] == '[':
            # 遍历子字符串的范围[.....] - 注：不存在嵌套的[]
            sub_start, sub_end = sp, -1
            while regex_exp[sp] != ']':
                sp += 1
            sub_end = sp + 1
            # 添加子序列
            scope_map.append(regex_exp[sub_start: sub_end])
        elif regex_exp[sp] == '\\':
            scope_map.append(regex_exp[sp: sp+4])
            sp += 3
        else:
            scope_map.append(regex_exp[sp])
        rep_regex += f'@{count}#'
        count += 1
        sp += 1     
    del count
    # print(f"[regex_reverse func: step1] normalize: {regex_exp} -> {rep_regex} | {scope_map}")

    # 如果当前正则表达式组合字节数小于对齐字节，那就全字节反转
    if len(scope_map) < reverse_unit:
        reverse_unit = len(scope_map)
    # 如果当前正则表达式组合不是"对齐字节"的整数倍，不做处理
    if len(scope_map) % reverse_unit:
        return regex_exp

    # 大小端转换
    reversed_regex = []
    for i, tag in enumerate(re.findall(r'@(\d)#', rep_regex)):
        reversed_regex.append(int(tag))
        if (i + 1) % reverse_unit == 0:
            if (d := i-reverse_unit) >= 0:
                reversed_regex[i+1-reverse_unit: i+1] = reversed_regex[i: d: -1]
            else:
                reversed_regex[i+1-reverse_unit: i+1] = reversed_regex[i: : -1]
    # print(f"[regex_reverse func: step2] reversing: {rep_regex} -> {reversed_regex} | {scope_map}")
    
    return ''.join([scope_map[i] for i in reversed_regex])
    

# “字节串-正则表达式形式的字符串”转成“字节串的正则表达式”：str -> Pattern[bytes]; 注意：本函数默认将.转化为[\\x00-\\xff]
def string2bytes_regex(regex_exp: str, reverse: bool = False, reverse_unit: int = 1):
    regex_exp = regex_exp.replace('.', '[\\x00-\\xff]')
    temp_exp = regex_exp.encode() if not reverse else regex_reverse(regex_exp=regex_exp, reverse_unit=reverse_unit).encode()
    # print("[Regex-expression] step1. Reverse:", regex_exp, "=(reverse)=>", temp_exp)
    while obj := re.search(rb'\\x..', temp_exp):
        cur_char = bytes.fromhex(obj.group().decode().replace('\\x', ''))
        # print("[Regex-expression] step2. b'\\\\x??'->b'\\x??':", obj.group(), "=(str2byte)=>", cur_char)
        temp_exp = temp_exp[:obj.start()] + (b'\\' + cur_char if cur_char in rb".*?+-\|^$()[]{}" else cur_char) + temp_exp[obj.end():]
    # print("[Regex-expression] step3. Final:", regex_exp, "=(final)=>" , temp_exp)
    return re.compile(temp_exp)


# 16进制数字形式的字符串“\\xff”转成字节串b“\xff”
def hexString2bytes(hex_str: str) -> bytes:    
    return b''.join([bytes.fromhex(hex_char) for hex_char in hex_str.split('\\x') if len(hex_char) > 0])


if __name__ == '__main__':
    hex_data = bytes.fromhex('93 42 01 d9 03 23 4d e0 29 4b 9b 68 03 f0 0c 02 7b 68 5b 68 9b 00 9a 42 eb d1 24 4b 1b 68 03 f0 0f 02 3b 68 9a 42 0c d9 20 4b 3a 68 d2 b2 1a 70 1e 4b 1b 68 03 f0 0f 02 3b 68 9a 42 01 d0 01 23 30 e0 7b 68 1b 68 03 f0 04 03 00 2b 08 d0'.replace(' ', ''))
    stand_pattern = br".[\x5b\x5d\x28-\x2f]"
    
    print(string2bytes_regex('\\x5c.', True, 4))
    print(re.findall(string2bytes_regex("[\\x5b\\x5d\\x28-\\x2f].", True, 2), hex_data))
    print(re.findall(stand_pattern, hex_data))
    print(regex_reverse('[\\x90-\\x9f]\\x00', 4))
    print(regex_reverse('\\xe8\\xbd[\\x00-\\x1f\\x40-\\x5f\\x80-\\x9f\\xc0-\\xdf].', 2))
    print(hexString2bytes('\\xe8\\xbd'))

