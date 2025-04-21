'''
指令对 = <指令1，指令2> - 指令1与指令2的数量对比
  指令1的数量 = ins1_num，指令2的数量 = ins2_num；
  指令对比率 = |ins1_num - ins2_num| / MAX(ins1_num, ins2_num)
'''
def calc_pair_rate(ins1_num: int, ins2_num: int) -> float:
    if ins1_num == ins2_num == 0:
        return 0
    return abs(ins1_num - ins2_num) / max(ins1_num, ins2_num)


'''
指令1的列表(insls) = [指令字节1, 指令字节2, 指令字节3...]，lbin = 二进制文件字节串长度；
  指定的“指令1”所占的字节长度(linsb) = SUM(指令字节1长度 + 指令字节2长度 + ...)
  指定占二进制内容比率(rate) = linsb / lbin
'''
def calc_InsBytesBinaryFile_rate(insls: list[tuple], lbin: int) -> float:
    linsb = sum([len(ins[0]) for ins in insls])
    return linsb / lbin

