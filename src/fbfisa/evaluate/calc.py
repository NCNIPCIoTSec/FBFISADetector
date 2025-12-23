def calc_pair_rate(ins1_num: int, ins2_num: int) -> float:
    '''
    指令对 = <指令1，指令2> - 指令1与指令2的数量对比  
    指令1的数量 = ins1_num，指令2的数量 = ins2_num；  
    指令对比率 = |ins1_num - ins2_num| / MAX(ins1_num, ins2_num)  
    '''
    if ins1_num == ins2_num == 0:
        return 0
    return abs(ins1_num - ins2_num) / max(ins1_num, ins2_num)


def calc_BlockPairInstrRates(instr_pair: tuple[str], instr_details: list, bin_num: int):
    def calc_InsBytesBinaryRate(insls: list[tuple], lbin: int) -> float:
        '''
        指令1的列表(insls) = [指令字节1, 指令字节2, 指令字节3...]，lbin = 二进制文件字节串长度；  
        指定的“指令1”所占的字节长度(linsb) = SUM(指令字节1长度 + 指令字节2长度 + ...)  
        指定占二进制内容比率(rate) = linsb / lbin  
        '''
        linsb = sum([len(ins[0]) for ins in insls])
        return linsb / lbin

    hinstr, tinstr = instr_pair[0].upper(), instr_pair[1].upper()
    hlen, tlen = len(instr_details[0]), len(instr_details[1])
    print(f"{hinstr}: {hlen} | {tinstr}: {tlen}")
    print(f"      PAIR_RATE = {calc_pair_rate(hlen, tlen) * 100: .2f}%")
    print(f"HEAD BYTES_RATE = {calc_InsBytesBinaryRate(instr_details[0], bin_num)*100: .5f}%")
    print(f"TAIL BYTES_RATE = {calc_InsBytesBinaryRate(instr_details[1], bin_num)*100: .5f}%")
    print("POSSIBLE CALL INS NUMBERS:", hlen)


def calc_BlockRates(blocks: int, blocks_with_pair: int, blocks_valid_reverse: int, blocks_valid_ir: int):
    print("Block Num | Num of Block with Inner Pairs | Num of Block that can be reversed | Valid Block Num | Rate of Block that has Inner Pairs | Rate of Block that has Inner Pairs and has Valid Reverse Result | Rate of Block that has Valid IR")
    if blocks == 0:
        print(f"{blocks: 9} | {blocks_with_pair: 29} | {blocks_valid_reverse: 32} | {blocks_valid_ir: 15} | {0.00: 33.2f}% | {0.00: 62.2f}% | {0.00: 31.2f}")
    elif blocks_valid_reverse > 0:
        print(f"{blocks: 9} | {blocks_with_pair: 29} | {blocks_valid_reverse: 32} | {blocks_valid_ir: 15} | {blocks_with_pair / blocks* 100:33.2f}% | {(blocks_valid_reverse/blocks_with_pair)*100: 62.2f}% | {(blocks_valid_ir/blocks_valid_reverse)*100: 31.2f}%")
    elif blocks_with_pair > 0:
        print(f"{blocks: 9} | {blocks_with_pair: 29} | {blocks_valid_reverse: 32} | {blocks_valid_ir: 15} | {blocks_with_pair / blocks* 100:33.2f}% | {(blocks_valid_reverse/blocks_with_pair)*100: 62.2f}% | {0.00: 31.2f}%")
    else:
        print(f"{blocks: 9} | {blocks_with_pair: 29} | {blocks_valid_reverse: 32} | {blocks_valid_ir: 15} | {blocks_with_pair/blocks*100:33.2f}% | {0.00: 62.2f}% | {0.00: 31.2f}%")

