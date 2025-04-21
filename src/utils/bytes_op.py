def bytes_reverse(curb: bytes, reverse_unit: int = 2) -> bytes:
    '''
    字节串按半字反转，用于大小端转化；  
    - 输入：  
      curb: bytes, 待反转的字节串    
      reverse_unit: int, 对齐字节数，默认为2字节  
    - 输出：  
      bytes，反转后的字节串  
    '''
    if len(curb) <= reverse_unit:
        return curb[::-1]
    
    new_byte, tb = b"", b""
    for i, item in enumerate(curb):
        tb += item.to_bytes()
        if i % reverse_unit == 1:
            new_byte += tb[::-1]
            tb = b""
    
    return new_byte


def bytes_fmt_compare(ins: bytes, mask: bytes, fmt_ins: bytes) -> bool:
    """
    判断字节是否属于指定的指令结构;  
    - 输入：  
      ins: bytes, 待判断的字节串  
      mask: bytes, 掩码  
      fmt_ins: bytes, 格式化的指令 = proper_ins & mask  
    - 输出：  
      bool, 是否符合指定的指令结构  
    """   
    if len(ins) != len(mask):
        return False
    mask_data = bytes([ins[i]&mask[i] for i in range(len(mask))])
    if mask_data != fmt_ins:
        return False
    return True


def bytes_and_operation(b1: bytes, b2: bytes) -> bytes:
    """
    **高位**相“与”运算。如果长度不相等，短的末尾补0再相“与”;  
    - 输入：  
      b1: bytes, 字节串1  
      b2: bytes, 字节串2  
    - 输出：  
      bytes, b1和b2的“与”运算结果  
    """
    lb1, lb2 = len(b1), len(b2)
    if lb1 < lb2:
        b1 += b"\x00" * (lb2 - lb1)
    elif lb2 < lb1:
        b2 += b"\x00" * (lb1 - lb2)
    return bytes([b1[i] & b2[i] for i in range(max(lb1, lb2))])


def bit_string2bytes(bits: str, is_unsigned: bool = True) -> str:
    """
    二进制字符串转16进制（带符号）字节串；  
    - 输入：  
      bits: str, 二进制字符串  
      is_unsigned: bool, 是否无符号，默认为True
    - 输出：  
      十六进制字符串，形如'0x????'或'-0x????'
    """
    # 若带符号位，且最高位为1，转补码
    original_code = bits
    if not is_unsigned and bits[0] == '1':
        original_code = bin(int(bits[1:], 2) - 1)[2:]
        original_code = ''.join(['1' if b == '0' else '0' for b in original_code])
        return '-0x' + hex(int(original_code, 2))[2:].zfill(len(original_code) // 4)
    
    # 其他情况，原码直接返回
    return '0x' + hex(int(bits, 2))[2:].zfill(len(bits) // 4)


def bytes2bit_string(byte_data: bytes) -> str:
    """将 bytes 类型转换为二进制字符串"""
    return ''.join(format(byte, '08b') for byte in byte_data)


def get_register_num(byte_data: bytes, mask: bytes) -> int:
    return int.from_bytes(bytes_and_operation(byte_data, mask)) >> bytes2bit_string(mask)[::-1].find("1")


if __name__ == "__main__":
    print(bytes_reverse(curb=b"\x6d\x00\x53\x00", reverse_unit=4).hex())
    print(get_register_num(b"\xD9\x44\xA4\xE2", b"\x00\x0f\x00\x00"))

