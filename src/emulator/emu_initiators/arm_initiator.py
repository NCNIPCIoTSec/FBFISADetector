import struct
try:
    from .initiator import InitiatorInterface
except ImportError:  # Support direct execution from src/emulator.
    from emu_initiators.initiator import InitiatorInterface

import unicorn
from unicorn import Uc, UC_MODE_LITTLE_ENDIAN, UC_MODE_BIG_ENDIAN
from unicorn.unicorn_const import UC_MODE_MCLASS
from unicorn.arm_const import (
    UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_CPSR,
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12,
)

try:
    from ..settings import STACK_TOP
except ImportError:  # Support direct execution from src/emulator.
    from settings import STACK_TOP


class ARMInitiator(InitiatorInterface):
    def __init__(self, entry_addr: int, stack_top: int, mode: int, args: list = None):
        # 变量字符串，用于记录与打印信息
        self.complete_arch = None  # 架构信息
        self.entry_addr = entry_addr  # 入口地址PC
        self.stack_top = stack_top  # 栈顶地址SP
        self.mode = self.mode_init(mode)
        # 初始化Unicorn
        self.uc = Uc(unicorn.UC_ARCH_ARM, self.mode)
        # 初始化寄存器
        self.reg_init(args)

    # 初始化Unicorn模式
    def mode_init(self, mode: int) -> int:
        '''
        初始化Unicorn模式
        - input: 
          - mode - Unicorn 模式
          - entry_pc - 入口地址PC
        - output: mode - Unicorn 模式
        '''
        # 端序记录字符
        endian = "BE" if mode & UC_MODE_BIG_ENDIAN else "LE"
        # ============ 向量表佐证 ============
        # 如果 chosen_entry 是奇数 => Thumb；偶数 => ARM（但 Cortex-M 基本都是 Thumb）
        is_thumb = (self.entry_addr & 1) == 1
        self.entry_addr = self.entry_addr | 1 if is_thumb else (self.entry_addr & ~1)
        # 如果你想强制 Thumb，可手动设置 CPSR T-bit（bit5）
        # cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        # cpsr |= (1 << 5)   # T=1
        # uc.reg_write(UC_ARM_REG_CPSR, cpsr)
        # ============ 初始化 Unicorn 模式 ============
        if is_thumb:
            mode = unicorn.UC_MODE_THUMB | UC_MODE_MCLASS | mode
        else:
            mode = unicorn.UC_MODE_ARM | mode
        
        # 记录架构字符串
        self.complete_arch = ("THUMB" if is_thumb else "ARM")+":"+endian

        return mode

    # 初始化寄存器
    def reg_init(self, args: list = None):
        '''
        初始化寄存器，需要根据具体架构配置相关寄存器
        - input: args - 可选参数列表，用于初始化寄存器
        - output: none
        '''
        # 初始化参数列表
        args = list(args or [])
        if len(args) < 5:
            args.extend([0] * (5 - len(args)))
        # ====== 初始化寄存器 ======
        self.uc.reg_write(UC_ARM_REG_SP, self.stack_top)
        self.uc.reg_write(UC_ARM_REG_LR, 0xDEADBEEF)     # 返回地址哨兵
        self.uc.reg_write(UC_ARM_REG_PC, self.entry_addr)
        # （如果你跑的是“函数入口”而非 reset handler）
        # 可选：给 r0-r4 一些初始参数
        self.uc.reg_write(UC_ARM_REG_R0, args[0]) 
        self.uc.reg_write(UC_ARM_REG_R1, args[1])
        self.uc.reg_write(UC_ARM_REG_R2, args[2])
        self.uc.reg_write(UC_ARM_REG_R3, args[3])
        self.uc.reg_write(UC_ARM_REG_R4, args[4])

    # 打印崩溃结果
    def println_crash(self, state):
        '''
        打印崩溃结果
        打印崩溃时的寄存器状态
        - input: state - Unicorn 状态字典
        - output: 打印寄存器状态
        '''
        # ====== 打印一些寄存器结果 ======
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        sp = self.uc.reg_read(UC_ARM_REG_SP)
        lr = self.uc.reg_read(UC_ARM_REG_LR)
        print(f"[done] insn={state['count']} PC=0x{pc:08X} SP=0x{sp:08X} LR=0x{lr:08X}")
        regs = [
            (UC_ARM_REG_R0, "R0"), (UC_ARM_REG_R1, "R1"), (UC_ARM_REG_R2, "R2"), (UC_ARM_REG_R3, "R3"),
            (UC_ARM_REG_R4, "R4"), (UC_ARM_REG_R5, "R5"), (UC_ARM_REG_R6, "R6"), (UC_ARM_REG_R7, "R7"),
            (UC_ARM_REG_R8, "R8"), (UC_ARM_REG_R9, "R9"), (UC_ARM_REG_R10, "R10"), (UC_ARM_REG_R11, "R11"),
            (UC_ARM_REG_R12, "R12"),
        ]
        for rid, name in regs:
            print(f"  {name} = 0x{self.uc.reg_read(rid):08X}")
    
    # 打印初始化信息
    def println_initInfo(self):
        '''
        打印初始化信息
        '''
        print(f"[info] entry_pc=0x{self.entry_addr:08X} arch={self.complete_arch}")
    

# 从向量表取初始 SP / Reset Handler  
def arm_vector_read(blob: bytes, entry_addr: int):
    '''
    从向量表取初始 SP / Reset Handler  
    - input:  
      - blob - 二进制文件内容  
      - entry_addr - 入口地址  
    - output:   
      - chosen_entry - 最终入口地址（ARM/Thumb）  
      - chosen_sp - 最终栈顶地址  
    '''
    def same_addr_ignore_thumbbit(a, b):
        # Cortex-M/Thumb 常见：向量表 reset_vec 会把 bit0=1；你识别出的入口可能是偶数
        return (a & ~1) == (b & ~1)

    initial_sp = struct.unpack_from("<I", blob, 0x0)[0]
    reset_vec  = struct.unpack_from("<I", blob, 0x4)[0]

    print(f"[vector] initial_sp=0x{initial_sp:08X} reset_vec=0x{reset_vec:08X}")
    print(f"[preset] preset_entry=0x{entry_addr:08X}")

    if same_addr_ignore_thumbbit(reset_vec, entry_addr):
        # 一致：用向量表的 reset handler（通常带 bit0=1）
        chosen_entry = reset_vec
        chosen_sp = initial_sp  # 既然用向量入口，也顺便用向量里的 SP，更“真实启动”
        print("[entry] use vector reset handler + vector SP")
    else:
        # 不一致：用你指定的入口（但仍推荐用我们自己提供的 SP / 或保持你原来的 STACK_TOP）
        chosen_entry = entry_addr
        chosen_sp = STACK_TOP
        print("[entry] use preset ENTRY_ADDR + preset SP")
    
    return chosen_entry, chosen_sp

