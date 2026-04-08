#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import struct
import argparse

import unicorn
from unicorn import Uc, UC_MODE_LITTLE_ENDIAN, UC_MODE_BIG_ENDIAN
from unicorn.unicorn_const import UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_INTR, UC_ERR_OK, UC_MODE_MCLASS
from unicorn.arm_const import (
    UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_CPSR,
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12,
)

def align_down(x, a=0x1000):
    return x & ~(a - 1)

def align_up(x, a=0x1000):
    return (x + (a - 1)) & ~(a - 1)

def hook_code(uc, address, size, user_data):
    st = user_data
    st["count"] += 1
    if st["count"] % TRACE_EVERY == 0:
        try:
            code = uc.mem_read(address, size)
            # 简单打印指令 bytes；想反汇编可接 capstone（此 demo 不依赖 capstone）
            print(f"[{st['count']:>8}] PC=0x{address:08X} size={size} bytes={code.hex()}")
        except Exception as e:
            print(f"[trace] read fail @0x{address:08X}: {e}")

    if st["count"] >= MAX_INSN:
        print(f"[stop] reached MAX_INSN={MAX_INSN}")
        uc.emu_stop()


def hook_intr(uc, intno, user_data):
    # ARM 下常见：SVC (software interrupt) 会走到这里
    pc = uc.reg_read(UC_ARM_REG_PC)
    print(f"[intr] intno={intno} PC=0x{pc:08X} -> stop")
    uc.emu_stop()


def hook_mem_invalid(uc, access, address, size, value, user_data):
    # 非法内存访问：读/写/取指 都会进来
    pc = uc.reg_read(UC_ARM_REG_PC)
    print(f"[mem_invalid] access={access} addr=0x{address:08X} size={size} value=0x{value:X} PC=0x{pc:08X}")

    # 演示：如果你想“自动兜底映射”，可以在这里按页映射 address 所在页，然后返回 True 让它继续。
    # 但注意：这会隐藏真实 bug/外设语义缺失。
    if STOP_ON_INVALID:
        uc.emu_stop()
        return False

    # 示例：自动映射一页 RAM（不建议默认开启）
    page = align_down(address)
    try:
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, b"\x00" * 0x1000)
        print(f"[mem_invalid] auto-mapped 0x{page:08X}-0x{page+0x1000:08X}")
        return True
    except Exception as e:
        print(f"[mem_invalid] auto-map failed: {e}")
        uc.emu_stop()
        return False


# 从向量表取初始 SP / Reset Handler
def arm_vector_read(blob: bytes, entry_addr: int):
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


# 初始化寄存器
def arm_init_reg(uc: Uc, entry_pc: int, stack_top: int):
    # ====== 初始化寄存器 ======
    uc.reg_write(UC_ARM_REG_SP, stack_top)
    uc.reg_write(UC_ARM_REG_LR, 0xDEADBEEF)     # 返回地址哨兵
    uc.reg_write(UC_ARM_REG_PC, entry_pc)
    # 可选：给 r0-r3 一些初始参数（如果你跑的是“函数入口”而非 reset handler）
    uc.reg_write(UC_ARM_REG_R0, 0)
    uc.reg_write(UC_ARM_REG_R1, 0)
    uc.reg_write(UC_ARM_REG_R2, 0)
    uc.reg_write(UC_ARM_REG_R3, 0)
    return uc


# 打印崩溃结果
def crash_result_println(uc: Uc, state: dict, arch: str):
    if arch == "ARM":
        # ====== 打印一些寄存器结果 ======
        pc = uc.reg_read(UC_ARM_REG_PC)
        sp = uc.reg_read(UC_ARM_REG_SP)
        lr = uc.reg_read(UC_ARM_REG_LR)
        print(f"[done] insn={state['count']} PC=0x{pc:08X} SP=0x{sp:08X} LR=0x{lr:08X}")
        regs = [
            (UC_ARM_REG_R0, "R0"), (UC_ARM_REG_R1, "R1"), (UC_ARM_REG_R2, "R2"), (UC_ARM_REG_R3, "R3"),
            (UC_ARM_REG_R4, "R4"), (UC_ARM_REG_R5, "R5"), (UC_ARM_REG_R6, "R6"), (UC_ARM_REG_R7, "R7"),
            (UC_ARM_REG_R8, "R8"), (UC_ARM_REG_R9, "R9"), (UC_ARM_REG_R10, "R10"), (UC_ARM_REG_R11, "R11"),
            (UC_ARM_REG_R12, "R12"),
        ]
        for rid, name in regs:
            print(f"  {name} = 0x{uc.reg_read(rid):08X}")
    elif arch == "POWERPC":
        pass
    elif arch == "MIPS":
        pass
    elif arch == "TRICORE":
        pass
    else:
        raise ValueError(f"Unsupported architecture: {arch}")


# 主函数初始化UNICORN并运行
def main(bin_path: str, arch: str, endian: str, entry_addr: int):
    if not os.path.exists(bin_path):
        raise FileNotFoundError(bin_path)

    with open(bin_path, "rb") as f:
        blob = f.read()

    flash_size = align_up(len(blob), FLASH_MAP_PAD)

    # ====== 模式判断与 PC 规范化 ======
    uc = None
    mode = UC_MODE_LITTLE_ENDIAN if endian == "LE" else UC_MODE_BIG_ENDIAN
    # 默认4字节字长（32位），小端序按字对齐，需要偏移3字节
    entry_pc = entry_addr
    complete_arch = arch
    if arch == "ARM":
        # ============ 向量表佐证 ============
        # 从向量表取初始 SP / Reset Handler
        chosen_entry, chosen_sp = arm_vector_read(blob, entry_addr)
        # 如果 chosen_entry 是奇数 => Thumb；偶数 => ARM（但 Cortex-M 基本都是 Thumb）
        is_thumb = (chosen_entry & 1) == 1
        entry_pc = chosen_entry | 1 if is_thumb else (chosen_entry & ~1)
        complete_arch = ("ARM" if is_thumb else "THUMB")+":"+endian
        # ============ 初始化 Unicorn 模式 ============
        if is_thumb:
            mode = unicorn.UC_MODE_THUMB | UC_MODE_MCLASS | mode
        else:
            mode = unicorn.UC_MODE_ARM | mode
        uc = Uc(unicorn.UC_ARCH_ARM, mode)
        # 如果你想强制 Thumb，可手动设置 CPSR T-bit（bit5）
        # cpsr = uc.reg_read(UC_ARM_REG_CPSR)
        # cpsr |= (1 << 5)   # T=1
        # uc.reg_write(UC_ARM_REG_CPSR, cpsr)
        # 初始化寄存器
        uc = arm_init_reg(uc, entry_pc, chosen_sp)
    elif arch == "POWERPC":
        # 初始化 Unicorn 模式
        complete_arch = "PPC32"+":"+endian
        mode = unicorn.UC_MODE_PPC32 | mode
        uc = Uc(unicorn.UC_ARCH_PPC, mode)
    elif arch == "MIPS":
        # 初始化 Unicorn 模式
        complete_arch = "MIPS32"+":"+endian
        mode = unicorn.UC_MODE_MIPS32 | mode
        uc = Uc(unicorn.UC_ARCH_MIPS, mode)
    elif arch == "TRICORE":
        # 初始化 Unicorn 模式
        complete_arch = "TRICORE"+":"+endian
        uc = Uc(unicorn.UC_ARCH_TRICORE, mode)
    else:
        raise ValueError(f"Unsupported architecture: {arch}")

    # 检查是否成功创建了 Unicorn 实例
    if uc is None:
        raise ValueError("UC is None")
    # 打印一些信息
    print(f"[info] bin={bin_path}")
    print(f"[info] base=0x{BASE_ADDR:08X} entry=0x{ENTRY_ADDR:08X} (pc=0x{entry_pc:08X}) arch={complete_arch}")
    print(f"[info] flash map size=0x{flash_size:X} (bin={len(blob)} bytes)")
        
    # ====== 映射 Flash 并加载固件 ======
    uc.mem_map(BASE_ADDR, flash_size)
    uc.mem_write(BASE_ADDR, blob)

    # ====== 映射 SRAM / MMIO（演示用，防止立刻崩） ======
    uc.mem_map(SRAM_BASE, SRAM_SIZE)
    uc.mem_write(SRAM_BASE, b"\x00" * min(SRAM_SIZE, 0x1000))  # 只清前 4KB 也行

    uc.mem_map(MMIO_BASE, MMIO_SIZE)
    # MMIO 区不清也行；这里随便写点 0
    uc.mem_write(MMIO_BASE, b"\x00" * 0x1000)

    # ====== hooks ======
    state = {"count": 0}
    uc.hook_add(UC_HOOK_CODE, hook_code, state)
    uc.hook_add(UC_HOOK_INTR, hook_intr, state)
    uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid, state)

    # ====== 开始执行 ======
    try:
        # end=0 表示不指定结束地址（靠 MAX_INSN / hook 停）
        uc.emu_start(entry_pc, 0)
    except Exception as e:
        print(f"[error] emu_start exception: {e}")

    crash_result_println(uc, state, arch)


if __name__ == "__main__":
    # ====== 解析命令行参数 ======
    praser = argparse.ArgumentParser(description="Run Unicorn Emulator")
    praser.add_argument("-f", "--file", help="storage path of target binary file", type=str)
    praser.add_argument("-b", "--base", help="base address of target binary file", type=str, default="0x08000000")
    praser.add_argument("-e", "--entry", help="entry address of target binary file", type=str, default="0x0800365c")
    praser.add_argument("-a", "--arch", help="architecture of target binary file, standard format like 'ARCH:ENDIAN'", type=str, default="ARM:LE")
    args = praser.parse_args()

    # ====== 你给的参数 ======
    ARCH, ENDIAN = args.arch.upper().split(":")
    BIN_PATH   = args.file
    BASE_ADDR  = int(args.base, 16)
    ENTRY_ADDR = int(args.entry, 16)

    # ====== 你预设的入口 ======
    PRESET_ENTRY = ENTRY_ADDR 

    # ====== 运行控制 ======
    MAX_INSN = 50_000            # 最大执行指令数，避免卡死
    TRACE_EVERY = 1              # 每条指令都打印；嫌吵可改成 10/100
    STOP_ON_INVALID = True       # 非法内存访问时停止

    # ====== 默认内存布局（你可按固件实际改）======
    # 从配置文件中读取内存布局
    with open("config/arch_mem_layout.json", "r") as f:
        mem_layout = json.load(f)
    # 从配置文件中读取默认内存布局
    default_layout = mem_layout[ARCH]
    FLASH_MAP_PAD = int(default_layout["FLASH_MAP_PAD"], 16)  # Flash：映射 bin 的区域的填充大小
    # FLASH_BASE = int(default_layout["FLASH_BASE"], 16)        # Flash：基址
    # ENTRY_ADDR = int(default_layout["ENTRY_ADDR"], 16)        # 入口地址
    SRAM_BASE = int(default_layout["SRAM_BASE"], 16)         # SRAM：基址
    SRAM_SIZE = int(default_layout["SRAM_SIZE"], 16)         # SRAM：大小
    MMIO_BASE = int(default_layout["MMIO_BASE"], 16)         # MMIO：基址
    MMIO_SIZE = int(default_layout["MMIO_SIZE"], 16)         # MMIO：大小
    STACK_TOP = int(default_layout["STACK_TOP"], 16)        # 栈顶地址

    # ====== 主函数 ======
    main(bin_path=BIN_PATH, arch=ARCH, endian=ENDIAN, entry_addr=ENTRY_ADDR)
