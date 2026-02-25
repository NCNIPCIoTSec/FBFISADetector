#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import struct

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UC_MODE_LITTLE_ENDIAN
from unicorn.unicorn_const import UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_INTR, UC_ERR_OK, UC_MODE_MCLASS
from unicorn.arm_const import (
    UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_CPSR,
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12,
)

# ====== 你给的参数 ======
BIN_PATH   = "/home/yq/workspace/studies/MyProjects/FBFISADetector/output/arm/bin/p2im_gateway_0x8000000.bin"
BASE_ADDR  = 0x08000000
ENTRY_ADDR = 0x0800365c

# ====== 你预设的入口 ======
PRESET_ENTRY = ENTRY_ADDR  # 0x0800365c

# ====== 运行控制 ======
MAX_INSN = 50_000            # 最大执行指令数，避免卡死
TRACE_EVERY = 1              # 每条指令都打印；嫌吵可改成 10/100
STOP_ON_INVALID = True       # 非法内存访问时停止

# ====== 内存布局（你可按固件实际改）======
# Flash：映射 bin 的区域
FLASH_MAP_PAD = 0x1000       # 映射向上取整用

# SRAM：给一个“假 RAM”当栈/数据区（固件如果访问 0x2000_0000 会需要它）
SRAM_BASE = 0x20000000
SRAM_SIZE = 0x00020000       # 128KB
STACK_TOP = SRAM_BASE + SRAM_SIZE - 0x10

# 外设 MMIO：如果固件会读写外设寄存器，可以先粗暴映射一段避免立刻 crash
MMIO_BASE = 0x40000000
MMIO_SIZE = 0x00100000       # 1MB（演示用）


def same_addr_ignore_thumbbit(a, b):
    # Cortex-M/Thumb 常见：向量表 reset_vec 会把 bit0=1；你识别出的入口可能是偶数
    return (a & ~1) == (b & ~1)

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


def main():
    if not os.path.exists(BIN_PATH):
        raise FileNotFoundError(BIN_PATH)

    with open(BIN_PATH, "rb") as f:
        blob = f.read()

    flash_size = align_up(len(blob), 0x1000)

    # ====== 从向量表取初始 SP / Reset Handler ======
    initial_sp = struct.unpack_from("<I", blob, 0x0)[0]
    reset_vec  = struct.unpack_from("<I", blob, 0x4)[0]

    print(f"[vector] initial_sp=0x{initial_sp:08X} reset_vec=0x{reset_vec:08X}")
    print(f"[preset] preset_entry=0x{PRESET_ENTRY:08X}")

    # ====== 选择最终入口 ======
    if same_addr_ignore_thumbbit(reset_vec, PRESET_ENTRY):
        # 一致：用向量表的 reset handler（通常带 bit0=1）
        chosen_entry = reset_vec
        chosen_sp = initial_sp  # 既然用向量入口，也顺便用向量里的 SP，更“真实启动”
        print("[entry] use vector reset handler + vector SP")
    else:
        # 不一致：用你指定的入口（但仍推荐用我们自己提供的 SP / 或保持你原来的 STACK_TOP）
        chosen_entry = PRESET_ENTRY
        chosen_sp = STACK_TOP
        print("[entry] use preset ENTRY_ADDR + preset SP")

    # ====== 模式判断与 PC 规范化 ======
    # 如果 chosen_entry 是奇数 => Thumb；偶数 => ARM（但 Cortex-M 基本都是 Thumb）
    is_thumb = (chosen_entry & 1) == 1
    entry_pc = chosen_entry | 1 if is_thumb else (chosen_entry & ~1)

    print(f"[entry] chosen_entry=0x{chosen_entry:08X} -> PC=0x{entry_pc:08X} mode={'THUMB' if is_thumb else 'ARM'}")

    if is_thumb:
        mode = UC_MODE_THUMB | UC_MODE_MCLASS | UC_MODE_LITTLE_ENDIAN
    else:
        mode = UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN

    print(f"[info] bin={BIN_PATH}")
    print(f"[info] base=0x{BASE_ADDR:08X} entry=0x{ENTRY_ADDR:08X} (pc=0x{entry_pc:08X}) mode={'THUMB' if is_thumb else 'ARM'}")
    print(f"[info] flash map size=0x{flash_size:X} (bin={len(blob)} bytes)")

    uc = Uc(UC_ARCH_ARM, mode)

    # ====== 映射 Flash 并加载固件 ======
    uc.mem_map(BASE_ADDR, flash_size)
    uc.mem_write(BASE_ADDR, blob)

    # ====== 映射 SRAM / MMIO（演示用，防止立刻崩） ======
    uc.mem_map(SRAM_BASE, SRAM_SIZE)
    uc.mem_write(SRAM_BASE, b"\x00" * min(SRAM_SIZE, 0x1000))  # 只清前 4KB 也行

    uc.mem_map(MMIO_BASE, MMIO_SIZE)
    # MMIO 区不清也行；这里随便写点 0
    uc.mem_write(MMIO_BASE, b"\x00" * 0x1000)

    # ====== 初始化寄存器 ======
    uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
    uc.reg_write(UC_ARM_REG_LR, 0xDEADBEEF)     # 返回地址哨兵
    uc.reg_write(UC_ARM_REG_PC, entry_pc)

    # 可选：给 r0-r3 一些初始参数（如果你跑的是“函数入口”而非 reset handler）
    uc.reg_write(UC_ARM_REG_R0, 0)
    uc.reg_write(UC_ARM_REG_R1, 0)
    uc.reg_write(UC_ARM_REG_R2, 0)
    uc.reg_write(UC_ARM_REG_R3, 0)

    # 如果你想强制 Thumb，可手动设置 CPSR T-bit（bit5）
    # cpsr = uc.reg_read(UC_ARM_REG_CPSR)
    # cpsr |= (1 << 5)   # T=1
    # uc.reg_write(UC_ARM_REG_CPSR, cpsr)

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


if __name__ == "__main__":
    main()
