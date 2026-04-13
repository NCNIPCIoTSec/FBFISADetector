#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import argparse

import unicorn
from unicorn import Uc, UC_MODE_LITTLE_ENDIAN, UC_MODE_BIG_ENDIAN
from unicorn.unicorn_const import UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_INTR

from emu_initiators.initiator import InitiatorInterface
from emu_initiators.arm_initiator import ARMInitiator, arm_vector_read
from hook_funcs import mem_hook, code_hook
from utils.calc import align_down, align_up


# 主函数初始化UNICORN并运行
def main(bin_path: str, arch: str, endian: str, entry_addr: int):
    if not os.path.exists(bin_path):
        raise FileNotFoundError(bin_path)

    with open(bin_path, "rb") as f:
        blob = f.read()
    flash_size = align_up(len(blob), FLASH_MAP_PAD)

    # 打印bin文件信息
    print(f"[info] Successfully load firmware and .bin={bin_path}")
    print(f"[info] flash map size=0x{flash_size:X} (bin={len(blob)} bytes)")

    # ====== 模式判断与 PC 规范化 ======
    uc: Uc = None
    mode = UC_MODE_LITTLE_ENDIAN if endian == "LE" else UC_MODE_BIG_ENDIAN
    initiator: InitiatorInterface = None
    # 默认4字节字长（32位），小端序按字对齐，需要偏移3字节
    entry_pc = entry_addr
    if arch == "ARM":
        # 入口地址与栈顶地址调整
        # 从向量表取初始 SP / Reset Handler
        entry_pc, stack_top = arm_vector_read(blob, entry_addr)
        initiator = ARMInitiator(entry_pc, stack_top, mode)
        uc = initiator.uc
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
    initiator.println_initInfo()
        
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
    uc.hook_add(UC_HOOK_CODE, code_hook.hook_code, state)
    uc.hook_add(UC_HOOK_INTR, mem_hook.hook_intr, state)
    uc.hook_add(UC_HOOK_MEM_INVALID, mem_hook.hook_mem_invalid, state)

    # ====== 开始执行 ======
    try:
        # end=0 表示不指定结束地址（靠 MAX_INSN / hook 停）
        uc.emu_start(entry_pc, 0)
    except Exception as e:
        print(f"[error] emu_start exception: {e}")

    initiator.println_crash(state)


if __name__ == "__main__":
    from settings import FLASH_MAP_PAD, ENTRY_ADDR, SRAM_BASE, SRAM_SIZE, MMIO_BASE, MMIO_SIZE, STACK_TOP

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
    STACK_TOP = int(default_layout["STACK_TOP"], 16)         # 栈顶地址

    # ====== 主函数 ======
    main(bin_path=BIN_PATH, arch=ARCH, endian=ENDIAN, entry_addr=ENTRY_ADDR)
