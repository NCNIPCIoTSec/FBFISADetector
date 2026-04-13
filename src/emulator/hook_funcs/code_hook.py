from unicorn import Uc

# ====== 运行控制 ======
MAX_INSN = 50_000            # 最大执行指令数，避免卡死
TRACE_EVERY = 1              # 每条指令都打印；嫌吵可改成 10/100


# 指令执行钩子
def hook_code(uc: Uc, address, size, user_data):
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