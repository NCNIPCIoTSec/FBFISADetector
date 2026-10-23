from unicorn import Uc
from unicorn.arm_const import UC_ARM_REG_PC
try:
    from ..utils.calc import align_down, align_up
except ImportError:  # Support direct execution from src/emulator.
    from utils.calc import align_down, align_up

STOP_ON_INVALID = True       # 非法内存访问时停止


# 非法内存访问钩子
def hook_mem_invalid(uc: Uc, access, address, size, value, user_data):
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


# 中断钩子
def hook_intr(uc: Uc, intno, user_data):
    # ARM 下常见：SVC (software interrupt) 会走到这里
    pc = uc.reg_read(UC_ARM_REG_PC)
    print(f"[intr] intno={intno} PC=0x{pc:08X} -> stop")
    uc.emu_stop()
