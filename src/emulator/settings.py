# ====== 你给的参数 ======
ARCH, ENDIAN = None, None
BIN_PATH   = None
BASE_ADDR  = None
ENTRY_ADDR = None

# ====== 你预设的入口 ======
PRESET_ENTRY =  None 

# ====== 默认内存布局（你可按固件实际改）======
FLASH_MAP_PAD = None  # Flash：映射 bin 的区域的填充大小
FLASH_BASE = None  # Flash：基址
ENTRY_ADDR = None  # 入口地址
SRAM_BASE = None  # SRAM：基址
SRAM_SIZE = None  # SRAM：大小
MMIO_BASE = None  # MMIO：基址
MMIO_SIZE = None  # MMIO：大小
STACK_TOP = None  # 栈顶地址
