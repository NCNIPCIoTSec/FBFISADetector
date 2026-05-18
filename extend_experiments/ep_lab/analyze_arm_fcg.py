import os
import struct
from collections import defaultdict


ARM_DIR = os.path.join(os.getcwd(), "arm")


def u16(b, off):
    if off < 0 or off + 2 > len(b):
        return None
    return struct.unpack_from("<H", b, off)[0]


def u32(b, off):
    if off < 0 or off + 4 > len(b):
        return None
    return struct.unpack_from("<I", b, off)[0]


class ELF:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 1 or self.data[5] != 1:
            raise ValueError("only little-endian ELF32 is supported")
        hdr = struct.unpack_from("<HHIIIIIHHHHHH", self.data, 16)
        (
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        ) = hdr
        self.sections = []
        self._read_sections()
        self.symbols = []
        self.funcs = []
        self._read_symbols()

    def _str(self, blob, off):
        end = blob.find(b"\x00", off)
        if end < 0:
            return ""
        return blob[off:end].decode("utf-8", "replace")

    def _read_sections(self):
        raw = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            vals = struct.unpack_from("<IIIIIIIIII", self.data, off)
            raw.append(
                {
                    "name_off": vals[0],
                    "type": vals[1],
                    "flags": vals[2],
                    "addr": vals[3],
                    "offset": vals[4],
                    "size": vals[5],
                    "link": vals[6],
                    "info": vals[7],
                    "addralign": vals[8],
                    "entsize": vals[9],
                    "idx": i,
                }
            )
        shstr = raw[self.e_shstrndx]
        names = self.data[shstr["offset"] : shstr["offset"] + shstr["size"]]
        for s in raw:
            s["name"] = self._str(names, s["name_off"])
        self.sections = raw

    def _read_symbols(self):
        for sec in self.sections:
            if sec["type"] not in (2, 11) or not sec["entsize"]:
                continue
            strsec = self.sections[sec["link"]]
            strings = self.data[strsec["offset"] : strsec["offset"] + strsec["size"]]
            for off in range(sec["offset"], sec["offset"] + sec["size"], sec["entsize"]):
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                    "<IIIBBH", self.data, off
                )
                name = self._str(strings, st_name)
                typ = st_info & 0xF
                bind = st_info >> 4
                sym = {
                    "name": name,
                    "value": st_value,
                    "addr": st_value & ~1,
                    "thumb": bool(st_value & 1),
                    "size": st_size,
                    "type": typ,
                    "bind": bind,
                    "shndx": st_shndx,
                }
                self.symbols.append(sym)
                if typ == 2 and name and st_shndx < len(self.sections) and st_value:
                    flags = self.sections[st_shndx]["flags"]
                    if flags & 0x4:
                        self.funcs.append(sym)
        best = {}
        for f in self.funcs:
            key = f["addr"]
            if key not in best or (f["size"], f["bind"]) > (best[key]["size"], best[key]["bind"]):
                best[key] = f
        self.funcs = sorted(best.values(), key=lambda x: x["addr"])
        for i, f in enumerate(self.funcs):
            if not f["size"]:
                sec = self.sections[f["shndx"]]
                next_addr = sec["addr"] + sec["size"]
                if i + 1 < len(self.funcs) and self.funcs[i + 1]["addr"] > f["addr"]:
                    next_addr = min(next_addr, self.funcs[i + 1]["addr"])
                f["size"] = max(0, next_addr - f["addr"])

    def bytes_at(self, addr, size):
        addr &= ~1
        for s in self.sections:
            if s["addr"] <= addr < s["addr"] + s["size"]:
                n = min(size, s["addr"] + s["size"] - addr)
                off = s["offset"] + addr - s["addr"]
                return self.data[off : off + n]
        return b""

    def executable_sections(self):
        return [s for s in self.sections if s["flags"] & 0x4 and s["size"]]

    def section_by_name(self, *names):
        for s in self.sections:
            if s["name"] in names:
                return s
        return None


def decode_thumb_calls(buf, base):
    calls = []
    i = 0
    while i + 4 <= len(buf):
        h1 = u16(buf, i)
        h2 = u16(buf, i + 2)
        if h1 is None or h2 is None:
            break
        # Thumb-2 BL / BLX immediate encoding.
        if (h1 & 0xF800) == 0xF000 and (h2 & 0xD000) == 0xD000:
            s = (h1 >> 10) & 1
            j1 = (h2 >> 13) & 1
            j2 = (h2 >> 11) & 1
            imm10 = h1 & 0x03FF
            imm11 = h2 & 0x07FF
            i1 = (~(j1 ^ s)) & 1
            i2 = (~(j2 ^ s)) & 1
            imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
            if s:
                imm25 -= 1 << 25
            target = (base + i + 4 + imm25) & 0xFFFFFFFF
            calls.append(target & ~1)
            i += 4
            continue
        # Thumb-2 unconditional B.W immediate. Startup code often tail-jumps
        # to the C runtime entry instead of using BL.
        if (h1 & 0xF800) == 0xF000 and (h2 & 0xD000) == 0x9000:
            s = (h1 >> 10) & 1
            j1 = (h2 >> 13) & 1
            j2 = (h2 >> 11) & 1
            imm10 = h1 & 0x03FF
            imm11 = h2 & 0x07FF
            i1 = (~(j1 ^ s)) & 1
            i2 = (~(j2 ^ s)) & 1
            imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
            if s:
                imm25 -= 1 << 25
            target = (base + i + 4 + imm25) & 0xFFFFFFFF
            calls.append(target & ~1)
            i += 4
            continue
        # Thumb-1 unconditional B immediate.
        if (h1 & 0xF800) == 0xE000:
            imm = h1 & 0x07FF
            if imm & 0x0400:
                imm -= 0x0800
            target = (base + i + 4 + (imm << 1)) & 0xFFFFFFFF
            calls.append(target & ~1)
        i += 2
    return calls


def decode_arm_calls(buf, base):
    calls = []
    for i in range(0, len(buf) - 3, 4):
        insn = u32(buf, i)
        if insn is None:
            continue
        if (insn & 0x0E000000) == 0x0A000000:
            imm = insn & 0x00FFFFFF
            if imm & 0x00800000:
                imm -= 0x01000000
            target = (base + i + 8 + (imm << 2)) & 0xFFFFFFFF
            calls.append(target & ~1)
    return calls


def vector_entries(elf):
    sec = elf.section_by_name(".isr_vector", ".vectors", ".vector_table", ".interrupt_vector")
    if sec is None:
        # Cortex-M images commonly place vectors at the first alloc section.
        alloc = [s for s in elf.sections if s["flags"] & 0x2 and s["size"] >= 64]
        sec = min(alloc, key=lambda s: s["addr"], default=None)
    if sec is None:
        return []
    raw = elf.data[sec["offset"] : sec["offset"] + min(sec["size"], 512)]
    vals = []
    for off in range(0, len(raw) - 3, 4):
        v = u32(raw, off)
        if not v:
            vals.append(None)
            continue
        vals.append(v & ~1)
    return vals


def build_graph(elf):
    addr_to_name = {f["addr"]: f["name"] for f in elf.funcs}
    sorted_addrs = sorted(addr_to_name)

    def containing(addr):
        lo, hi = 0, len(sorted_addrs)
        while lo < hi:
            mid = (lo + hi) // 2
            if sorted_addrs[mid] <= addr:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return None
        start = sorted_addrs[lo - 1]
        f = next(x for x in elf.funcs if x["addr"] == start)
        if start <= addr < start + max(f["size"], 1):
            return start
        return None

    graph = defaultdict(set)
    text_base = min((s["addr"] for s in elf.executable_sections()), default=0)
    thumb_image = bool(elf.e_entry & 1) or elf.e_machine == 40
    for f in elf.funcs:
        buf = elf.bytes_at(f["addr"], f["size"])
        calls = decode_thumb_calls(buf, f["addr"]) if thumb_image or f["thumb"] else []
        if not calls and not f["thumb"]:
            calls = decode_arm_calls(buf, f["addr"])
        for t in calls:
            c = containing(t)
            if c is not None and c != f["addr"]:
                graph[f["addr"]].add(c)
    return graph, addr_to_name, sorted_addrs


def max_depth(graph, start):
    memo = {}
    visiting = set()

    def rec(n):
        if n in memo:
            return memo[n]
        if n in visiting:
            return 0
        visiting.add(n)
        best = 0
        for c in graph.get(n, ()):
            best = max(best, 1 + rec(c))
        visiting.remove(n)
        memo[n] = best
        return best

    return rec(start)


CORE_EXC_NAMES = [
    "Initial_SP",
    "Reset",
    "NMI",
    "HardFault",
    "MemManage",
    "BusFault",
    "UsageFault",
    "Reserved7",
    "Reserved8",
    "Reserved9",
    "Reserved10",
    "SVC",
    "DebugMon",
    "Reserved13",
    "PendSV",
    "SysTick",
]


def analyze(path):
    elf = ELF(path)
    graph, addr_to_name, addrs = build_graph(elf)
    name_to_addr = {}
    for a, n in addr_to_name.items():
        name_to_addr.setdefault(n, a)
    main_addr = None
    for n in ("main", "app_main", "Main"):
        if n in name_to_addr:
            main_addr = name_to_addr[n]
            break
    vecs = vector_entries(elf)
    startup_addr = vecs[1] if len(vecs) > 1 and vecs[1] in addr_to_name else None
    exceptions = []
    irqs = []
    seen_exc = set()
    seen_irq = set()
    for idx, a in enumerate(vecs[1:], start=1):
        if a not in addr_to_name:
            continue
        item = (idx, a, addr_to_name[a], max_depth(graph, a))
        if idx < 16:
            if a not in seen_exc:
                exceptions.append(item)
                seen_exc.add(a)
        else:
            if a not in seen_irq:
                irqs.append(item)
                seen_irq.add(a)
    main_depth = max_depth(graph, main_addr) if main_addr is not None else None
    startup_depth = max_depth(graph, startup_addr) if startup_addr is not None else None
    all_depths = [(a, n, max_depth(graph, a)) for a, n in addr_to_name.items()]
    maxd = max((d for _, _, d in all_depths), default=0)
    rank = None
    if main_addr is not None:
        higher = sum(1 for _, _, d in all_depths if d > main_depth)
        rank = higher + 1
    startup_rank = None
    if startup_addr is not None:
        higher = sum(1 for _, _, d in all_depths if d > startup_depth)
        startup_rank = higher + 1
    user_entry = choose_user_entry(name_to_addr, addr_to_name, graph)
    user_depth = max_depth(graph, user_entry[0]) if user_entry[0] is not None else None
    user_rank = None
    if user_entry[0] is not None:
        higher = sum(1 for _, _, d in all_depths if d > user_depth)
        user_rank = higher + 1
    return {
        "file": os.path.basename(path),
        "func_count": len(addr_to_name),
        "edge_count": sum(len(v) for v in graph.values()),
        "main": (main_addr, addr_to_name.get(main_addr), main_depth, rank, maxd),
        "startup": (
            startup_addr,
            addr_to_name.get(startup_addr),
            startup_depth,
            startup_rank,
            maxd,
        ),
        "user_entry": (
            user_entry[0],
            addr_to_name.get(user_entry[0]),
            user_depth,
            user_rank,
            maxd,
            user_entry[1],
            user_entry[2],
        ),
        "global_max": sorted(
            [(a, n, d) for a, n, d in all_depths if d == maxd],
            key=lambda x: x[1],
        ),
        "exceptions": exceptions,
        "irqs": irqs,
        "max_depth": maxd,
    }


def choose_user_entry(name_to_addr, addr_to_name, graph):
    # Arduino/Teensy/STM32duino: main is framework glue; setup is the first
    # user callback and loop is the recurring user logic.
    if "setup" in name_to_addr and "loop" in name_to_addr:
        return (
            name_to_addr["setup"],
            "Arduino-like: first user callback; loop is recurring logic",
            [name_to_addr["loop"], name_to_addr.get("main")],
        )
    for name in ("app_main", "main", "Main"):
        if name in name_to_addr:
            return (name_to_addr[name], "main-like application entry", [])
    process_threads = sorted(
        (addr, name) for addr, name in addr_to_name.items() if name.startswith("process_thread_")
    )
    user_threads = [
        (addr, name)
        for addr, name in process_threads
        if not any(
            x in name
            for x in (
                "tcpip",
                "etimer",
                "ctimer",
                "sensors",
                "rf233_radio",
                "servreg_hack",
                "simple_udp",
            )
        )
    ]
    if user_threads:
        return (user_threads[-1][0], "Contiki process thread candidate", [x[0] for x in user_threads[:-1]])
    if process_threads:
        return (process_threads[0][0], "Contiki process thread candidate", [x[0] for x in process_threads[1:]])
    return (None, "no user entry symbol found", [])


def fmt_items(items, limit=None):
    if not items:
        return "-"
    vals = []
    for idx, addr, name, depth in sorted(items, key=lambda x: (x[3], x[2]), reverse=True):
        label = CORE_EXC_NAMES[idx] if idx < len(CORE_EXC_NAMES) else f"IRQ{idx-16}"
        vals.append(f"{label}:{name}@0x{addr:08x}={depth}")
    if limit and len(vals) > limit:
        return "; ".join(vals[:limit]) + f"; ...(+{len(vals)-limit})"
    return "; ".join(vals)


def reliability(r, entry_key="main"):
    entry = r[entry_key]
    if entry[0] is None:
        return "低：无目标函数"
    _, _, md, rank, maxd = entry[:5]
    exc_max = max((x[3] for x in r["exceptions"] if x[0] != 1), default=-1)
    irq_max = max((x[3] for x in r["irqs"]), default=-1)
    if md == maxd and md > exc_max and md > irq_max:
        return "高：目标函数为全局最深且深于异常/中断"
    if rank <= 3 and md >= exc_max and md >= irq_max:
        return "中高：目标函数接近最深且不低于异常/中断"
    if md >= exc_max and md >= irq_max:
        return "中：目标函数不低于异常/中断，但不是全局最深"
    return "低：存在异常/中断处理函数深度不低于目标函数"


def entry_candidate_assessment(name):
    if not name:
        return "低：无函数名"
    lower = name.lower()
    if name in ("main", "app_main", "loop", "setup") or lower.endswith("_main"):
        return "高：可作为用户主逻辑入口"
    if "reset" in lower or lower in ("_start", "start") or "crtstartup" in lower:
        return "低：启动/CRT入口，不是用户主逻辑"
    if (
        name.startswith("__")
        or lower.startswith("_v")
        or lower.startswith("_f")
        or lower.startswith("_s")
        or "printf" in lower
        or "fopen" in lower
        or "sread" in lower
        or "swrite" in lower
        or "mbed" in lower
        or "global__sub_i" in lower
    ):
        return "低：库/运行时/底层I/O函数，不适合作用户仿真入口"
    if "irqhandler" in lower or lower.endswith("_handler") or lower.endswith("_isr") or lower.startswith("isr_"):
        return "中低：中断/异常入口，只适合事件级仿真"
    if any(k in lower for k in ("tcp", "udp", "ethernet", "dhcp", "receive", "update", "timer", "tmr", "saul")):
        return "中：业务/协议回调入口，可作局部仿真入口"
    return "中：非库函数且深度最大，建议作为候选入口验证"


def main():
    files = sorted(
        os.path.join(ARM_DIR, f)
        for f in os.listdir(ARM_DIR)
        if f.lower().endswith(".elf")
    )
    results = [analyze(p) for p in files]
    print("| 固件 | 函数/边 | 推荐用户入口地址 | 用户入口函数FCG深度(排名/最大) | 框架/依据 | 关联候选 | 全局最大深度函数 | 异常函数FCG深度 | 中断函数FCG深度 | 可靠性判断 |")
    print("|---|---:|---:|---:|---|---|---|---|---|---|")
    for r in results:
        user_entry = r["user_entry"]
        if user_entry[0] is None:
            addr_s = "-"
            entry_s = "-"
        else:
            addr_s = f"0x{user_entry[0]:08x}"
            entry_s = f"{user_entry[1]}={user_entry[2]} ({user_entry[3]}/{user_entry[4]})"
        alt_names = []
        addr_to_name = {}
        for addr, name, _ in r["global_max"]:
            addr_to_name[addr] = name
        # Re-read names only for alternate entry labels; this keeps analyze()
        # focused on metrics and the CLI output readable.
        elf = ELF(os.path.join(ARM_DIR, r["file"]))
        all_names = {f["addr"]: f["name"] for f in elf.funcs}
        for alt in user_entry[6]:
            if alt:
                alt_names.append(f"{all_names.get(alt, '?')}@0x{alt:08x}")
        alt_s = "; ".join(alt_names[:4]) if alt_names else "-"
        max_funcs = "; ".join(
            f"{name}@0x{addr:08x}={depth}" for addr, name, depth in r["global_max"][:6]
        )
        if len(r["global_max"]) > 6:
            max_funcs += f"; ...(+{len(r['global_max'])-6})"
        print(
            f"| {r['file']} | {r['func_count']}/{r['edge_count']} | {addr_s} | {entry_s} | "
            f"{user_entry[5]} | {alt_s} | {max_funcs} | "
            f"{fmt_items(r['exceptions'], 6)} | {fmt_items(r['irqs'], 8)} | {reliability(r, 'user_entry')} |"
        )


if __name__ == "__main__":
    main()
