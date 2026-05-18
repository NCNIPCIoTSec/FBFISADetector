import csv
import math
import struct
from collections import Counter
from pathlib import Path


ARM_PROLOGUES = {
    # Thumb PUSH register-list encodings. Common function entries: b5xx.
    "thumb_push_b5": lambda b: len(b) >= 2 and b[1] == 0xB5,
    "thumb_push_b4": lambda b: len(b) >= 2 and b[1] == 0xB4,
    # ARM little-endian stmdb sp!, {..., lr}; high byte e9/e8 is common.
    "arm_push_e92d": lambda b: len(b) >= 4 and b[2] == 0x2D and b[3] == 0xE9,
}

ARM_EPILOGUES = {
    # Thumb POP register-list encodings. bdxx often returns through pc.
    "thumb_pop_bd": lambda b: len(b) >= 2 and b[1] == 0xBD,
    "thumb_pop_bc": lambda b: len(b) >= 2 and b[1] == 0xBC,
    # bx lr in Thumb little-endian.
    "thumb_bx_lr": lambda b: len(b) >= 2 and b[0] == 0x70 and b[1] == 0x47,
    # ARM little-endian ldmia sp!, {..., pc}; e8bd....
    "arm_pop_e8bd": lambda b: len(b) >= 4 and b[2] == 0xBD and b[3] == 0xE8,
}


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def byte_hist(data):
    n = len(data) or 1
    return [data.count(i) / n for i in range(256)]


def l1_distance(a, b):
    return sum(abs(x - y) for x, y in zip(a, b))


def top_bytes(data, k=8):
    n = len(data) or 1
    return " ".join(f"{byte:02x}:{count / n * 100:.1f}%" for byte, count in Counter(data).most_common(k))


def count_patterns(data, patterns, stride):
    totals = {name: 0 for name in patterns}
    if len(data) < stride:
        return totals
    for i in range(0, len(data) - stride + 1, stride):
        window = data[i : i + stride]
        for name, pred in patterns.items():
            if pred(window):
                totals[name] += 1
    return totals


def parse_elf_loads(path):
    blob = path.read_bytes()
    if blob[:4] != b"\x7fELF":
        raise ValueError(f"{path} is not an ELF file")

    cls = blob[4]
    endian = "<" if blob[5] == 1 else ">"
    machine = struct.unpack_from(endian + "H", blob, 18)[0]

    if cls == 1:
        e_phoff = struct.unpack_from(endian + "I", blob, 28)[0]
        e_phentsize = struct.unpack_from(endian + "H", blob, 42)[0]
        e_phnum = struct.unpack_from(endian + "H", blob, 44)[0]
        ph_fmt = endian + "IIIIIIII"
    elif cls == 2:
        e_phoff = struct.unpack_from(endian + "Q", blob, 32)[0]
        e_phentsize = struct.unpack_from(endian + "H", blob, 54)[0]
        e_phnum = struct.unpack_from(endian + "H", blob, 56)[0]
        ph_fmt = endian + "IIQQQQQQ"
    else:
        raise ValueError(f"{path} has unknown ELF class {cls}")

    code = bytearray()
    load_file = bytearray()
    load_mem_slack = 0
    exec_segments = 0
    load_segments = 0

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        ph = struct.unpack_from(ph_fmt, blob, off)
        if cls == 1:
            p_type, p_offset, _vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = ph
        else:
            p_type, p_flags, p_offset, _vaddr, _paddr, p_filesz, p_memsz, _align = ph

        if p_type != 1:
            continue
        seg = blob[p_offset : p_offset + p_filesz]
        load_file.extend(seg)
        load_mem_slack += max(0, p_memsz - p_filesz)
        load_segments += 1
        if p_flags & 0x1:
            code.extend(seg)
            exec_segments += 1

    return {
        "blob": blob,
        "code": bytes(code),
        "load_file": bytes(load_file),
        "load_mem_slack": load_mem_slack,
        "machine": machine,
        "exec_segments": exec_segments,
        "load_segments": load_segments,
    }


def main():
    rows = []
    for path in sorted(Path("arm").glob("*.elf")):
        parsed = parse_elf_loads(path)
        whole = parsed["blob"]
        code = parsed["code"]
        load_file = parsed["load_file"]

        whole_hist = byte_hist(whole)
        code_hist = byte_hist(code)
        load_hist = byte_hist(load_file)
        pro_whole = count_patterns(whole, ARM_PROLOGUES, 2)
        epi_whole = count_patterns(whole, ARM_EPILOGUES, 2)
        pro_code = count_patterns(code, ARM_PROLOGUES, 2)
        epi_code = count_patterns(code, ARM_EPILOGUES, 2)

        rows.append(
            {
                "file": path.name,
                "size": len(whole),
                "exec_code_bytes": len(code),
                "load_file_bytes": len(load_file),
                "mem_slack_bss_bytes": parsed["load_mem_slack"],
                "code_ratio_file": f"{len(code) / len(whole):.3f}",
                "load_ratio_file": f"{len(load_file) / len(whole):.3f}",
                "entropy_whole": f"{entropy(whole):.3f}",
                "entropy_code": f"{entropy(code):.3f}",
                "entropy_load": f"{entropy(load_file):.3f}",
                "hist_l1_whole_vs_code": f"{l1_distance(whole_hist, code_hist):.3f}",
                "hist_l1_load_vs_code": f"{l1_distance(load_hist, code_hist):.3f}",
                "zero_whole_pct": f"{whole.count(0) / len(whole) * 100:.1f}",
                "zero_code_pct": f"{(code.count(0) / len(code) * 100) if code else 0:.1f}",
                "ff_whole_pct": f"{whole.count(255) / len(whole) * 100:.1f}",
                "ff_code_pct": f"{(code.count(255) / len(code) * 100) if code else 0:.1f}",
                "prologue_whole_per_kb": f"{sum(pro_whole.values()) / (len(whole) / 1024):.2f}",
                "prologue_code_per_kb": f"{sum(pro_code.values()) / (len(code) / 1024):.2f}" if code else "0.00",
                "epilogue_whole_per_kb": f"{sum(epi_whole.values()) / (len(whole) / 1024):.2f}",
                "epilogue_code_per_kb": f"{sum(epi_code.values()) / (len(code) / 1024):.2f}" if code else "0.00",
                "top_whole": top_bytes(whole),
                "top_code": top_bytes(code),
            }
        )

    out = Path("arm_elf_feature_experiment.csv")
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {out} with {len(rows)} ELF samples")
    print("file,code_ratio_file,hist_l1_whole_vs_code,entropy_whole,entropy_code,prologue_whole_per_kb,prologue_code_per_kb,epilogue_whole_per_kb,epilogue_code_per_kb")
    for r in rows:
        print(
            ",".join(
                [
                    r["file"],
                    r["code_ratio_file"],
                    r["hist_l1_whole_vs_code"],
                    r["entropy_whole"],
                    r["entropy_code"],
                    r["prologue_whole_per_kb"],
                    r["prologue_code_per_kb"],
                    r["epilogue_whole_per_kb"],
                    r["epilogue_code_per_kb"],
                ]
            )
        )


if __name__ == "__main__":
    main()
