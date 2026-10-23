import os
import re

def elfFile2binFile(elf_file_load_path: str, bin_file_store_dir: str):
    """Extract file-backed PT_LOAD segments at their physical load addresses.

    BSS is not stored in flash and must not add RAM-sized gaps to the image.
    Return the output path so callers never have to parse diagnostic messages.
    """
    from pathlib import Path
    from elftools.elf.elffile import ELFFile

    source = Path(elf_file_load_path)
    with source.open("rb") as stream:
        elf = ELFFile(stream)
        segments = sorted(
            (int(seg["p_paddr"]), seg.data())
            for seg in elf.iter_segments()
            if seg["p_type"] == "PT_LOAD" and seg["p_filesz"] > 0
        )
    if not segments:
        raise ValueError(f"No file-backed PT_LOAD segments: {source}")
    base = segments[0][0]
    size = max(address + len(data) for address, data in segments) - base
    if size > 256 * 1024 * 1024:
        raise ValueError(f"Load segments span {size} bytes; select a contiguous flash image first")
    image = bytearray(b"\xff") * size
    previous_end = base
    for address, data in segments:
        if address < previous_end:
            raise ValueError(f"Overlapping load segments at 0x{address:x}: {source}")
        image[address - base:address - base + len(data)] = data
        previous_end = address + len(data)
    output = Path(bin_file_store_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    target = output / f"{source.stem}_{hex(base)}.bin"
    target.write_bytes(image)
    print(f"[INFO] {source} -> {target} ({size} bytes, base={base:#x})")
    return str(target)


def multi_process():
    from fbfisa.settings import OUTPUT_DIR, SAMPLES_DIR

    tricore_samples = [
        "ADC_Background_Scan_1_KIT_TC297_TFT.elf",
        "ADC_Filtering_1_KIT_TC375_LK.elf",
        "ASCLIN_LIN_Master_1_KIT_TC297_TFT.elf",
        "ASCLIN_Shell_UART_1_KIT_TC297_TFT.elf",
        "iLLD_TC375_ADS_Bluetooth_RFCOMM.elf",
        "GPIO_LED_Button_1_KIT_TC297_TFT.elf",
        "SPI_CPU_1_KIT_TC275_LK.elf",
        "UART_DMA_Transfer_1_KIT_TC297_TFT"
    ]

    for arh in os.listdir(SAMPLES_DIR):
        out_dir = os.path.join(OUTPUT_DIR, arh, 'bin')
        os.makedirs(out_dir, exist_ok=True)
        processed_bin_files = set([re.sub(r'_0x.*?\.bin', '.elf', fnm) for fnm in os.listdir(out_dir) if fnm.endswith('.bin')])
        sample_dir = os.path.join(SAMPLES_DIR, arh)
        if not os.path.isdir(sample_dir):
            continue
        for demo in os.listdir(sample_dir):
            if arh == "tricore" and demo not in tricore_samples:
                continue
            # 处理过，pass
            if demo in processed_bin_files:
                continue
            file_name = os.path.join(sample_dir, demo)
            # 如果是文件夹，pass
            if not os.path.isfile(file_name):
                continue
            elfFile2binFile(elf_file_load_path=file_name, bin_file_store_dir=out_dir)


def main(argv=None):
    import argparse
    from fbfisa.settings import SAMPLES_DIR, OUTPUT_DIR

    # 设置参数
    parser = argparse.ArgumentParser(
        prog="ELF2BIN", description="Convert ELF file to BIN file", epilog='Have Fun!!!'
    )
    parser.add_argument('-f', '--file', help="storage path of target binary file", type=str)
    parser.add_argument('-o', '--output_dir', help="storage path of output directory", type=str, default=os.path.join(OUTPUT_DIR, "bin"))
    parser.add_argument('-m', '--multiprocessing', action="store_true", help="start multiprocessing and run multi_process function, default is False")
    parser.add_argument("--print-path", action="store_true", help="print only the output path to stdout")
    args = parser.parse_args(argv)

    # 处理文件
    if args.multiprocessing:
        multi_process()
    else:
        if not args.file:
            parser.error("-f/--file is required unless -m/--multiprocessing is used")
        import contextlib
        import sys
        from elftools.common.exceptions import ELFError

        try:
            with contextlib.redirect_stdout(sys.stderr if args.print_path else sys.stdout):
                result = elfFile2binFile(args.file, args.output_dir)
        except (OSError, ValueError, ELFError) as exc:
            parser.exit(1, f"ELF2BIN: {exc}\n")
        if args.print_path:
            print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

