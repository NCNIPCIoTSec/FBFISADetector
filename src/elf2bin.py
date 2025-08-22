import os
import re

from settings import SAMPLES_DIR, OUTPUT_DIR
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile


def elfFile2binFile(elf_file_load_path: str, bin_file_store_dir: str):
    print("=" * 50)
    # 获取原二进制文件内容
    original_bin = b""
    with open(file=elf_file_load_path, mode='rb') as fr:
        # 原二进制文件内容
        original_bin = fr.read()
    # 打开 ELF 文件，并读取信息
    with open(file=elf_file_load_path, mode='rb') as f:
        try:
            if not elf_file_load_path.endswith('.elf'):
                os.rename(elf_file_load_path, elf_file_load_path+".elf")
            elf = ELFFile(f)
        except ELFError as e:
            print(f"[Error: {e}] ===> 文件<{elf_file_load_path}>不是ELF文件！！！")
            return 
        print(f"[INFO] ===> 处理文件<{elf_file_load_path}>")
        # 获取程序头（Program Header）表
        elf_record = {}
        print(f"[INFO] 原来ELF文件大小为: {len(original_bin)} Bytes")
        if len(original_bin) < 1000:
            print(f"[ERROR] 终止！文件太小，可能不适用于当前分析！！!>")
            return
        
        for i, segment in enumerate(elf.iter_segments()):
            physical_addr = segment["p_paddr"]
            file_size = segment['p_filesz']
            mem_size = segment['p_memsz']
            # 在文件中存在的数据/代码
            seg_tag = f"segment{i}"
            offset = segment["p_offset"]
            elf_record[seg_tag] = {"offset": offset, "address": physical_addr, "file_size": file_size, "memory_size": mem_size}
    
    # 按照ADDRESS对SEG信息进行排序
    sorted_elf_record = sorted(elf_record, key=lambda key: elf_record[key]["address"])
    # print([hex(elf_record[k]["address"]) for k in sorted_elf_record])
    # 组成新的二进制串
    bin_format_content = b""
    file_start_address = elf_record[sorted_elf_record[0]]["address"]
    temp_address = file_start_address
    for key in sorted_elf_record:
        # print(elf_record[key])
        # print(f"补充字节量：{hex(elf_record[key]["address"] - temp_address)}")
        bin_format_content += b"\xff" * (elf_record[key]["address"] - temp_address)
        bin_format_content += original_bin[elf_record[key]["offset"]: elf_record[key]["offset"] + elf_record[key]["file_size"]]
        bin_format_content += b'\xff'*(elf_record[key]["memory_size"] - elf_record[key]["file_size"])
        temp_address = elf_record[key]["address"] + elf_record[key]["memory_size"]
        
        # print(f"TEMP ADDRESS: {hex(temp_address)}")
        # time.sleep(10)
    print(f"[INFO] 新建立的BIN文件大小为: {len(bin_format_content)} Bytes")
    print(f"[INFO] 新建立的BIN物理起始地址为: {hex(file_start_address)}")
    # 将结果存储到目标文件夹内
    fnm_rmv_elf = os.path.split(elf_file_load_path)[-1].replace(".elf", "")
    target_path = bin_file_store_dir + f"{fnm_rmv_elf}_{hex(file_start_address)}.bin"
    with open(file=target_path, mode='wb') as fw:
        fw.write(bin_format_content)
    print(f"[INFO] 成功！！！ ===> 处理结果已经存储到文件<{target_path}>")


if __name__ == "__main__":
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
        out_dir = OUTPUT_DIR + f'{arh}/bin/'
        processed_bin_files = set([re.sub(r'_0x.*?\.bin', '.elf', fnm) for fnm in os.listdir(out_dir) if fnm.endswith('.bin')])
        for demo in os.listdir(SAMPLES_DIR + f'{arh}/'):
            if arh == "tricore" and demo not in tricore_samples:
                continue
            # 处理过，pass
            if demo in processed_bin_files:
                continue
            file_name = SAMPLES_DIR + f'{arh}/{demo}'
            # 如果是文件夹，pass
            if not os.path.isfile(file_name):
                continue
            elfFile2binFile(elf_file_load_path=file_name, bin_file_store_dir=out_dir)
