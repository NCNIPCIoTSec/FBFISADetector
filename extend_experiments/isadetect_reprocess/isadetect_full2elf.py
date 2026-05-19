# -*- coding: utf-8 -*-
import os
import shutil


def is_elf_file_fast(filepath: str) -> bool:
    """仅检查 ELF 魔数，不依赖 pyelftools"""
    try:
        with open(filepath, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


# 递归处理目录下的所有文件，如果是ELF格式文件，则添加ELF后缀
def convert_to_elf(dir_path):
    for root, _, files in os.walk(dir_path):
        for file in files:
            # 检查是否是 ELF 文件
            if not is_elf_file_fast(os.path.join(root, file)):
                continue
            # 添加 ELF 后缀，并删除原文件
            org_file = os.path.join(root, file)
            elf_file = os.path.join(root, file+".elf")
            if not os.path.exists(elf_file):
                shutil.copy(org_file, elf_file)
                print(f"Add ELF suffix to {org_file} -> {elf_file}")
            if os.path.exists(org_file):
                os.remove(org_file)
                print(f"Remove original file {org_file}")


if __name__ == "__main__":
    convert_to_elf('../../resources/data/firmwares/isadetect/')

