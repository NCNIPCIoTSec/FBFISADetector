import pyghidra

# 启动 Ghidra，启动后才可以加载 ghidra 模块
pyghidra.start(install_dir="/home/yq/workspace/studies/MyProjects/FBFISADetector/requirements/ghidra", verbose=True)
from ghidra.program.model.lang import LanguageID

# 运行 Ghidra，进行基址求解
def run_ghidra_base_address_solver(bin_file: str, variant: str):
    with pyghidra.open_program(binary_path=bin_file, language=LanguageID(variant).getIdAsString()) as flat_api:
        print("###"*50)
        print("### 成功启动 Ghidra 并加载二进制文件")
        print(f"### 二进制文件路径：{bin_file}")
        print(f"### 架构变体：{variant}")
        print("###"*50)
        # 在这里使用 flat_api 进行操作
        program = flat_api.getCurrentProgram()
        listing = program.getListing()
        print(listing.getCodeUnitAt(flat_api.toAddr(0x1234)))


if __name__ == "__main__":
    arm_bin_sample = "/home/yq/workspace/studies/MyProjects/FBFISADetector/output/arm/bin/p2im_drone_0x8000000.bin"
    run_ghidra_base_address_solver(bin_file=arm_bin_sample, variant="ARM:LE:32:Cortex")

