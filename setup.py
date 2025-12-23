import os
from setuptools import setup, find_packages

# 辅助函数：递归获取目录下所有配置文件（避免手动列）
def get_config_files():
    config_files = []
    # 遍历src/fbfisa/config下所有.json文件（含arch子目录）
    for root, _, files in os.walk("src/fbfisa/config"):
        for file in files:
            if file.endswith(".json"):
                # 转换为相对config包的路径（如arch/arm.json）
                rel_path = os.path.relpath(os.path.join(root, file), "src/fbfisa/config")
                config_files.append(rel_path)
    return config_files

# print(find_packages(where="./src", exclude=["*.test", "*.test.*", "demo.*"]))

# 打包
setup(
    name="FBFISADetector",
    version="0.1.0",
    description="FBFISADetector is a tool to detect Instruction Set Arch (ISA) of raw binary files / monolithic firmware",
    long_description=open("./README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="QingYang",
    author_email="yqingiot@163.com",
    url="https://github.com/NCNIPCIoTSec/FBFISADetector.git",
    python_requires=">=3.11",
    install_requires=[
        "angr>=9.2.165", "capstone>=5.0.3", "sympy>=1.13.3", "pyelftools>=0.32", "numpy>=2.3.1", "matplotlib>=3.10.3",
        "pypcode @ git+https://github.com/angr/pypcode.git@master",
        # The newest version of capstone conflicts with capstone angr!!!
        # "capstone @ git+https://github.com/capstone-engine/capstone.git@next#subdirectory=bindings/python"
    ],
    packages=find_packages(where="./src", exclude=["*.test", "*.test.*", "demo.*"]),
    package_dir={"": "src"},
    py_modules=["detectisa"],
    package_data={
        "fbfisa.config": get_config_files()
    },
    # 排除无关文件
    exclude_package_data={
        "": ["__pycache__", "*.pyc", "*.ipynb", ".gitignore"],
    }
)
