#!/usr/bin/env python3

import sys
import os

# 检查并安装必要的依赖
def install_dependencies():
    try:
        import elftools
    except ImportError:
        print("正在安装必要的依赖: pyelftools")
        try:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyelftools"])
            print("依赖安装成功")
        except Exception as e:
            print(f"安装依赖失败: {e}")
            print("请手动安装: pip install pyelftools")
            sys.exit(1)

# 安装依赖
install_dependencies()

# 导入必要的模块
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

class ELFSymbolChecker:
    def __init__(self):
        pass
    
    def check_elf_symbols(self, elf_file_path):
        """检查单个ELF文件的符号表信息，过滤掉大小为0的符号"""
        try:
            with open(elf_file_path, 'rb') as f:
                elffile = ELFFile(f)
                
                # 获取ELF文件的基本信息
                elf_info = {
                    'file_path': elf_file_path,
                    'elf_type': elffile['e_type'],
                    'machine': elffile['e_machine'],
                    'symbol_tables': []
                }
                
                # 遍历所有符号表
                total_symbols = 0
                for section in elffile.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        # 过滤掉大小为0的符号
                        non_zero_symbols = 0
                        for sym_idx in range(section.num_symbols()):
                            symbol = section.get_symbol(sym_idx)
                            # 检查符号大小是否大于0
                            if symbol['st_size'] > 0:
                                non_zero_symbols += 1
                        
                        # 只有当有非零大小符号时才记录该符号表
                        if non_zero_symbols > 0:
                            total_symbols += non_zero_symbols
                            symbol_table_info = {
                                'section_name': section.name,
                                'num_symbols': non_zero_symbols
                            }
                            elf_info['symbol_tables'].append(symbol_table_info)
                
                elf_info['total_symbols'] = total_symbols
                return elf_info
        except Exception as e:
            return {
                'file_path': elf_file_path,
                'error': str(e)
            }
    
    def is_elf_file(self, file_path):
        """检查文件是否为ELF文件"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except:
            return False
    
    def batch_check_directory(self, directory_path):
        """批量检查目录中的所有ELF文件"""
        results = []
        file_count = 0
        
        if not os.path.isdir(directory_path):
            print(f"错误: {directory_path} 不是一个有效的目录")
            return results
        
        # 遍历目录中的所有文件
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # 检查是否为ELF文件
                if self.is_elf_file(file_path):
                    file_count += 1
                    print(f"[{file_count}] 分析文件: {file_path}")
                    
                    # 检查ELF文件的符号表
                    elf_info = self.check_elf_symbols(file_path)
                    results.append(elf_info)
        
        return results
    
    def check_single_file(self, file_path):
        """检查单个ELF文件"""
        results = []
        
        if not os.path.isfile(file_path):
            print(f"错误: {file_path} 不是一个有效的文件")
            return results
        
        # 检查是否为ELF文件
        if self.is_elf_file(file_path):
            print(f"分析文件: {file_path}")
            # 检查ELF文件的符号表
            elf_info = self.check_elf_symbols(file_path)
            results.append(elf_info)
        else:
            print(f"错误: {file_path} 不是一个ELF文件")
        
        return results
    
    def generate_report(self, results):
        """生成分析报告"""
        print("\n=== 符号表分析报告 ===")
        print(f"总共分析文件数: {len(results)}")
        
        total_all_symbols = 0
        error_files = 0
        
        for result in results:
            if 'error' in result:
                print(f"\n文件: {result['file_path']}")
                print(f"  错误: {result['error']}")
                error_files += 1
            else:
                print(f"\n文件: {result['file_path']}")
                print(f"  ELF类型: {result['elf_type']}")
                print(f"  机器架构: {result['machine']}")
                print(f"  非零大小符号总数: {result['total_symbols']}")
                
                for sym_table in result['symbol_tables']:
                    print(f"    符号表 '{sym_table['section_name']}': {sym_table['num_symbols']} 个非零大小符号")
                
                total_all_symbols += result['total_symbols']
        
        print(f"\n=== 总结 ===")
        print(f"成功分析文件数: {len(results) - error_files}")
        print(f"分析失败文件数: {error_files}")
        print(f"所有文件非零大小符号总数: {total_all_symbols}")


def main():
    if len(sys.argv) < 2:
        print("用法:")
        print("  python elfSymbolChecker.py <目录路径>  # 分析目录中的所有ELF文件")
        print("  python elfSymbolChecker.py <文件路径>  # 分析单个ELF文件")
        print("示例:")
        print("  python elfSymbolChecker.py /path/to/elf/files  # 分析目录")
        print("  python elfSymbolChecker.py /path/to/executable  # 分析单个文件")
        sys.exit(1)
    
    target_path = sys.argv[1]
    checker = ELFSymbolChecker()
    results = []
    
    # 判断输入是目录还是文件
    if os.path.isdir(target_path):
        # 批量分析目录中的ELF文件
        results = checker.batch_check_directory(target_path)
    elif os.path.isfile(target_path):
        # 分析单个ELF文件
        results = checker.check_single_file(target_path)
    else:
        print(f"错误: {target_path} 不是有效的目录或文件")
        sys.exit(1)
    
    # 生成分析报告
    if results:
        checker.generate_report(results)
    else:
        print("未找到可分析的ELF文件或分析失败")


if __name__ == "__main__":
    main()