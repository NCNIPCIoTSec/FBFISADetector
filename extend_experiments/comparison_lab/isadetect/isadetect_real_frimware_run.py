import os
import re
import weka.core.jvm as jvm

from tools.process_files_storage import convert_paths
from tools.extract_feature import FeatureCalculator
from isadetect_run import main_run

def calculate_features(arch: list, input_path: str, output_path: str, thread_count: int = 10, limit_number_of_binaries: int = 10000):
    '''
    计算输入目录下文件的特征，输出到指定文件  
    - 参数:  
      - arch: 目标架构列表，例如 ["armhf", "powerpc", ...]
      - input_path: 输入目录路径，包含待计算特征的二进制文件
      - output_path: 输出目录路径，用于存储计算得到的特征文件
      - thread_count: 线程数量，默认为 10
      - limit_number_of_binaries: 限制处理的二进制文件数量，默认为 10000
    '''
    print("Starting to calculate features")
    featureCalculator = FeatureCalculator()
    featureCalculator.init(
        # 线程配置
        thread_count=thread_count,
        limit_number_of_binaries=limit_number_of_binaries,
        # 文件配置
        architectures=arch,
        input_path=input_path, 
        output_path=output_path,
        # 其他配置 - 默认值（固定值，不可修改）
        create_testset=True, full_binaries=True, random_sampling=False, code_section_minimum_size=0, sample_size=0
    )
    featureCalculator.calculate_bfd()
    print("Calculating features done")


def real_firm_run(input_path: str, dir_name: str):
    '''
    运行特征计算程序，计算输入目录下文件的特征，输出到指定文件  
    - 参数:  
      - input_path: 输入目录路径，包含待计算特征的二进制文件
    '''
    # 运行主函数
    arch = f"ARM_RealFirm_{dir_name}"
    print("-----------------------")
    output_path = f'./resources/data/ISADetect_{arch.upper()}_Features.csv'
    # 如果存在相关输出文件，pass
    if os.path.exists(output_path):
        print(f">> SKIPPING ARCH: {arch.upper()} (Output file={output_path} already exists)")
        # 运行ISADetect模型，对指定CSV文件进行预测
        main_run(output_path, f'./output/{arch}')
        print(f">> DONE! PREDICTED FILE IS SAVED TO ./output/ARM_RealFirms/{arch}/accuracy_report*")
        return
    print(">> PROCESSING ARCH: {}".format(arch.upper()))
    print(f">> PROCESSING PATH: {input_path}")
    calculate_features(["armhf"], input_path, output_path)
    print(">> DONE! OUTPUT FILE IS SAVED TO {}".format(output_path), end='\n\n')
    # 运行ISADetect模型，对指定CSV文件进行预测
    main_run(output_path, f'./output/ARM_RealFirms/{arch}')
    print(f">> DONE! PREDICTED FILE IS SAVED TO ./output/ARM_RealFirms/{arch}/accuracy_report*")


if __name__ == '__main__':
    # 转换路径，将../../../output/arm/bin下的文件复制到./output/realfirms/armhf目录下
    convert_paths('../../../output/arm/bin', './output/realfirms', arch="armhf", copy_files=True)
    # 遍历所有文件夹（可能有多层遍历）
    try:
        # 启动JVM
        print("正在启动JVM...")
        jvm.start(packages=True)
        print("JVM启动成功")
        workspace = './output/realfirms'
        for root, _, files in os.walk(workspace):
            # 过滤出二进制文件
            binaries = [f for f in files if len(re.findall(r'\.(bin@[0-9a-fA-F]+|bin|elf)$', f)) > 0]
            if binaries:
                # 获取上级目录路径字符串
                up_root = os.path.split(root)[0]
                real_firm_run(up_root, os.path.split(up_root)[1])
    except Exception as e:
        print(f"程序执行出错: {e}")
        import traceback
        traceback.print_exc()  # 打印详细的错误堆栈信息
    finally:
        # 确保JVM关闭
        print("正在关闭JVM...")
        jvm.stop()
        print("JVM已关闭")

