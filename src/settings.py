import os

# 路径配置
CONFIG_DIR = '../resources/ISA/config/'
SAMPLES_DIR = '../resources/samples/'

# 获取所有架构的配置文件路径信息
ARCH_INFO = dict()
for arch_file in os.listdir(CONFIG_DIR+'arch/'):
    arch = arch_file.replace(".json", "")
    ARCH_INFO[arch] = CONFIG_DIR+'arch/'+arch_file

