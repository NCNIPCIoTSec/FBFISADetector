import os
import importlib.resources

# 兼容开发模式（直接运行）和安装模式（包导入）
def get_config_dir():
    try:
        # 安装模式：从config包获取绝对路径
        with importlib.resources.files("fbfisa.config") as config_path:
            return str(config_path.absolute())
    except (ImportError, FileNotFoundError):
        # 开发模式：使用相对路径
        return os.path.join(os.path.dirname(__file__), "config/")

def get_resource_dir(subdir):
    """获取resources/输出目录（开发模式）"""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base_dir, subdir)

# 路径配置（修改后）
CONFIG_DIR = get_config_dir()  # 优先用包资源路径，兼容开发模式
SAMPLES_DIR = get_resource_dir("resources/samples/")  # 开发模式的资源目录
OUTPUT_DIR = get_resource_dir("output/")  # 开发模式的输出目录

# 可选：确保输出目录存在
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 获取所有架构的配置文件路径信息
ARCH_INFO = dict()
for arch_file in os.listdir(os.path.join(CONFIG_DIR ,'arch')):
    arch = arch_file.replace(".json", "")
    ARCH_INFO[arch] = os.path.join(CONFIG_DIR, 'arch/'+arch_file)
