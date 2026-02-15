import hashlib
import os
import re
import shutil

def convert_paths(input_path: str, output_path: str, arch: str = "armhf", copy_files: bool = False):
    '''
    转换文件路径格式（仅移动.bin或.bin@[0-9a-fA-F]+格式的文件）
    - 参数:
      - input_path: 输入目录路径
      - output_path: 输出目录路径
      - arch: 架构名称，默认为 "armhf"
      - copy_files: 是否复制文件，默认为 False（仅打印路径）
    '''
    if not os.path.exists(input_path):
        print(f"错误：输入路径不存在: {input_path}")
        return
    
    converted_count = 0
    
    for root, dirs, files in os.walk(input_path):
        # 获取D_XXX目录
        d_xxx_dir = re.findall(r'/D_[0-9a-zA-Z]+', root)
        for file in files:
            if len(re.findall(r'\.bin(@[0-9a-zA-Z]+)?$', file)) == 0:
                continue
            # 移动的目标目录
            input_file_path = os.path.join(root, file)
            new_path = os.path.join(output_path, "others", arch, file)
            output_dir = os.path.join(output_path, "others", arch)
            if len(d_xxx_dir) > 0:
                last_dir = d_xxx_dir[0].strip('/')
                new_path = os.path.join(output_path, last_dir, arch, file)
                output_dir = os.path.join(output_path, last_dir, arch)
            if '@' not in file:
                new_path = new_path+'@'+str(hashlib.md5(input_file_path.encode('utf-8')).hexdigest())
            print(f"{input_file_path} -> {new_path}")
            if copy_files:
                # 检查文件是否存在，存在就pass
                if os.path.exists(new_path):
                    print(f"文件已存在，跳过复制: {new_path}")
                    continue
                os.makedirs(output_dir, exist_ok=True)
                shutil.copy2(input_file_path, new_path)
            
            converted_count += 1
    
    print(f"\n总共处理了 {converted_count} 个文件")
    if copy_files:
        print(f"文件已复制到: {output_path}")
    else:
        print("（仅显示路径，未复制文件。如需复制，请设置 copy_files=True）")


if __name__ == '__main__':
    input_path = "my_root"
    output_path = "output_path"
    
    convert_paths(input_path, output_path, arch="armhf", copy_files=False)