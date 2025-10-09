# 从CSV文件一行一行地读取数据，并将数据存在一个列表中
import csv

def read_csv_to_list(file_path, encoding='utf-8'):
    """
    从CSV文件一行一行地读取数据，并将数据存储在一个列表中
    
    参数:
        file_path (str): CSV文件的路径
        encoding (str): 文件编码，默认为'utf-8'
    
    返回:
        list: 包含CSV文件所有行数据的列表，每行数据也是一个列表
    """
    data_list = []
    
    try:
        with open(file_path, 'r', encoding=encoding, newline='') as csvfile:
            csv_reader = csv.reader(csvfile)
            # 逐行读取数据并添加到列表中
            for row in csv_reader:
                data_list.append(row)
        return data_list
    except FileNotFoundError:
        print(f"错误：找不到文件 '{file_path}'")
        return []
    except UnicodeDecodeError:
        print(f"错误：无法使用编码 '{encoding}' 解码文件，请尝试其他编码格式")
        return []
    except Exception as e:
        print(f"读取CSV文件时发生错误：{e}")
        return []

# 如果需要从项目中的resources/data目录读取CSV文件的示例
# 可以取消下面的注释并根据实际情况修改

# if __name__ == "__main__":
#     csv_file_path = "resources/data/ISAdetect_full_binaries_features.csv"
#     data = read_csv_to_list(csv_file_path)
#     print(f"读取到 {len(data)} 行数据")
#     if data:
#         print("前5行数据示例:")
#         for i, row in enumerate(data[:5]):
#             print(f"第{i+1}行: {row}")