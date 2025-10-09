# 基于PyWeka，加载模型simple_logistic.model，并将data中的数据一行一行作为输入，将模型的预测结果存储在一个列表中

import os
# 导入readt.py中的函数
from readt import read_csv_to_list
# 导入PyWeka相关库
from weka.core.converters import Loader
from weka.classifiers import Classifier
from weka.core import serialization
import weka.core.jvm as jvm

def load_model(model_path):
    """
    加载Weka模型文件
    
    参数:
        model_path (str): 模型文件路径
    
    返回:
        Classifier: 加载好的分类器模型
    """
    try:
        print(f"正在加载模型: {model_path}")
        # 检查模型文件是否存在
        if not os.path.exists(model_path):
            print(f"错误: 模型文件不存在: {model_path}")
            return None
        
        # 使用serialization模块从文件加载模型
        loaded_model = serialization.read(model_path)
        # 将Java对象包装成PyWeka的Classifier对象
        classifier = Classifier(jobject=loaded_model)
        print(f"成功加载模型: {model_path}")
        return classifier
    except Exception as e:
        print(f"加载模型失败: {e}")
        return None

def create_instances_from_csv(data):
    """
    从CSV数据创建Weka Instances对象（优化版）
    
    参数:
        data (list): CSV数据列表
    
    返回:
        Instances: Weka实例对象
    """
    if not data or len(data) < 2:
        print("数据不足，无法创建Instances对象")
        return None
    
    print(f"开始处理数据，总数据行数: {len(data)}")
    
    # 使用第一行作为属性名称
    header = data[0]
    data_rows = data[1:]
    total_rows = len(data_rows)
    
    print(f"标题行已读取，数据行数量: {total_rows}")
    
    # 创建一个临时ARFF格式文件，但分批写入以减少内存使用
    relation_name = "temp_data"
    temp_arff = "temp_data.arff"
    
    try:
        # 写入关系名称和属性定义
        with open(temp_arff, "w", encoding="utf-8") as f:
            f.write(f"@relation {relation_name}\n\n")
            
            # 添加属性定义
            for i, attr in enumerate(header):
                if i == len(header) - 1:
                    # 根据用户要求，最后一列architecture是类别属性，范围1-23
                    # 使用标称型定义，包含所有可能的类别值
                    categories = [str(j) for j in range(1, 24)]  # 1-23的类别
                    categories_str = "{" + ",".join(categories) + "}"
                    f.write(f"@attribute {attr} {categories_str}\n")
                    print(f"已正确设置类别属性 {attr} 为标称型，包含1-23个类别")
                else:
                    f.write(f"@attribute {attr} numeric\n")
            
            f.write("\n@data\n")
        
        # 分批写入数据，每批处理一定数量的行
        batch_size = 1000  # 根据内存情况调整批次大小
        print(f"开始分批写入数据，每批 {batch_size} 行")
        
        with open(temp_arff, "a", encoding="utf-8") as f:
            for i in range(0, total_rows, batch_size):
                end_idx = min(i + batch_size, total_rows)
                batch = data_rows[i:end_idx]
                
                # 写入当前批次
                for row in batch:
                    f.write(",".join(row) + "\n")
                
                # 显示进度
                print(f"已写入 {end_idx}/{total_rows} 行数据")
        
        print(f"ARFF文件创建完成，文件路径: {temp_arff}")
        
        # 使用Loader加载ARFF文件
        print("开始加载ARFF文件到Weka Instances...")
        loader = Loader(classname="weka.core.converters.ArffLoader")
        instances = loader.load_file(temp_arff)
        
        # 设置类别索引为最后一个属性
        instances.class_index = instances.num_attributes - 1
        
        print(f"Instances对象创建成功，包含 {instances.num_instances} 个实例和 {instances.num_attributes} 个属性")
        
        # 删除临时文件
        try:
            os.remove(temp_arff)
            print("临时ARFF文件已删除")
        except Exception as e:
            print(f"删除临时文件时出错: {e}")
        
        return instances
    
    except Exception as e:
        print(f"创建Instances对象时发生错误: {e}")
        # 确保临时文件被删除
        try:
            if os.path.exists(temp_arff):
                os.remove(temp_arff)
        except:
            pass
        return None

def predict_with_model(model, instances, debug_file=None):
    # 初始化预测结果列表
    predictions = []
    true_labels = []
    total_processed = 0
    
    # 打印实例属性信息以调试
    print(f"实例总数: {instances.num_instances}")
    print(f"属性总数: {instances.num_attributes}")
    
    # 获取类别索引（architecture列）
    class_idx = None
    for i in range(instances.num_attributes):
        attr = instances.attribute(i)
        attr_name = str(attr.name)
        print(f"属性 {i}: {attr_name}")  # 打印所有属性名称以识别正确的列
        if attr_name.lower() == "architecture":
            class_idx = i
            print(f"找到目标列 'architecture' 在索引位置 {i}")
            break
    
    # 如果没有找到architecture列，尝试使用最后一列
    if class_idx is None:
        class_idx = instances.num_attributes - 1
        print(f"未找到 'architecture' 列，使用最后一列索引 {class_idx}")
    
    try:
        # 写入调试信息到文件
        with open("debug_info.txt", "w", encoding="utf-8") as f_debug:
            f_debug.write("索引,原始值类型,原始值,转换后类别,预测值\n")
            
            # 遍历每个实例进行预测
            for i in range(instances.num_instances):
                try:
                    instance = instances.get_instance(i)
                    
                    # 直接从指定的class_idx获取真实类别值
                    true_class_val = instance.get_value(class_idx)
                    
                    # 预测类别
                    predicted_class = model.classify_instance(instance)
                    
                    # 处理真实类别值的转换 - 增强的类型处理
                    true_class = "未知"
                    try:
                        # 尝试多种方式转换真实类别值
                        if true_class_val is None:
                            true_class = "未知"
                        elif isinstance(true_class_val, (int, float)):
                            # 如果是数字，转换为整数字符串
                            true_class = str(int(round(float(true_class_val))))
                        elif hasattr(true_class_val, 'toString'):
                            # Weka对象可能有toString方法
                            true_class = str(true_class_val.toString()).strip()
                        elif hasattr(true_class_val, 'value'):
                            # 某些Weka对象可能需要调用value方法
                            true_class = str(true_class_val.value()).strip()
                        else:
                            # 转换为字符串并去除空白
                            true_class_str = str(true_class_val).strip()
                            # 尝试进一步清理，去除可能的引号或特殊字符
                            if true_class_str.startswith('"') and true_class_str.endswith('"'):
                                true_class_str = true_class_str[1:-1].strip()
                            if true_class_str.isdigit():
                                true_class = str(int(true_class_str))  # 去除前导零
                            else:
                                true_class = true_class_str
                    except Exception as e:
                        print(f"转换真实类别出错 (索引 {i}): {e}")
                    
                    # 处理预测值
                    predicted_class_str = "未知"
                    try:
                        if isinstance(predicted_class, (int, float)):
                            predicted_class_str = str(int(round(float(predicted_class))))
                        elif hasattr(predicted_class, 'toString'):
                            predicted_class_str = str(predicted_class.toString()).strip()
                        else:
                            predicted_class_str = str(predicted_class).strip()
                    except Exception as e:
                        print(f"转换预测类别出错 (索引 {i}): {e}")
                    
                    # 存储结果
                    predictions.append(predicted_class_str)
                    true_labels.append(true_class)
                    total_processed += 1
                    
                    # 记录调试信息
                    f_debug.write(f"{i},{type(true_class_val).__name__},{str(true_class_val)},{true_class},{predicted_class_str}\n")
                    
                    # 每1000个实例打印一次进度
                    if (i + 1) % 1000 == 0:
                        print(f"已处理 {i + 1} 个实例")
                        
                except Exception as e:
                    print(f"处理实例 {i} 时出错: {e}")
                    import traceback
                    traceback.print_exc()
                    # 即使出错也添加默认值以保持列表长度一致
                    predictions.append("未知")
                    true_labels.append("未知")
        
        # 验证结果长度
        print(f"\n预测结果统计:")
        print(f"处理的实例总数: {total_processed}")
        print(f"预测结果列表长度: {len(predictions)}")
        print(f"真实标签列表长度: {len(true_labels)}")
        
        # 显示一些样本数据用于调试
        print("\n前10个真实标签样本:", true_labels[:10])
        print("前10个预测结果样本:", predictions[:10])
        
        return predictions, true_labels
    except Exception as e:
        print(f"预测过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        return predictions, true_labels

def calculate_accuracy_statistics(predictions, actual_labels):
    """
    计算准确率统计信息
    
    参数:
        predictions (list): 预测结果列表
        actual_labels (list): 真实标签列表
    
    返回:
        dict: 包含每个类别的统计信息
    """
    # 初始化准确率统计字典
    stats = {}
    
    # 验证输入列表有效性
    if not isinstance(predictions, list) or not isinstance(actual_labels, list):
        print("错误: 预测结果和真实标签必须是列表类型!")
        return stats
    
    # 验证输入列表长度是否一致
    if len(predictions) != len(actual_labels):
        print(f"警告: 预测结果和真实标签列表长度不一致! 预测: {len(predictions)}, 真实: {len(actual_labels)}")
        # 截断较长的列表到较短列表的长度
        min_len = min(len(predictions), len(actual_labels))
        predictions = predictions[:min_len]
        actual_labels = actual_labels[:min_len]
    
    print(f"\n开始计算准确率统计: 处理 {len(predictions)} 个样本")
    
    # 遍历所有预测结果
    for i, (pred, actual) in enumerate(zip(predictions, actual_labels)):
        # 确保值是字符串类型，并进行清理
        pred_str = str(pred).strip()
        actual_str = str(actual).strip()
        
        # 跳过空值或无效值
        if not actual_str or actual_str == "未知":
            continue
        
        # 初始化类别统计
        if actual_str not in stats:
            stats[actual_str] = {
                'count': 0,
                'correct': 0
            }
        
        # 更新统计信息
        stats[actual_str]['count'] += 1
        if pred_str == actual_str and pred_str != "未知" and pred_str != "预测失败":
            stats[actual_str]['correct'] += 1
    
    # 计算每个类别的准确率
    for arch in stats:
        stats[arch]['accuracy'] = stats[arch]['correct'] / stats[arch]['count'] if stats[arch]['count'] > 0 else 0
    
    # 添加总体统计
    total_count = sum(stat['count'] for stat in stats.values())
    total_correct = sum(stat['correct'] for stat in stats.values())
    stats['总体'] = {
        'count': total_count,
        'correct': total_correct,
        'accuracy': total_correct / total_count if total_count > 0 else 0.0
    }
    
    print(f"准确率统计完成: 共有 {len(stats)} 个类别（含总体）")
    
    return stats

def print_accuracy_statistics(statistics, model_type):
    # 创建报告字符串，使用显式的UTF-8编码确保中文正确显示
    report_lines = []
    report_lines.append("="*70)
    report_lines.append("架构类别预测准确率统计")
    report_lines.append("="*70)
    report_lines.append("架构编号       数据量       正确预测数       准确率      ")
    report_lines.append("-"*70)
    
    # 按架构编号排序并打印，分别处理数字和非数字键
    numeric_arches = []
    non_numeric_arches = []
    
    # 确保statistics是字典
    if not isinstance(statistics, dict):
        print(f"错误: statistics参数类型错误，期望dict但得到{type(statistics).__name__}")
        return
    
    for arch in statistics.keys():
        # 确保每个键都有正确的统计数据结构
        if not isinstance(statistics[arch], dict) or 'count' not in statistics[arch] or 'correct' not in statistics[arch] or 'accuracy' not in statistics[arch]:
            continue
            
        if isinstance(arch, str) and arch.isdigit():
            numeric_arches.append((int(arch), arch))
        else:
            non_numeric_arches.append(arch)
    
    # 先按数字排序
    numeric_arches.sort(key=lambda x: x[0])
    sorted_arches = [arch for _, arch in numeric_arches] + sorted(non_numeric_arches)
    
    # 排除'总体'键，避免重复计算
    if '总体' in sorted_arches:
        sorted_arches.remove('总体')
    
    # 打印每个类别的统计信息
    for arch in sorted_arches:
        if isinstance(statistics[arch], dict):
            count = statistics[arch]['count']
            correct = statistics[arch]['correct']
            accuracy = statistics[arch]['accuracy']
            report_lines.append(f"{arch:<12} {count:<12} {correct:<16} {accuracy:.4f}")
    
    report_lines.append("-"*70)
    
    # 计算总数，确保正确处理数据结构
    total_count = 0
    total_correct = 0
    for arch, stat in statistics.items():
        if arch != '总体' and isinstance(stat, dict):
            if 'count' in stat and 'correct' in stat:
                total_count += stat['count']
                total_correct += stat['correct']
    
    total_accuracy = total_correct / total_count if total_count > 0 else 0.0
    report_lines.append(f"{'总计':<12} {total_count:<12} {total_correct:<16} {total_accuracy:.4f}")
    report_lines.append("="*70)
    
    # 打印到控制台
    report = "\n".join(report_lines)
    print(report)
    
    # 保存到文件，使用UTF-8编码确保中文正确显示
    try:
        with open(f"accuracy_report_{model_type}.txt", "w", encoding="utf-8-sig") as f:  # 使用utf-8-sig解决BOM问题
            f.write(report)
        print(f"\n准确率报告已保存到 accuracy_report_{model_type}.txt")
    except Exception as e:
        print(f"保存报告时出错: {str(e)}")
        import traceback
        traceback.print_exc()

def main(model_type):
     # 加载模型
    # model_path = "resources/models/simple_logistic.model"
    # model_path = "resources/models/smo.model"
    # model_path = "resources/models/random_forest.model"
    # model_path = "resources/models/ibk.model"
    # model_path = "resources/models/ibk3.model"
    model_path = f"resources/models/{model_type}.model"
    model = load_model(model_path)
    if model is None:
        raise Exception("无法加载模型")
    
    # 进行预测
    print("开始预测...")
    predictions, actual_labels = predict_with_model(model, instances)
    print(f"预测完成，共预测 {len(predictions)} 个实例")
    
    # 验证预测结果
    print(f"\n预测结果验证:")
    print(f"预测结果总数: {len(predictions)}")
    print(f"真实标签总数: {len(actual_labels)}")
    
    # 显示预测分布统计
    if len(predictions) > 0:
        prediction_counts = {}
        for pred in predictions:
            prediction_counts[pred] = prediction_counts.get(pred, 0) + 1
        
        print(f"\n预测结果分布 (前20个):")
        sorted_predictions = sorted(prediction_counts.items(), key=lambda x: x[1], reverse=True)
        for pred, count in sorted_predictions[:20]:
            print(f"  预测类别 {pred}: {count} 次")
    
    # 计算每个类别的准确率统计
    if predictions and actual_labels:
        print("开始计算准确率统计...")
        # 使用修改后的calculate_accuracy_statistics函数
        accuracy_statistics = calculate_accuracy_statistics(predictions, actual_labels)
        # 打印准确率统计信息
        print_accuracy_statistics(accuracy_statistics, model_type)

if __name__ == "__main__":
    try:
        # 启动JVM
        print("正在启动JVM...")
        jvm.start(packages=True)
        print("JVM启动成功")
        
        # 读取数据
        csv_file_path = "resources/data/ISAdetect_full_binaries_features.csv"
        print(f"正在读取数据: {csv_file_path}")
        data = read_csv_to_list(csv_file_path)
        print(f"成功读取 {len(data)} 行数据")
        
        # 显示数据头部信息
        if data and len(data) > 0:
            print(f"数据头部包含 {len(data[0])} 个属性")
            print(f"前5个属性名: {data[0][:5]}")
            print(f"最后一个属性名(类别): {data[0][-1]}")
        
        # 创建Instances对象
        print("正在创建Instances对象...")
        instances = create_instances_from_csv(data)
        if instances is None:
            raise Exception("无法创建Instances对象")
        print(f"成功创建包含 {instances.num_instances} 个实例的Instances对象")
        print(f"类别索引设置为: {instances.class_index}")
        
        # DONE: "simple_logistic", "smo", "random_forest", "ibk", "ibk3"
        # ERROR: naive_bayes
        for md_tp in ["bayesnet", "mlp", "j48", "random_tree"]:
            print(f"========================>> 正在处理模型类型: {md_tp} <<========================")
            main(md_tp)
    
    except Exception as e:
        print(f"程序执行出错: {e}")
        import traceback
        traceback.print_exc()  # 打印详细的错误堆栈信息
    finally:
        # 确保JVM关闭
        print("正在关闭JVM...")
        jvm.stop()
        print("JVM已关闭")
