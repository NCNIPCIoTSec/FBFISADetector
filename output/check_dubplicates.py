#!/usr/bin/env python3
import json
import os

# 读取JSON文件
file_path = '/home/yq/workspace/studies/MyProjects/FBFISADetector/output/arm-cortex-m_accuracy_records.json'

with open(file_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

# 提取所有键
keys = list(data.keys())
print(f"Total entries: {len(keys)}")

# 检查重复
seen = set()
duplicates = set()

for key in keys:
    if key in seen:
        duplicates.add(key)
    else:
        seen.add(key)

if duplicates:
    print(f"Found {len(duplicates)} duplicate entries:")
    for dup in duplicates:
        print(f"  - {dup}")
else:
    print("No duplicate entries found.")