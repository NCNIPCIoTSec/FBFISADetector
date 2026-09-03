# Firmware Identify Agents 任务
这是一项固件的ISA识别的任务，主要负责将源码 `./src` 重构变成 Agent 的skills，并加以优化改良，任务涉及了2项目标。  

## 【目标1】识别出固件的二进制特征
阅读论文 `docs/FBFISADetector__TrustCom_2025.pdf` 获取指令对的构造思路，并完成 skill-1 `./skills/ins-pairs-finder` 实现对一类架构二进制指令对的识别、抽取与组合以及可信度验证。


## 【目标2】依赖多项特征识别出固件信息
结合目标1的指令对信息以及输入固件，读取更多的信息，完成skill-2 `./skills/isa-detector` 实现对固件指令集架构的识别（最好能获取具体的variant）。

## 注意事项
项目实现过程中请注意将生成的临时文件存入 `./temp` 中，如果有其它知识类/文本介绍类文件，请记录在 `./logs` 中。仅允许修改 `./skills` 文件夹中的内容，不允许对其他文件夹内的信息进行修改。
