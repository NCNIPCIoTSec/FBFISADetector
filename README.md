# FirmISAIdentify
识别固件的指令集架构  
Identify the **ISA (Instrunction Set Architecture)** of firmware

## 前期配置
**下载虚拟环境：** 使用的Python的virtualenv库（[环境配置参考链接](https://blog.csdn.net/littlefun591/article/details/135740075)）  
  ```shell
  pip install virtualenv virtualenvwrapper
  mkdir ~/.virtualenvs
  sudo find / -name virtualenvwrapper.sh
  ```
`vim ~/.bashrc` **修改~/.bashrc**
  ```shell
  export VIRTUALENVWRAPPER_PYTHON=/usr/local/bin/python3
  export WORKON_HOME=$HOME/.virtualenvs
  export VIRTUALENVWRAPPER_VIRTUALENV=$HOME/.local/bin/virtualenv
  source ~/.local/bin/virtualenvwrapper.sh
  ```
**创建虚拟环境并进入**  
  ```shell
  mkvirtualenv FirmISAIdentify --python=$(which python)
  workon FirmISAIdentify
  ```
**下载项目并下载依赖的库**  
  ```shell
  git clone https://github.com/NCNIPCIoTSec/FirmISAIdentify.git
  cd FirmISAIdentify 
  git install -r requirements.txt
  mkdir requirements && cd requirements
  git clone https://github.com/capstone-engine/capstone.git
  cd capstone/bindings/python
  python setup.py install
  ```

## 嵌入式固件的指令集架构识别的意义
- 主要意义：
  - **降低识别成本**。无需再依据产品型号、硬件型号手动搜索MCU使用的指令集架构；  
  - **大规模自动化固件分析**。信息收集作为固件分析的重要阶段之一，往往涉及大量的人力成本去进行指令集架构分析、固件Flash基地址分析、程序入口点分析，这些分析获取的内容对于接下来的静态、动态分析挖掘程序漏洞都是必要的。一个完善的自动化识别工具能够大大提高固件分析效率；  
- 其他极端场景：
  - 硬件缺失或者硬件识别信息磨损的环境下，固件的信息收集需要额外的工作；
  - 不可/难以拆卸的嵌入式设备的固件调试；
  - 固件烧录前的黑盒测试 / 其他方式获取固件，如一些侧信道方法获取等非法或合法手段；

## 相关工作
- 【 Binwalk 二进制识别工具】解包含系统的路由器固件

  - CCFA NDSS'17 - [Firmdyne](https://www.ndss-symposium.org/wp-content/uploads/2017/09/towards-automated-dynamic-analysis-linux-based-embedded-firmware.pdf)
  - CCFB ACSAC'20 - [FirmAE](https://dl.acm.org/doi/abs/10.1145/3427228.3427294)
  - CCFA S&P'21 - [Enabling the Large-Scale Emulation of Internet of Things Firmware With Heuristic Workarounds](https://ieeexplore.ieee.org/abstract/document/9431371)
- 【机器学习方法】对*nix系统仓库的二进制可执行文件进行ISA识别
  - CCFC DFRWS'15 - [Automatic classification of object code using machine learning](https://www.sciencedirect.com/science/article/pii/S1742287615000523)  
  - CCFC DIMVA'18 - [ELISA: ELiciting ISA of Raw Binaries for Fine-Grained Code and Data Separation](https://link.springer.com/chapter/10.1007/978-3-319-93411-2_16)

## 挑战  
- 先前的研究工作存在的问题：  
  **首先，概率模型（频率分析的方法）因为是黑盒，无法被严格的证明其识别结果的准确性。** 尤其是对于一些传统的分类模型，存在明显的数据先验知识依赖的情况，哪怕是大模型也存在此类问题，比如给一段 “Tricore 1.80” 的指令代码询问 deepseek 这段二进制内容使用的指令集架构，也许是由于 Tricore 指令集的使用场景有限，大模型的语料库中并不包含此类信息，但模型的局限性就在于“我可能不知道，但我绝对会说一个可能的答案装作我知道” —— <strong><font color="red">机器幻觉</font></strong>，所以它宁愿会返回错误的“x86架构”信息，也不会返回一个“我不知道”。  
  再者，概率模型方法的灵活性性、可扩展性有限。  

## 技术方法
- ISA识别方法采用**指令对**的方式：  
  **指令对：** 堆栈的 `push {lr, rx, ry}` 与 `pop {pc, rx, ry}` 指令、条件语句的 `cmp` 和 `bxx` 指令。我们将指令对的类型分为两大类，“块指令对”类型以及“块内指令对类型”。   
