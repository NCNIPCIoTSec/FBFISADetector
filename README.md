# FirmISAIdentify
识别固件的指令集架构  
Identify the **ISA(Instrunction Set Architecture)** of firmware

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

## 嵌入式固件的ISA识别的意义
- 硬件缺失或者硬件识别信息磨损的环境下，固件的信息收集需要额外的工作；
- 不可/难以拆卸的嵌入式设备的固件调试；
- 固件烧录前的黑盒测试 / 其他方式获取固件，如一些侧信道方法获取等非法或合法手段；

## 技术研究
- ISA识别方法采用**指令对**的方式：  
  **指令对：** 堆栈的push(lr)与pop(pc)指令、条件语句的cmp和bxx指令；   
  **原因：** 分析 `binwalk -Y` 原来的方法，查询500条指令是否符合某ISA下的特征，但是thumb指令集16bits（2bytes），很容易被错误识别，所以，这就是为什么 binwalk 之前的分析方法总会错误地讲固件识别成ARM架构；  
- 目前困难点：  
  1. 短指令，导致个别指令对儿匹配范围过大，如：\xbd\x??  pop {pc, xxx} | \xb5\x??  push {lr, xxx}，实际上其匹配方式只关注一个字节“\xbd\xb5” -> <font color="red">上下文分析/地址对齐（如，每个指令的起始地址必为偶数）</font>
  2. 指令对是否强耦合？即，是否存在其他指令（组合）替代了指令对中其中一条指令的作用？ *e.g. pop.w v.s. ldr.w + sub sp, 0x??*  
  3. 指令对频率的计算方法？当固件很小时，函数量导致push和pop的数量较少，这就会导致 $|num(push) - num(pop)| \over max(num(push), num(pop))$ 计算出的比例扩大，即，有1个指令识别的误差，就会大大影响计算出的比率；

