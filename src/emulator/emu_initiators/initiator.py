from abc import abstractmethod, ABC

class InitiatorInterface(ABC):
    @abstractmethod
    def mode_init(self, mode: int) -> int:
        '''
        初始化Unicorn模式
        - input: 
          - mode - Unicorn 模式（UC_MODE_ARM, UC_MODE_POWERPC, UC_MODE_MIPS）
          - entry_pc - 入口地址（ARM/Thumb）
        - output: 初始化后的模式
        '''
        pass
    
    @abstractmethod
    def reg_init(self):
        '''
        初始化寄存器，需要根据具体架构配置相关寄存器
        - input: none
        - output: 初始化后的Unicorn实例
        '''
        pass
    
    @abstractmethod
    def println_crash(self, state):
        '''
        打印崩溃结果
        打印崩溃时的寄存器状态
        - input: state - Unicorn 状态字典
        - output: 打印寄存器状态
        '''
        pass
    
    @abstractmethod
    def println_initInfo(self):
        '''
        打印初始化信息
        '''
        pass
