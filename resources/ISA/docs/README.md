# ATTENTION - INSTR PAIRS SELECTION 
## TRICORE  
切块方式 BLOCK-PAIRS = {"ins":["call-r-func", "ret"], **"type": "BRANCH"**, "features":{}} 并不是最佳的方法，因为这种方式需要大量的偏移地址计算，不仅会导致识别效率降低，对于ELF文件，还会爆出大量错误字节块。   