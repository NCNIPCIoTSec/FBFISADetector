from utils.translator import hexString2bytes


# TODO：完善features的预处理
def features_configure_init(head_instr: str, tail_instr: str, features: dict) -> dict:
    '''
    将配置文件中feature不能直接利用的部分处理一下；
    '''
    new_features = features.copy()
    for key in new_features.keys():
        cur_feature = new_features[key]
        # 将寄存器特征部分的掩码字符串转成bytes类型
        if key.lower() == "register" and len(cur_feature) == 4:
            # 寄存器掩码
            register_mask = []
            for i, mask_set in enumerate(cur_feature[-1]):
                register_mask.append([])
                for msk in mask_set:
                    register_mask[i].append(hexString2bytes(msk) if type(msk) == type(str()) else msk)
            cur_feature[-1] = register_mask
        # 指令逆序，则位置置换
        if cur_feature[0].lower() == tail_instr.lower() and cur_feature[1].lower() == head_instr.lower():
            cur_feature[0], cur_feature[1] = tail_instr, head_instr
            # 最后的特征识别式置换
            if len(cur_feature[-1]) == 2:
                if key.lower() == 'scope':
                    if cur_feature[-1][0] > 0:
                        print("[ERROR in SCOPE Feature] the scope must be (front-instr's head - head-instr'tail + 1)，If your instruction order is in reverse order, please make sure the number in the range representation is negative.")
                        raise ValueError
                    cur_feature[-1] = [-1*e for e in cur_feature[-1]]
                cur_feature[-1] = [cur_feature[-1][1], cur_feature[-1][0]]
                    
        # 重置结构
        new_features[key] = cur_feature
    

    return new_features