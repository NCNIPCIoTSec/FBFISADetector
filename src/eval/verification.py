import re


def verify_instructions(path):
    context = ''
    with open(file=path, mode='r', encoding='utf-8') as fr:
        context = fr.read()
    results = [str(res).lower().replace("call | ", "").strip("\n").strip() for res in re.findall(r"call \| 6.*?\n", context)]
    results = set(results)

    # 验证
    pos_instr = ['6d000201', '6d00e100', '6d000d00', '6d00c610', '6d00490f', '6d00fa11', '6d00f30f', '6d007212', '6d00ea11', '6d007112', '6d00500c', '6d005f0c', '6d00380b', '6d004400', '6d002701', '6dffb7fe', '6dffbdff', '6dffb9ff', '6dffb4ff', '6dffafff', '6d00150c', '6d000e00', '6d00f100', '6d002f00', '6dffe0ff', '6d00a50b', '6dffc0ff', '6d00c30b', '6d006b0b', '6d00bc09', '6d00720b', '6dffd6ff', '6dff28ff', '6dff71ff', '6d005b06', '6d006509', '6d00f907', '6d003a08', '6dfff2fc', '6d009a08', '6d00dc08', '6d00f004', '6dff0dfe', '6dff04fe', '6dffdeff', '6dffb2ff', '6dffe8ff', '6d004304', '6d005404', '6d009102', '6d004a04', '6d00a402', '6d00c401', '6d002904', '6d005a02', '6d00bb01', '6d008c01', '6d00f102', '6d00e800', '6d00ab02', '6d000301', '6d00b302', '6d009100', '6d00ca00', '6d008702', '6d009200', '6d004702', '6d001f02', '6d003400', '6d00ea01', '6dff21fd', '6dff9dff', '6dff02fe', '6dffb3ff', '6d001b00', '6dffbeff', '6dff58ff', '6dffbdfd', '6dff6aff', '6dff94fa', '6dff87fa', '6dff9aff', '6dff4eff', '6dff83ff', '6dff37ff', '6dff32fa', '6dffc3ff', '6dff1efa', '6dffa6ff', '6dff26ff', '6dffdafe', '6dffdcfe', '6dff8dfe', '6dffa6fe', '6dff19fe', '6dffbcfd', '6dff22fe', '6dffcbfd', '6dff1efd', '6dff5cfd', '6dff2efd', '6dff06fe', '6dfffefd', '6dfff2fd', '6dffeafd', '6dffdefd', '6dffd6fd', '6dff7afb', '6dff18fb', '6dff85fa', '6dffd6f8', '6dff9cfa', '6dff00fc', '6dffc6fb', '6dffa9fb', '6dff45fb', '6dffdefa', '6dff89fa', '6dffe8fb', '6dffeefa', '6dff73f5', '6d005300', '6d003800', '6d001500', '6d000400', '5c08', '5c08', '5cfd', '5c82', '5c08']
    print(len(pos_instr), len(set(pos_instr)))
    for pi in pos_instr:
        if pi in results:
            print(pi, "=> OK")
        else:
            print(pi, "=> NO")
    print("NOT IN PROPER INSTRUCTION: ", results - set(pos_instr))


def verify_address_correction(test_fpath, verify_fpath):
    context = ''
    with open(file=verify_fpath, mode='r', encoding='utf-8') as fr:
        context = fr.read()
    ver_res = set([tuple(res) for res in re.findall(r"java> (.*?)==>(.*?) \|", context)])
    # print(ver_res)

    context = ''
    with open(file=test_fpath, mode='r', encoding='utf-8') as fr:
        context = fr.read()
    test_res = [list(tuple(res)) for res in re.findall(r"= (.*?)==>(.*?) =", context)]
    # print(test_res)
    for i, addr_ls in enumerate(test_res):
        call_addr, ref_addr = addr_ls
        call_addr = "8" + call_addr[1:]
        ref_addr = "8" + ref_addr[1:]
        test_res[i] = (call_addr, ref_addr)
    test_res = set(test_res)
    del context

    print("验证集有, 但是输出集不存在：", ver_res - test_res)
    print("输出集有，但是验证集不存在：", test_res - ver_res)
    

if __name__ == "__main__":
    # 读取验证集
    output_path = '../resources/tmp1.txt'
    verify_path = '../resources/tmp.txt'

    # 验证模式识别获取的指令是否存在缺失
    verify_instructions(verify_path)
    verify_address_correction(test_fpath=output_path, verify_fpath=verify_path)

