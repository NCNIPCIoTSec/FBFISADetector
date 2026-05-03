import json
import configparser
import textwrap
from pathlib import Path
from openai import OpenAI


_AUTH_CONF = Path(__file__).parent / "auth.conf"
_BATCH_SZ  = 30
_CTX_BYTES = 16

class LLMAgent:
    """
    独立的 LLM 分类工具，不依赖任何 analyzer 内部结构。
    analyzer 按需调用，传入数据，拿回分类结果。

    使用示例：
        agent = LLMAgent()
        func_addrs, data_addrs, unknown_addrs = agent.classify_addresses(
            candidates  = self.mixed_abs_addresses,
            arch        = self.arch,
            bits_width  = self.bits_width,
            endian      = self.endian,
            file_bytes  = self.file_bytes,
            file_size   = self.FILE_SIZE,
        )
    """

    def __init__(self, conf_path: Path = _AUTH_CONF):
        self.cfg    = self._load_config(conf_path)
        self.client = OpenAI(
            api_key  = self.cfg["api_key"],
            base_url = self.cfg["base_url"],
        )

    # ────────────────────────────────────────────────────────────────────────
    #  公开接口
    # ────────────────────────────────────────────────────────────────────────

    def classify_addresses(
        self,
        candidates : dict,      # {offset: abs_addr}
        arch       : str,
        bits_width : int,
        endian     : str,
        file_bytes,             # Ghidra FileBytes 对象 或 bytes
        file_size  : int,
    ) -> tuple[dict, dict, dict]:
        """
        对候选地址进行分类。

        :param candidates:  待分类地址字典 {文件偏移: 绝对地址}
        :param arch:        架构字符串，如 "ARM:LE:32:v7"
        :param bits_width:  地址位宽，如 32
        :param endian:      字节序 "LE" 或 "BE"
        :param file_bytes:  原始字节数据（Ghidra FileBytes 或 bytes 对象）
        :param file_size:   文件总大小（字节数）
        :return: (func_addresses, data_addresses, unknown_addresses)
                 三个字典结构均为 {offset: abs_addr}
        """
        if not candidates:
            return {}, {}, {}

        func_result    = {}
        data_result    = {}
        unknown_result = {}

        items   = list(candidates.items())
        batches = [items[i:i + _BATCH_SZ] for i in range(0, len(items), _BATCH_SZ)]

        for idx, batch in enumerate(batches, 1):
            print(f"[LLMAgent] 批次 {idx}/{len(batches)}，共 {len(batch)} 条...")

            entries = self._build_entries(batch, arch, file_bytes, file_size)
            prompt  = self._build_prompt(entries, arch, bits_width, endian)

            try:
                raw    = self._call(prompt)
                result = self._parse(raw)
                print(f"[LLMAgent] 批次 {idx} 成功，原始响应：{raw}")
                print(f"[LLMAgent] 批次 {idx} 解析结果：{result}")
            except Exception as e:
                print(f"[LLMAgent] 批次 {idx} 失败，归入 unknown：{e}")
                for offset, abs_addr in batch:
                    unknown_result[offset] = abs_addr
                continue

            addr_map   = {f"0x{abs_addr:08X}": (offset, abs_addr) for offset, abs_addr in batch}
            classified = set()

            for key, label in result.items():
                if key not in addr_map:
                    continue
                classified.add(key)
                offset, abs_addr = addr_map[key]
                if label == "function":
                    func_result[offset] = abs_addr
                elif label == "data":
                    data_result[offset] = abs_addr
                else:
                    unknown_result[offset] = abs_addr

            for offset, abs_addr in batch:
                if f"0x{abs_addr:08X}" not in classified:
                    unknown_result[offset] = abs_addr

        print(f"[LLMAgent] 完成 | "
              f"函数={len(func_result)}  数据={len(data_result)}  待定={len(unknown_result)}")

        return func_result, data_result, unknown_result

    # ────────────────────────────────────────────────────────────────────────
    #  内部方法
    # ────────────────────────────────────────────────────────────────────────

    def _build_entries(self, batch: list, arch: str, file_bytes, file_size: int) -> list:
        entries = []
        for offset, abs_addr in batch:
            real_addr = abs_addr & ~1
            is_thumb  = bool(abs_addr & 1) and arch.startswith("ARM")
            entries.append({
                "abs_addr"  : f"0x{abs_addr:08X}",
                "is_thumb"  : is_thumb,
                "hex_bytes" : self._read_bytes(real_addr, _CTX_BYTES, file_bytes, file_size),
            })
        return entries

    def _read_bytes(self, addr: int, n: int, file_bytes, file_size: int) -> str:
        # ── Ghidra FileBytes ────────────────────────────────────────────────
        if hasattr(file_bytes, "getOriginalByte"):
            try:
                buf = []
                for i in range(n):
                    if addr + i >= file_size:
                        break
                    buf.append(file_bytes.getOriginalByte(addr + i) & 0xFF)
                return bytes(buf).hex(" ").upper() if buf else "<out-of-range>"
            except Exception:
                pass

        # ── 纯 bytes ────────────────────────────────────────────────────────
        if isinstance(file_bytes, (bytes, bytearray)):
            if addr < 0 or addr >= len(file_bytes):
                return "<out-of-range>"
            return file_bytes[addr: addr + n].hex(" ").upper()

        return "<no-data>"

    def _build_prompt(self, entries: list, arch: str, bits_width: int, endian: str) -> str:
        entry_lines = "\n".join(
            f'  abs_addr={e["abs_addr"]}  is_thumb={e["is_thumb"]}'
            f'  target_bytes=[{e["hex_bytes"]}]'
            for e in entries
        )
        return textwrap.dedent(f"""
            你是嵌入式固件逆向专家。
            目标架构：{arch}  字宽：{bits_width}位  字节序：{endian}

            任务：对以下每个候选绝对地址，根据目标位置的原始字节，
            判断其是「函数入口」(function)、「数据」(data) 或「无法判断」(unknown)。

            判断依据：
            1. function：字节符合该架构函数常见的函数地址范围
            2. data：字节符合该架构数据表常见的地址范围
            3. unknown：可能是字符串等数据的情
            4. is_thumb=true 表示 Thumb 指针（低位已剥离，bytes 为真实地址字节）
            5. 如果函数的地址范围于数据表地址范围有交叉，将此范围内的字节地址同时加入func和data分类

            候选地址：
            {entry_lines}

            严格返回如下 JSON，不要有任何额外文字或 markdown 包裹：
            {{
              "0xXXXXXXXX": "function" | "data" | "unknown"
            }}
            键为 abs_addr 原始值（含 Thumb 低位标志位）。
        """).strip()

    def _call(self, prompt: str) -> str:
        style = self.cfg.get("api_style", "chat")

        if style == "responses":
            # 仅原生 OpenAI 支持，中转站不支持
            ...
        else:
            # ← 走这里，标准 /chat/completions，所有中转站都支持
            response = self.client.chat.completions.create(
                model       = self.cfg["model"],
                temperature = 0,
                max_tokens  = 1024,
                messages    = [
                    {"role": "system", "content": "你是嵌入式固件逆向专家，只输出 JSON，不附加任何说明。"},
                    {"role": "user",   "content": prompt},
                ],
            )
            return response.choices[0].message.content.strip()

    def _parse(self, raw: str) -> dict:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = "\n".join(
                l for l in clean.splitlines()
                if not l.strip().startswith("```")
            ).strip()
        parsed = json.loads(clean)
        valid  = {"function", "data", "unknown"}
        result = {}
        for k, v in parsed.items():
            try:
                addr  = int(k, 16)
                label = str(v).lower().strip()
                result[f"0x{addr:08X}"] = label if label in valid else "unknown"
            except (ValueError, TypeError):
                continue
        return result

    @staticmethod
    def _load_config(conf_path: Path) -> dict:
        cfg = configparser.ConfigParser()
        cfg.read(conf_path, encoding="utf-8")
        if "llm" not in cfg:
            raise KeyError(f"auth.conf 缺少 [llm] 节：{conf_path}")
        section = cfg["llm"]
        for key in ("base_url", "api_key", "model"):
            if key not in section:
                raise KeyError(f"auth.conf [llm] 缺少字段：{key}")
        return {
            "base_url"  : section["base_url"].rstrip("/"),
            "api_key"   : section["api_key"],
            "model"     : section["model"],
            "api_style" : section.get("api_style", "chat"),   # 默认 chat
        }