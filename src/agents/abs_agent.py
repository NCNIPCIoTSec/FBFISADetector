import json
import os
import configparser
import textwrap
from pathlib import Path
from openai import OpenAI

'''
auth.conf
[llm]
base_url = https://xxxx.com/
api_key  = sk-xxxxx
model    = xxxx
api_style = chat 
'''

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

    def __init__(self, conf_path: Path | None = None):
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

            for offset, abs_addr in batch:
                label = result.get(f"0x{abs_addr:08X}", "unknown")
                if label == "function":
                    func_result[offset] = abs_addr
                elif label == "data":
                    data_result[offset] = abs_addr
                else:
                    unknown_result[offset] = abs_addr

        print(f"[LLMAgent] 完成 | "
              f"函数={len(func_result)}  数据={len(data_result)}  待定={len(unknown_result)}")

        return func_result, data_result, unknown_result

    def classify_base_addresses(
        self,
        base_addresses : dict,      # {addr: count}
        arch           : str,
        bits_width     : int,
        endian         : str
    ) -> dict:
        """
        对候选基地址进行分类。
        """
        if not base_addresses:
            return dict()
        
        final_results = dict()

        items   = list(base_addresses.items())
        batches = [items[i:i + _BATCH_SZ] for i in range(0, len(items), _BATCH_SZ)]

        for idx, batch in enumerate(batches, 1):
            print(f"[LLMAgent] 批次 {idx}/{len(batches)}，共 {len(batch)} 条...")
            prompt  = self._build_addr_id_promt(batch, arch, bits_width, endian)
            try:
                raw    = self._call(prompt)
                result = self._id_parse(raw)
                print(f"[LLMAgent] 批次 {idx} 成功，原始响应：{raw}")
                print(f"[LLMAgent] 批次 {idx} 解析结果：{result}")
            except Exception as e:
                print(f"[LLMAgent] 批次 {idx} 失败，归入 unknown：{e}")
                continue

            requested = {f"0x{addr:08X}" for addr, _ in batch}
            final_results.update({key: value for key, value in result.items() if key in requested})

        return final_results


    # ────────────────────────────────────────────────────────────────────────
    #  内部方法
    # ────────────────────────────────────────────────────────────────────────

    def _build_entries(self, batch: list, arch: str, file_bytes, file_size: int) -> list:
        entries = []
        for offset, abs_addr in batch:
            is_thumb  = bool(abs_addr & 1) and arch.startswith("ARM")
            entries.append({
                "abs_addr"  : f"0x{abs_addr:08X}",
                "source_offset": f"0x{offset:X}",
                "is_thumb"  : is_thumb,
                "hex_bytes" : self._read_bytes(offset, _CTX_BYTES, file_bytes, file_size),
            })
        return entries

    def _read_bytes(self, addr: int, n: int, file_bytes, file_size: int) -> str:
        if addr < 0 or addr >= file_size:
            return "<out-of-range>"
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
            f'  source_offset={e["source_offset"]}  source_bytes=[{e["hex_bytes"]}]'
            for e in entries
        )
        return textwrap.dedent(f"""
            你是嵌入式固件逆向专家。
            目标架构：{arch}  字宽：{bits_width}位  字节序：{endian}

            任务：对以下每个候选绝对地址，根据地址范围及引用位置的原始字节，
            判断其是「函数入口」(function)、「数据」(data) 或「无法判断」(unknown)。

            判断依据：
            1. function：字节符合该架构函数常见的函数地址范围
            2. data：字节符合该架构数据表常见的地址范围
            3. unknown：可能是字符串等数据的情
            4. is_thumb=true 表示 Thumb 指针；source_bytes 来自文件内引用位置，目标字节因基址未知而不可用
            5. 如果函数的地址范围于数据表地址范围有交叉，将此范围内的字节地址同时加入func和data分类

            候选地址：
            {entry_lines}

            严格返回如下 JSON，不要有任何额外文字或 markdown 包裹：
            {{
              "0xXXXXXXXX": "function" | "data" | "unknown"
            }}
            键为 abs_addr 原始值（含 Thumb 低位标志位）。
        """).strip()

    def _build_addr_id_promt(self, base_addresses: list[tuple], arch: str, bits_width: int, endian: str) -> str:
        base_addresses = "\n".join([f"base_address=0x{addr:08X}, occur_count={count}" for addr, count in base_addresses])
        return textwrap.dedent(f"""
            你是嵌入式固件逆向专家。
            目标架构：{arch}  字宽：{bits_width}位  字节序：{endian}

            任务：对以下每个通过左移操作获取的候选基地址，根据目标架构的常见基地址范围与频率进行分类，
            判断其是「flash基地址」(flash)、「ram基地址」(ram) 、「其他基地址」(other)、「无法判断」(unknown)。

            判断依据：
            1. flash：字节符合该架构常见的程序基地址/flash地址范围
            2. ram：字节符合该架构常见的数据基地址/ram基地址范围
            3. other：字节不符合以上任何基地址范围，但是属于其他类别的基地址（例如，某总线控制单元基地址）
            4. unknown：可能是纯粹的计算数据的情况

            候选地址（base_address为基地址，occur_count为出现次数）：
            {base_addresses}

            严格返回如下 JSON，不要有任何额外文字或 markdown 包裹：
            {{
              "0xXXXXXXXX": "flash" | "ram" | "other_<category>" | "unknown"
            }}
            键为 base_addresses 原始值，其中<category> 为其他基地址的分类，例如 "other_sbcu"、"other_can" 等。
        """).strip()

    def _call(self, prompt: str) -> str:
        style = self.cfg.get("api_style", "chat")

        if style == "responses":
            response = self.client.responses.create(
                model=self.cfg["model"], input=prompt,
                instructions="你是嵌入式固件逆向专家，只输出 JSON，不附加任何说明。",
                max_output_tokens=1024,
            )
            return (response.output_text or "").strip()
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
            return (response.choices[0].message.content or "").strip()

    def _parse(self, raw: str) -> dict:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = "\n".join(
                l for l in clean.splitlines()
                if not l.strip().startswith("```")
            ).strip()
        parsed = json.loads(clean)
        if not isinstance(parsed, dict):
            raise ValueError("Expected a JSON object of address labels")
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
    
    def _id_parse(self, raw: str) -> dict:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = "\n".join(
                l for l in clean.splitlines()
                if not l.strip().startswith("```")
            ).strip()
        parsed = json.loads(clean)
        if not isinstance(parsed, dict):
            raise ValueError("Expected a JSON object of address labels")
        valid  = {"flash", "ram", "other", "unknown"}
        result = {}
        for k, v in parsed.items():
            try:
                addr  = int(k, 16)
                label = str(v).lower().strip()
                temp_label = label.split("_")[0] if label.startswith("other") else label
                result[f"0x{addr:08X}"] = label if temp_label in valid else "unknown"
            except (ValueError, TypeError):
                continue
        return result

    @staticmethod
    def _load_config(conf_path: Path | None = None) -> dict:
        explicit = conf_path or os.environ.get("FBFISA_LLM_CONFIG")
        conf_path = Path(explicit).expanduser() if explicit else _AUTH_CONF
        if explicit and not conf_path.is_file():
            raise ValueError(f"LLM config does not exist: {conf_path}")
        cfg = configparser.ConfigParser(interpolation=None)
        cfg.read(conf_path, encoding="utf-8")
        section = cfg["llm"] if "llm" in cfg else {}
        result = {
            "base_url": os.environ.get("OPENAI_BASE_URL", section.get("base_url", "https://api.openai.com/v1")).rstrip("/"),
            "api_key": os.environ.get("OPENAI_API_KEY", section.get("api_key", "")),
            "model": os.environ.get("OPENAI_MODEL", section.get("model", "")),
            "api_style": os.environ.get("OPENAI_API_STYLE", section.get("api_style", "chat")),
        }
        if not result["api_key"] or not result["model"]:
            raise ValueError("Set OPENAI_API_KEY and OPENAI_MODEL, provide --llm-config, or use --no-llm")
        if result["api_style"] not in {"chat", "responses"}:
            raise ValueError("LLM api_style must be chat or responses")
        return result
