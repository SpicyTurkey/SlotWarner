#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional


# =========================
# 数据结构
# =========================

@dataclass
class StorageVar:
    name: str
    slot: int
    offset: int  # bytes
    type: str
    bits: int  # estimated bit width inside this slot (<=256)


@dataclass
class ContractLayout:
    name: str
    storage: List[StorageVar] = field(default_factory=list)


@dataclass
class FunctionInfo:
    name: str
    params: List[str]
    modifiers: str
    body: str
    is_public_or_external: bool


# =========================
# 输出重定向（控制台 + 文件）
# =========================

class TeeOutput:
    def __init__(self, terminal, file):
        self.terminal = terminal
        self.file = file

    def write(self, message):
        self.terminal.write(message)
        self.file.write(message)

    def flush(self):
        self.terminal.flush()
        self.file.flush()


def setup_output_redirection(output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    output_file = open(output_path, "w", encoding="utf-8")
    original_stdout = sys.stdout
    sys.stdout = TeeOutput(original_stdout, output_file)
    return output_file, original_stdout


def restore_output_redirection(output_file, original_stdout):
    sys.stdout = original_stdout
    output_file.close()


# =========================
# 布局解析
# =========================

def type_to_bits(type_str: str) -> int:
    """
    对 Hardhat storageLayout.type 做保守估计，目标是槽内 bit 区间定位，不追求类型完整精确。
    """
    type_str = (type_str or "").strip()

    if type_str.startswith("t_address"):
        return 160

    m = re.match(r"t_u?int(\d+)", type_str)
    if m:
        return int(m.group(1))

    m = re.match(r"t_bytes(\d+)", type_str)
    if m:
        return 8 * int(m.group(1))

    if type_str.startswith("t_bool"):
        return 8  # Solidity bool 常按 1 字节打包

    # mapping/array/struct 等统一按 256（槽内定位用，跨槽结构不在本阶段展开）
    return 256


def parse_layout_file(path: str) -> Dict[str, ContractLayout]:
    """
    支持：
    1) 标准 JSON 数组
    2) 多个 JSON 对象顺序拼接（{...}{...}）
    返回：contract_name -> ContractLayout
    """
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()

    if not text:
        return {}

    if text.startswith("["):
        objects = json.loads(text)
    else:
        patched = re.sub(r"}\s*{", "},{", text)
        patched = "[" + patched + "]"
        objects = json.loads(patched)

    layouts: Dict[str, ContractLayout] = {}
    for obj in objects:
        cname = obj.get("contract")
        if not cname:
            continue
        cl = ContractLayout(name=cname, storage=[])
        for item in obj.get("storage", []) or []:
            raw_slot = item.get("slot", "0")
            try:
                slot_int = int(str(raw_slot), 0)
            except Exception:
                slot_int = int(raw_slot)
            cl.storage.append(
                StorageVar(
                    name=item.get("variable", ""),
                    slot=slot_int,
                    offset=int(item.get("offset", 0) or 0),
                    type=item.get("type", "") or "",
                    bits=type_to_bits(item.get("type", "") or ""),
                )
            )
        layouts[cname] = cl

    return layouts


# =========================
# 注释屏蔽（保持长度一致，便于索引与行号定位）
# =========================

def mask_comments_preserve_length(src: str) -> str:
    """
    将 // 与 /* */ 注释位置替换为空格，但保留换行与整体长度。
    简单处理字符串字面量，避免把字符串中的 // 当注释。
    """
    s = src
    out = list(s)
    i = 0
    in_str = False
    str_ch = ""

    while i < len(s):
        ch = s[i]
        nxt = s[i + 1] if i + 1 < len(s) else ""

        if in_str:
            if ch == "\\" and i + 1 < len(s):
                i += 2
                continue
            if ch == str_ch:
                in_str = False
                str_ch = ""
            i += 1
            continue

        if ch in ("'", '"'):
            in_str = True
            str_ch = ch
            i += 1
            continue

        if ch == "/" and nxt == "/":
            # line comment
            j = i
            while j < len(s) and s[j] != "\n":
                out[j] = " "
                j += 1
            i = j
            continue

        if ch == "/" and nxt == "*":
            # block comment
            out[i] = " "
            out[i + 1] = " "
            j = i + 2
            while j + 1 < len(s) and not (s[j] == "*" and s[j + 1] == "/"):
                if s[j] != "\n":
                    out[j] = " "
                j += 1
            if j + 1 < len(s):
                out[j] = " "
                out[j + 1] = " "
                i = j + 2
            else:
                i = len(s)
            continue

        i += 1

    return "".join(out)


def extract_block(text: str, brace_start: int) -> Tuple[str, int]:
    assert text[brace_start] == "{"
    depth = 1
    i = brace_start + 1
    start = i
    while i < len(text) and depth > 0:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    body = text[start: i - 1]
    return body, i


def parse_contract_spans(masked_source: str) -> Dict[str, Tuple[int, int, int]]:
    """
    返回：contract_name -> (body_start_index, body_end_index, brace_start_index)
    body_end_index 为 '}' 之后的位置索引（与 extract_block 一致）
    """
    spans: Dict[str, Tuple[int, int, int]] = {}
    pattern = re.compile(r"\bcontract\s+([A-Za-z_]\w*)\b[^{]*{")
    for m in pattern.finditer(masked_source):
        name = m.group(1)
        brace_start = masked_source.find("{", m.start())
        if brace_start == -1:
            continue
        _, end_idx = extract_block(masked_source, brace_start)
        body_start = brace_start + 1
        body_end = end_idx - 1
        spans[name] = (body_start, body_end, brace_start)
    return spans


def parse_contracts(masked_source: str) -> Dict[str, str]:
    contracts: Dict[str, str] = {}
    spans = parse_contract_spans(masked_source)
    for name, (bs, be, _) in spans.items():
        contracts[name] = masked_source[bs:be]
    return contracts


SOLIDITY_KEYWORDS = {
    "memory", "calldata", "storage",
    "public", "external", "internal", "private",
    "view", "pure", "payable", "returns", "return",
    "event", "mapping", "struct", "contract",
    "function", "modifier",
    "if", "else", "for", "while", "do",
    "assembly", "break", "continue", "emit",
    "using", "library",
    "address", "uint", "int", "bool", "string", "bytes",
    "require", "assert", "revert",
    "true", "false",
}


def parse_parameters(params_str: str) -> List[str]:
    names: List[str] = []
    for part in (params_str or "").split(","):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        cand = tokens[-1]
        if not re.match(r"^[A-Za-z_]\w*$", cand):
            continue
        if cand in SOLIDITY_KEYWORDS:
            continue
        names.append(cand)
    return names


def parse_functions(contract_body: str) -> List[FunctionInfo]:
    funs: List[FunctionInfo] = []
    pattern = re.compile(r"\bfunction\b\s*([A-Za-z_]\w*)?\s*\(([^)]*)\)\s*([^{;]*){")
    pos = 0
    while True:
        m = pattern.search(contract_body, pos)
        if not m:
            break
        name = m.group(1) or ""
        params_str = m.group(2) or ""
        tail = m.group(3) or ""
        brace_start = contract_body.find("{", m.start())
        if brace_start == -1:
            pos = m.end()
            continue
        body, end_idx = extract_block(contract_body, brace_start)
        param_names = parse_parameters(params_str)
        modifiers = tail.strip()
        tokens = modifiers.split()
        is_pub_ext = ("public" in tokens) or ("external" in tokens)
        funs.append(
            FunctionInfo(
                name=name,
                params=param_names,
                modifiers=modifiers,
                body=body,
                is_public_or_external=is_pub_ext,
            )
        )
        pos = end_idx
    return funs


ASSIGN_PATTERN = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:\[[^;\n=]*\])*\s*([\+\-\*/%&\|\^]?=)(?!=)\s*(.+?);"
)


def extract_identifiers(code: str) -> Set[str]:
    ids = set(re.findall(r"\b([A-Za-z_]\w*)\b", code or ""))
    ids -= SOLIDITY_KEYWORDS
    return ids


# =========================
# taint（逻辑合约）
# =========================

def analyze_contract_taint(contract_body: str, storage_var_names: Set[str]) -> Set[str]:
    funs = parse_functions(contract_body)
    polluted_state: Set[str] = set()

    changed = True
    while changed:
        changed = False
        for fn in funs:
            tainted_locals: Set[str] = set()
            if fn.is_public_or_external:
                tainted_locals.update(fn.params)

            state_sources = set(polluted_state)

            for m in ASSIGN_PATTERN.finditer(fn.body):
                lhs = m.group(1)
                rhs = m.group(3)
                rhs_ids = extract_identifiers(rhs)

                rhs_has_param = fn.is_public_or_external and bool(rhs_ids & set(fn.params))
                rhs_has_tainted = bool(rhs_ids & (tainted_locals | state_sources))
                is_state_var = lhs in storage_var_names

                if is_state_var and (rhs_has_param or rhs_has_tainted):
                    if lhs not in polluted_state:
                        polluted_state.add(lhs)
                        changed = True

                if (rhs_has_param or rhs_has_tainted) and not is_state_var:
                    if lhs not in tainted_locals:
                        tainted_locals.add(lhs)

    return polluted_state


def compute_bits_for_var(sv: StorageVar) -> Set[int]:
    bits: Set[int] = set()
    offset_bits = sv.offset * 8
    width_bits = sv.bits
    if width_bits <= 0:
        return bits
    width_bits = min(width_bits, 256 - offset_bits)
    for b in range(offset_bits, offset_bits + width_bits):
        bits.add(b)
    return bits


def compute_polluted_bits_for_contract(layout: ContractLayout, polluted_vars: Set[str]) -> Dict[int, Set[int]]:
    slot_bits: Dict[int, Set[int]] = defaultdict(set)
    for sv in layout.storage:
        if sv.name not in polluted_vars:
            continue
        slot_bits[sv.slot].update(compute_bits_for_var(sv))
    return slot_bits


def compute_polluted_var_bitsets(layout: ContractLayout, polluted_vars: Set[str]) -> Dict[str, Tuple[int, Set[int]]]:
    res: Dict[str, Tuple[int, Set[int]]] = {}
    for sv in layout.storage:
        if sv.name in polluted_vars:
            res[sv.name] = (sv.slot, compute_bits_for_var(sv))
    return res


def merge_slot_bits(a: Dict[int, Set[int]], b: Dict[int, Set[int]]) -> Dict[int, Set[int]]:
    res: Dict[int, Set[int]] = defaultdict(set)
    for d in (a, b):
        for s, bits in d.items():
            res[s].update(bits)
    return res


def format_bit_ranges(bits: Set[int]) -> str:
    if not bits:
        return ""
    sorted_bits = sorted(bits)
    ranges: List[Tuple[int, int]] = []
    start = prev = sorted_bits[0]
    for b in sorted_bits[1:]:
        if b == prev + 1:
            prev = b
        else:
            ranges.append((start, prev))
            start = prev = b
    ranges.append((start, prev))
    parts = []
    for s, e in ranges:
        parts.append(f"{s}" if s == e else f"{s}-{e}")
    return ", ".join(parts)


def analyze_logic_contracts(layout_map: Dict[str, ContractLayout],
                            contract_bodies: Dict[str, str],
                            logic_contract_name: str) -> Tuple[Dict[int, Set[int]], Dict[str, Tuple[int, Set[int]]]]:
    """
    分析指定逻辑合约的污染情况

    返回：
    1) all_logic_bits: slot -> polluted bits union
    2) var_bits: var -> (slot, bits)
    """
    all_logic_bits: Dict[int, Set[int]] = defaultdict(set)
    var_bits: Dict[str, Tuple[int, Set[int]]] = {}

    if logic_contract_name not in contract_bodies:
        print(f"[Error] Logic contract '{logic_contract_name}' not found in source file")
        return all_logic_bits, var_bits

    layout = layout_map.get(logic_contract_name)
    if not layout or not layout.storage:
        print(f"[Error] No storage layout found for contract '{logic_contract_name}'")
        return all_logic_bits, var_bits

    body = contract_bodies[logic_contract_name]
    storage_var_names = {sv.name for sv in layout.storage if sv.name}
    polluted = analyze_contract_taint(body, storage_var_names)
    slot_bits = compute_polluted_bits_for_contract(layout, polluted)
    var_bits = compute_polluted_var_bitsets(layout, polluted)

    all_logic_bits = merge_slot_bits(all_logic_bits, slot_bits)

    print(f"[Logic] Contract {logic_contract_name}")
    print(f"  Polluted state variables: {sorted(polluted) if polluted else 'None'}")
    if slot_bits:
        print("  Polluted slots (bit ranges within each slot):")
        for s in sorted(slot_bits.keys()):
            print(f"    slot {s}: {format_bit_ranges(slot_bits[s])}")
    else:
        print("  No polluted storage slots detected.")
    print()

    return all_logic_bits, var_bits


def analyze_single_file_all_contracts(layout_map: Dict[str, ContractLayout], source_path: str):
    """
    原单文件模式：将所有合约作为逻辑合约分析
    """
    with open(source_path, "r", encoding="utf-8") as f:
        src = f.read()
    masked = mask_comments_preserve_length(src)
    contract_bodies = parse_contracts(masked)

    all_logic_bits: Dict[int, Set[int]] = defaultdict(set)
    per_contract_var_bits: Dict[str, Dict[str, Tuple[int, Set[int]]]] = {}

    for cname, body in contract_bodies.items():
        layout = layout_map.get(cname)
        if not layout or not layout.storage:
            continue
        storage_var_names = {sv.name for sv in layout.storage if sv.name}
        polluted = analyze_contract_taint(body, storage_var_names)
        slot_bits = compute_polluted_bits_for_contract(layout, polluted)
        var_bits = compute_polluted_var_bitsets(layout, polluted)

        all_logic_bits = merge_slot_bits(all_logic_bits, slot_bits)
        per_contract_var_bits[cname] = var_bits

        print(f"[Logic] Contract {cname}")
        print(f"  Polluted state variables: {sorted(polluted) if polluted else 'None'}")
        if slot_bits:
            print("  Polluted slots (bit ranges within each slot):")
            for s in sorted(slot_bits.keys()):
                print(f"    slot {s}: {format_bit_ranges(slot_bits[s])}")
        else:
            print("  No polluted storage slots detected.")
        print()

    print("[Mapping] Single-contract mode ends here. (No proxy to map into.)")


# =========================
# 代理合约识别与重要性评估
# =========================

def detect_delegatecall_in_body(contract_body: str) -> bool:
    return bool(re.search(r"\bdelegatecall\b", contract_body))


def group_proxy_vars_by_slot(layout: ContractLayout) -> Dict[int, List[StorageVar]]:
    by_slot: Dict[int, List[StorageVar]] = defaultdict(list)
    for sv in layout.storage:
        if sv.name:
            by_slot[sv.slot].append(sv)
    return by_slot


def find_guard_key_vars(contract_body: str, storage_var_names: Set[str]) -> Set[str]:
    """
    以 require/assert/revert 中出现为守卫变量候选。
    """
    guard_vars: Set[str] = set()
    for var in storage_var_names:
        pat = r"\b(require|assert|revert)\b\s*\([^;]*\b" + re.escape(var) + r"\b"
        if re.search(pat, contract_body):
            guard_vars.add(var)
    return guard_vars


def find_name_based_key_vars(storage_var_names: Set[str]) -> Set[str]:
    key_vars: Set[str] = set()
    KEY = ("owner", "admin", "authority", "governor", "controller", "manager", "superuser", "root", "master",
           "deployer", "creator", "guardian",
           "ownerAddress", "adminAddress", "contractOwner", "defaultAdmin", "primaryOwner", "secondaryOwner",
           "ownerWallet", "adminWallet",
           "_owner", "_admin", "_authority", "_governor", "_controller", "_manager", "_superuser", "_root", "_master",
           "_deployer", "_creator", "_guardian", "_minter",
           "owner_", "admin_", "Owner", "Admin", "Authority", "Governor", "Controller", "Manager", "SuperUser", "Root",
           "Master", "Deployer", "Creator", "Guardian",
           "contractOwner", "projectAdmin", "systemOwner", "globalAdmin", "feeOwner", "tokenOwner", "vaultOwner",
           "securityOwner", "upgradeOwner")
    for v in storage_var_names:
        lv = v.lower()
        if any(k in lv for k in KEY):
            key_vars.add(v)
    return key_vars


def find_sensitive_use_vars(contract_body: str, storage_var_names: Set[str]) -> Set[str]:
    """
    粗略定位敏感操作中的变量：transfer/send/call{value:}/approve/transferFrom 等参数出现的状态变量名。
    """
    sensitive: Set[str] = set()
    # 抽取可能的参数片段，再提取标识符
    patterns = [
        r"\.transfer\s*\(([^)]*)\)",
        r"\.send\s*\(([^)]*)\)",
        r"\.call\s*\{[^}]*\bvalue\s*:\s*([^,}]+)[^}]*\}\s*\(([^)]*)\)",
        r"\bapprove\s*\(([^)]*)\)",
        r"\btransferFrom\s*\(([^)]*)\)",
        r"\btransfer\s*\(([^)]*)\)",
    ]
    for pat in patterns:
        for m in re.finditer(pat, contract_body):
            segs = [g for g in m.groups() if g is not None]
            for seg in segs:
                ids = extract_identifiers(seg)
                for v in storage_var_names:
                    if v in ids:
                        sensitive.add(v)
    return sensitive


def classify_importance(var_name: str, name_keys: Set[str], guard_keys: Set[str], sensitive_keys: Set[str]) -> str:
    score = 0
    if var_name in name_keys:
        score += 2
    if var_name in guard_keys:
        score += 2
    if var_name in sensitive_keys:
        score += 2
    if score >= 4:
        return "HIGH"
    if score >= 2:
        return "MEDIUM"
    return "LOW"


def severity_from_overlaps(overlapped_importances: List[str]) -> str:
    if not overlapped_importances:
        return "LOW"
    if "HIGH" in overlapped_importances:
        return "CRITICAL"
    if "MEDIUM" in overlapped_importances:
        return "HIGH"
    return "MEDIUM"


def index_to_line(src: str, idx: int) -> int:
    # 1-based line number
    return src.count("\n", 0, max(0, idx)) + 1


def locate_var_declaration_lines(src: str, masked: str, contract_span: Tuple[int, int, int], var_name: str) -> List[
    int]:
    """
    在 contract 主体范围内按行搜索变量声明的近似位置，返回行号列表（1-based）。
    """
    (bs, be, _) = contract_span
    segment_src = src[bs:be]
    segment_masked = masked[bs:be]
    lines_src = segment_src.splitlines(keepends=True)
    lines_masked = segment_masked.splitlines(keepends=True)

    res: List[int] = []
    running_idx = bs
    for ls, lm in zip(lines_src, lines_masked):
        line_text = lm
        if re.search(r"\b" + re.escape(var_name) + r"\b", line_text):
            # 过滤函数头、事件、结构等明显非声明行
            if "function" in line_text or "(" in line_text and ")" in line_text and "{" in line_text:
                pass
            else:
                if ";" in line_text:
                    res.append(index_to_line(src, running_idx))
        running_idx += len(ls)
    return res


# =========================
# 映射与碰撞分析（核心）
# =========================

def analyze_mapping_between_contracts(
        logic_bits: Dict[int, Set[int]],
        proxy_layout: ContractLayout,
        proxy_contract_name: str,
        proxy_src: str,
        proxy_masked: str,
        proxy_spans: Dict[str, Tuple[int, int, int]]
):
    """
    分析逻辑合约污染位与代理合约存储槽的映射关系
    """
    proxy_span = proxy_spans.get(proxy_contract_name)
    if not proxy_span:
        print(f"[Proxy] Contract {proxy_contract_name} span not found in source file.")
        return

    proxy_contract_body_masked = proxy_masked[proxy_span[0]:proxy_span[1]]
    storage_var_names = {sv.name for sv in proxy_layout.storage if sv.name}

    name_keys = find_name_based_key_vars(storage_var_names)
    guard_keys = find_guard_key_vars(proxy_contract_body_masked, storage_var_names)
    sensitive_keys = find_sensitive_use_vars(proxy_contract_body_masked, storage_var_names)

    by_slot = group_proxy_vars_by_slot(proxy_layout)

    print(f"[Proxy] Detected proxy contract: {proxy_contract_name}")
    print(f"  Key vars(by-name): {sorted(name_keys) if name_keys else 'None'}")
    print(f"  Key vars(guards): {sorted(guard_keys) if guard_keys else 'None'}")
    print(f"  Key vars(sensitive-ops): {sorted(sensitive_keys) if sensitive_keys else 'None'}")
    print()

    if not logic_bits:
        print("[Mapping] Logic taint result is empty, no mapping needed.")
        return

    print("[Mapping] Bit-level mapping: logic(slot,bit) -> proxy(slot,bit)")
    print("  Rule: delegatecall uses caller storage, so slot index is preserved.")
    print()

    # 汇总：按 slot 输出映射结论
    all_slots = sorted(logic_bits.keys())
    for slot in all_slots:
        polluted_bits = logic_bits.get(slot, set())
        proxy_vars = by_slot.get(slot, [])

        # 代理 slot 的占用 bit 集合
        occupied: Set[int] = set()
        for sv in proxy_vars:
            occupied.update(compute_bits_for_var(sv))

        # slot 内的覆盖情况
        overlap_vars: List[Tuple[StorageVar, Set[int], str, List[int]]] = []
        for sv in proxy_vars:
            vb = compute_bits_for_var(sv)
            ov = vb & polluted_bits
            if ov:
                imp = classify_importance(sv.name, name_keys, guard_keys, sensitive_keys)
                decl_lines = locate_var_declaration_lines(proxy_src, proxy_masked, proxy_span, sv.name)
                overlap_vars.append((sv, ov, imp, decl_lines))

        gap_bits = polluted_bits - occupied

        # 情况判定：整槽承载 / 打包碰撞 / 空隙 / 布局缺失
        is_full_single = (
                len(proxy_vars) == 1
                and proxy_vars[0].offset == 0
                and min(proxy_vars[0].bits, 256) == 256
        )

        if not proxy_vars:
            case = "LAYOUT_MISSING_OR_EMPTY_SLOT"
            severity = "MEDIUM"  # 无法归因变量，保守给中等
            decision = "该 slot 在 layout 中为空或未记录，脚本无法定位变量语义；建议结合代理源码中的 assembly/unstructured storage 核查。"
        elif is_full_single:
            case = "FULL_SLOT_SINGLE_VAR"
            imp = overlap_vars[0][2] if overlap_vars else classify_importance(proxy_vars[0].name, name_keys, guard_keys,
                                                                              sensitive_keys)
            severity = "HIGH" if imp == "HIGH" else ("MEDIUM" if imp == "MEDIUM" else "LOW")
            decision = "该 slot 为单变量整槽承载，污染会直接作用于该变量；风险取决于变量语义重要性。"
        else:
            # packed slot
            if overlap_vars:
                case = "PACKED_SLOT_COLLISION"
                severity = severity_from_overlaps([x[2] for x in overlap_vars])
                decision = "该 slot 存在打包变量且发生覆盖，属于存储碰撞；应按覆盖到的变量重要性决策是否终止调用。"
            else:
                case = "POLLUTION_IN_GAP"
                severity = "LOW"
                decision = "污染 bit 落在槽内空隙区域（未被声明变量占用），风险受控；仍需确认该空隙是否被手写 assembly 使用。"

        print(f"== Slot {slot} ==")
        print(f"  Logic polluted bits: {format_bit_ranges(polluted_bits)}")
        print(
            f"  Proxy vars in slot: {[f'{sv.name}(off={sv.offset}B,type={sv.type},bits={min(sv.bits, 256)})' for sv in proxy_vars] if proxy_vars else 'None'}")
        if gap_bits:
            print(f"  Gap bits (not covered by declared vars): {format_bit_ranges(gap_bits)}")
        if overlap_vars:
            print("  Overlapped variables:")
            for sv, ov, imp, decl_lines in overlap_vars:
                loc = f"lines {decl_lines}" if decl_lines else "line unknown"
                print(
                    f"    {sv.name} [importance={imp}] (slot={sv.slot}, off={sv.offset}B, type={sv.type}, {loc}) => overlapped bits: {format_bit_ranges(ov)}")
        print(f"  Case: {case}")
        print(f"  Severity: {severity}")
        if severity in ("CRITICAL", "HIGH"):
            print("  Recommendation: 必须终止调用流程或更换被 delegatecall 的逻辑合约。")
        elif severity == "MEDIUM":
            print("  Recommendation: 建议暂停上线并做人工复核，优先核查权限控制与资金相关变量。")
        else:
            print("  Recommendation: 风险较低，仍建议结合代理中 assembly 存储使用做一次核验。")
        print(f"  Note: {decision}")
        print()


def analyze_two_contracts_from_single_file(
        source_path: str,
        layout_map: Dict[str, ContractLayout],
        logic_contract_name: str,
        proxy_contract_name: str
):
    """
    从单个文件中分析两个合约（逻辑和代理），使用同一个布局文件
    """
    print(f"=== SlotWarner Mapping Stage: Single-file dual-contract mode ===")
    print(f"  Source file: {source_path}")
    print(f"  Logic contract: {logic_contract_name}")
    print(f"  Proxy contract: {proxy_contract_name}")
    print()

    # 读取源代码
    with open(source_path, "r", encoding="utf-8") as f:
        src = f.read()
    masked = mask_comments_preserve_length(src)

    # 解析所有合约
    contract_bodies = parse_contracts(masked)
    contract_spans = parse_contract_spans(masked)

    # 检查合约是否存在
    if logic_contract_name not in contract_bodies:
        print(f"[Error] Logic contract '{logic_contract_name}' not found in source file")
        return
    if proxy_contract_name not in contract_bodies:
        print(f"[Error] Proxy contract '{proxy_contract_name}' not found in source file")
        return

    # 从布局文件中获取逻辑合约布局
    logic_layout = layout_map.get(logic_contract_name)
    if not logic_layout:
        print(f"[Error] No storage layout found for logic contract '{logic_contract_name}' in layout file")
        return

    # 从布局文件中获取代理合约布局
    proxy_layout = layout_map.get(proxy_contract_name)
    if not proxy_layout:
        print(f"[Error] No storage layout found for proxy contract '{proxy_contract_name}' in layout file")
        return

    # 分析逻辑合约
    logic_bits, _ = analyze_logic_contracts({logic_contract_name: logic_layout},
                                            contract_bodies, logic_contract_name)

    # 分析映射关系
    analyze_mapping_between_contracts(
        logic_bits=logic_bits,
        proxy_layout=proxy_layout,
        proxy_contract_name=proxy_contract_name,
        proxy_src=src,
        proxy_masked=masked,
        proxy_spans=contract_spans
    )


def analyze_two_files(
        logic_src_path: str,
        proxy_src_path: str,
        logic_layout_map: Dict[str, ContractLayout],
        proxy_layout_map: Dict[str, ContractLayout]
):
    """
    分析两个独立的合约文件
    """
    print(f"=== SlotWarner Mapping Stage: Two-contract mode ===")
    print(f"  Logic file: {logic_src_path}")
    print(f"  Proxy file: {proxy_src_path}")
    print()

    # 读取逻辑合约源代码
    with open(logic_src_path, "r", encoding="utf-8") as f:
        logic_src = f.read()
    logic_masked = mask_comments_preserve_length(logic_src)
    logic_contracts = parse_contracts(logic_masked)

    # 自动检测逻辑合约（第一个合约）
    logic_contract_name = next(iter(logic_contracts.keys())) if logic_contracts else ""
    if not logic_contract_name:
        print("[Error] No contracts found in logic source file")
        return

    # 分析逻辑合约
    logic_bits, _ = analyze_logic_contracts(logic_layout_map, logic_contracts, logic_contract_name)

    # 读取代理合约源代码
    with open(proxy_src_path, "r", encoding="utf-8") as f:
        proxy_src = f.read()
    proxy_masked = mask_comments_preserve_length(proxy_src)
    proxy_spans = parse_contract_spans(proxy_masked)

    # 自动检测代理合约（包含delegatecall的合约）
    proxy_contract_name = ""
    for name, span in proxy_spans.items():
        body = proxy_masked[span[0]:span[1]]
        if detect_delegatecall_in_body(body):
            proxy_contract_name = name
            break

    if not proxy_contract_name:
        print("[Error] No contract with delegatecall found in proxy source file.")
        return

    # 获取代理合约布局
    proxy_layout = proxy_layout_map.get(proxy_contract_name)
    if not proxy_layout:
        print(f"[Error] No storage layout found for proxy contract '{proxy_contract_name}'")
        return

    # 分析映射关系
    analyze_mapping_between_contracts(
        logic_bits=logic_bits,
        proxy_layout=proxy_layout,
        proxy_contract_name=proxy_contract_name,
        proxy_src=proxy_src,
        proxy_masked=proxy_masked,
        proxy_spans=proxy_spans
    )


# =========================
# CLI
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="SlotWarner - Slot pollution mapping stage (logic taint -> proxy storage region)."
    )
    parser.add_argument(
        "-f", "--file-count",
        type=int, choices=[1, 2], required=True,
        help="1: single source file; 2: two source files (logic + proxy)."
    )
    parser.add_argument(
        "-d", "--dual-contracts",
        action="store_true",
        help="When -f 1, treat single file as containing both logic and proxy contracts."
    )
    parser.add_argument(
        "--logic-contract",
        type=str,
        help="Name of logic contract (required when -f 1 -d)."
    )
    parser.add_argument(
        "--proxy-contract",
        type=str,
        help="Name of proxy contract (required when -f 1 -d)."
    )
    parser.add_argument(
        "--layout",
        required=False,
        help="Path to Hardhat storage layout JSON (used for -f 1 without -d, or with -f 1 -d)."
    )
    parser.add_argument(
        "--logic-layout",
        required=False,
        help="Path to Hardhat storage layout JSON for logic contract(s) (alternative to --layout, used for -f 2)."
    )
    parser.add_argument(
        "--proxy-layout",
        required=False,
        help="Path to Hardhat storage layout JSON for proxy contract (used for -f 2)."
    )
    parser.add_argument(
        "sources",
        nargs="+",
        help="Solidity source files: -f 1: one .sol file; -f 2: logic.sol proxy.sol"
    )

    args = parser.parse_args()

    # 参数验证
    if args.file_count == 1:
        if len(args.sources) != 1:
            parser.error("For -f 1 you must provide exactly ONE Solidity source file.")

        if args.dual_contracts:
            if not args.logic_contract or not args.proxy_contract:
                parser.error("When using -f 1 -d, you must provide --logic-contract and --proxy-contract.")
            if not args.layout:
                parser.error("When using -f 1 -d, --layout is required.")
        else:
            if not args.layout:
                parser.error("When using -f 1 without -d, --layout is required.")
    else:  # args.file_count == 2
        if len(args.sources) != 2:
            parser.error("For -f 2 you must provide exactly TWO Solidity source files.")
        if not args.logic_layout or not args.proxy_layout:
            parser.error("For -f 2, both --logic-layout and --proxy-layout are required.")
        if args.dual_contracts:
            print("[Warning] -d flag is ignored when -f 2 is specified.")

    # 确定使用哪个布局文件
    layout_map = {}
    if args.file_count == 1 and args.dual_contracts:
        # 双合约模式：使用单个布局文件
        layout_map = parse_layout_file(args.layout)
    elif args.file_count == 1 and not args.dual_contracts:
        # 原单文件模式：使用单个布局文件
        layout_map = parse_layout_file(args.layout)
    else:  # args.file_count == 2
        # 双文件模式：分别解析两个布局文件
        logic_layout_map = parse_layout_file(args.logic_layout)
        proxy_layout_map = parse_layout_file(args.proxy_layout)

    # 输出文件名
    if args.file_count == 1 and not args.dual_contracts:
        base = os.path.splitext(os.path.basename(args.sources[0]))[0]
        out_path = f"output/{base}.map"
    elif args.file_count == 1 and args.dual_contracts:
        base = os.path.splitext(os.path.basename(args.sources[0]))[0]
        out_path = f"output/{base}_dual.map"
    else:  # args.file_count == 2
        # 使用代理合约文件名
        s1, s2 = args.sources
        with open(s1, "r", encoding="utf-8") as f:
            m1 = mask_comments_preserve_length(f.read())
        with open(s2, "r", encoding="utf-8") as f:
            m2 = mask_comments_preserve_length(f.read())

        s1_has = detect_delegatecall_in_body(m1)
        s2_has = detect_delegatecall_in_body(m2)
        proxy_src = s1 if (s1_has and not s2_has) else (s2 if (s2_has and not s1_has) else s2)
        base = os.path.splitext(os.path.basename(proxy_src))[0]
        out_path = f"output/{base}.map"

    output_file, original_stdout = setup_output_redirection(out_path)

    try:
        if args.file_count == 1 and not args.dual_contracts:
            # 原单文件模式：所有合约作为逻辑合约
            analyze_single_file_all_contracts(layout_map, args.sources[0])

        elif args.file_count == 1 and args.dual_contracts:
            # 新单文件模式：指定逻辑和代理合约
            analyze_two_contracts_from_single_file(
                source_path=args.sources[0],
                layout_map=layout_map,
                logic_contract_name=args.logic_contract,
                proxy_contract_name=args.proxy_contract
            )

        else:  # args.file_count == 2
            # 双文件模式
            analyze_two_files(
                logic_src_path=args.sources[0],
                proxy_src_path=args.sources[1],
                logic_layout_map=logic_layout_map,
                proxy_layout_map=proxy_layout_map
            )

    finally:
        restore_output_redirection(output_file, original_stdout)
        print(f"Output has been saved to: {out_path}")


if __name__ == "__main__":
    main()