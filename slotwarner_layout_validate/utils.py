from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import semantic_version

ADDRESS_FILE_RE = re.compile(r"^(?P<addr>[0-9a-fA-F]{40})_(?P<name>.+)\.sol$")
PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
IMPORT_RE = re.compile(r"(?:import\s+(?:[^\"']*?from\s+)?[\"']([^\"']+)[\"']\s*;)", re.IGNORECASE)
DECL_RE = re.compile(r"\b(?:abstract\s+contract|contract|interface|library|struct|enum)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", errors="replace"))


def sha256_json(obj: Any) -> str:
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def read_text(path: Path) -> str:
    raw = path.read_bytes()
    return raw.decode("utf-8-sig", errors="replace")


def parse_filename(path: Path) -> tuple[str | None, str | None]:
    m = ADDRESS_FILE_RE.match(path.name)
    if not m:
        return None, path.stem
    return "0x" + m.group("addr").lower(), m.group("name")


def filename_suffix_without_address(path: Path) -> str:
    m = ADDRESS_FILE_RE.match(path.name)
    return (m.group("name") + ".sol") if m else path.name


def extract_pragmas(source: str) -> list[str]:
    return [normalize_pragma_expr(x.strip()) for x in PRAGMA_RE.findall(source)]


def extract_imports(source: str) -> list[str]:
    return [normalize_source_unit_name(x) for x in IMPORT_RE.findall(source)]


def declared_symbols(source: str) -> set[str]:
    return {m.group("name") for m in DECL_RE.finditer(source)}


def normalize_pragma_expr(expr: str) -> str:
    # semantic-version 的 NpmSpec 对 ">= 0.5.13" 这类空格较敏感。
    expr = re.sub(r"(>=|<=|>|<|=|\^|~)\s+", r"\1", expr)
    expr = re.sub(r"\s+", " ", expr).strip()
    return expr


def normalize_source_unit_name(name: str) -> str:
    x = str(name).replace("\\", "/").strip()
    while x.startswith("./"):
        x = x[2:]
    parts: list[str] = []
    for part in x.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            else:
                # 保留越界语义，不把任意目录外源码猜进来。
                return x
        else:
            parts.append(part)
    return "/".join(parts)


def detect_features(source: str) -> dict[str, bool]:
    # 只用于分层抽样，不参与布局判定。
    patterns = {
        "inheritance": r"\bcontract\s+\w+\s+is\s+",
        "struct": r"\bstruct\s+\w+\s*\{",
        "mapping": r"\bmapping\s*\(",
        "dynamic_array": r"\[[ \t]*\]",
        "fixed_array": r"\[[ \t]*\d+[ \t]*\]",
        "small_value_type": r"\b(?:bool|address|bytes(?:[1-9]|[12]\d|3[0-2])|u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248))\b",
        "enum": r"\benum\s+\w+\s*\{",
        "user_defined_value_type": r"\btype\s+\w+\s+is\s+",
        "custom_layout_at": r"\blayout\s+at\b",
        "transient": r"\btransient\b",
    }
    return {k: bool(re.search(v, source, re.IGNORECASE)) for k, v in patterns.items()}


def complexity_stratum(features: dict[str, bool]) -> str:
    hard = [k for k in ("inheritance", "struct", "mapping", "dynamic_array", "fixed_array") if features.get(k)]
    if len(hard) >= 3:
        return "complex_3plus"
    if len(hard) == 2:
        return "complex_2"
    if len(hard) == 1:
        return hard[0]
    if features.get("small_value_type"):
        return "packing_only"
    return "simple"


def version_family_from_pragmas(pragmas: list[str]) -> str:
    joined = " ".join(pragmas)
    for family in ("0.5", "0.6", "0.7", "0.8", "0.9"):
        if family in joined:
            return family
    return "broad_or_unknown"


@lru_cache(maxsize=4096)
def _npm_spec(expr: str) -> semantic_version.NpmSpec:
    return semantic_version.NpmSpec(normalize_pragma_expr(expr))


@lru_cache(maxsize=1)
def _synthetic_layout_capable_versions() -> tuple[semantic_version.Version, ...]:
    # 这里只做 manifest 快速、确定性的“是否存在 >=0.5.13 可满足版本”判断。
    # 使用宽松的补丁号网格避免 ^0.5.14 之类被字符串规则误排；真实可安装版本由 compiler.py 再确认。
    out: list[semantic_version.Version] = []
    for minor, patch_start in ((5, 13), (6, 0), (7, 0), (8, 0), (9, 0)):
        for patch in range(patch_start, 100):
            out.append(semantic_version.Version(f"0.{minor}.{patch}"))
    return tuple(out)


@lru_cache(maxsize=16384)
def _pragma_supports_layout_compiler_cached(pragmas: tuple[str, ...]) -> bool:
    if not pragmas:
        return False
    try:
        specs = [_npm_spec(p) for p in pragmas]
    except Exception:
        return False
    return any(all(spec.match(v) for spec in specs) for v in _synthetic_layout_capable_versions())


def pragma_supports_layout_compiler(pragmas: list[str]) -> bool:
    # Phase 0 会扫描几十万源码，而 pragma 组合高度重复。
    # v1.1 只缓存 NpmSpec，却仍对每个文件重复遍历约 487 个 synthetic versions，
    # 会造成上亿次 spec.match。v1.2 对“整个 pragma 组合的判断结果”做缓存。
    return _pragma_supports_layout_compiler_cached(tuple(pragmas or ()))


@lru_cache(maxsize=16384)
def _pragma_allows_pre_0_5_13_cached(pragmas: tuple[str, ...]) -> bool:
    if not pragmas:
        return False
    try:
        specs = [_npm_spec(p) for p in pragmas]
    except Exception:
        return False
    probes = tuple(semantic_version.Version(f"0.4.{p}") for p in range(0, 27))
    probes += tuple(semantic_version.Version(f"0.5.{p}") for p in range(0, 13))
    return any(all(spec.match(v) for spec in specs) for v in probes)


def pragma_allows_pre_0_5_13(pragmas: list[str]) -> bool:
    return _pragma_allows_pre_0_5_13_cached(tuple(pragmas or ()))


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=False) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as f:
        for line in f:
            if line.strip():
                out.append(json.loads(line))
    return out


def stable_rank(seed: int, *parts: str) -> str:
    payload = "|".join([str(seed), *parts]).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


def int_from_slot(x: Any) -> int:
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        return int(x, 0) if x.lower().startswith("0x") else int(x)
    raise TypeError(f"Unsupported slot value: {x!r}")
