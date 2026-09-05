from __future__ import annotations

import csv
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

ADDRESS_FILE_RE = re.compile(r"^(?P<addr>[0-9a-fA-F]{40})_(?P<name>.+)\.sol$")


def read_jsonl(path: str | Path):
    with Path(path).open("r", encoding="utf-8-sig") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def append_jsonl(path: str | Path, row: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def write_csv(path: str | Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def source_contract_hint(path: str | Path) -> str:
    p = Path(str(path).replace("\\", "/"))
    m = ADDRESS_FILE_RE.match(p.name)
    if m:
        return m.group("name")
    return p.stem


def normalize_address(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text


def normalize_logic_source_map(row: dict[str, Any], logic_address: str) -> list[str]:
    target = normalize_address(logic_address)
    out: list[str] = []
    mapping = row.get("local_logic_sources") or {}
    if isinstance(mapping, dict):
        for key, values in mapping.items():
            if normalize_address(key) != target:
                continue
            if isinstance(values, (list, tuple)):
                out.extend(str(v) for v in values if v)
            elif values:
                out.append(str(values))
    # Stable de-duplication.
    return list(dict.fromkeys(out))


def parse_path_maps(items: list[str] | None) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"--path-map 必须使用 OLD=NEW：{item}")
        old, new = item.split("=", 1)
        old, new = old.strip(), new.strip()
        if not old:
            raise ValueError(f"--path-map OLD 不能为空：{item}")
        out.append((old, new))
    return out


def apply_path_maps(path: str, maps: list[tuple[str, str]]) -> str:
    value = str(path or "")
    for old, new in maps:
        if os.name == "nt":
            if value.lower().startswith(old.lower()):
                return new + value[len(old):]
        elif value.startswith(old):
            return new + value[len(old):]
    return value


def is_file(path: str | Path) -> bool:
    try:
        return Path(path).is_file()
    except Exception:
        return False
