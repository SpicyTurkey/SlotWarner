from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .utils import (
    ADDRESS_FILE_RE,
    declared_symbols,
    extract_imports,
    extract_pragmas,
    filename_suffix_without_address,
    normalize_source_unit_name,
    parse_filename,
    read_text,
    sha256_json,
)


NATSPEC_COLON_TAG_RE = re.compile(r"@(author|title|notice|dev|param|return|inheritdoc):(?=\s|$)", re.IGNORECASE)

def _comment_only_mask(source: str) -> str:
    """Return a same-length mask that preserves comments and blanks code/strings."""
    out = [" "] * len(source)
    i = 0
    state = "code"
    quote = ""
    while i < len(source):
        c = source[i]
        n = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if c == "/" and n == "/":
                out[i] = "/"; out[i + 1] = "/"; i += 2; state = "line"; continue
            if c == "/" and n == "*":
                out[i] = "/"; out[i + 1] = "*"; i += 2; state = "block"; continue
            if c in {'\"', "'"}:
                quote = c; i += 1; state = "string"; continue
            if c in {"\r", "\n"}: out[i] = c
            i += 1; continue
        if state == "line":
            out[i] = c
            if c in {"\r", "\n"}: state = "code"
            i += 1; continue
        if state == "block":
            out[i] = c
            if c == "*" and n == "/":
                out[i + 1] = "/"; i += 2; state = "code"; continue
            i += 1; continue
        # string
        if c == "\\":
            i += 2; continue
        if c == quote:
            i += 1; state = "code"; continue
        if c in {"\r", "\n"}: out[i] = c
        i += 1
    return "".join(out)

def _normalize_malformed_natspec_colons(source: str) -> tuple[str, int]:
    """Normalize only malformed recognized NatSpec tags inside comments.

    Example: ``/// @author: alice`` -> ``/// @author  alice``.
    The colon is replaced by a space, so source length and all AST offsets remain unchanged.
    ``@custom:...`` is intentionally untouched.
    """
    mask = _comment_only_mask(source)
    chars = list(source)
    count = 0
    for m in NATSPEC_COLON_TAG_RE.finditer(mask):
        colon = m.end() - 1
        if 0 <= colon < len(chars) and chars[colon] == ":":
            chars[colon] = " "
            count += 1
    return "".join(chars), count

IMPORT_STMT_RE = re.compile(
    r"import\s+(?:[^\"']*?from\s+)?(?P<q>[\"'])(?P<path>[^\"']+)(?P=q)\s*;",
    re.IGNORECASE,
)
SPDX_RE = re.compile(r"^[ \t]*//[ \t]*SPDX-License-Identifier:[^\r\n]*", re.MULTILINE | re.IGNORECASE)
ABI_V2_RE = re.compile(r"pragma\s+(?:experimental\s+ABIEncoderV2|abicoder\s+v[12])\s*;", re.IGNORECASE)
_CONTRACT_HEAD_RE = re.compile(
    r"\b(?:(?:abstract)\s+)?(?P<kind>contract|interface)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<tail>[^{};]*?)\{",
    re.IGNORECASE | re.DOTALL,
)
_SPDX_MARKER = "SPDX-License-Identifier:"


def _blank_preserve_newlines(text: str) -> str:
    return "".join(ch if ch in "\r\n" else " " for ch in text)


def _neutralize_duplicate_directives(source: str) -> tuple[str, list[str]]:
    transforms: list[str] = []
    # SPDX markers can appear in both // and /* */ comments in flattened artifacts.
    # Neutralize every marker after the first by changing only the colon; this is length preserving.
    positions = [m.start() for m in re.finditer(re.escape(_SPDX_MARKER), source, flags=re.IGNORECASE)]
    if len(positions) > 1:
        chars = list(source)
        for pos in positions[1:]:
            # Break the marker itself (length preserving) so solc no longer recognizes it.
            chars[pos] = "X"
            transforms.append("neutralized_duplicate_spdx")
        source = "".join(chars)

    chars = list(source)
    matches = list(ABI_V2_RE.finditer(source))
    for m in matches[1:]:
        replacement = _blank_preserve_newlines("".join(chars[m.start():m.end()]))
        chars[m.start():m.end()] = list(replacement)
        transforms.append("neutralized_duplicate_abi_coder")
    return "".join(chars), transforms


def _lexical_mask(source: str) -> str:
    chars = list(source)
    out = list(source)
    i = 0
    state = "code"
    quote = ""
    while i < len(chars):
        c = chars[i]
        n = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if c == "/" and n == "/":
                out[i] = out[i + 1] = " "; i += 2; state = "line"; continue
            if c == "/" and n == "*":
                out[i] = out[i + 1] = " "; i += 2; state = "block"; continue
            if c in {'\"', "'"}:
                quote = c; out[i] = " "; i += 1; state = "string"; continue
            i += 1; continue
        if state == "line":
            if c in {"\r", "\n"}: state = "code"
            else: out[i] = " "
            i += 1; continue
        if state == "block":
            if c == "*" and n == "/":
                out[i] = out[i + 1] = " "; i += 2; state = "code"; continue
            if c not in {"\r", "\n"}: out[i] = " "
            i += 1; continue
        if c == "\\":
            out[i] = " "
            if i + 1 < len(chars):
                if chars[i + 1] not in {"\r", "\n"}: out[i + 1] = " "
                i += 2
            else: i += 1
            continue
        if c == quote:
            out[i] = " "; state = "code"; i += 1; continue
        if c not in {"\r", "\n"}: out[i] = " "
        i += 1
    return "".join(out)


def _inheritance_names(tail: str) -> list[str]:
    m = re.search(r"\bis\s+(.+)$", tail, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return []
    text = m.group(1)
    names: list[str] = []
    depth = 0
    buf: list[str] = []
    parts: list[str] = []
    for c in text:
        if c == "(": depth += 1
        elif c == ")" and depth: depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(buf)); buf = []
        else:
            buf.append(c)
    if buf: parts.append("".join(buf))
    for part in parts:
        head = part.split("(", 1)[0].strip()
        ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", head)
        if ids: names.append(ids[-1])
    return names


def _reorder_flattened_base_declarations(source: str) -> tuple[str, int]:
    """Stable topological reorder of same-source top-level contract/interface declarations.

    This is compile-only normalization for verified flattened artifacts that place a derived
    declaration before a base declaration.  It never pulls declarations from another address.
    """
    mask = _lexical_mask(source)
    depth_at = [0] * (len(mask) + 1)
    depth = 0
    for i, c in enumerate(mask):
        depth_at[i] = depth
        if c == "{": depth += 1
        elif c == "}" and depth: depth -= 1
    depth_at[len(mask)] = depth
    blocks: list[dict[str, Any]] = []
    for m in _CONTRACT_HEAD_RE.finditer(mask):
        if depth_at[m.start()] != 0:
            continue
        open_pos = mask.find("{", m.start(), m.end() + 1)
        if open_pos < 0:
            continue
        d = 1; j = open_pos + 1
        while j < len(mask) and d:
            if mask[j] == "{": d += 1
            elif mask[j] == "}": d -= 1
            j += 1
        if d != 0:
            continue
        blocks.append({"start": m.start(), "end": j, "name": m.group("name"), "bases": _inheritance_names(m.group("tail") or "")})
    if len(blocks) < 2:
        return source, 0
    names = [b["name"] for b in blocks]
    if len(set(names)) != len(names):
        return source, 0
    pos = {name: i for i, name in enumerate(names)}
    violations = sum(1 for i, b in enumerate(blocks) for base in b["bases"] if base in pos and pos[base] > i)
    if not violations:
        return source, 0
    deps = {b["name"]: {x for x in b["bases"] if x in pos} for b in blocks}
    ordered_names: list[str] = []
    remaining = set(names)
    while remaining:
        ready = [n for n in names if n in remaining and not (deps[n] & remaining)]
        if not ready:
            return source, 0
        for n in ready:
            ordered_names.append(n); remaining.remove(n)
    if ordered_names == names:
        return source, 0
    leading = source[:blocks[0]["start"]]
    trailing = source[blocks[-1]["end"]:]
    segments: dict[str, str] = {}
    prev_end = blocks[0]["start"]
    for b in blocks:
        prefix = source[prev_end:b["start"]]
        segments[b["name"]] = prefix + source[b["start"]:b["end"]]
        prev_end = b["end"]
    return leading + "".join(segments[n] for n in ordered_names) + trailing, violations


def _resolve_import_key(importer_key: str, import_path: str) -> str:
    raw = import_path.replace("\\", "/")
    if raw.startswith("./") or raw.startswith("../"):
        base = posixpath.dirname(importer_key.replace("\\", "/"))
        return normalize_source_unit_name(posixpath.normpath(posixpath.join(base, raw)))
    return normalize_source_unit_name(raw)


def _neutralize_redundant_missing_imports(
    source: str,
    importer_key: str,
    resolvable_keys: set[str],
) -> tuple[str, list[str]]:
    """仅处理中和“源码本身已内嵌同名声明、且当前bundle无法解析”的残留 import。

    替换保持字节/字符长度与换行不变。若被导入文件还有其他必需符号，后续solc仍会报未声明，
    因此不会凭空伪造依赖。
    """
    symbols = declared_symbols(source)
    chars = list(source)
    transforms: list[str] = []
    for m in list(IMPORT_STMT_RE.finditer(source)):
        imp = str(m.group("path") or "")
        key = _resolve_import_key(importer_key, imp)
        if key in resolvable_keys:
            continue
        stem = Path(imp.replace("\\", "/")).stem
        if stem and stem in symbols:
            replacement = _blank_preserve_newlines(source[m.start():m.end()])
            chars[m.start():m.end()] = list(replacement)
            transforms.append(f"neutralized_embedded_import:{imp}")
    return "".join(chars), transforms


def _verified_source_tree_root(path: Path) -> Path | None:
    """Return a verified-source bundle root for Sourcify/Blockscout materializations.

    ProxyEx benchmark materialization preserves the provider tree under a directory named
    ``sourcify`` or ``blockscout``.  Unlike legacy Sanctuary artifacts, these are genuine
    multi-file source trees and must be compiled with their original relative source-unit
    names rather than the single-file sibling heuristic.
    """
    try:
        cur = path.resolve().parent
    except Exception:
        cur = path.parent
    for candidate in (cur, *cur.parents):
        if candidate.name.lower() in {"sourcify", "blockscout"}:
            return candidate
    return None



def _looks_like_verified_solidity_source(path: Path, raw: str, primary: Path) -> bool:
    if path == primary or path.suffix.lower() == ".sol":
        return True
    # Sourcify/Blockscout can preserve an extensionless source-unit name.  Provider
    # roots are source trees, but avoid ingesting metadata/binary noise blindly.
    head = raw[:65536]
    return bool(re.search(r"\b(?:pragma\s+solidity|contract\s+[A-Za-z_]|interface\s+[A-Za-z_]|library\s+[A-Za-z_]|import\s+[\\\"'])", head))


def _trailing_component_score(wanted: str, candidate: str) -> int:
    a=[x.lower() for x in normalize_source_unit_name(wanted).split('/') if x and x not in {'.','..'}]
    b=[x.lower() for x in normalize_source_unit_name(candidate).split('/') if x and x not in {'.','..'}]
    n=0
    while n < min(len(a),len(b)) and a[-1-n] == b[-1-n]:
        n += 1
    return n


def _add_verified_import_aliases(
    sources: dict[str, str], source_paths: dict[str, str], transformations: list[str]
) -> None:
    """Recover compiler-remapped source-unit aliases from a verified source tree.

    The provider tree may store ``lib/openzeppelin-contracts/contracts/...`` while
    Solidity imports ``@openzeppelin/contracts/...``.  Add an alias only when the
    missing import has a unique longest path-suffix match (>=2 components).  This
    is deterministic and content-preserving; it never fabricates a dependency.
    """
    for _ in range(8):
        added=0
        snapshot=list(sources.items())
        keys=list(sources)
        for importer_key, text in snapshot:
            # IMPORT_STMT_RE preserves ./ and ../, unlike the normalized helper.
            for m in IMPORT_STMT_RE.finditer(text):
                imp = m.group("path")
                wanted=_resolve_import_key(importer_key, imp)
                if wanted in sources:
                    continue
                scored=[]
                for cand in keys:
                    score=_trailing_component_score(wanted,cand)
                    if score >= 2:
                        scored.append((score,cand))
                if not scored:
                    continue
                best=max(x[0] for x in scored)
                winners=[cand for score,cand in scored if score==best]
                if len(winners) != 1:
                    continue
                cand=winners[0]
                sources[wanted]=sources[cand]
                source_paths[wanted]=source_paths.get(cand, source_paths.get(importer_key,''))
                transformations.append(f"verified_import_alias:{wanted}<-{cand}:suffix={best}")
                keys.append(wanted); added += 1
        if not added:
            break

def _build_verified_tree_bundle(path: Path, root: Path) -> "SourceBundle":
    sources: dict[str, str] = {}
    source_paths: dict[str, str] = {}
    transformations: list[str] = []

    primary_resolved = path.resolve() if path.exists() else path
    for source_file in sorted((x for x in root.rglob("*") if x.is_file()), key=lambda x: x.as_posix().lower()):
        try:
            if source_file.stat().st_size > 32 * 1024 * 1024:
                continue
            raw = read_text(source_file)
        except Exception:
            continue
        if not _looks_like_verified_solidity_source(source_file, raw, primary_resolved):
            continue
        try:
            key = normalize_source_unit_name(source_file.relative_to(root).as_posix())
        except Exception:
            continue
        # Keep the same conservative compile-only normalizations used by legacy bundles.
        norm, t = _neutralize_duplicate_directives(raw)
        norm, natspec_count = _normalize_malformed_natspec_colons(norm)
        if natspec_count:
            t.append(f"normalized_malformed_natspec_colons={natspec_count}")
        norm, reorder_count = _reorder_flattened_base_declarations(norm)
        if reorder_count:
            t.append(f"reordered_flattened_base_declarations={reorder_count}")
        sources[key] = norm
        source_paths[key] = str(source_file)
        transformations.extend(f"{key}:{x}" for x in t)

    try:
        primary_key = normalize_source_unit_name(path.resolve().relative_to(root.resolve()).as_posix())
    except Exception:
        primary_key = normalize_source_unit_name(path.name)
    if primary_key not in sources:
        # Never silently select another contract when the requested primary file was not loaded.
        raise FileNotFoundError(f"verified_tree_primary_missing:{path}")

    _add_verified_import_aliases(sources, source_paths, transformations)

    all_pragmas: list[str] = []
    for source in sources.values():
        all_pragmas.extend(extract_pragmas(source))
    all_pragmas = sorted(set(all_pragmas))
    bundle_hash = sha256_json({
        "primary": primary_key,
        "sources": {k: sources[k] for k in sorted(sources)},
    })
    transformations.append(f"verified_source_tree:{root.name}:sources={len(sources)}")
    return SourceBundle(
        primary_source_key=primary_key,
        sources=sources,
        bundle_sha256=bundle_hash,
        transformations=transformations,
        source_paths=source_paths,
        pragmas=all_pragmas,
    )


@dataclass(frozen=True)
class SourceBundle:
    primary_source_key: str
    sources: dict[str, str]
    bundle_sha256: str
    transformations: list[str]
    source_paths: dict[str, str]
    pragmas: list[str]


def build_source_bundle(path: Path) -> SourceBundle:
    verified_root = _verified_source_tree_root(path)
    if verified_root is not None:
        return _build_verified_tree_bundle(path, verified_root)

    primary_raw = read_text(path)
    primary_key = normalize_source_unit_name(path.name)
    address, _ = parse_filename(path)

    # 仅允许“同部署地址 sibling source”作为缺失依赖候选，禁止跨地址按同名文件猜依赖。
    sibling_by_basename: dict[str, list[tuple[Path, str]]] = {}
    if address:
        for sibling in path.parent.glob("*.sol"):
            saddr, _ = parse_filename(sibling)
            if saddr != address:
                continue
            try:
                text = read_text(sibling)
            except Exception:
                continue
            suffix = filename_suffix_without_address(sibling)
            sibling_by_basename.setdefault(Path(suffix).name.lower(), []).append((sibling, text))

    sources: dict[str, str] = {}
    source_paths: dict[str, str] = {}
    candidate_assigned_key: dict[str, str] = {}
    transformations: list[str] = []

    root_norm, t = _neutralize_duplicate_directives(primary_raw)
    root_norm, natspec_count = _normalize_malformed_natspec_colons(root_norm)
    if natspec_count:
        t.append(f"normalized_malformed_natspec_colons={natspec_count}")
    root_norm, reorder_count = _reorder_flattened_base_declarations(root_norm)
    if reorder_count:
        t.append(f"reordered_flattened_base_declarations={reorder_count}")
    transformations.extend(f"{primary_key}:{x}" for x in t)
    sources[primary_key] = root_norm
    source_paths[primary_key] = str(path)
    candidate_assigned_key[str(path.resolve())] = primary_key

    # 按需求递归恢复 import。每个物理 sibling 只允许成为一个 source unit，避免同一声明被不同alias重复编译。
    changed = True
    while changed:
        changed = False
        for importer_key, importer_source in list(sources.items()):
            for imp in extract_imports(importer_source):
                target_key = _resolve_import_key(importer_key, imp)
                if target_key in sources:
                    continue
                basename = Path(target_key).name.lower()
                candidates = sibling_by_basename.get(basename) or []
                if len(candidates) != 1:
                    continue
                candidate_path, candidate_text = candidates[0]
                physical = str(candidate_path.resolve())
                assigned = candidate_assigned_key.get(physical)
                if assigned is not None and assigned != target_key:
                    # 同一物理源码被两个不同source-unit路径请求，宁可保留一个未解析import，不复制声明。
                    transformations.append(f"alias_collision_refused:{imp}->{assigned}")
                    continue
                norm, t2 = _neutralize_duplicate_directives(candidate_text)
                norm, natspec_count = _normalize_malformed_natspec_colons(norm)
                if natspec_count:
                    t2.append(f"normalized_malformed_natspec_colons={natspec_count}")
                norm, reorder_count = _reorder_flattened_base_declarations(norm)
                if reorder_count:
                    t2.append(f"reordered_flattened_base_declarations={reorder_count}")
                sources[target_key] = norm
                source_paths[target_key] = str(candidate_path)
                candidate_assigned_key[physical] = target_key
                transformations.append(f"same_address_import_alias:{target_key}<-{candidate_path.name}")
                transformations.extend(f"{target_key}:{x}" for x in t2)
                changed = True

    # 对已经flatten到本源码、但残留且无法解析的 import 做保守中和。
    resolvable = set(sources)
    for key, source in list(sources.items()):
        norm, t3 = _neutralize_redundant_missing_imports(source, key, resolvable)
        if t3:
            sources[key] = norm
            transformations.extend(f"{key}:{x}" for x in t3)

    all_pragmas: list[str] = []
    for source in sources.values():
        all_pragmas.extend(extract_pragmas(source))
    # 多source unit中同一pragma重复不影响交集，去重便于记录。
    all_pragmas = sorted(set(all_pragmas))

    bundle_hash = sha256_json({"primary": primary_key, "sources": {k: sources[k] for k in sorted(sources)}})
    return SourceBundle(
        primary_source_key=primary_key,
        sources=sources,
        bundle_sha256=bundle_hash,
        transformations=transformations,
        source_paths=source_paths,
        pragmas=all_pragmas,
    )
