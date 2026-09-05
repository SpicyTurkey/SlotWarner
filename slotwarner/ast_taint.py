from __future__ import annotations

import copy
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .bit_taint import (
    BitInfluence,
    add_sub_conservative,
    and_constant,
    bitwise_or,
    bitwise_xor,
    extract_bits,
    nonlinear_full_dependency,
    or_constant,
    range_mask,
    shift_left,
    shift_right,
    width_mask,
)
from .footprints import layout_footprints


GLOBAL_MEMBER_SOURCES = {
    ("msg", "sender"): ("MSG_SENDER", 160),
    ("msg", "value"): ("MSG_VALUE", 256),
    ("tx", "origin"): ("TX_ORIGIN", 160),
    ("block", "number"): ("BLOCK_NUMBER", 256),
    ("block", "timestamp"): ("BLOCK_TIMESTAMP", 256),
    ("block", "prevrandao"): ("BLOCK_PREVRANDAO", 256),
    ("block", "coinbase"): ("BLOCK_COINBASE", 160),
    ("block", "chainid"): ("BLOCK_CHAINID", 256),
}


def _walk(node: Any) -> Iterable[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for x in node:
            yield from _walk(x)


def _type_string(node: dict[str, Any] | None) -> str:
    if not isinstance(node, dict):
        return ""
    return str((node.get("typeDescriptions") or {}).get("typeString") or "")


def semantic_width_from_type(type_string: str, *, physical_fallback: int = 256) -> int:
    text = str(type_string or "").strip()
    low = text.lower()
    if low.startswith("bool"):
        return 1
    if low.startswith("address") or low.startswith("contract "):
        return 160
    m = re.search(r"\b(?:u?int)(\d+)?\b", low)
    if m:
        return int(m.group(1) or 256)
    m = re.search(r"\bbytes([1-9]|[12]\d|3[0-2])\b", low)
    if m:
        return int(m.group(1)) * 8
    if low.startswith("enum "):
        return max(1, min(int(physical_fallback), 8))
    return max(1, min(256, int(physical_fallback or 256)))


def _truncate(inf: BitInfluence, width: int) -> BitInfluence:
    width = max(1, int(width))
    keep = width_mask(width)
    return BitInfluence(
        width=width,
        mask=inf.mask & keep,
        source_masks={k: v & keep for k, v in inf.source_masks.items() if v & keep},
        notes=inf.notes,
    )


def _expand_control(inf: BitInfluence, width: int) -> BitInfluence:
    if not inf.mask:
        return BitInfluence(width=width)
    full = width_mask(width)
    return BitInfluence(
        width=width,
        mask=full,
        source_masks={k: full for k, v in inf.source_masks.items() if v},
        notes=inf.notes + ("control_dependency",),
    )


def _literal_int(node: Any) -> int | None:
    if not isinstance(node, dict) or node.get("nodeType") != "Literal":
        return None
    val = node.get("value")
    if val is None:
        val = node.get("hexValue")
    try:
        return int(str(val), 0)
    except Exception:
        try:
            return int(str(val))
        except Exception:
            return None


def _identifier_name(node: Any) -> str:
    if not isinstance(node, dict):
        return ""
    if node.get("nodeType") == "Identifier":
        return str(node.get("name") or "")
    if node.get("nodeType") == "MemberAccess":
        return str(node.get("memberName") or "")
    return ""


def _node_contains_global_caller(node: Any) -> bool:
    for n in _walk(node):
        if n.get("nodeType") != "MemberAccess":
            continue
        base = n.get("expression")
        if isinstance(base, dict) and base.get("nodeType") == "Identifier":
            key = (str(base.get("name") or ""), str(n.get("memberName") or ""))
            if key in {("msg", "sender"), ("tx", "origin")}:
                return True
    return False


def _state_decl_ids_in(node: Any, state_ids: set[int]) -> set[int]:
    out: set[int] = set()
    for n in _walk(node):
        ref = n.get("referencedDeclaration")
        if isinstance(ref, int) and ref in state_ids:
            out.add(ref)
    return out


@dataclass
class ContractModel:
    source_path: str
    contract_name: str
    compiler_version: str
    primary_source_key: str
    asts: dict[str, dict[str, Any]]
    program: Any
    contract: dict[str, Any]
    functions: dict[int, dict[str, Any]]
    modifiers: dict[int, dict[str, Any]]
    state_decls: dict[int, dict[str, Any]]
    footprints_by_path: dict[str, dict[str, Any]]
    paths_by_root_id: dict[int, list[str]]
    footprint_visibility: dict[str, str]
    footprint_decl_id: dict[str, int]
    footprint_type_string: dict[str, str]
    layout_record: dict[str, Any]

    @property
    def direct_paths(self) -> list[str]:
        return sorted(self.footprints_by_path)


@dataclass
class AnalysisResult:
    source_path: str
    contract_name: str
    compiler_version: str
    mode: str
    state_taint: dict[str, BitInfluence]
    write_effect_masks: dict[str, int]
    write_events: list[dict[str, Any]]
    state_edges: list[dict[str, Any]]
    roles: dict[str, set[str]]
    externally_seeded_functions: list[str]
    restricted_functions: list[str]
    activated_restricted_functions: list[str]
    selector_blocked_functions: list[str]
    iterations: int

    def state_rows(self, model: ContractModel) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for path in model.direct_paths:
            fp = model.footprints_by_path[path]
            pwidth = int(fp["width_bits"])
            inf = self.state_taint.get(path, BitInfluence(width=pwidth))
            write_mask = int(self.write_effect_masks.get(path, 0)) & width_mask(pwidth)
            sem_width = semantic_width_from_type(str(fp.get("type_label") or ""), physical_fallback=pwidth)
            sem_affected = min(inf.affected_bits, sem_width)
            rows.append({
                "path": path,
                "root_name": fp.get("root_name"),
                "visibility": model.footprint_visibility.get(path, "internal"),
                "type_label": fp.get("type_label"),
                "type_category": fp.get("type_category"),
                "slot": fp.get("slot"),
                "slot_bit_start": fp.get("slot_bit_start"),
                "slot_bit_end": fp.get("slot_bit_end"),
                "width_bits": pwidth,
                "tainted": bool(inf.mask),
                "taint_mask_hex": hex(inf.mask),
                "taint_intervals": [[a, b] for a, b in inf.intervals],
                "affected_bits": inf.affected_bits,
                "coverage_ratio": inf.affected_bits / pwidth if pwidth else 0.0,
                "physical_coverage_ratio": inf.affected_bits / pwidth if pwidth else 0.0,
                "semantic_width_bits": sem_width,
                "semantic_affected_bits": sem_affected,
                "semantic_coverage_ratio": sem_affected / sem_width if sem_width else 0.0,
                "coverage_basis": "physical_storage_width",
                "source_masks": {k: hex(v) for k, v in sorted(inf.source_masks.items())},
                "write_effect_mask_hex": hex(write_mask),
                "write_effect_intervals": [[a, b] for a, b in _mask_intervals(write_mask, pwidth)],
                "roles": sorted(self.roles.get(path, set())),
            })
        return rows


def _mask_intervals(mask: int, width: int) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    i = 0
    while i < width:
        if not ((mask >> i) & 1):
            i += 1
            continue
        a = i
        while i + 1 < width and ((mask >> (i + 1)) & 1):
            i += 1
        out.append((a, i))
        i += 1
    return out


def compile_contract_model(
    source_path: str,
    contract_hint: str = "",
    *,
    install_solc: bool = False,
    max_version_attempts: int = 8,
    max_direct_footprints: int = 50000,
    existing_layout: dict[str, Any] | None = None,
) -> ContractModel:
    # Heavy compiler dependencies are imported lazily so the pure taint engine and
    # its unit tests do not require a local solc/py-solc-x installation.
    from slotwarner_layout_validate.compiler import all_asts, compile_ast_selecting_version, compile_with_version
    from slotwarner_layout_validate.reconstruct import AstProgram, reconstruct_storage_layout
    from slotwarner_layout_validate.utils import extract_pragmas

    def select_contract(asts: dict[str, dict[str, Any]], primary_key: str, hint: str) -> tuple[str, str]:
        program0 = AstProgram(asts, primary_key)
        if hint:
            try:
                program0.target_contract(hint)
                return hint, "exact_hint"
            except Exception:
                pass
        primary_base = primary_key.replace("\\", "/").split("/")[-1]
        concrete: list[str] = []
        for (source_key, name), items in program0.contracts_by_source_name.items():
            if source_key.replace("\\", "/").split("/")[-1] != primary_base:
                continue
            for c in items:
                if str(c.get("contractKind") or "contract") == "contract" and c.get("abstract") is not True:
                    concrete.append(str(name))
        concrete = list(dict.fromkeys(concrete))
        if len(concrete) == 1:
            return concrete[0], "single_concrete_contract"
        raise RuntimeError(f"target_contract_not_resolved:hint={hint};candidates={concrete[:12]}")

    path = Path(source_path)
    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    # If an earlier validated layout already records the compiler version, prefer
    # that exact compiler for AST reconstruction.  Falling back to pragma-based
    # selection is retained for artifacts without compiler provenance or when
    # the exact-version attempt cannot be completed in the current environment.
    result = None
    preferred_raw = str((existing_layout or {}).get("compiler_version") or "")
    preferred_match = re.search(r"(?:^|[^0-9])(\d+\.\d+\.\d+)(?:[^0-9]|$)", preferred_raw)
    if preferred_match:
        preferred_version = preferred_match.group(1)
        exact = compile_with_version(path, preferred_version, phase="ast", install=install_solc)
        if exact.ok:
            result = exact

    if result is None:
        result = compile_ast_selecting_version(
            path,
            extract_pragmas(raw),
            install=install_solc,
            policy="lowest",
            max_attempts=max_version_attempts,
        )
    if not result.ok or not result.output:
        raise RuntimeError(f"compile_failed:{result.failure_category}:{result.error_text}")
    asts = all_asts(result.output)
    primary_key = result.primary_source_key or path.name
    program = AstProgram(asts, primary_key)
    hint = contract_hint or (existing_layout or {}).get("contract_name") or ""
    cname, _ = select_contract(asts, primary_key, str(hint))
    contract = program.target_contract(cname)

    if existing_layout and existing_layout.get("success") and existing_layout.get("footprints"):
        footprints = existing_layout["footprints"]
        layout_record = existing_layout
    else:
        source_texts = dict(result.source_bundle_texts or {})
        primary_text = source_texts.get(primary_key, raw)
        layout = reconstruct_storage_layout(asts, primary_key, cname, primary_text, source_texts)
        footprints = layout_footprints(layout, max_direct_footprints=max_direct_footprints)
        layout_record = {
            "success": True,
            "layout_mode": "validated_ast_v1_4",
            "compiler_version": result.compiler_version,
            "contract_name": cname,
            "footprints": footprints,
        }

    base_ids = [x for x in (contract.get("linearizedBaseContracts") or []) if isinstance(x, int)]
    if not base_ids and isinstance(contract.get("id"), int):
        base_ids = [contract["id"]]
    included_contracts = [program.contracts[x] for x in base_ids if x in program.contracts]
    functions: dict[int, dict[str, Any]] = {}
    modifiers: dict[int, dict[str, Any]] = {}
    state_decls: dict[int, dict[str, Any]] = {}
    for c in included_contracts:
        for node in c.get("nodes") or []:
            if not isinstance(node, dict) or not isinstance(node.get("id"), int):
                continue
            if node.get("nodeType") == "FunctionDefinition":
                functions[node["id"]] = node
            elif node.get("nodeType") == "ModifierDefinition":
                modifiers[node["id"]] = node
            elif node.get("nodeType") == "VariableDeclaration" and node.get("stateVariable") is True:
                if node.get("constant") is not True and str(node.get("mutability") or "") != "immutable":
                    state_decls[node["id"]] = node

    fps = {str(x["path"]): x for x in (footprints.get("direct") or []) if x.get("kind") == "direct"}
    paths_by_root: dict[int, list[str]] = {}
    vis: dict[str, str] = {}
    decl_ids: dict[str, int] = {}
    types: dict[str, str] = {}
    for pth, fp in fps.items():
        rid = fp.get("root_ast_id")
        if isinstance(rid, int):
            paths_by_root.setdefault(rid, []).append(pth)
            decl = state_decls.get(rid) or program.by_id.get(rid) or {}
            visibility = str(decl.get("visibility") or "internal")
            vis[pth] = visibility
            decl_ids[pth] = rid
            types[pth] = _type_string(decl) or str(fp.get("type_label") or "")
        else:
            vis[pth] = "internal"
            types[pth] = str(fp.get("type_label") or "")

    return ContractModel(
        source_path=str(path),
        contract_name=cname,
        compiler_version=str(result.compiler_version or ""),
        primary_source_key=primary_key,
        asts=asts,
        program=program,
        contract=contract,
        functions=functions,
        modifiers=modifiers,
        state_decls=state_decls,
        footprints_by_path=fps,
        paths_by_root_id=paths_by_root,
        footprint_visibility=vis,
        footprint_decl_id=decl_ids,
        footprint_type_string=types,
        layout_record=layout_record,
    )


class _FunctionExecutor:
    def __init__(
        self,
        model: ContractModel,
        state_taint: dict[str, BitInfluence],
        write_effect_masks: dict[str, int],
        write_events: list[dict[str, Any]],
        roles: dict[str, set[str]],
        *,
        allow_external_sources: bool,
        root_entry: str,
    ) -> None:
        self.m = model
        self.state_taint = state_taint
        self.write_effect_masks = write_effect_masks
        self.write_events = write_events
        self.roles = roles
        self.allow_external_sources = allow_external_sources
        self.root_entry = root_entry
        self._return_stack: list[list[BitInfluence]] = []

    def _state_path_from_lvalue(self, node: Any) -> str | None:
        if not isinstance(node, dict):
            return None
        nt = node.get("nodeType")
        if nt == "Identifier":
            ref = node.get("referencedDeclaration")
            if isinstance(ref, int) and ref in self.m.paths_by_root_id:
                paths = self.m.paths_by_root_id[ref]
                if len(paths) == 1:
                    return paths[0]
                name = str(node.get("name") or "")
                if name in self.m.footprints_by_path:
                    return name
                # Struct/fixed-array roots expand into multiple footprint paths.  Returning
                # the root name here lets MemberAccess/IndexAccess resolve a concrete leaf.
                if paths and name:
                    return name
            return None
        if nt == "MemberAccess":
            base_path = self._state_path_from_lvalue(node.get("expression"))
            if base_path:
                cand = f"{base_path}.{node.get('memberName') or ''}"
                if cand in self.m.footprints_by_path:
                    return cand
                # If base was a struct root represented by multiple leaves, match suffix.
                root_ref = self._root_state_ref(node)
                if root_ref in self.m.paths_by_root_id:
                    suffix = f".{node.get('memberName') or ''}"
                    matches = [p for p in self.m.paths_by_root_id[root_ref] if p.endswith(suffix)]
                    if len(matches) == 1:
                        return matches[0]
            return None
        if nt == "IndexAccess":
            base_path = self._state_path_from_lvalue(node.get("baseExpression"))
            idx = _literal_int(node.get("indexExpression"))
            if base_path and idx is not None:
                cand = f"{base_path}[{idx}]"
                if cand in self.m.footprints_by_path:
                    return cand
            # A dynamic index into a fixed-array root cannot be resolved to one leaf.
            # Return the aggregate root so the write handler can conservatively expand
            # the effect to all direct leaves instead of silently dropping the write.
            if base_path and self._aggregate_paths(base_path):
                return base_path
            return None
        return None

    def _direct_paths_from_access(self, node: Any) -> list[str]:
        """Resolve one or more direct storage leaves touched by an AST access.

        A dynamic index into a fixed array or a member access through such an index
        can denote multiple concrete leaves.  Returning all feasible leaves avoids both
        KeyError on aggregate roots and silent loss of those accesses.
        """
        if not isinstance(node, dict):
            return []
        nt = node.get("nodeType")
        if nt == "Identifier":
            ref = node.get("referencedDeclaration")
            if isinstance(ref, int):
                return list(self.m.paths_by_root_id.get(ref) or [])
            return []
        if nt == "MemberAccess":
            member = str(node.get("memberName") or "")
            base = node.get("expression")
            base_paths = self._direct_paths_from_access(base)
            if not base_paths:
                root_ref = self._root_state_ref(node)
                base_paths = list(self.m.paths_by_root_id.get(root_ref) or []) if isinstance(root_ref, int) else []
            if not member:
                return base_paths
            suffix = "." + member
            exact = [p for p in base_paths if p.endswith(suffix)]
            if exact:
                return sorted(dict.fromkeys(exact))
            # Scalar base paths may form a concrete member path directly.
            made = [f"{p}.{member}" for p in base_paths if f"{p}.{member}" in self.m.footprints_by_path]
            return sorted(dict.fromkeys(made))
        if nt == "IndexAccess":
            base = node.get("baseExpression")
            base_paths = self._direct_paths_from_access(base)
            if not base_paths:
                root_ref = self._root_state_ref(node)
                base_paths = list(self.m.paths_by_root_id.get(root_ref) or []) if isinstance(root_ref, int) else []
            idx = _literal_int(node.get("indexExpression"))
            if idx is None:
                return sorted(dict.fromkeys(base_paths))
            token = f"[{idx}]"
            exact = [p for p in base_paths if token in p]
            return sorted(dict.fromkeys(exact))
        return []

    def _read_paths(self, paths: list[str], width: int = 256) -> BitInfluence:
        paths = [p for p in dict.fromkeys(paths) if p in self.m.footprints_by_path]
        if not paths:
            return BitInfluence(width=width)
        if len(paths) == 1:
            return _truncate(self._read_state(paths[0]), width)
        out = BitInfluence(width=width)
        for p in paths:
            out = bitwise_or(out, _truncate(self._read_state(p), width))
        return BitInfluence(
            width=width, mask=out.mask, source_masks=dict(out.source_masks),
            notes=out.notes + ("multi_storage_access_conservative",),
        )

    def _read_path_or_aggregate(self, path: str, width: int = 256) -> BitInfluence:
        if path in self.m.footprints_by_path:
            return _truncate(self._read_state(path), width)
        leaves = self._aggregate_paths(path)
        if leaves:
            return self._read_paths(leaves, width)
        return BitInfluence(width=width)

    def _aggregate_paths(self, root: str) -> list[str]:
        """Return direct footprint leaves belonging to an aggregate storage root."""
        root = str(root or "")
        if not root:
            return []
        out = [
            p for p, fp in self.m.footprints_by_path.items()
            if str(fp.get("root_name") or "") == root
            or p.startswith(root + ".")
            or p.startswith(root + "[")
        ]
        return sorted(dict.fromkeys(out))

    def _read_aggregate(self, root: str, width: int = 256) -> BitInfluence:
        """Conservative whole-aggregate read used only when no concrete leaf is named.

        The current abstract domain is scalar, so a whole struct/fixed-array value does
        not have a member-wise tuple representation.  If any direct leaf is influenced,
        conservatively mark the aggregate expression as influenced while retaining the
        contributing source provenance.  Concrete MemberAccess/constant IndexAccess
        still use exact leaf-level masks.
        """
        leaves = self._aggregate_paths(root)
        if not leaves:
            return BitInfluence(width=width)
        source_masks: dict[str, int] = {}
        any_mask = False
        full = width_mask(width)
        for p in leaves:
            inf = self.state_taint.get(p, BitInfluence(width=int(self.m.footprints_by_path[p]["width_bits"])))
            if not inf.mask:
                continue
            any_mask = True
            for k, v in inf.source_masks.items():
                if v:
                    source_masks[k] = full
            source_masks[f"STATE:{p}"] = full
        if not any_mask:
            return BitInfluence(width=width)
        return BitInfluence(
            width=width,
            mask=full,
            source_masks=source_masks,
            notes=("aggregate_state_read_conservative",),
        )

    def _root_state_ref(self, node: Any) -> int | None:
        if not isinstance(node, dict):
            return None
        nt = node.get("nodeType")
        if nt == "Identifier":
            ref = node.get("referencedDeclaration")
            return ref if isinstance(ref, int) and ref in self.m.state_decls else None
        if nt == "MemberAccess":
            return self._root_state_ref(node.get("expression"))
        if nt == "IndexAccess":
            return self._root_state_ref(node.get("baseExpression"))
        return None

    def _read_state(self, path: str) -> BitInfluence:
        fp = self.m.footprints_by_path[path]
        pwidth = int(fp["width_bits"])
        stored = self.state_taint.get(path, BitInfluence(width=pwidth))
        tcat = str(fp.get("type_category") or "")
        tlabel = str(fp.get("type_label") or "")
        sem = semantic_width_from_type(tlabel, physical_fallback=pwidth)
        if tcat == "bool" or tlabel.strip() == "bool":
            # Typed Solidity bool read collapses any possibly influential physical bool bit
            # to the one-bit truth value. Raw SLOAD/SSTORE semantics are out of scope here.
            if not stored.mask:
                return BitInfluence(width=1)
            src = {k: 1 for k, v in stored.source_masks.items() if v}
            src[f"STATE:{path}"] = 1
            return BitInfluence(width=1, mask=1, source_masks=src, notes=("typed_bool_read",))
        out = _truncate(stored, sem)
        if out.mask:
            src = dict(out.source_masks)
            src[f"STATE:{path}"] = out.mask
            out = BitInfluence(width=out.width, mask=out.mask, source_masks=src, notes=out.notes + ("state_read",))
        return out

    def _expr_width(self, node: Any) -> int:
        if not isinstance(node, dict):
            return 256
        return semantic_width_from_type(_type_string(node), physical_fallback=256)

    def eval_expr(self, node: Any, env: dict[int, BitInfluence], pc: BitInfluence, call_stack: tuple[int, ...]) -> BitInfluence:
        if not isinstance(node, dict):
            return BitInfluence(width=256)
        nt = node.get("nodeType")
        width = self._expr_width(node)
        if nt == "Literal":
            return BitInfluence(width=width)
        if nt == "Identifier":
            name = str(node.get("name") or "")
            if name == "now" and self.allow_external_sources:
                return BitInfluence.source("NOW", 0, 255, width=256)
            ref = node.get("referencedDeclaration")
            if isinstance(ref, int):
                if ref in env:
                    return _truncate(env[ref], width)
                paths = self.m.paths_by_root_id.get(ref) or []
                if len(paths) == 1:
                    return self._read_state(paths[0])
                if len(paths) > 1:
                    return _truncate(self._read_aggregate(str(node.get("name") or ""), width), width)
            return BitInfluence(width=width)
        if nt == "MemberAccess":
            base = node.get("expression")
            if isinstance(base, dict) and base.get("nodeType") == "Identifier" and self.allow_external_sources:
                key = (str(base.get("name") or ""), str(node.get("memberName") or ""))
                spec = GLOBAL_MEMBER_SOURCES.get(key)
                if spec:
                    nm, w = spec
                    return BitInfluence.source(nm, 0, w - 1, width=w)
            paths = self._direct_paths_from_access(node)
            if paths:
                return self._read_paths(paths, width)
            path = self._state_path_from_lvalue(node)
            if path:
                return self._read_path_or_aggregate(path, width)
            return _truncate(self.eval_expr(base, env, pc, call_stack), width)
        if nt == "IndexAccess":
            paths = self._direct_paths_from_access(node)
            if paths:
                return self._read_paths(paths, width)
            path = self._state_path_from_lvalue(node)
            if path:
                return self._read_path_or_aggregate(path, width)
            base_inf = self.eval_expr(node.get("baseExpression"), env, pc, call_stack)
            idx_inf = self.eval_expr(node.get("indexExpression"), env, pc, call_stack)
            if base_inf.mask or idx_inf.mask:
                return nonlinear_full_dependency(base_inf, idx_inf, width=width, label="index_access")
            return BitInfluence(width=width)
        if nt == "TupleExpression":
            inf = BitInfluence(width=width)
            for c in node.get("components") or []:
                inf = bitwise_or(_truncate(inf, width), _truncate(self.eval_expr(c, env, pc, call_stack), width))
            return inf
        if nt == "Conditional":
            c = self.eval_expr(node.get("condition"), env, pc, call_stack)
            a = self.eval_expr(node.get("trueExpression"), env, pc, call_stack)
            b = self.eval_expr(node.get("falseExpression"), env, pc, call_stack)
            merged = bitwise_or(_truncate(a, width), _truncate(b, width))
            return bitwise_or(merged, _expand_control(c, width))
        if nt == "UnaryOperation":
            op = str(node.get("operator") or "")
            sub = self.eval_expr(node.get("subExpression"), env, pc, call_stack)
            if op == "!":
                if not sub.mask:
                    return BitInfluence(width=1)
                return BitInfluence(width=1, mask=1, source_masks={k: 1 for k, v in sub.source_masks.items() if v}, notes=("logical_not",))
            if op == "~":
                return _truncate(sub, width)
            if op in {"-", "+"}:
                return nonlinear_full_dependency(sub, width=width, label=f"unary_{op}") if sub.mask else BitInfluence(width=width)
            return _truncate(sub, width)
        if nt == "BinaryOperation":
            op = str(node.get("operator") or "")
            lnode, rnode = node.get("leftExpression"), node.get("rightExpression")
            l = self.eval_expr(lnode, env, pc, call_stack)
            r = self.eval_expr(rnode, env, pc, call_stack)
            if op == "&":
                rc = _literal_int(rnode); lc = _literal_int(lnode)
                if rc is not None:
                    return _truncate(and_constant(_truncate(l, width), rc), width)
                if lc is not None:
                    return _truncate(and_constant(_truncate(r, width), lc), width)
                return _truncate(bitwise_or(l, r), width)
            if op == "|":
                rc = _literal_int(rnode); lc = _literal_int(lnode)
                if rc is not None:
                    return _truncate(or_constant(_truncate(l, width), rc), width)
                if lc is not None:
                    return _truncate(or_constant(_truncate(r, width), lc), width)
                return _truncate(bitwise_or(l, r), width)
            if op == "^":
                return _truncate(bitwise_xor(l, r), width)
            if op in {"<<", ">>"}:
                amt = _literal_int(rnode)
                if amt is not None:
                    return _truncate(shift_left(l, amt) if op == "<<" else shift_right(l, amt), width)
                return nonlinear_full_dependency(l, r, width=width, label=f"dynamic_shift_{op}")
            if op in {"+", "-"}:
                return _truncate(add_sub_conservative(l, r, op="add" if op == "+" else "sub"), width)
            if op in {"*", "/", "%", "**"}:
                return nonlinear_full_dependency(l, r, width=width, label=f"binary_{op}")
            if op in {"==", "!=", "<", ">", "<=", ">=", "&&", "||"}:
                if not (l.mask or r.mask):
                    return BitInfluence(width=1)
                src = {}
                for inf in (l, r):
                    for k, v in inf.source_masks.items():
                        if v:
                            src[k] = 1
                return BitInfluence(width=1, mask=1, source_masks=src, notes=(f"predicate_{op}",))
            return nonlinear_full_dependency(l, r, width=width, label=f"binary_{op}")
        if nt == "FunctionCall":
            expr = node.get("expression")
            args = [self.eval_expr(x, env, pc, call_stack) for x in (node.get("arguments") or [])]
            name = _identifier_name(expr)
            # Elementary casts and user-defined value-type casts truncate to destination width.
            kind = str(node.get("kind") or "")
            if kind == "typeConversion" or (isinstance(expr, dict) and expr.get("nodeType") == "ElementaryTypeNameExpression"):
                return _truncate(args[0] if args else BitInfluence(width=width), width)
            ref = None
            if isinstance(expr, dict):
                ref = expr.get("referencedDeclaration")
            if isinstance(ref, int) and ref in self.m.functions and ref not in call_stack:
                returns = self.execute_function(self.m.functions[ref], args, pc, call_stack + (ref,))
                if returns:
                    return _truncate(returns[0], width)
                return BitInfluence(width=width)
            if name in {"keccak256", "sha256", "ripemd160", "ecrecover"}:
                return nonlinear_full_dependency(*args, width=width, label=name)
            if name in {"require", "assert", "revert"}:
                return BitInfluence(width=width)
            if any(x.mask for x in args):
                return nonlinear_full_dependency(*args, width=width, label="unknown_call")
            return BitInfluence(width=width)
        if nt == "FunctionCallOptions":
            return self.eval_expr(node.get("expression"), env, pc, call_stack)
        if nt == "Assignment":
            # Assignment used as expression; statement handler performs state/local update.
            return self.eval_expr(node.get("rightHandSide"), env, pc, call_stack)
        return BitInfluence(width=width)

    def _write_state(self, path: str, rhs: BitInfluence, pc: BitInfluence, *, function: dict[str, Any], operator: str) -> None:
        if path not in self.m.footprints_by_path:
            leaves = self._aggregate_paths(path)
            if not leaves:
                return
            # Whole-struct/fixed-array assignment.  The scalar abstract domain cannot
            # split an aggregate RHS member-by-member, so preserve soundness by applying
            # the RHS provenance to every concrete direct leaf.  This is deliberately
            # marked as conservative in the event stream so it can be separated later.
            for leaf in leaves:
                fp_leaf = self.m.footprints_by_path[leaf]
                lw = int(fp_leaf["width_bits"])
                lsem = semantic_width_from_type(str(fp_leaf.get("type_label") or ""), physical_fallback=lw)
                if rhs.mask:
                    full = width_mask(lsem)
                    leaf_rhs = BitInfluence(
                        width=lsem,
                        mask=full,
                        source_masks={k: full for k, v in rhs.source_masks.items() if v},
                        notes=rhs.notes + ("aggregate_write_conservative",),
                    )
                else:
                    leaf_rhs = BitInfluence(width=lsem, notes=("aggregate_write_conservative",))
                self._write_state(
                    leaf,
                    leaf_rhs,
                    pc,
                    function=function,
                    operator=f"{operator}[aggregate]",
                )
            return
        fp = self.m.footprints_by_path[path]
        pwidth = int(fp["width_bits"])
        tcat = str(fp.get("type_category") or "")
        tlabel = str(fp.get("type_label") or "")
        sem = semantic_width_from_type(tlabel, physical_fallback=pwidth)
        rhs2 = _truncate(rhs, sem)
        control_dependent = bool(pc.mask)
        if control_dependent:
            rhs2 = bitwise_or(rhs2, _expand_control(pc, sem))
        if tcat == "bool" or tlabel.strip() == "bool":
            # Typed bool assignment stores a canonical 0/1 value: only bit0 carries data influence.
            phys = BitInfluence(
                width=pwidth,
                mask=1 if rhs2.mask else 0,
                source_masks={k: 1 for k, v in rhs2.source_masks.items() if v},
                notes=rhs2.notes + ("typed_bool_write",),
            )
        else:
            phys = BitInfluence(
                width=pwidth,
                mask=rhs2.mask & width_mask(pwidth),
                source_masks={k: v & width_mask(pwidth) for k, v in rhs2.source_masks.items() if v & width_mask(pwidth)},
                notes=rhs2.notes,
            )
        old = self.state_taint.get(path, BitInfluence(width=pwidth))
        # May-analysis across paths/transactions: union, never let an unrelated constant write erase a proven influence.
        merged = bitwise_or(old, phys)
        self.state_taint[path] = merged
        self.write_effect_masks[path] = self.write_effect_masks.get(path, 0) | width_mask(pwidth)
        state_deps = sorted(k[6:] for k in phys.source_masks if k.startswith("STATE:"))
        event = {
            "entry_function": self.root_entry,
            "function": str(function.get("name") or function.get("kind") or ""),
            "function_visibility": str(function.get("visibility") or ""),
            "target_path": path,
            "target_visibility": self.m.footprint_visibility.get(path, "internal"),
            "operator": operator,
            "write_effect_mask_hex": hex(width_mask(pwidth)),
            "taint_mask_hex": hex(phys.mask),
            "taint_intervals": [[a, b] for a, b in phys.intervals],
            "affected_bits": phys.affected_bits,
            "source_masks": {k: hex(v) for k, v in sorted(phys.source_masks.items())},
            "state_dependencies": state_deps,
            "control_dependent": control_dependent,
        }
        self.write_events.append(event)

    def _compound_value(self, old: BitInfluence, rhs: BitInfluence, op: str, rhs_node: Any) -> BitInfluence:
        if op in {"+=", "-="}:
            return add_sub_conservative(old, rhs, op="add" if op == "+=" else "sub")
        if op == "&=":
            c = _literal_int(rhs_node)
            return and_constant(old, c) if c is not None else bitwise_or(old, rhs)
        if op == "|=":
            c = _literal_int(rhs_node)
            return or_constant(old, c) if c is not None else bitwise_or(old, rhs)
        if op == "^=":
            c = _literal_int(rhs_node)
            return old if c is not None else bitwise_xor(old, rhs)
        if op in {"<<=", ">>="}:
            amt = _literal_int(rhs_node)
            return (shift_left(old, amt) if op == "<<=" else shift_right(old, amt)) if amt is not None else nonlinear_full_dependency(old, rhs, width=old.width, label=op)
        return nonlinear_full_dependency(old, rhs, width=max(old.width, rhs.width), label=op)

    def _handle_assignment(self, expr: dict[str, Any], env: dict[int, BitInfluence], pc: BitInfluence, function: dict[str, Any], call_stack: tuple[int, ...]) -> None:
        lhs, rhs_node = expr.get("leftHandSide"), expr.get("rightHandSide")
        op = str(expr.get("operator") or "=")
        rhs = self.eval_expr(rhs_node, env, pc, call_stack)
        paths = self._direct_paths_from_access(lhs)
        if paths:
            if op != "=":
                old_inf = self._read_paths(paths, max(self._expr_width(lhs), 1))
                rhs = self._compound_value(old_inf, rhs, op, rhs_node)
            for path in paths:
                self._write_state(
                    path, rhs, pc, function=function,
                    operator=(op if len(paths) == 1 else f"{op}[aggregate_multi_access]"),
                )
            return
        path = self._state_path_from_lvalue(lhs)
        if path:
            if op != "=":
                rhs = self._compound_value(self._read_path_or_aggregate(path, self._expr_width(lhs)), rhs, op, rhs_node)
            self._write_state(path, rhs, pc, function=function, operator=op)
            return
        if isinstance(lhs, dict) and lhs.get("nodeType") == "Identifier":
            ref = lhs.get("referencedDeclaration")
            if isinstance(ref, int):
                if op != "=" and ref in env:
                    rhs = self._compound_value(env[ref], rhs, op, rhs_node)
                env[ref] = _truncate(rhs, self._expr_width(lhs))

    def execute_statement(self, st: Any, env: dict[int, BitInfluence], pc: BitInfluence, function: dict[str, Any], call_stack: tuple[int, ...]) -> None:
        if not isinstance(st, dict):
            return
        nt = st.get("nodeType")
        if nt == "Block" or nt == "UncheckedBlock":
            for x in st.get("statements") or []:
                self.execute_statement(x, env, pc, function, call_stack)
            return
        if nt == "VariableDeclarationStatement":
            init = self.eval_expr(st.get("initialValue"), env, pc, call_stack)
            decls = [x for x in (st.get("declarations") or []) if isinstance(x, dict)]
            if len(decls) == 1 and isinstance(decls[0].get("id"), int):
                env[decls[0]["id"]] = _truncate(init, semantic_width_from_type(_type_string(decls[0]), physical_fallback=256))
            else:
                for d in decls:
                    if isinstance(d.get("id"), int):
                        env[d["id"]] = _truncate(init, semantic_width_from_type(_type_string(d), physical_fallback=256))
            return
        if nt == "ExpressionStatement":
            e = st.get("expression")
            if isinstance(e, dict) and e.get("nodeType") == "Assignment":
                self._handle_assignment(e, env, pc, function, call_stack)
                return
            if isinstance(e, dict) and e.get("nodeType") == "UnaryOperation" and str(e.get("operator") or "") in {"++", "--"}:
                sub = e.get("subExpression")
                paths = self._direct_paths_from_access(sub)
                if paths:
                    old = self._read_paths(paths, self._expr_width(sub))
                    one = BitInfluence(width=old.width)
                    rhs = add_sub_conservative(old, one, op="add" if e.get("operator") == "++" else "sub")
                    for path in paths:
                        self._write_state(path, rhs, pc, function=function, operator=str(e.get("operator")) + ("[aggregate_multi_access]" if len(paths) > 1 else ""))
                    return
                path = self._state_path_from_lvalue(sub)
                if path:
                    old = self._read_path_or_aggregate(path, self._expr_width(sub))
                    one = BitInfluence(width=old.width)
                    rhs = add_sub_conservative(old, one, op="add" if e.get("operator") == "++" else "sub")
                    self._write_state(path, rhs, pc, function=function, operator=str(e.get("operator")))
                    return
            self.eval_expr(e, env, pc, call_stack)
            return
        if nt == "IfStatement":
            cond = self.eval_expr(st.get("condition"), env, pc, call_stack)
            branch_pc = bitwise_or(_truncate(pc, 1), _truncate(cond, 1)) if (pc.mask or cond.mask) else BitInfluence(width=1)
            env_t = dict(env); env_f = dict(env)
            self.execute_statement(st.get("trueBody"), env_t, branch_pc, function, call_stack)
            self.execute_statement(st.get("falseBody"), env_f, branch_pc, function, call_stack)
            # May-merge local environments.
            for k in set(env_t) | set(env_f):
                a = env_t.get(k, BitInfluence(width=256)); b = env_f.get(k, BitInfluence(width=256))
                env[k] = bitwise_or(a, b)
            return
        if nt in {"ForStatement", "WhileStatement", "DoWhileStatement"}:
            if nt == "ForStatement":
                self.execute_statement(st.get("initializationExpression"), env, pc, function, call_stack)
            cond = self.eval_expr(st.get("condition"), env, pc, call_stack)
            loop_pc = bitwise_or(_truncate(pc, 1), _truncate(cond, 1)) if (pc.mask or cond.mask) else BitInfluence(width=1)
            self.execute_statement(st.get("body"), env, loop_pc, function, call_stack)
            if nt == "ForStatement":
                loop = st.get("loopExpression")
                if isinstance(loop, dict) and loop.get("nodeType") == "ExpressionStatement":
                    self.execute_statement(loop, env, loop_pc, function, call_stack)
                else:
                    self.eval_expr(loop, env, loop_pc, call_stack)
            return
        if nt == "Return":
            inf = self.eval_expr(st.get("expression"), env, pc, call_stack)
            if self._return_stack:
                self._return_stack[-1].append(inf)
            return
        if nt == "TryStatement":
            for clause in st.get("clauses") or []:
                self.execute_statement((clause or {}).get("block"), dict(env), pc, function, call_stack)
            return
        # Generic fallback: evaluate expression-bearing children conservatively.
        for child in st.values():
            if isinstance(child, dict) and child.get("nodeType") in {"Assignment", "FunctionCall", "BinaryOperation", "UnaryOperation"}:
                self.eval_expr(child, env, pc, call_stack)

    @staticmethod
    def _replace_modifier_placeholders(node: Any, continuation: Any) -> Any:
        """Return a deep AST copy with Solidity modifier placeholders replaced.

        Solidity modifiers wrap the next modifier / function body at each `_`
        (PlaceholderStatement).  Reconstructing that wrapper is necessary for
        write-effect analysis because security-critical state writes frequently
        live inside modifiers such as OpenZeppelin's `initializer`.
        """
        if isinstance(node, dict):
            if node.get("nodeType") == "PlaceholderStatement":
                return copy.deepcopy(continuation)
            return {
                k: _FunctionExecutor._replace_modifier_placeholders(v, continuation)
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [
                _FunctionExecutor._replace_modifier_placeholders(v, continuation)
                for v in node
            ]
        return copy.deepcopy(node)

    def _wrap_function_with_modifiers(
        self,
        fn: dict[str, Any],
        env: dict[int, BitInfluence],
        pc: BitInfluence,
        call_stack: tuple[int, ...],
    ) -> Any:
        """Build the effective function body after applying resolved modifiers.

        Modifier invocation arguments are evaluated in the function-parameter
        environment and bound to the modifier declaration parameter ids.  The
        modifiers are then wrapped right-to-left so runtime execution remains
        left-to-right, matching Solidity semantics.

        If a modifier cannot be resolved from the compiled inheritance closure,
        we conservatively leave that invocation out rather than inventing its
        behavior.  The caller/function body is still analyzed as before.
        """
        wrapped: Any = copy.deepcopy(fn.get("body"))
        invocations = [x for x in (fn.get("modifiers") or []) if isinstance(x, dict)]

        # Bind modifier parameters before wrapping. Invocation expressions are
        # written in the function declaration scope and may reference function
        # parameters, state, msg.*, etc.
        resolved: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for inv in invocations:
            name = inv.get("modifierName")
            ref = name.get("referencedDeclaration") if isinstance(name, dict) else None
            if not isinstance(ref, int) or ref not in self.m.modifiers:
                continue
            mod = self.m.modifiers[ref]
            mparams = ((mod.get("parameters") or {}).get("parameters") or [])
            iargs = inv.get("arguments") or []
            for idx, mp in enumerate(mparams):
                if not isinstance(mp, dict) or not isinstance(mp.get("id"), int):
                    continue
                width = semantic_width_from_type(_type_string(mp), physical_fallback=256)
                if idx < len(iargs):
                    val = self.eval_expr(iargs[idx], env, pc, call_stack)
                    env[mp["id"]] = _truncate(val, width)
                else:
                    env[mp["id"]] = BitInfluence(width=width)
            resolved.append((inv, mod))

        for _inv, mod in reversed(resolved):
            body = mod.get("body")
            if isinstance(body, dict):
                wrapped = self._replace_modifier_placeholders(body, wrapped)
        return wrapped

    def execute_function(self, fn: dict[str, Any], args: list[BitInfluence], pc: BitInfluence, call_stack: tuple[int, ...]) -> list[BitInfluence]:
        env: dict[int, BitInfluence] = {}
        params = ((fn.get("parameters") or {}).get("parameters") or [])
        for i, p in enumerate(params):
            if not isinstance(p, dict) or not isinstance(p.get("id"), int):
                continue
            w = semantic_width_from_type(_type_string(p), physical_fallback=256)
            env[p["id"]] = _truncate(args[i], w) if i < len(args) else BitInfluence(width=w)
        self._return_stack.append([])
        effective_body = self._wrap_function_with_modifiers(fn, env, pc, call_stack)
        self.execute_statement(effective_body, env, pc, fn, call_stack)
        returns = self._return_stack.pop()
        return returns


def _function_guard_state_ids(model: ContractModel, fn: dict[str, Any]) -> set[int]:
    state_ids = set(model.state_decls)
    out: set[int] = set()
    nodes: list[Any] = [fn.get("body")]
    for inv in fn.get("modifiers") or []:
        if not isinstance(inv, dict):
            continue
        name = inv.get("modifierName")
        ref = name.get("referencedDeclaration") if isinstance(name, dict) else None
        if isinstance(ref, int) and ref in model.modifiers:
            nodes.append(model.modifiers[ref].get("body"))
    for root in nodes:
        for n in _walk(root):
            if n.get("nodeType") != "FunctionCall":
                continue
            name = _identifier_name(n.get("expression"))
            if name not in {"require", "assert"}:
                continue
            args = n.get("arguments") or []
            if not args:
                continue
            cond = args[0]
            if _node_contains_global_caller(cond):
                out.update(_state_decl_ids_in(cond, state_ids))
    return out


def _function_has_proven_caller_guard(model: ContractModel, fn: dict[str, Any]) -> bool:
    return bool(_function_guard_state_ids(model, fn))

def _infer_roles(model: ContractModel) -> dict[str, set[str]]:
    roles: dict[str, set[str]] = {p: set() for p in model.direct_paths}
    state_ids = set(model.state_decls)
    path_by_id = {rid: paths[0] for rid, paths in model.paths_by_root_id.items() if len(paths) == 1}
    for fn in model.functions.values():
        for n in _walk(fn.get("body")):
            nt = n.get("nodeType")
            if nt == "FunctionCall":
                name = _identifier_name(n.get("expression"))
                if name in {"require", "assert"}:
                    args = n.get("arguments") or []
                    if args:
                        refs = _state_decl_ids_in(args[0], state_ids)
                        caller = _node_contains_global_caller(args[0])
                        for rid in refs:
                            p = path_by_id.get(rid)
                            if p:
                                roles[p].add("auth_guard" if caller else "condition_guard")
            if nt == "IfStatement":
                for rid in _state_decl_ids_in(n.get("condition"), state_ids):
                    p = path_by_id.get(rid)
                    if p:
                        roles[p].add("condition_guard")
            if nt == "MemberAccess" and str(n.get("memberName") or "") in {"delegatecall", "call", "staticcall"}:
                for rid in _state_decl_ids_in(n.get("expression"), state_ids):
                    p = path_by_id.get(rid)
                    if p:
                        roles[p].add("external_call_target")
    return roles


def analyze_contract_taint(
    model: ContractModel,
    *,
    initial_state_masks: dict[str, BitInfluence] | None = None,
    seed_external_inputs: bool = True,
    max_iterations: int = 8,
    excluded_external_selectors: set[str] | None = None,
    include_guarded_entries: bool = False,
) -> AnalysisResult:
    state: dict[str, BitInfluence] = {}
    for path in model.direct_paths:
        w = int(model.footprints_by_path[path]["width_bits"])
        seed = (initial_state_masks or {}).get(path)
        state[path] = BitInfluence(width=w, mask=seed.mask, source_masks=dict(seed.source_masks), notes=seed.notes) if seed else BitInfluence(width=w)
    write_effect: dict[str, int] = {p: 0 for p in model.direct_paths}
    events: list[dict[str, Any]] = []
    roles = _infer_roles(model)
    external_fns: list[str] = []
    restricted_fns: list[str] = []
    entry_fns: list[dict[str, Any]] = []
    guarded_fns: list[tuple[dict[str, Any], set[int]]] = []
    activated_restricted: set[str] = set()
    blocked_selectors = {str(x).lower().removeprefix("0x") for x in (excluded_external_selectors or set()) if str(x)}
    selector_blocked_functions: list[str] = []
    for fn in model.functions.values():
        if fn.get("implemented") is False or not isinstance(fn.get("body"), dict):
            continue
        if str(fn.get("kind") or "function") in {"constructor"}:
            continue
        vis = str(fn.get("visibility") or "")
        if vis not in {"public", "external"}:
            continue
        name = str(fn.get("name") or fn.get("kind") or f"fn_{fn.get('id')}")
        selector = str(fn.get("functionSelector") or "").lower().removeprefix("0x")
        if selector and selector in blocked_selectors:
            selector_blocked_functions.append(name)
            continue
        guard_ids = _function_guard_state_ids(model, fn)
        if guard_ids:
            restricted_fns.append(name)
            guarded_fns.append((fn, guard_ids))
            # For attacker-reachability analysis, caller/state guarded entries are
            # excluded until the guard state itself becomes influenced.  For the
            # operational collision layer, a privileged but executable entry still
            # represents a real storage write and is therefore analyzed directly.
            if not include_guarded_entries:
                continue
        external_fns.append(name)
        entry_fns.append(fn)

    iteration = 0
    last_signature = None
    while iteration < max(1, int(max_iterations)):
        iteration += 1
        before_events = len(events)
        active_fns = list(entry_fns)
        # A proven caller/state guard is initially treated as restrictive.  If one of the
        # state variables participating in that guard has itself become tainted, the guard
        # may no longer be stable, so the guarded entry is conservatively activated.
        if not include_guarded_entries:
            for gfn, gids in guarded_fns:
                guard_tainted = False
                for gid in gids:
                    for pth in model.paths_by_root_id.get(gid) or []:
                        if state.get(pth, BitInfluence(width=int(model.footprints_by_path[pth]["width_bits"]))).mask:
                            guard_tainted = True
                            break
                    if guard_tainted:
                        break
                if guard_tainted:
                    active_fns.append(gfn)
                    activated_restricted.add(str(gfn.get("name") or gfn.get("kind") or f"fn_{gfn.get('id')}"))
        for fn in active_fns:
            fname = str(fn.get("name") or fn.get("kind") or f"fn_{fn.get('id')}")
            params = ((fn.get("parameters") or {}).get("parameters") or [])
            args: list[BitInfluence] = []
            guard_enabled = fname in activated_restricted
            seed_call_inputs = bool(seed_external_inputs or guard_enabled)
            for p in params:
                w = semantic_width_from_type(_type_string(p), physical_fallback=256)
                if seed_call_inputs:
                    pname = str(p.get("name") or f"arg{len(args)}")
                    prefix = "PARAM" if seed_external_inputs else "GUARD_ENABLED_PARAM"
                    args.append(BitInfluence.source(f"{prefix}:{fname}:{pname}", 0, w - 1, width=w))
                else:
                    args.append(BitInfluence(width=w))
            ex = _FunctionExecutor(
                model, state, write_effect, events, roles,
                allow_external_sources=seed_call_inputs,
                root_entry=fname,
            )
            ex.execute_function(fn, args, BitInfluence(width=1), (int(fn.get("id") or -1),))
        sig = tuple((p, state[p].mask, tuple(sorted(state[p].source_masks.items()))) for p in sorted(state))
        if sig == last_signature:
            break
        last_signature = sig
        if len(events) == before_events and iteration > 1:
            break

    # De-duplicate write events accumulated across fixed-point iterations.
    deduped_events: list[dict[str, Any]] = []
    event_seen: set[tuple[Any, ...]] = set()
    for ev in events:
        key = (
            ev.get("entry_function"), ev.get("function"), ev.get("target_path"), ev.get("operator"),
            ev.get("taint_mask_hex"), tuple(sorted((ev.get("source_masks") or {}).items())),
            bool(ev.get("control_dependent")),
        )
        if key not in event_seen:
            event_seen.add(key); deduped_events.append(ev)
    events = deduped_events

    # De-duplicate state dependency edges.
    edges_seen: set[tuple[str, str]] = set()
    edges: list[dict[str, Any]] = []
    for ev in events:
        target = str(ev.get("target_path") or "")
        for src in ev.get("state_dependencies") or []:
            key = (str(src), target)
            if src and target and src != target and key not in edges_seen:
                edges_seen.add(key)
                edges.append({"source_path": src, "target_path": target, "via_function": ev.get("function")})

    return AnalysisResult(
        source_path=model.source_path,
        contract_name=model.contract_name,
        compiler_version=model.compiler_version,
        mode=(
            "operational_external_taint"
            if seed_external_inputs and include_guarded_entries
            else ("external_taint" if seed_external_inputs else "seeded_state_propagation")
        ),
        state_taint=state,
        write_effect_masks=write_effect,
        write_events=events,
        state_edges=edges,
        roles=roles,
        externally_seeded_functions=external_fns,
        restricted_functions=restricted_fns,
        activated_restricted_functions=sorted(activated_restricted),
        selector_blocked_functions=sorted(set(selector_blocked_functions)),
        iterations=iteration,
    )
