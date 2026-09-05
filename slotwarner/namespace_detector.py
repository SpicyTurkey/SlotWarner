from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .ast_taint import GLOBAL_MEMBER_SOURCES, _function_guard_state_ids, _walk, _literal_int, compile_contract_model
from .detector import _normalize_storage_path, _external_selector_set
from .utils import read_jsonl, write_jsonl


def _pair_key(r: dict[str, Any]) -> tuple[str, str]:
    return (str(r.get("proxy_address") or "").lower(), str(r.get("logic_address") or "").lower())


def _norm_ns_path(path: str) -> str:
    # Ignore fixed-array concrete indices only for matching an AST access back to its
    # declared namespace root. This does not alter storage-address derivation.
    return re.sub(r"\[\d+\]", "[]", str(path or "")).lstrip("_").lower()


def _ast_access_path(node: Any, state_ids: set[int]) -> str:
    if not isinstance(node, dict):
        return ""
    nt = node.get("nodeType")
    if nt == "Identifier":
        ref = node.get("referencedDeclaration")
        return str(node.get("name") or "") if isinstance(ref, int) and ref in state_ids else ""
    if nt == "MemberAccess":
        base = _ast_access_path(node.get("expression"), state_ids)
        return f"{base}.{node.get('memberName') or ''}" if base else ""
    if nt == "IndexAccess":
        return _ast_access_path(node.get("baseExpression"), state_ids)
    return ""


def _namespace_rows(model) -> list[dict[str, Any]]:
    return list((((model.layout_record or {}).get("footprints") or {}).get("namespaces") or []))


def _namespace_path_for_access(model, node: Any) -> str | None:
    nss = _namespace_rows(model)
    if not nss:
        return None
    raw = _ast_access_path(node, set(model.state_decls))
    if not raw:
        return None
    nr = _norm_ns_path(raw)
    exact = [str(x.get("path") or "") for x in nss if _norm_ns_path(str(x.get("path") or "")) == nr]
    if len(exact) == 1:
        return exact[0]
    # Nested mapping accesses may have more IndexAccess nodes but the namespace path is
    # still the declared root. Prefer the longest normalized prefix match.
    cands = []
    for x in nss:
        p = str(x.get("path") or "")
        np = _norm_ns_path(p)
        if nr.startswith(np) or np.startswith(nr):
            cands.append((len(np), p))
    if cands:
        cands.sort(reverse=True)
        if len(cands) == 1 or cands[0][0] > cands[1][0]:
            return cands[0][1]
    return None


def _external_dep(node: Any, param_ids: set[int]) -> bool:
    for n in _walk(node):
        ref = n.get("referencedDeclaration")
        if isinstance(ref, int) and ref in param_ids:
            return True
        if n.get("nodeType") == "MemberAccess":
            base = n.get("expression")
            if isinstance(base, dict) and base.get("nodeType") == "Identifier":
                if (str(base.get("name") or ""), str(n.get("memberName") or "")) in GLOBAL_MEMBER_SOURCES:
                    return True
    return False


def _location_external_dep(node: Any, param_ids: set[int]) -> bool:
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") == "IndexAccess":
        if _external_dep(node.get("indexExpression"), param_ids):
            return True
        return _location_external_dep(node.get("baseExpression"), param_ids)
    if node.get("nodeType") == "MemberAccess":
        return _location_external_dep(node.get("expression"), param_ids)
    return False


def analyze_namespace_influence(model, *, excluded_external_selectors: set[str] | None = None, include_guarded_entries: bool = False) -> dict[str, dict[str, Any]]:
    blocked_selectors = {str(x).lower().removeprefix("0x") for x in (excluded_external_selectors or set()) if str(x)}
    nss = {str(x.get("path") or ""): x for x in _namespace_rows(model) if x.get("path")}
    out: dict[str, dict[str, Any]] = {}
    for path, ns in nss.items():
        rid = ns.get("root_ast_id")
        decl = model.state_decls.get(rid) if isinstance(rid, int) else None
        out[path] = {
            "path": path,
            "slot": ns.get("slot"),
            "namespace_kind": ns.get("kind"),
            "type_label": ns.get("type_label"),
            "type_category": ns.get("type_category"),
            "visibility": str((decl or {}).get("visibility") or "internal"),
            "reachable_write": False,
            "external_value_influence": False,
            "external_location_influence": False,
            "write_functions": [],
            "evidence_scope": "direct_public_entry_ast_namespace_write",
        }
    if not out:
        return out

    def visit(st: Any, *, params: set[int], pc_external: bool, fn_name: str):
        if not isinstance(st, dict):
            return
        nt = st.get("nodeType")
        if nt in {"Block", "UncheckedBlock"}:
            for x in st.get("statements") or []:
                visit(x, params=params, pc_external=pc_external, fn_name=fn_name)
            return
        if nt == "IfStatement":
            cext = pc_external or _external_dep(st.get("condition"), params)
            visit(st.get("trueBody"), params=params, pc_external=cext, fn_name=fn_name)
            visit(st.get("falseBody"), params=params, pc_external=cext, fn_name=fn_name)
            return
        if nt in {"ForStatement", "WhileStatement", "DoWhileStatement"}:
            cext = pc_external or _external_dep(st.get("condition"), params)
            visit(st.get("body"), params=params, pc_external=cext, fn_name=fn_name)
            return
        if nt == "ExpressionStatement":
            e = st.get("expression")
            if isinstance(e, dict) and e.get("nodeType") == "Assignment":
                lhs = e.get("leftHandSide")
                path = _namespace_path_for_access(model, lhs)
                if path in out:
                    rec = out[path]
                    rec["reachable_write"] = True
                    rec["external_value_influence"] = bool(rec["external_value_influence"] or pc_external or _external_dep(e.get("rightHandSide"), params))
                    rec["external_location_influence"] = bool(rec["external_location_influence"] or _location_external_dep(lhs, params))
                    if fn_name not in rec["write_functions"]:
                        rec["write_functions"].append(fn_name)
            # push/pop on a dynamic array/bytes root are writes even without Assignment.
            if isinstance(e, dict) and e.get("nodeType") == "FunctionCall":
                callee = e.get("expression")
                if isinstance(callee, dict) and callee.get("nodeType") == "MemberAccess" and str(callee.get("memberName") or "") in {"push", "pop"}:
                    path = _namespace_path_for_access(model, callee.get("expression"))
                    if path in out:
                        rec = out[path]
                        rec["reachable_write"] = True
                        rec["external_value_influence"] = bool(rec["external_value_influence"] or pc_external or any(_external_dep(a, params) for a in (e.get("arguments") or [])))
                        if fn_name not in rec["write_functions"]:
                            rec["write_functions"].append(fn_name)
            return
        # Conservative fallback for nested statements not explicitly modelled.
        for v in st.values():
            if isinstance(v, dict) and v.get("nodeType") in {"Block", "ExpressionStatement", "IfStatement", "ForStatement", "WhileStatement", "DoWhileStatement"}:
                visit(v, params=params, pc_external=pc_external, fn_name=fn_name)

    for fn in model.functions.values():
        if fn.get("implemented") is False or not isinstance(fn.get("body"), dict):
            continue
        if str(fn.get("visibility") or "") not in {"public", "external"}:
            continue
        selector = str(fn.get("functionSelector") or "").lower().removeprefix("0x")
        if selector and selector in blocked_selectors:
            continue
        if (not include_guarded_entries) and _function_guard_state_ids(model, fn):
            continue
        params = {int(p["id"]) for p in ((fn.get("parameters") or {}).get("parameters") or []) if isinstance(p, dict) and isinstance(p.get("id"), int)}
        name = str(fn.get("name") or fn.get("kind") or f"fn_{fn.get('id')}")
        visit(fn.get("body"), params=params, pc_external=False, fn_name=name)
    return out




def _root_type_layout(model, ns: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve the declared namespace root type using the same frozen AST layout resolver.

    This is downstream metadata extraction only; it does not modify v1.4 reconstruction rules.
    """
    rid = ns.get("root_ast_id")
    if not isinstance(rid, int) or model.program is None:
        return None
    decl = model.state_decls.get(rid) or model.program.by_id.get(rid)
    if not isinstance(decl, dict):
        return None
    try:
        from slotwarner_layout_validate.reconstruct import TypeResolver
        return TypeResolver(model.program).resolve_var(decl).asdict()
    except Exception:
        return None


def _type_signature(t: dict[str, Any] | None) -> str:
    if not isinstance(t, dict):
        return "unknown"
    cat = str(t.get("category") or "")
    label = " ".join(str(t.get("label") or "").split())
    det = t.get("details") or {}
    if cat == "mapping":
        return f"mapping<{_type_signature(det.get('key'))},{_type_signature(det.get('value'))}>"
    if cat in {"dynamic_array", "fixed_array"}:
        ln = f",{det.get('length')}" if cat == "fixed_array" else ""
        return f"{cat}<{_type_signature(det.get('base'))}{ln}>"
    if cat == "struct":
        members = det.get("members") or []
        body = ",".join(
            f"{m.get('label')}@{m.get('slot')}:{m.get('offset')}:{_type_signature(m.get('type'))}"
            for m in members if isinstance(m, dict)
        )
        return f"struct<{body}>"
    return f"{cat}:{label}:{t.get('numberOfBytes')}"


def _relative_direct_leaves(t: dict[str, Any] | None, *, prefix: str = "value", base_slot: int = 0, base_offset: int = 0) -> list[dict[str, Any]]:
    """Expand one value type into direct leaves relative to an entry/array-element base."""
    if not isinstance(t, dict):
        return []
    cat = str(t.get("category") or "")
    enc = str(t.get("encoding") or "")
    det = t.get("details") or {}
    try:
        nbytes = int(t.get("numberOfBytes") or 32)
    except Exception:
        nbytes = 32
    if cat in {"mapping", "dynamic_array", "string", "bytes_dynamic"} or enc in {"mapping", "dynamic_array", "bytes"}:
        return []
    if cat == "struct":
        out=[]
        for m in det.get("members") or []:
            if not isinstance(m, dict):
                continue
            label=str(m.get("label") or "member")
            out.extend(_relative_direct_leaves(
                m.get("type"), prefix=f"{prefix}.{label}",
                base_slot=base_slot + int(m.get("slot") or 0),
                base_offset=int(m.get("offset") or 0),
            ))
        return out
    if cat == "fixed_array":
        base=det.get("base") or {}
        try: length=int(det.get("length") or 0)
        except Exception: length=0
        if length <= 0: return []
        bpack=bool(base.get("packable")); bbytes=int(base.get("numberOfBytes") or 32); bslots=max(1,int(base.get("slots") or 1))
        out=[]
        if bpack and bbytes <= 32:
            per=max(1,32//bbytes)
            for i in range(length):
                out.extend(_relative_direct_leaves(base,prefix=f"{prefix}[{i}]",base_slot=base_slot+i//per,base_offset=(i%per)*bbytes))
        else:
            for i in range(length):
                out.extend(_relative_direct_leaves(base,prefix=f"{prefix}[{i}]",base_slot=base_slot+i*bslots,base_offset=0))
        return out
    if enc == "inplace" and 0 < nbytes <= 32:
        start=base_offset*8; width=nbytes*8
        return [{
            "path":prefix,"rel_slot":base_slot,"slot_bit_start":start,"slot_bit_end":start+width-1,
            "width_bits":width,"type_label":str(t.get("label") or ""),"type_category":cat,
            "type_signature":_type_signature(t),
        }]
    return []


def _access_components(node: Any, state_ids: set[int]) -> tuple[int | None, list[dict[str, Any]]]:
    """Return root state declaration and ordered member/index operations."""
    if not isinstance(node, dict):
        return None, []
    nt=node.get("nodeType")
    if nt=="Identifier":
        ref=node.get("referencedDeclaration")
        return (ref, []) if isinstance(ref,int) and ref in state_ids else (None,[])
    if nt=="MemberAccess":
        rid,ops=_access_components(node.get("expression"),state_ids)
        if rid is None: return None,[]
        return rid, ops+[{"kind":"member","name":str(node.get("memberName") or "")}]
    if nt=="IndexAccess":
        rid,ops=_access_components(node.get("baseExpression"),state_ids)
        if rid is None: return None,[]
        idx=node.get("indexExpression")
        return rid, ops+[{"kind":"index","literal":_literal_int(idx),"node":idx}]
    return None,[]


def _namespace_access_descriptor(model, node: Any, param_ids: set[int]) -> dict[str, Any] | None:
    rid,ops=_access_components(node,set(model.state_decls))
    if rid is None: return None
    nss=[x for x in _namespace_rows(model) if x.get("root_ast_id")==rid]
    if not nss: return None
    # A declared root may have nested namespace rows. The first namespace operation belongs
    # to the shortest path/root; later nested namespaces are kept as unresolved detail.
    nss=sorted(nss,key=lambda x:(str(x.get("path") or "").count("."),len(str(x.get("path") or ""))))
    ns=nss[0]
    idx_ops=[o for o in ops if o.get("kind")=="index"]
    members=[str(o.get("name") or "") for o in ops if o.get("kind")=="member" and o.get("name")]
    first_idx=idx_ops[0] if idx_ops else None
    index_desc=[{
        "literal":o.get("literal"),
        "external":bool(_external_dep(o.get("node"),param_ids)),
    } for o in idx_ops]
    return {
        "path":str(ns.get("path") or ""),
        "namespace_kind":str(ns.get("kind") or ""),
        "root_ast_id":rid,
        "member_chain":members,
        "index_literal":first_idx.get("literal") if first_idx else None,
        "index_external":any(bool(x.get("external")) for x in index_desc),
        "index_count":len(idx_ops),
        "indices":index_desc,
    }


def analyze_namespace_accesses(model, *, excluded_external_selectors: set[str] | None = None) -> list[dict[str, Any]]:
    """Collect public-entry namespace writes with member/index detail.

    The result remains symbolic. No concrete hash is fabricated when key/index data is unknown.
    """
    out=[]
    blocked_selectors={str(x).lower().removeprefix("0x") for x in (excluded_external_selectors or set()) if str(x)}
    def visit(st:Any, *, params:set[int], pc_external:bool, fn_name:str):
        if not isinstance(st,dict): return
        nt=st.get("nodeType")
        if nt in {"Block","UncheckedBlock"}:
            for x in st.get("statements") or []: visit(x,params=params,pc_external=pc_external,fn_name=fn_name)
            return
        if nt=="IfStatement":
            c=pc_external or _external_dep(st.get("condition"),params)
            visit(st.get("trueBody"),params=params,pc_external=c,fn_name=fn_name); visit(st.get("falseBody"),params=params,pc_external=c,fn_name=fn_name); return
        if nt in {"ForStatement","WhileStatement","DoWhileStatement"}:
            c=pc_external or _external_dep(st.get("condition"),params)
            visit(st.get("body"),params=params,pc_external=c,fn_name=fn_name); return
        if nt=="ExpressionStatement":
            e=st.get("expression")
            if isinstance(e,dict) and e.get("nodeType")=="Assignment":
                d=_namespace_access_descriptor(model,e.get("leftHandSide"),params)
                if d:
                    out.append({**d,"function":fn_name,"operator":str(e.get("operator") or "="),
                                "external_value_influence":bool(pc_external or _external_dep(e.get("rightHandSide"),params)),
                                "control_external":bool(pc_external)})
            if isinstance(e,dict) and e.get("nodeType")=="UnaryOperation" and str(e.get("operator") or "") in {"++","--"}:
                d=_namespace_access_descriptor(model,e.get("subExpression"),params)
                if d: out.append({**d,"function":fn_name,"operator":str(e.get("operator")),"external_value_influence":bool(pc_external),"control_external":bool(pc_external)})
            if isinstance(e,dict) and e.get("nodeType")=="FunctionCall":
                cal=e.get("expression")
                if isinstance(cal,dict) and cal.get("nodeType")=="MemberAccess" and str(cal.get("memberName") or "") in {"push","pop"}:
                    d=_namespace_access_descriptor(model,cal.get("expression"),params)
                    if d: out.append({**d,"function":fn_name,"operator":str(cal.get("memberName")),
                                      "external_value_influence":bool(pc_external or any(_external_dep(a,params) for a in e.get("arguments") or [])),
                                      "control_external":bool(pc_external)})
            return
        for v in st.values():
            if isinstance(v,dict) and v.get("nodeType") in {"Block","ExpressionStatement","IfStatement","ForStatement","WhileStatement","DoWhileStatement"}:
                visit(v,params=params,pc_external=pc_external,fn_name=fn_name)
    for fn in model.functions.values():
        if fn.get("implemented") is False or not isinstance(fn.get("body"),dict): continue
        if str(fn.get("visibility") or "") not in {"public","external"}: continue
        selector=str(fn.get("functionSelector") or "").lower().removeprefix("0x")
        if selector and selector in blocked_selectors: continue
        if _function_guard_state_ids(model,fn): continue
        params={int(p["id"]) for p in ((fn.get("parameters") or {}).get("parameters") or []) if isinstance(p,dict) and isinstance(p.get("id"),int)}
        name=str(fn.get("name") or fn.get("kind") or f"fn_{fn.get('id')}")
        visit(fn.get("body"),params=params,pc_external=False,fn_name=name)
    return out


def _select_logic_leaves(leaves:list[dict[str,Any]], members:list[str]) -> list[dict[str,Any]]:
    if not members: return leaves
    suffix="."+".".join(members)
    exact=[x for x in leaves if str(x.get("path") or "").endswith(suffix)]
    return exact or leaves


def _interval_overlap(a0:int,a1:int,b0:int,b1:int) -> tuple[int,int] | None:
    lo=max(a0,b0); hi=min(a1,b1)
    return (lo,hi) if lo<=hi else None


def _interpret_proxy_array_position(proxy_base:dict[str,Any], rel_slot:int, bit0:int, bit1:int) -> list[dict[str,Any]]:
    """Interpret a physical relative slot/bit interval under the proxy dynamic-array element type."""
    ppack=bool(proxy_base.get("packable")); pbytes=int(proxy_base.get("numberOfBytes") or 32); pslots=max(1,int(proxy_base.get("slots") or 1))
    if ppack and pbytes<=32:
        per=max(1,32//pbytes); out=[]; width=pbytes*8
        for pos in range(per):
            s=pos*width; e=s+width-1; ov=_interval_overlap(bit0,bit1,s,e)
            if ov: out.append({"proxy_element_position_in_slot":pos,"proxy_element_index_delta":None,"proxy_leaf":"element","overlap_bits":list(ov),
                              "proxy_leaf_type":str(proxy_base.get("label") or ""),"proxy_leaf_type_signature":_type_signature(proxy_base),
                              "proxy_leaf_slot_bit_start":s,"proxy_leaf_slot_bit_end":e,"proxy_leaf_width_bits":width})
        return out
    rem=rel_slot%pslots
    jbase=rel_slot//pslots
    out=[]
    for leaf in _relative_direct_leaves(proxy_base,prefix="element"):
        if int(leaf.get("rel_slot") or 0)!=rem: continue
        ov=_interval_overlap(bit0,bit1,int(leaf["slot_bit_start"]),int(leaf["slot_bit_end"]))
        if ov: out.append({"proxy_element_index_delta":jbase,"proxy_leaf":leaf["path"],"overlap_bits":list(ov),
                              "proxy_leaf_type":leaf.get("type_label"),"proxy_leaf_type_signature":leaf.get("type_signature"),
                              "proxy_leaf_slot_bit_start":int(leaf["slot_bit_start"]),"proxy_leaf_slot_bit_end":int(leaf["slot_bit_end"]),
                              "proxy_leaf_width_bits":int(leaf.get("width_bits") or 0)})
    return out


def _mapping_chain(t: dict[str, Any] | None) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Return mapping key types from outermost to innermost and the final value type."""
    keys: list[dict[str, Any]] = []
    cur = t
    while isinstance(cur, dict) and str(cur.get("category") or "") == "mapping":
        det = cur.get("details") or {}
        key = det.get("key") or {}
        keys.append(key)
        nxt = det.get("value")
        cur = nxt if isinstance(nxt, dict) else None
    return keys, cur


def _leaf_suffix(path: str) -> str:
    p = str(path or "")
    for pref in ("element.", "value."):
        if p.startswith(pref):
            return p[len(pref):]
    return p


def _concrete_alignment_class(row: dict[str, Any]) -> str:
    """Classify one projected namespace member at the concrete leaf level.

    Root-level struct labels may differ while the actually reachable member is structurally
    identical.  Such a write is an observation, not an anomaly candidate.
    """
    ov = row.get("overlap_bits") or []
    if len(ov) != 2:
        return "concrete_unresolved"
    try:
        lo, hi = int(ov[0]), int(ov[1])
        ls, le = int(row.get("logic_leaf_slot_bit_start")), int(row.get("logic_leaf_slot_bit_end"))
        ps, pe = int(row.get("proxy_leaf_slot_bit_start")), int(row.get("proxy_leaf_slot_bit_end"))
    except Exception:
        return "concrete_unresolved"
    full_logic = lo == ls and hi == le
    full_proxy = lo == ps and hi == pe
    same_sig = str(row.get("logic_leaf_type_signature") or row.get("logic_leaf_type") or "") == str(row.get("proxy_leaf_type_signature") or row.get("proxy_leaf_type") or "")
    same_member = _leaf_suffix(str(row.get("logic_leaf") or "")) == _leaf_suffix(str(row.get("proxy_leaf") or ""))
    same_root = _normalize_storage_path(str(row.get("logic_path") or "")) == _normalize_storage_path(str(row.get("proxy_path") or ""))
    deriv = str(row.get("derivation") or "")
    index_compatible = True
    if deriv == "dynamic_array_same_seed":
        index_compatible = bool(row.get("element_stride_equal"))
        if row.get("index_mode") == "literal_index":
            index_compatible = index_compatible and int(row.get("logic_index_or_residue") or 0) == int(row.get("proxy_element_index_delta") or 0)
    if full_logic and full_proxy and same_sig and same_member and same_root and index_compatible:
        return "compatible_concrete_member_alignment"
    if not full_logic or not full_proxy:
        return "partial_concrete_member_overlap"
    if same_sig:
        return "cross_member_same_shape"
    return "cross_member_shape_mismatch"


def project_namespace_candidate(proxy_model, logic_model, proxy_ns:dict[str,Any], logic_ns:dict[str,Any], access_events:list[dict[str,Any]]) -> list[dict[str,Any]]:
    """Project concrete/symbolic mapping or dynamic-array entry writes into proxy interpretation.

    For dynamic arrays of non-packable elements, externally selected indices are reduced to
    an exact finite residue period derived from the two element strides. This is sufficient to
    enumerate all repeated member-alignment patterns without choosing arbitrary example indices.
    """
    pt=_root_type_layout(proxy_model,proxy_ns); lt=_root_type_layout(logic_model,logic_ns)
    if not pt or not lt: return []
    pk=str(proxy_ns.get("kind") or ""); lk=str(logic_ns.get("kind") or "")
    out=[]
    if pk==lk=="mapping_namespace":
        pkeys,pvalue=_mapping_chain(pt); lkeys,lvalue=_mapping_chain(lt)
        if not pkeys or not lkeys:
            return []
        pks=[_type_signature(x) for x in pkeys]; lks=[_type_signature(x) for x in lkeys]
        for ev in access_events:
            depth=int(ev.get("index_count") or 1)
            # A concrete value member exists only after all nested mapping keys are supplied
            # on both interpretations, and every key encoding in the chain is identical.
            if depth != len(lkeys) or depth != len(pkeys) or pks != lks:
                continue
            pleaves=_relative_direct_leaves(pvalue,prefix="value")
            lleaves=_relative_direct_leaves(lvalue,prefix="value")
            if not pleaves or not lleaves:
                continue
            selected=_select_logic_leaves(lleaves,ev.get("member_chain") or [])
            for ll in selected:
                for pl in pleaves:
                    if int(ll["rel_slot"])!=int(pl["rel_slot"]): continue
                    ov=_interval_overlap(int(ll["slot_bit_start"]),int(ll["slot_bit_end"]),int(pl["slot_bit_start"]),int(pl["slot_bit_end"]))
                    if not ov: continue
                    out.append({"derivation":"mapping_chain_same_seed_same_key_encoding","mapping_depth":depth,
                                "mapping_key_signatures":lks,"function":ev.get("function"),"operator":ev.get("operator"),
                                "location_external":bool(ev.get("index_external")),"value_external":bool(ev.get("external_value_influence")),
                                "logic_leaf":ll["path"],"proxy_leaf":pl["path"],"entry_rel_slot":int(ll["rel_slot"]),"overlap_bits":list(ov),
                                "logic_leaf_type":ll.get("type_label"),"proxy_leaf_type":pl.get("type_label"),
                                "logic_leaf_type_signature":ll.get("type_signature"),"proxy_leaf_type_signature":pl.get("type_signature"),
                                "logic_leaf_slot_bit_start":int(ll["slot_bit_start"]),"logic_leaf_slot_bit_end":int(ll["slot_bit_end"]),
                                "logic_leaf_width_bits":int(ll.get("width_bits") or 0),
                                "proxy_leaf_slot_bit_start":int(pl["slot_bit_start"]),"proxy_leaf_slot_bit_end":int(pl["slot_bit_end"]),
                                "proxy_leaf_width_bits":int(pl.get("width_bits") or 0)})
        return out
    if pk==lk=="dynamic_array_namespace":
        pbase=(pt.get("details") or {}).get("base") or {}; lbase=(lt.get("details") or {}).get("base") or {}
        lleaves=_relative_direct_leaves(lbase,prefix="element")
        if not lleaves: return []
        lpack=bool(lbase.get("packable")); ppack=bool(pbase.get("packable"))
        lbytes=int(lbase.get("numberOfBytes") or 32); lslots=max(1,int(lbase.get("slots") or 1)); pslots=max(1,int(pbase.get("slots") or 1))
        for ev in access_events:
            selected=_select_logic_leaves(lleaves,ev.get("member_chain") or [])
            literal=ev.get("index_literal")
            if literal is not None and int(literal)>=0:
                indices=[int(literal)]; mode="literal_index"
            elif ev.get("index_external") and not lpack and not ppack:
                import math
                period=max(1,pslots//math.gcd(lslots,pslots)); indices=list(range(period)); mode="external_index_residue_period"
            else:
                # Without a concrete or externally selectable index we avoid pretending a specific element collision.
                continue
            for i in indices:
                for ll in selected:
                    if lpack and lbytes<=32:
                        per=max(1,32//lbytes); rel_slot=i//per; b0=(i%per)*lbytes*8; b1=b0+lbytes*8-1
                    else:
                        rel_slot=i*lslots+int(ll["rel_slot"]); b0=int(ll["slot_bit_start"]); b1=int(ll["slot_bit_end"])
                    for hit in _interpret_proxy_array_position(pbase,rel_slot,b0,b1):
                        out.append({"derivation":"dynamic_array_same_seed","function":ev.get("function"),"operator":ev.get("operator"),
                                    "index_mode":mode,"logic_index_or_residue":i,"residue_period":len(indices) if mode.endswith("period") else None,
                                    "location_external":bool(ev.get("index_external")),"value_external":bool(ev.get("external_value_influence")),
                                    "logic_leaf":ll["path"],"logic_leaf_type":ll.get("type_label"),"logic_leaf_type_signature":ll.get("type_signature"),
                                    "logic_rel_slot":rel_slot,"logic_leaf_slot_bit_start":b0,"logic_leaf_slot_bit_end":b1,
                                    "logic_leaf_width_bits":max(0,b1-b0+1),
                                    "logic_element_slots":lslots,"proxy_element_slots":pslots,"element_stride_equal":bool(lslots==pslots),
                                    **hit})
        # Dedupe repeated equivalent residue/member mappings.
        uniq={json.dumps(x,sort_keys=True,ensure_ascii=False):x for x in out}
        return list(uniq.values())
    return []


def _namespace_roots_read(model, node:Any) -> set[str]:
    roots=set()
    for n in _walk(node):
        if n.get("nodeType") not in {"IndexAccess","MemberAccess","Identifier"}: continue
        d=_namespace_access_descriptor(model,n,set())
        if d and d.get("path"): roots.add(str(d["path"]))
    return roots


def analyze_single_contract_namespaces(model) -> dict[str,Any]:
    """Root-level single-contract namespace influence and propagation summary.

    Exact bit positions are retained only for direct leaves. Namespace roots are symbolic storage
    regions, so this stage reports root/key-index influence rather than inventing fixed slot bits.
    """
    influence=analyze_namespace_influence(model)
    accesses=analyze_namespace_accesses(model)
    externally={p for p,r in influence.items() if r.get("reachable_write") and (r.get("external_value_influence") or r.get("external_location_influence"))}
    edges=[]
    # Direct root map for assigning namespace-read -> direct-state dependencies.
    state_ids=set(model.state_decls)
    def visit(st:Any,fn_name:str):
        if not isinstance(st,dict): return
        if st.get("nodeType")=="ExpressionStatement":
            e=st.get("expression")
            if isinstance(e,dict) and e.get("nodeType")=="Assignment":
                src_ns=_namespace_roots_read(model,e.get("rightHandSide"))
                if src_ns:
                    lhs=e.get("leftHandSide")
                    # Target namespace root.
                    td=_namespace_access_descriptor(model,lhs,set())
                    if td:
                        for s in src_ns: edges.append({"source_kind":"namespace","source_path":s,"target_kind":"namespace","target_path":td["path"],"function":fn_name})
                    else:
                        rid,_=_access_components(lhs,state_ids)
                        if isinstance(rid,int):
                            for dp in model.paths_by_root_id.get(rid) or []:
                                for s in src_ns: edges.append({"source_kind":"namespace","source_path":s,"target_kind":"direct","target_path":dp,"function":fn_name})
            return
        for v in st.values():
            if isinstance(v,dict): visit(v,fn_name)
            elif isinstance(v,list):
                for x in v:
                    if isinstance(x,dict): visit(x,fn_name)
    for fn in model.functions.values():
        if fn.get("implemented") is False or not isinstance(fn.get("body"),dict): continue
        if str(fn.get("visibility") or "") not in {"public","external","internal","private"}: continue
        visit(fn.get("body"),str(fn.get("name") or fn.get("kind") or f"fn_{fn.get('id')}"))
    active=set(("namespace",p) for p in externally); changed=True
    while changed:
        changed=False
        for e in edges:
            if (e["source_kind"],e["source_path"]) in active and (e["target_kind"],e["target_path"]) not in active:
                active.add((e["target_kind"],e["target_path"])); changed=True
    downstream_direct=[]
    for kind,path in sorted(active):
        if kind!="direct": continue
        vis=model.footprint_visibility.get(path,"internal")
        if vis in {"private","internal"}: downstream_direct.append(path)
    downstream_ns=[]
    for kind,path in sorted(active):
        if kind=="namespace" and path not in externally:
            ns=next((x for x in _namespace_rows(model) if str(x.get("path") or "")==path),{})
            rid=ns.get("root_ast_id"); decl=model.state_decls.get(rid) if isinstance(rid,int) else {}
            if str((decl or {}).get("visibility") or "internal") in {"private","internal"}: downstream_ns.append(path)
    return {"namespace_count":len(influence),"externally_influenced_namespace_count":len(externally),
            "externally_influenced_namespace_paths":sorted(externally),"namespace_access_events":accesses,
            "namespace_edges":edges,"private_or_internal_downstream_direct_paths":downstream_direct,
            "private_or_internal_downstream_namespace_paths":downstream_ns,
            "evidence_scope":"symbolic namespace root/key-index influence; direct leaves retain separate bit-level analysis"}

def _derivation_family(kind: str) -> str:
    k = str(kind or "")
    if k == "mapping_namespace": return "mapping_hash"
    if k == "dynamic_array_namespace": return "array_hash"
    if k == "bytes_namespace": return "bytes_hash"
    return k or "unknown"


def _ns_alignment(proxy_ns: dict[str, Any], logic_ns: dict[str, Any], proxy_path: str, logic_path: str) -> str:
    same_path = _normalize_storage_path(proxy_path) == _normalize_storage_path(logic_path)
    same_kind = str(proxy_ns.get("kind")) == str(logic_ns.get("kind"))
    same_type = " ".join(str(proxy_ns.get("type_label") or "").split()) == " ".join(str(logic_ns.get("type_label") or "").split())
    if same_path and same_kind and same_type:
        return "compatible_namespace_alignment"
    if _derivation_family(str(proxy_ns.get("kind"))) != _derivation_family(str(logic_ns.get("kind"))):
        return "derivation_family_mismatch"
    if same_kind and same_type:
        return "cross_variable_same_namespace_shape"
    return "cross_variable_namespace_shape_mismatch"


def _recover_pair_contract_hint(pair: dict[str, Any], side: str) -> str:
    """Recover a target-contract hint lost by intermediate pair serialization.

    Priority is explicit hint -> artifact-key suffix -> address-prefixed source filename.
    This is general metadata recovery; it does not infer roles from variable names.
    """
    explicit = str(pair.get(f"{side}_contract_hint") or "").strip()
    if explicit:
        return explicit
    artifact_key = str(pair.get(f"{side}_artifact_key") or "").strip()
    if "|" in artifact_key:
        suffix = artifact_key.rsplit("|", 1)[-1].strip()
        if suffix:
            return suffix
    source = str(pair.get(f"{side}_source_path") or "").strip()
    if source:
        stem = Path(source).stem
        # Sanctuary names are commonly <40-hex-address>_<Contract>.sol.
        if "_" in stem:
            prefix, suffix = stem.split("_", 1)
            if len(prefix) == 40 and all(c in "0123456789abcdefABCDEF" for c in prefix) and suffix:
                return suffix
    return ""


def run_namespace_alias_analysis(*, pairs_path: str, aliases_path: str, out_dir: str, install_solc: bool = False, max_version_attempts: int = 8, workers: int = 6) -> dict[str, Any]:
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    pairs = {_pair_key(r): r for r in read_jsonl(pairs_path)}
    aliases_by_pair: dict[tuple[str,str], list[dict[str,Any]]] = defaultdict(list)
    for r in read_jsonl(aliases_path): aliases_by_pair[_pair_key(r)].append(r)
    model_cache: dict[tuple[str,str], Any] = {}
    model_errors: dict[tuple[str,str], str] = {}
    failures=[]; effects=[]; candidates=[]; aligned=[]; mismatched=[]; pair_rows=[]
    concrete=[]; concrete_candidates=[]; concrete_aligned=[]; concrete_unresolved=[]

    # Large-corpus mode precompiles unique source/contract targets concurrently.
    specs: set[tuple[str,str]] = set()
    for pair in pairs.values():
        specs.add((str(pair.get("proxy_source_path") or ""), _recover_pair_contract_hint(pair, "proxy")))
        specs.add((str(pair.get("logic_source_path") or ""), _recover_pair_contract_hint(pair, "logic")))

    def compile_one(spec: tuple[str,str]):
        path,hint=spec
        try:
            return spec, compile_contract_model(path,hint,install_solc=install_solc,max_version_attempts=max_version_attempts), None
        except Exception as exc:
            return spec, None, f"{type(exc).__name__}:{exc}"

    sequential_retry_specs: list[tuple[str, str]] = []
    if specs:
        # First pass keeps the high-throughput parallel compilation used by the large-corpus run.
        # Some Windows/solcx/source-bundle combinations are not reliably re-entrant under a
        # highly parallel first pass even though the exact same source compiles sequentially.
        # Therefore every failed unique spec is retried once in a deterministic sequential pass.
        with ThreadPoolExecutor(max_workers=max(1,int(workers))) as pool:
            futs=[pool.submit(compile_one,spec) for spec in sorted(specs)]
            done=0
            for fut in as_completed(futs):
                spec,m,err=fut.result(); done+=1
                if m is not None:
                    model_cache[spec]=m
                    model_errors.pop(spec, None)
                else:
                    model_errors[spec]=str(err)
                if done%25==0 or done==len(futs):
                    print(f"namespace compile models {done}/{len(futs)} success={len(model_cache)} first_pass_failures={len(model_errors)}",flush=True)
        sequential_retry_specs = sorted(model_errors)
        if sequential_retry_specs:
            print(f"namespace sequential recovery: retrying {len(sequential_retry_specs)} first-pass failures", flush=True)
            recovered = 0
            for done, spec in enumerate(sequential_retry_specs, 1):
                spec2, m, err = compile_one(spec)
                if m is not None:
                    model_cache[spec2] = m
                    model_errors.pop(spec2, None)
                    recovered += 1
                else:
                    model_errors[spec2] = str(err)
                if done % 25 == 0 or done == len(sequential_retry_specs):
                    print(f"namespace sequential recovery {done}/{len(sequential_retry_specs)} recovered={recovered} remaining={len(model_errors)}", flush=True)

    for i,(k,pair) in enumerate(sorted(pairs.items()),1):
        pspec=(str(pair.get("proxy_source_path") or ""), _recover_pair_contract_hint(pair, "proxy"))
        lspec=(str(pair.get("logic_source_path") or ""), _recover_pair_contract_hint(pair, "logic"))
        pm=model_cache.get(pspec); lm=model_cache.get(lspec)
        if pm is None or lm is None:
            failures.append({**pair,"error":";".join(x for x in [model_errors.get(pspec),model_errors.get(lspec)] if x) or "model_unavailable"}); continue
        pns={str(x.get("path") or ""):x for x in _namespace_rows(pm)}
        lns={str(x.get("path") or ""):x for x in _namespace_rows(lm)}
        proxy_selectors=_external_selector_set(pm)
        linf=analyze_namespace_influence(lm, excluded_external_selectors=proxy_selectors)
        access_by_path:dict[str,list[dict[str,Any]]]=defaultdict(list)
        for ev in analyze_namespace_accesses(lm, excluded_external_selectors=proxy_selectors): access_by_path[str(ev.get("path") or "")].append(ev)
        pcand=0; palign=0; pmismatch=0; unresolved=0; pconcrete=0; pconcrete_candidate=0; pconcrete_aligned=0
        for a in aliases_by_pair.get(k,[]):
            pp=str(a.get("proxy_path") or ""); lp=str(a.get("logic_path") or "")
            pn=pns.get(pp); ln=lns.get(lp)
            if not pn or not ln:
                unresolved+=1; continue
            influence=linf.get(lp) or {"reachable_write":False,"external_value_influence":False,"external_location_influence":False}
            cls=_ns_alignment(pn,ln,pp,lp)
            same_family=_derivation_family(str(pn.get("kind")))==_derivation_family(str(ln.get("kind")))
            is_candidate=bool(influence.get("reachable_write") and same_family and cls!="compatible_namespace_alignment")
            kind=("tainted_namespace_value_alias" if influence.get("external_value_influence") else "externally_selected_namespace_alias" if influence.get("external_location_influence") else "reachable_namespace_write_alias") if is_candidate else "namespace_seed_alias_observation"
            row={**a,"proxy_contract":pm.contract_name,"logic_contract":lm.contract_name,
                 "proxy_type_label":pn.get("type_label"),"logic_type_label":ln.get("type_label"),
                 "proxy_derivation_family":_derivation_family(str(pn.get("kind"))),"logic_derivation_family":_derivation_family(str(ln.get("kind"))),
                 "alignment_class":cls,"logic_reachable_namespace_write":bool(influence.get("reachable_write")),
                 "logic_external_value_influence":bool(influence.get("external_value_influence")),
                 "logic_external_location_influence":bool(influence.get("external_location_influence")),
                 "logic_write_functions":influence.get("write_functions") or [],"finding_kind":kind,
                 "is_namespace_conflict_candidate":is_candidate,
                 "candidate_pattern_key":"|".join([pm.contract_name,pp,str(pn.get("type_label") or ""),lm.contract_name,lp,str(ln.get("type_label") or ""),cls]),
                 "evidence_scope":"namespace-seed alias + public-entry AST write summary"}
            effects.append(row)
            if cls=="compatible_namespace_alignment": aligned.append(row); palign+=1
            elif cls=="derivation_family_mismatch": mismatched.append(row); pmismatch+=1
            if is_candidate:
                candidates.append(row); pcand+=1
                projections=project_namespace_candidate(pm,lm,pn,ln,access_by_path.get(lp,[]))
                if not projections:
                    concrete_unresolved.append({**row,"concrete_status":"unresolved_or_no_direct_value_leaf",
                                                "access_events":access_by_path.get(lp,[])})
                for pr in projections:
                    cr={**row,**pr,"concrete_status":"projected"}
                    ccls=_concrete_alignment_class(cr)
                    cr["concrete_alignment_class"]=ccls
                    cr["is_concrete_namespace_candidate"]=ccls not in {"compatible_concrete_member_alignment"}
                    cr["concrete_pattern_key"]="|".join([
                        str(cr.get("candidate_pattern_key") or ""),
                        str(cr.get("logic_leaf") or ""),str(cr.get("proxy_leaf") or ""),ccls,
                    ])
                    concrete.append(cr); pconcrete+=1
                    if cr["is_concrete_namespace_candidate"]:
                        concrete_candidates.append(cr); pconcrete_candidate+=1
                    else:
                        concrete_aligned.append(cr); pconcrete_aligned+=1
        pair_rows.append({**pair,"status":"analyzed","alias_records":len(aliases_by_pair.get(k,[])),"aligned_aliases":palign,
                          "proxy_direct_selector_count":len(proxy_selectors),
                          "derivation_mismatch_aliases":pmismatch,"namespace_conflict_candidates":pcand,
                          "concrete_namespace_projection_records":pconcrete,"concrete_namespace_candidates":pconcrete_candidate,
                          "concrete_aligned_projection_records":pconcrete_aligned,"unresolved_alias_paths":unresolved})
        if i%20==0 or i==len(pairs):
            print(f"namespace alias {i}/{len(pairs)} symbolic={len(candidates)} concrete={len(concrete_candidates)}",flush=True)

    write_jsonl(out/'namespace_all_alias_effects.jsonl',effects)
    write_jsonl(out/'namespace_aligned_aliases.jsonl',aligned)
    write_jsonl(out/'namespace_derivation_mismatches.jsonl',mismatched)
    write_jsonl(out/'namespace_conflict_candidates.jsonl',candidates)
    write_jsonl(out/'namespace_concrete_projection_records.jsonl',concrete)
    write_jsonl(out/'namespace_concrete_candidates.jsonl',concrete_candidates)
    write_jsonl(out/'namespace_concrete_aligned.jsonl',concrete_aligned)
    write_jsonl(out/'namespace_concrete_unresolved.jsonl',concrete_unresolved)
    write_jsonl(out/'namespace_pair_summary.jsonl',pair_rows)
    write_jsonl(out/'namespace_compile_failures.jsonl',failures)
    summary={
        "schema":"slotwarner_namespace_alias_summary_v3","pairs_requested":len(pairs),"pairs_analyzed":len(pair_rows),"compile_failures":len(failures),"compile_workers":max(1,int(workers)),
        "unique_compile_specs":len(specs),"parallel_first_pass_failed_specs":len(sequential_retry_specs),"unrecovered_compile_specs":len(model_errors),
        "compile_recovery":"parallel first pass + deterministic sequential retry",
        "alias_records":len(effects),"aligned_alias_records":len(aligned),"derivation_mismatch_records":len(mismatched),"namespace_conflict_candidates":len(candidates),
        "concrete_projection_records":len(concrete),"concrete_aligned_projection_records":len(concrete_aligned),
        "concrete_namespace_candidates":len(concrete_candidates),"concrete_unresolved":len(concrete_unresolved),
        "unique_symbolic_candidate_patterns":len({str(x.get("candidate_pattern_key") or "") for x in candidates}),
        "unique_concrete_candidate_patterns":len({str(x.get("concrete_pattern_key") or x.get("candidate_pattern_key") or "") for x in concrete_candidates}),
        "candidate_kinds":dict(Counter(str(x.get('finding_kind') or '') for x in candidates)),
        "alignment_classes":dict(Counter(str(x.get('alignment_class') or '') for x in effects)),
        "concrete_alignment_classes":dict(Counter(str(x.get('concrete_alignment_class') or '') for x in concrete)),
        "concrete_derivations":dict(Counter(str(x.get('derivation') or '') for x in concrete)),
        "scope_note":"Namespace v3 separates root-level structural mismatch from the actually reachable concrete leaf. A root mismatch is not promoted when the written member has the same path, type encoding, full bit interval, and index semantics on both interpretations. Nested mapping chains are projected only when every key encoding matches.",
        "outputs":{
            "all_effects":str(out/'namespace_all_alias_effects.jsonl'),"candidates":str(out/'namespace_conflict_candidates.jsonl'),
            "concrete_projection_records":str(out/'namespace_concrete_projection_records.jsonl'),"concrete_candidates":str(out/'namespace_concrete_candidates.jsonl'),
            "concrete_aligned":str(out/'namespace_concrete_aligned.jsonl'),
            "concrete_unresolved":str(out/'namespace_concrete_unresolved.jsonl'),"pair_summary":str(out/'namespace_pair_summary.jsonl'),
            "failures":str(out/'namespace_compile_failures.jsonl')}
    }
    (out/'namespace_summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    return summary

