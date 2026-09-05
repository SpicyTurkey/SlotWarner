from __future__ import annotations

import json
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .ast_taint import AnalysisResult, ContractModel, analyze_contract_taint, compile_contract_model
from .bit_taint import BitInfluence, range_mask, width_mask
from .utils import read_jsonl, write_jsonl


def _pair_key(row: dict[str, Any]) -> tuple[str, str]:
    return (str(row.get("proxy_address") or "").lower(), str(row.get("logic_address") or "").lower())


def _normalize_storage_path(path: str) -> str:
    """Normalize narrow, storage-preserving identifier evolution.

    We intentionally recognize only common cosmetic/preservation patterns:
    leading/trailing underscores and an explicit ``Deprecated`` suffix.  Array
    indices and member structure are preserved, so unrelated variables remain
    unrelated even when they occupy the same physical interval.
    """
    import re

    def norm_component(text: str) -> str:
        text = str(text or "").strip().lower().strip("_")
        if text.endswith("deprecated") and len(text) > len("deprecated"):
            text = text[: -len("deprecated")].rstrip("_")
        return text.strip("_")

    text = str(path or "").strip()
    parts = re.split(r"(\[[^\]]+\]|\.)", text)
    out: list[str] = []
    for part in parts:
        if part == "." or part.startswith("["):
            out.append(part)
        else:
            out.append(norm_component(part))
    return "".join(out)


def _normalize_scalar_type_label(label: str) -> str:
    import re
    text = " ".join(str(label or "").strip().lower().split())
    text = re.sub(r"\s+(storage|memory|calldata)(\s+ref)?$", "", text).strip()
    if text == "address payable":
        return "address"
    if text.startswith("contract "):
        return "contract-address"
    return text


def _same_path_representation_compatible(ov: dict[str, Any]) -> str:
    """Return a narrow compatibility reason for exact same-path evolution.

    These rules are representation-level, not arbitrary same-width equivalence.
    They therefore do not hide cross-variable reinterpretations such as an admin
    address becoming a guardian address merely because both are 160 bits wide.
    """
    old_type = _normalize_scalar_type_label(str(ov.get("proxy_type") or ""))
    new_type = _normalize_scalar_type_label(str(ov.get("logic_type") or ""))
    width = int(ov.get("overlap_width_bits") or 0)

    if width == 160 and {old_type, new_type} <= {"address", "contract-address"}:
        return "address_representation_equivalence"
    if width == 8 and {old_type, new_type} == {"bool", "uint8"}:
        return "bool_uint8_representation_evolution"
    return ""


def _is_reserved_storage_gap_path(path: str) -> bool:
    """Return True for a concrete element of a conventional upgrade storage gap.

    Upgradeable Solidity contracts commonly reserve future storage with arrays such as
    ``uint256[50] private __gap``.  Consuming one of those old-version reserved words
    with a new-version variable is an intended storage-preserving upgrade operation,
    not a collision.  We require an indexed element so a normal variable merely named
    ``gap`` is not treated specially.
    """
    import re
    text = str(path or "").strip().lower()
    return bool(re.search(r"(?:^|\.)(?:_+)?gap\[\d+\](?:$|\.)", text))


def _is_explicit_deprecated_placeholder(path: str) -> bool:
    import re
    leaf = str(path or "").strip().split(".")[-1]
    return bool(re.fullmatch(r"_+deprecated(?:_?\d+)?", leaf, flags=re.IGNORECASE))


def _is_explicit_gap_was_preservation(path: str) -> bool:
    """Recognize explicit replacement placeholders such as ``__gap_was_treasury``.

    These names are used by upgradeable contracts to preserve an old storage
    interval after the original variable has been retired.  The rule is
    intentionally narrow and only applies on the *new-version* side.
    """
    import re
    leaf = str(path or "").strip().split(".")[-1]
    return bool(re.fullmatch(r"_+gap_was_[A-Za-z0-9_]+(?:\[\d+\])?", leaf))


def _alignment_compatibility_reason(ov: dict[str, Any], logic_path: str, proxy_path: str) -> str:
    overlap_kind = str(ov.get("overlap_kind") or "")

    # A new-version variable whose entire identifier is an explicit deprecated
    # placeholder is intended to preserve the physical location of removed state.
    # Accept it only at the exact same interval and storage width; representation
    # equivalence such as contract-address -> address is also permitted.
    if overlap_kind == "exact_interval_overlap" and _is_explicit_deprecated_placeholder(logic_path):
        try:
            old_w = int(ov.get("proxy_slot_bit_end")) - int(ov.get("proxy_slot_bit_start")) + 1
            new_w = int(ov.get("logic_slot_bit_end")) - int(ov.get("logic_slot_bit_start")) + 1
        except Exception:
            old_w = new_w = 0
        if old_w and old_w == new_w:
            shape = str(ov.get("storage_shape_relation") or "")
            if shape == "same_storage_shape" or _same_path_representation_compatible({**ov, "overlap_width_bits": old_w}):
                return "explicit_deprecated_placeholder_preservation"

    # Explicit new-version gap placeholders preserve the old physical interval
    # without reusing it for live state.  This covers patterns such as
    # ``treasury -> __gap_was_treasury`` and ``fee -> __gap_was_fees[0]``.
    if overlap_kind == "exact_interval_overlap" and _is_explicit_gap_was_preservation(logic_path):
        try:
            old_w = int(ov.get("proxy_slot_bit_end")) - int(ov.get("proxy_slot_bit_start")) + 1
            new_w = int(ov.get("logic_slot_bit_end")) - int(ov.get("logic_slot_bit_start")) + 1
        except Exception:
            old_w = new_w = 0
        if old_w and old_w == new_w and str(ov.get("storage_shape_relation") or "") == "same_storage_shape":
            return "explicit_gap_was_preservation"

    # Replacing a retired full storage word with an indexed reserved ``__gap``
    # element is likewise layout-preserving: the word remains reserved and is not
    # reinterpreted as live state.  Restrict this to exact 256-bit word overlap.
    if overlap_kind == "exact_interval_overlap" and _is_reserved_storage_gap_path(logic_path):
        try:
            old_w = int(ov.get("proxy_slot_bit_end")) - int(ov.get("proxy_slot_bit_start")) + 1
            new_w = int(ov.get("logic_slot_bit_end")) - int(ov.get("logic_slot_bit_start")) + 1
        except Exception:
            old_w = new_w = 0
        if old_w == 256 and new_w == 256:
            return "new_reserved_gap_preservation"

    # Direction is old -> new for the pair comparison.  If the old-side footprint is
    # a concrete reserved storage-gap word, a new variable occupying all or part of
    # that word is legitimate gap consumption.  This remains narrow: only indexed
    # __gap/_gap elements qualify, and the overlap must be physically inside that
    # old 256-bit reservation.
    if _is_reserved_storage_gap_path(proxy_path):
        try:
            proxy_width = int(ov.get("proxy_slot_bit_end") or 0) - int(ov.get("proxy_slot_bit_start") or 0) + 1
        except Exception:
            proxy_width = 0
        if proxy_width == 256 and overlap_kind in {"exact_interval_overlap", "proxy_contains_logic"}:
            return "reserved_storage_gap_consumption"

    if overlap_kind != "exact_interval_overlap":
        return ""
    if _normalize_storage_path(logic_path) != _normalize_storage_path(proxy_path):
        return ""
    if str(ov.get("storage_shape_relation") or "") == "same_storage_shape":
        return "same_path_same_storage_shape"
    return _same_path_representation_compatible(ov)


def _alignment_class(ov: dict[str, Any], logic_path: str, proxy_path: str) -> str:
    overlap_kind = str(ov.get("overlap_kind") or "")
    shape = str(ov.get("storage_shape_relation") or "")
    if _alignment_compatibility_reason(ov, logic_path, proxy_path):
        return "compatible_alignment"
    if overlap_kind != "exact_interval_overlap":
        return "partial_or_containment_misalignment"
    if shape != "same_storage_shape":
        return "cross_variable_shape_mismatch"
    return "cross_variable_same_shape"


def _direct_to_namespace_seed_reinterpretations(old_footprints: dict[str, Any], new_footprints: dict[str, Any]) -> list[dict[str, Any]]:
    """Return fixed/direct old-state -> new mapping-seed reinterpretations.

    Dynamic variables (mapping, string, bytes, dynamic arrays) also have a declared
    root slot and therefore appear in both the direct-footprint and namespace views.
    Treating an unchanged dynamic root as "direct -> namespace" caused a large
    false-positive explosion in v4.2.9.  A true cross-shape reinterpretation exists
    only when the *old* slot had no namespace root at all, while the new version
    introduces a mapping namespace at that same slot.

    We deliberately restrict this relation to mappings.  Strings/bytes/dynamic arrays
    keep meaningful data in their root word and have additional representation rules;
    they must not be promoted by this cross-view helper.
    """
    old_direct = list((old_footprints or {}).get("direct") or [])
    old_ns = list((old_footprints or {}).get("namespaces") or [])
    new_ns = list((new_footprints or {}).get("namespaces") or [])

    old_namespace_slots: set[int] = set()
    for ns in old_ns:
        try:
            old_namespace_slots.add(int(ns.get("slot")))
        except Exception:
            continue

    by_slot: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for fp in old_direct:
        try:
            by_slot[int(fp.get("slot"))].append(fp)
        except Exception:
            continue

    out: list[dict[str, Any]] = []
    for ns in new_ns:
        # v4.2.9 incorrectly included unchanged string/array roots.  Only a newly
        # introduced mapping seed is considered by this relation.
        if str(ns.get("kind") or "") != "mapping_namespace":
            continue
        try:
            slot = int(ns.get("slot"))
        except Exception:
            continue

        # If the old layout already had any namespace rooted at this slot, the slot
        # was already a dynamic-storage seed.  This is not direct->namespace reuse.
        if slot in old_namespace_slots:
            continue

        for old in by_slot.get(slot, []):
            old_path = str(old.get("path") or "")
            if _is_reserved_storage_gap_path(old_path):
                continue
            out.append({
                "slot": slot,
                "proxy_path": old_path,
                "logic_path": str(ns.get("path") or ""),
                "proxy_type": str(old.get("type_label") or ""),
                "logic_type": str(ns.get("type_label") or ""),
                "logic_namespace_kind": str(ns.get("kind") or ""),
                "record_kind": "direct_to_mapping_seed_reinterpretation",
            })
    return out



def _external_selector_set(model: ContractModel) -> set[str]:
    """Return concrete Solidity selectors implemented directly by a contract/base.

    The compiler AST exposes ``functionSelector`` on externally dispatchable functions
    for the compiler versions used by the experiment corpus.  We intentionally do not
    guess selectors when the compiler did not emit one; missing evidence stays
    conservative rather than inventing dispatch facts.
    """
    out: set[str] = set()
    for fn in model.functions.values():
        if str(fn.get("visibility") or "") not in {"public", "external"}:
            continue
        if str(fn.get("kind") or "function") == "constructor":
            continue
        sel = str(fn.get("functionSelector") or "").lower().removeprefix("0x")
        if len(sel) == 8 and all(c in "0123456789abcdef" for c in sel):
            out.add(sel)
    return out

def _artifact_by_key(path: str | Path) -> dict[str, dict[str, Any]]:
    return {str(r.get("artifact_key")): r for r in read_jsonl(path)}


def _compile_models(
    artifacts: dict[str, dict[str, Any]],
    keys: set[str],
    *,
    install_solc: bool,
    workers: int,
    max_version_attempts: int,
) -> tuple[dict[str, ContractModel], list[dict[str, Any]]]:
    models: dict[str, ContractModel] = {}
    failures: list[dict[str, Any]] = []

    def one(key: str) -> tuple[str, ContractModel | None, str | None]:
        art = artifacts[key]
        try:
            m = compile_contract_model(
                str(art.get("source_path") or ""),
                str(art.get("contract_name") or art.get("contract_hint") or ""),
                install_solc=install_solc,
                max_version_attempts=max_version_attempts,
                existing_layout=art,
            )
            return key, m, None
        except Exception as exc:
            return key, None, f"{type(exc).__name__}:{exc}"

    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
        futs = {pool.submit(one, k): k for k in sorted(keys) if k in artifacts}
        done = 0
        for fut in as_completed(futs):
            key, model, err = fut.result()
            done += 1
            if model is not None:
                models[key] = model
            else:
                art = artifacts.get(key) or {}
                failures.append({
                    "artifact_key": key,
                    "source_path": art.get("source_path"),
                    "contract_name": art.get("contract_name"),
                    "error": err,
                })
            if done % 25 == 0 or done == len(futs):
                print(f"compile taint models {done}/{len(futs)} success={len(models)} failures={len(failures)}", flush=True)
    return models, failures


def _single_result_row(key: str, model: ContractModel, result: AnalysisResult) -> dict[str, Any]:
    states = result.state_rows(model)
    by_path = {str(x["path"]): x for x in states}
    tainted = [x for x in states if x["tainted"]]

    direct_paths: set[str] = set()
    for ev in result.write_events:
        try:
            taint_nonzero = int(str(ev.get("taint_mask_hex") or "0"), 16) != 0
        except Exception:
            taint_nonzero = False
        if not taint_nonzero or (ev.get("state_dependencies") or []):
            continue
        srcs = ev.get("source_masks") or {}
        if any(
            k.startswith("PARAM:") or k in {
                "MSG_SENDER", "MSG_VALUE", "TX_ORIGIN", "BLOCK_NUMBER", "BLOCK_TIMESTAMP",
                "BLOCK_PREVRANDAO", "BLOCK_COINBASE", "BLOCK_CHAINID", "NOW"
            }
            for k in srcs
        ):
            direct_paths.add(str(ev.get("target_path") or ""))

    downstream_paths = {str(e.get("target_path") or "") for e in result.state_edges if e.get("target_path")}
    private_downstream = [
        by_path[p] for p in sorted(downstream_paths)
        if p in by_path and by_path[p].get("tainted") and by_path[p].get("visibility") in {"private", "internal"}
    ]
    private_tainted = [x for x in tainted if x.get("visibility") in {"private", "internal"}]
    return {
        "schema": "slotwarner_single_contract_bit_taint_v1",
        "artifact_key": key,
        "source_path": model.source_path,
        "contract_name": model.contract_name,
        "compiler_version": model.compiler_version,
        "externally_seeded_functions": result.externally_seeded_functions,
        "proven_restricted_functions": result.restricted_functions,
        "activated_restricted_functions": result.activated_restricted_functions,
        "iterations": result.iterations,
        "state_variable_count": len(states),
        "tainted_state_count": len(tainted),
        "direct_external_state_count": len(direct_paths),
        "private_or_internal_tainted_count": len(private_tainted),
        "private_or_internal_downstream_count": len(private_downstream),
        "direct_external_state_paths": sorted(x for x in direct_paths if x),
        "private_or_internal_downstream_paths": [str(x["path"]) for x in private_downstream],
        "state_variables": states,
        "state_edges": result.state_edges,
        "write_events": result.write_events,
    }


def _rebind_artifact_source_paths_from_pairs(
    artifacts: dict[str, dict[str, Any]],
    pairs: list[dict[str, Any]],
) -> tuple[int, int]:
    """Make current pair-manifest source locations authoritative.

    Layout facts are reusable by source hash, but cached filesystem paths are
    not reusable after an older experiment directory is deleted or moved.
    """
    desired: dict[str, str] = {}
    conflicts = 0
    for pair in pairs:
        for key_field, path_field in (("proxy_artifact_key", "proxy_source_path"), ("logic_artifact_key", "logic_source_path")):
            key = str(pair.get(key_field) or "")
            path = str(pair.get(path_field) or "")
            if not key or not path:
                continue
            previous = desired.get(key)
            if previous is not None and previous != path:
                conflicts += 1
                continue
            desired[key] = path
    rebound = 0
    for key, path in desired.items():
        art = artifacts.get(key)
        if art is None:
            continue
        if str(art.get("source_path") or "") != path:
            updated = dict(art)
            updated["source_path"] = path
            artifacts[key] = updated
            rebound += 1
    return rebound, conflicts


def run_upgradeable_and_single_detection(
    *,
    pairs_path: str,
    artifact_layouts_path: str,
    bit_overlaps_path: str,
    out_dir: str,
    install_solc: bool = False,
    workers: int = 6,
    max_version_attempts: int = 8,
    pair_limit: int | None = None,
) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    artifacts = _artifact_by_key(artifact_layouts_path)
    pairs = list(read_jsonl(pairs_path))
    if pair_limit is not None:
        pairs = pairs[: max(0, int(pair_limit))]
    source_path_rebindings, source_path_conflicts = _rebind_artifact_source_paths_from_pairs(artifacts, pairs)
    if source_path_rebindings or source_path_conflicts:
        print(
            f"detector source-path preflight: rebound={source_path_rebindings} conflicts={source_path_conflicts}",
            flush=True,
        )
    pair_map = {_pair_key(p): p for p in pairs}
    overlaps_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(bit_overlaps_path):
        k = _pair_key(row)
        if k in pair_map:
            overlaps_by_pair[k].append(row)
    keys: set[str] = set()
    for p in pairs:
        keys.add(str(p["proxy_artifact_key"])); keys.add(str(p["logic_artifact_key"]))

    models, compile_failures = _compile_models(
        artifacts, keys,
        install_solc=install_solc,
        workers=workers,
        max_version_attempts=max_version_attempts,
    )
    write_jsonl(out / "compile_failures.jsonl", compile_failures)

    # Single-contract direction reuses the same compiled models.
    single_rows: list[dict[str, Any]] = []
    single_failures: list[dict[str, Any]] = []
    single_analysis: dict[str, AnalysisResult] = {}
    for i, key in enumerate(sorted(models), 1):
        model = models[key]
        try:
            res = analyze_contract_taint(model, seed_external_inputs=True)
            single_analysis[key] = res
            single_rows.append(_single_result_row(key, model, res))
        except Exception as exc:
            failure = {
                "schema": "slotwarner_single_contract_bit_taint_v1",
                "artifact_key": key,
                "source_path": model.source_path,
                "contract_name": model.contract_name,
                "analysis_error": f"{type(exc).__name__}:{exc}",
            }
            single_rows.append(failure)
            single_failures.append(failure)
        if i % 25 == 0 or i == len(models):
            print(f"single-contract bit taint {i}/{len(models)}", flush=True)
    write_jsonl(out / "single_contract_results.jsonl", single_rows)
    write_jsonl(out / "single_contract_analysis_failures.jsonl", single_failures)

    # `all_effects` keeps every physical bit effect for auditability.  Only effects
    # classified as cross-variable/misaligned are promoted to storage-conflict
    # candidates.  Compatible same-variable alignment is expected in many proxy designs
    # and must not be counted as a conflict candidate.
    all_effects: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    aligned_effects: list[dict[str, Any]] = []
    pair_rows: list[dict[str, Any]] = []
    proxy_downstream_rows: list[dict[str, Any]] = []
    pair_skips: list[dict[str, Any]] = []
    # Pair-specific logic analysis is cached by (logic artifact, proxy selector set).
    # This removes logic entry points whose 4-byte selector is implemented directly by
    # the proxy/base contracts, because such calls are dispatched locally and do not
    # enter fallback delegation.
    pair_logic_cache: dict[tuple[str, tuple[str, ...]], AnalysisResult] = {}
    selector_shadowed_pairs = 0
    selector_shadowed_functions_total = 0
    for idx, pair in enumerate(pairs, 1):
        pkey = str(pair["proxy_artifact_key"]); lkey = str(pair["logic_artifact_key"])
        pm = models.get(pkey); lm = models.get(lkey)
        if not pm or not lm:
            reasons = []
            if not pm: reasons.append("proxy_model_unavailable")
            if not lm: reasons.append("logic_model_unavailable")
            row = {**pair, "status": "taint_model_unavailable", "skip_reasons": reasons}
            pair_rows.append(row)
            pair_skips.append(row)
            continue
        proxy_selectors = set() if bool(pair.get("disable_selector_interception")) else _external_selector_set(pm)
        cache_key = (lkey, tuple(sorted(proxy_selectors)))
        la = pair_logic_cache.get(cache_key)
        if la is None:
            try:
                la = analyze_contract_taint(
                    lm, seed_external_inputs=True,
                    excluded_external_selectors=proxy_selectors,
                    include_guarded_entries=True,
                )
                pair_logic_cache[cache_key] = la
            except Exception as exc:
                row = {
                    **pair,
                    "status": "taint_model_unavailable",
                    "skip_reasons": ["pair_specific_logic_analysis_unavailable"],
                    "analysis_error": f"{type(exc).__name__}:{exc}",
                }
                pair_rows.append(row); pair_skips.append(row)
                continue
        blocked_functions = list(la.selector_blocked_functions or [])
        if blocked_functions:
            selector_shadowed_pairs += 1
            selector_shadowed_functions_total += len(blocked_functions)
        seeds: dict[str, BitInfluence] = {}
        pfind: list[dict[str, Any]] = []
        unresolved_overlap_paths = 0
        for ov in overlaps_by_pair.get(_pair_key(pair), []):
            lpath = str(ov.get("logic_path") or "")
            ppath = str(ov.get("proxy_path") or "")
            lfp = lm.footprints_by_path.get(lpath); pfp = pm.footprints_by_path.get(ppath)
            if not lfp or not pfp:
                unresolved_overlap_paths += 1
                continue
            linf = la.state_taint.get(lpath, BitInfluence(width=int(lfp["width_bits"])))
            lwrite = int(la.write_effect_masks.get(lpath, 0)) & width_mask(int(lfp["width_bits"]))
            physical_taint = linf.mask << int(lfp["slot_bit_start"])
            physical_write = lwrite << int(lfp["slot_bit_start"])
            overlap_mask = range_mask(int(ov["overlap_slot_bit_start"]), int(ov["overlap_slot_bit_end"]), width=256)
            taint_hit = physical_taint & overlap_mask
            write_hit = physical_write & overlap_mask
            if not (taint_hit or write_hit):
                continue
            proxy_rel_taint = (taint_hit >> int(pfp["slot_bit_start"])) & width_mask(int(pfp["width_bits"]))
            alignment_class = _alignment_class(ov, lpath, ppath)
            alignment_compatibility_reason = _alignment_compatibility_reason(ov, lpath, ppath)
            is_conflict_candidate = alignment_class != "compatible_alignment"
            # Downstream proxy propagation belongs to the cross-layout mismatch path.
            # Aligned same-variable effects are retained as evidence but are not used as
            # mismatch seeds, otherwise normal proxy state updates dominate the result.
            if proxy_rel_taint and is_conflict_candidate:
                existing = seeds.get(ppath, BitInfluence(width=int(pfp["width_bits"])))
                projected = BitInfluence(
                    width=int(pfp["width_bits"]),
                    mask=proxy_rel_taint,
                    source_masks={f"PROJECTED:{lm.contract_name}:{lpath}": proxy_rel_taint},
                    notes=("cross_layout_projection",),
                )
                # union seeds
                sm = dict(existing.source_masks)
                for k, v in projected.source_masks.items():
                    sm[k] = sm.get(k, 0) | v
                seeds[ppath] = BitInfluence(width=existing.width, mask=existing.mask | projected.mask, source_masks=sm, notes=existing.notes + projected.notes)
            finding = {
                "schema": "slotwarner_upgradeable_bit_effect_v2",
                "proxy_address": pair.get("proxy_address"),
                "logic_address": pair.get("logic_address"),
                "proxy_contract": pm.contract_name,
                "logic_contract": lm.contract_name,
                "relation_kind": pair.get("relation_kind"),
                "slot": ov.get("slot"),
                "logic_path": lpath,
                "proxy_path": ppath,
                "logic_tainted": bool(linf.mask),
                "logic_taint_mask_hex": hex(linf.mask),
                "logic_write_effect_mask_hex": hex(lwrite),
                "physical_taint_hit_mask_hex": hex(taint_hit),
                "physical_write_hit_mask_hex": hex(write_hit),
                "proxy_projected_taint_mask_hex": hex(proxy_rel_taint),
                "proxy_projected_affected_bits": int(proxy_rel_taint).bit_count(),
                "proxy_width_bits": int(pfp["width_bits"]),
                "proxy_projected_coverage_ratio": int(proxy_rel_taint).bit_count() / int(pfp["width_bits"]) if int(pfp["width_bits"]) else 0.0,
                "proxy_visibility": pm.footprint_visibility.get(ppath, "internal"),
                "proxy_roles": sorted((single_analysis.get(pkey).roles.get(ppath, set()) if single_analysis.get(pkey) else set())),
                "logic_roles": sorted(la.roles.get(lpath, set())),
                "logic_visibility": lm.footprint_visibility.get(lpath, "internal"),
                "proxy_direct_selector_count": len(proxy_selectors),
                "logic_selector_blocked_functions": blocked_functions,
                "finding_kind": "tainted_bit_collision" if taint_hit else "reachable_write_collision",
                "overlap_kind": ov.get("overlap_kind"),
                "storage_shape_relation": ov.get("storage_shape_relation"),
                "proxy_type": ov.get("proxy_type"),
                "logic_type": ov.get("logic_type"),
                "alignment_class": alignment_class,
                "alignment_compatibility_reason": alignment_compatibility_reason,
                "is_storage_conflict_candidate": is_conflict_candidate,
            }
            all_effects.append(finding)
            if is_conflict_candidate:
                pfind.append(finding); findings.append(finding)
            else:
                aligned_effects.append(finding)

        # Layout evolution can also replace old direct state with a new dynamic
        # namespace rooted at the same declared slot (e.g., mapping seed).  This
        # relation is not a direct bit overlap, so it is handled separately from
        # the physical-overlap loop above.  It is promoted to an operational
        # candidate only when the new namespace is actually written from a
        # public/external entry; guarded entries are retained for pair-level
        # upgrade compatibility analysis just like guarded direct writes.
        ns_reinterpretations = _direct_to_namespace_seed_reinterpretations(
            (pm.layout_record or {}).get("footprints") or {},
            (lm.layout_record or {}).get("footprints") or {},
        )
        if ns_reinterpretations:
            from .namespace_detector import analyze_namespace_influence
            ns_influence = analyze_namespace_influence(
                lm,
                excluded_external_selectors=proxy_selectors,
                include_guarded_entries=True,
            )
            for nr in ns_reinterpretations:
                npath = str(nr.get("logic_path") or "")
                inf = ns_influence.get(npath) or {}
                operational = bool(inf.get("reachable_write"))
                nfinding = {
                    "schema": "slotwarner_upgradeable_bit_effect_v2",
                    "proxy_address": pair.get("proxy_address"),
                    "logic_address": pair.get("logic_address"),
                    "proxy_contract": pm.contract_name,
                    "logic_contract": lm.contract_name,
                    "relation_kind": pair.get("relation_kind"),
                    "slot": nr.get("slot"),
                    "logic_path": npath,
                    "proxy_path": nr.get("proxy_path"),
                    "logic_tainted": bool(inf.get("external_value_influence") or inf.get("external_location_influence")),
                    "logic_taint_mask_hex": "0x0",
                    "logic_write_effect_mask_hex": "0x0",
                    "physical_taint_hit_mask_hex": "0x0",
                    "physical_write_hit_mask_hex": "0x0",
                    "proxy_projected_taint_mask_hex": "0x0",
                    "proxy_projected_affected_bits": 0,
                    "proxy_width_bits": 0,
                    "proxy_projected_coverage_ratio": 0.0,
                    "proxy_visibility": pm.footprint_visibility.get(str(nr.get("proxy_path") or ""), "internal"),
                    "proxy_roles": sorted((single_analysis.get(pkey).roles.get(str(nr.get("proxy_path") or ""), set()) if single_analysis.get(pkey) else set())),
                    "logic_roles": [],
                    "logic_visibility": str(inf.get("visibility") or "internal"),
                    "proxy_direct_selector_count": len(proxy_selectors),
                    "logic_selector_blocked_functions": blocked_functions,
                    "finding_kind": "namespace_seed_reinterpretation",
                    "overlap_kind": "namespace_seed_reinterpretation",
                    "storage_shape_relation": "direct_to_namespace",
                    "proxy_type": nr.get("proxy_type"),
                    "logic_type": nr.get("logic_type"),
                    "alignment_class": "direct_to_namespace_seed_reinterpretation",
                    "alignment_compatibility_reason": "",
                    "namespace_kind": nr.get("logic_namespace_kind"),
                    "namespace_reachable_write": operational,
                    "namespace_external_value_influence": bool(inf.get("external_value_influence")),
                    "namespace_external_location_influence": bool(inf.get("external_location_influence")),
                    "namespace_write_functions": list(inf.get("write_functions") or []),
                    "is_storage_conflict_candidate": operational,
                }
                all_effects.append(nfinding)
                if operational:
                    pfind.append(nfinding)
                    findings.append(nfinding)

        downstream = None
        if seeds:
            try:
                pres = analyze_contract_taint(pm, initial_state_masks=seeds, seed_external_inputs=False)
                downstream_states = [x for x in pres.state_rows(pm) if x["tainted"]]
                downstream = {
                    "proxy_address": pair.get("proxy_address"),
                    "logic_address": pair.get("logic_address"),
                    "proxy_contract": pm.contract_name,
                    "seed_paths": {k: {"mask_hex": hex(v.mask), "intervals": [[a,b] for a,b in v.intervals]} for k, v in seeds.items()},
                    "downstream_tainted_states": downstream_states,
                    "state_edges": pres.state_edges,
                    "iterations": pres.iterations,
                }
                proxy_downstream_rows.append(downstream)
            except Exception as exc:
                downstream = {
                    "proxy_address": pair.get("proxy_address"),
                    "logic_address": pair.get("logic_address"),
                    "proxy_contract": pm.contract_name,
                    "seed_paths": {k: {"mask_hex": hex(v.mask), "intervals": [[a,b] for a,b in v.intervals]} for k, v in seeds.items()},
                    "error": f"{type(exc).__name__}:{exc}",
                }
                proxy_downstream_rows.append(downstream)
        pair_rows.append({
            **pair,
            "status": "analyzed",
            "geometric_overlap_records": len(overlaps_by_pair.get(_pair_key(pair), [])),
            "storage_conflict_candidates": len(pfind),
            "projected_seed_variables": len(seeds),
            "proxy_downstream_tainted_count": len((downstream or {}).get("downstream_tainted_states") or []),
            "unresolved_overlap_paths": unresolved_overlap_paths,
            "proxy_downstream_error": (downstream or {}).get("error"),
            "proxy_direct_selector_count": len(proxy_selectors),
            "logic_selector_blocked_functions": blocked_functions,
        })
        if idx % 20 == 0 or idx == len(pairs):
            print(f"upgradeable bit collision {idx}/{len(pairs)} findings={len(findings)}", flush=True)

    write_jsonl(out / "upgradeable_pair_summary.jsonl", pair_rows)
    write_jsonl(out / "upgradeable_pair_skips.jsonl", pair_skips)
    write_jsonl(out / "upgradeable_all_bit_effects.jsonl", all_effects)
    write_jsonl(out / "upgradeable_aligned_effects.jsonl", aligned_effects)
    write_jsonl(out / "upgradeable_collision_findings.jsonl", findings)
    write_jsonl(out / "proxy_downstream_taint.jsonl", proxy_downstream_rows)

    single_ok = [r for r in single_rows if not r.get("analysis_error")]
    single_counts = Counter()
    private_impacts = 0
    for r in single_ok:
        if int(r.get("tainted_state_count") or 0): single_counts["contracts_with_tainted_state"] += 1
        if int(r.get("private_or_internal_downstream_count") or 0): single_counts["contracts_with_private_downstream"] += 1
        private_impacts += int(r.get("private_or_internal_downstream_count") or 0)
    find_counts = Counter(str(x.get("finding_kind") or "") for x in findings)
    alignment_counts = Counter(str(x.get("alignment_class") or "") for x in all_effects)
    summary = {
        "schema": "slotwarner_bit_level_detection_summary_v1",
        "scope": {
            "upgradeable_pairs_requested": len(pairs),
            "unique_artifacts_requested": len(keys),
            "compiled_models": len(models),
            "compile_failures": len(compile_failures),
            "single_analysis_failures": len(single_failures),
            "pair_skips": len(pair_skips),
            "source_path_rebindings": source_path_rebindings,
            "source_path_conflicts": source_path_conflicts,
            "single_contract_direction_reuses_upgradeable_artifacts": True,
        },
        "single_contract": {
            "contracts_analyzed": len(single_ok),
            "contracts_with_tainted_state": single_counts["contracts_with_tainted_state"],
            "contracts_with_private_or_internal_downstream": single_counts["contracts_with_private_downstream"],
            "private_or_internal_downstream_state_records": private_impacts,
        },
        "upgradeable": {
            "pairs_analyzed": sum(1 for r in pair_rows if r.get("status") == "analyzed"),
            "all_bit_effect_records": len(all_effects),
            "aligned_effect_records": len(aligned_effects),
            "storage_conflict_candidates": len(findings),
            "candidate_kinds": dict(find_counts),
            "alignment_classes": dict(alignment_counts),
            "pairs_with_storage_conflict_candidates": sum(1 for r in pair_rows if int(r.get("storage_conflict_candidates") or 0) > 0),
            "pairs_with_projected_taint": sum(1 for r in pair_rows if int(r.get("projected_seed_variables") or 0) > 0),
            "proxy_downstream_records": len(proxy_downstream_rows),
            "proxy_downstream_errors": sum(1 for r in proxy_downstream_rows if r.get("error")),
            "unresolved_overlap_paths": sum(int(r.get("unresolved_overlap_paths") or 0) for r in pair_rows),
            "pairs_with_proxy_local_selector_interception": selector_shadowed_pairs,
            "selector_blocked_logic_functions_total": selector_shadowed_functions_total,
            "dispatch_filter": "proxy-local 4-byte selectors are excluded from fallback-delegated logic entry points when compiler AST selector evidence is available",
        },
        "method_scope": {
            "external_sources": "public/external parameters + selected EVM environment sources",
            "access_control": "pair-level collision detection uses operational reachability (guarded public/external writes are retained); single-contract attacker-influence analysis keeps proven caller/state guards restricted",
            "bit_semantics": "typed Solidity state access; raw SLOAD/SSTORE bool semantics excluded",
            "dynamic_storage": "direct fixed storage footprints are analyzed at bit level; mapping/dynamic namespaces are not yet projected as direct bits",
            "severity": "facts-first; rejected coverage-only x/y thresholds are not used as final severity cutoffs",
        },
        "outputs": {
            "single_contract_results": str(out / "single_contract_results.jsonl"),
            "upgradeable_pair_summary": str(out / "upgradeable_pair_summary.jsonl"),
            "upgradeable_all_bit_effects": str(out / "upgradeable_all_bit_effects.jsonl"),
            "upgradeable_aligned_effects": str(out / "upgradeable_aligned_effects.jsonl"),
            "upgradeable_collision_findings": str(out / "upgradeable_collision_findings.jsonl"),
            "proxy_downstream_taint": str(out / "proxy_downstream_taint.jsonl"),
            "compile_failures": str(out / "compile_failures.jsonl"),
            "single_analysis_failures": str(out / "single_contract_analysis_failures.jsonl"),
            "pair_skips": str(out / "upgradeable_pair_skips.jsonl"),
        },
    }
    (out / "detection_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary

