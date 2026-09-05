from __future__ import annotations

from collections import defaultdict
from typing import Any


def _group_by_slot(rows: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    out: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        out[int(row["slot"])].append(row)
    return dict(out)


def _interval_overlap(a: dict[str, Any], b: dict[str, Any]) -> tuple[int, int] | None:
    start = max(int(a["slot_bit_start"]), int(b["slot_bit_start"]))
    end = min(int(a["slot_bit_end"]), int(b["slot_bit_end"]))
    if start > end:
        return None
    return start, end


def _interval_relation(a: dict[str, Any], b: dict[str, Any]) -> str:
    a0, a1 = int(a["slot_bit_start"]), int(a["slot_bit_end"])
    b0, b1 = int(b["slot_bit_start"]), int(b["slot_bit_end"])
    if a0 == b0 and a1 == b1:
        return "exact_interval_overlap"
    if a0 <= b0 and a1 >= b1:
        return "proxy_contains_logic"
    if b0 <= a0 and b1 >= a1:
        return "logic_contains_proxy"
    return "partial_bit_overlap"


def _shape_relation(a: dict[str, Any], b: dict[str, Any]) -> str:
    if (
        a.get("type_category") == b.get("type_category")
        and a.get("type_label") == b.get("type_label")
        and int(a.get("size_bytes") or 0) == int(b.get("size_bytes") or 0)
    ):
        return "same_storage_shape"
    if int(a.get("size_bytes") or 0) == int(b.get("size_bytes") or 0):
        return "same_width_different_shape"
    return "different_width_or_shape"


def compare_pair(
    pair: dict[str, Any],
    proxy_artifact: dict[str, Any],
    logic_artifact: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Compare one source pair at the geometric storage-layout layer only.

    v4.0 deliberately stops at physical geometry.  Reachable writes and value influence
    are separate later stages; they are not inferred here.
    """
    proxy_rows = list((proxy_artifact.get("footprints") or {}).get("direct") or [])
    logic_rows = list((logic_artifact.get("footprints") or {}).get("direct") or [])
    proxy_by_slot = _group_by_slot(proxy_rows)
    logic_by_slot = _group_by_slot(logic_rows)

    overlaps: list[dict[str, Any]] = []
    slot_only: list[dict[str, Any]] = []

    common_slots = sorted(set(proxy_by_slot) & set(logic_by_slot))
    for slot in common_slots:
        for pv in proxy_by_slot[slot]:
            for lv in logic_by_slot[slot]:
                common = {
                    "proxy_address": pair["proxy_address"],
                    "logic_address": pair["logic_address"],
                    "relation_kind": pair.get("relation_kind"),
                    "reference_block": pair.get("reference_block"),
                    "proxy_contract": proxy_artifact.get("contract_name"),
                    "logic_contract": logic_artifact.get("contract_name"),
                    "proxy_source_path": pair["proxy_source_path"],
                    "logic_source_path": pair["logic_source_path"],
                    "slot": slot,
                    "proxy_path": pv.get("path"),
                    "logic_path": lv.get("path"),
                    "proxy_type": pv.get("type_label"),
                    "logic_type": lv.get("type_label"),
                    "proxy_slot_bit_start": pv.get("slot_bit_start"),
                    "proxy_slot_bit_end": pv.get("slot_bit_end"),
                    "logic_slot_bit_start": lv.get("slot_bit_start"),
                    "logic_slot_bit_end": lv.get("slot_bit_end"),
                    "storage_shape_relation": _shape_relation(pv, lv),
                }
                ov = _interval_overlap(pv, lv)
                if ov is None:
                    slot_only.append({
                        **common,
                        "record_kind": "same_slot_non_overlap",
                    })
                else:
                    overlaps.append({
                        **common,
                        "record_kind": "bit_overlap",
                        "overlap_kind": _interval_relation(pv, lv),
                        "overlap_slot_bit_start": ov[0],
                        "overlap_slot_bit_end": ov[1],
                        "overlap_width_bits": ov[1] - ov[0] + 1,
                        "overlap_global_start_bit": slot * 256 + ov[0],
                        "overlap_global_end_bit": slot * 256 + ov[1],
                    })

    proxy_ns = list((proxy_artifact.get("footprints") or {}).get("namespaces") or [])
    logic_ns = list((logic_artifact.get("footprints") or {}).get("namespaces") or [])
    proxy_ns_by_slot = _group_by_slot(proxy_ns)
    logic_ns_by_slot = _group_by_slot(logic_ns)
    namespace_aliases: list[dict[str, Any]] = []
    for slot in sorted(set(proxy_ns_by_slot) & set(logic_ns_by_slot)):
        for a in proxy_ns_by_slot[slot]:
            for b in logic_ns_by_slot[slot]:
                namespace_aliases.append({
                    "proxy_address": pair["proxy_address"],
                    "logic_address": pair["logic_address"],
                    "relation_kind": pair.get("relation_kind"),
                    "slot": slot,
                    "proxy_path": a.get("path"),
                    "logic_path": b.get("path"),
                    "proxy_namespace_kind": a.get("kind"),
                    "logic_namespace_kind": b.get("kind"),
                    "record_kind": "namespace_seed_alias",
                })

    slot_level_records = len(overlaps) + len(slot_only)
    removed = len(slot_only)
    bit_overlap_slots = {int(x["slot"]) for x in overlaps}
    slots_removed = len(set(common_slots) - bit_overlap_slots)
    summary = {
        "proxy_address": pair["proxy_address"],
        "logic_address": pair["logic_address"],
        "relation_kind": pair.get("relation_kind"),
        "proxy_contract": proxy_artifact.get("contract_name"),
        "logic_contract": logic_artifact.get("contract_name"),
        "proxy_target_selection": proxy_artifact.get("target_selection"),
        "logic_target_selection": logic_artifact.get("target_selection"),
        "layout_mode": "validated_ast_v1_4",
        "common_direct_slots": len(common_slots),
        "slot_level_candidate_slots": len(common_slots),
        "bit_overlap_slots": len(bit_overlap_slots),
        "slots_removed_by_bit_precision": slots_removed,
        "slot_reduction_ratio": (slots_removed / len(common_slots)) if common_slots else 0.0,
        "slot_level_candidate_records": slot_level_records,
        "bit_overlap_records": len(overlaps),
        "same_slot_non_overlap_records": removed,
        "records_removed_by_bit_precision": removed,
        "record_reduction_ratio": (removed / slot_level_records) if slot_level_records else 0.0,
        "namespace_seed_alias_records": len(namespace_aliases),
        "has_slot_level_candidate": slot_level_records > 0,
        "has_bit_overlap": bool(overlaps),
        "all_slot_candidates_removed_by_bit_precision": bool(slot_level_records and not overlaps),
    }
    return overlaps, slot_only, namespace_aliases, summary
