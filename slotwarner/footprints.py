from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import re


class FootprintIncomplete(RuntimeError):
    pass


@dataclass
class _Budget:
    max_direct: int
    count: int = 0

    def consume(self) -> None:
        self.count += 1
        if self.count > self.max_direct:
            raise FootprintIncomplete(f"too_many_direct_footprints:{self.count}>{self.max_direct}")


def _direct(
    *,
    root_name: str,
    leaf_name: str,
    path: str,
    root_ast_id: int | None,
    declaring_contract: str,
    slot: int,
    offset_bytes: int,
    size_bytes: int,
    type_meta: dict[str, Any],
    budget: _Budget,
) -> dict[str, Any]:
    if size_bytes <= 0 or size_bytes > 32:
        raise FootprintIncomplete(f"invalid_leaf_size:{path}:{size_bytes}")
    if offset_bytes < 0 or offset_bytes + size_bytes > 32:
        raise FootprintIncomplete(f"invalid_leaf_offset:{path}:{offset_bytes}+{size_bytes}")
    budget.consume()
    local_start = offset_bytes * 8
    width = size_bytes * 8
    global_start = slot * 256 + local_start
    return {
        "kind": "direct",
        "root_name": root_name,
        "leaf_name": leaf_name,
        "path": path,
        "root_ast_id": root_ast_id,
        "declaring_contract": declaring_contract,
        "slot": slot,
        "offset_bytes": offset_bytes,
        "size_bytes": size_bytes,
        "slot_bit_start": local_start,
        "slot_bit_end": local_start + width - 1,
        "start_bit": global_start,
        "end_bit": global_start + width - 1,
        "width_bits": width,
        "type_label": str(type_meta.get("label") or ""),
        "type_category": str(type_meta.get("category") or ""),
        "encoding": str(type_meta.get("encoding") or ""),
    }


def _namespace(
    *,
    kind: str,
    root_name: str,
    path: str,
    root_ast_id: int | None,
    declaring_contract: str,
    slot: int,
    type_meta: dict[str, Any],
) -> dict[str, Any]:
    details = type_meta.get("details") or {}
    row = {
        "kind": kind,
        "root_name": root_name,
        "path": path,
        "root_ast_id": root_ast_id,
        "declaring_contract": declaring_contract,
        "slot": slot,
        "type_label": str(type_meta.get("label") or ""),
        "type_category": str(type_meta.get("category") or ""),
        "encoding": str(type_meta.get("encoding") or ""),
    }
    if kind == "mapping_namespace":
        key = details.get("key") or {}
        value = details.get("value") or {}
        row["mapping_key_type"] = str(key.get("label") or key.get("category") or "")
        row["mapping_value_type"] = str(value.get("label") or value.get("category") or "")
    return row


def _emit_type(
    direct: list[dict[str, Any]],
    namespaces: list[dict[str, Any]],
    *,
    root_name: str,
    leaf_name: str,
    root_ast_id: int | None,
    declaring_contract: str,
    slot: int,
    offset_bytes: int,
    t: dict[str, Any],
    path: str,
    budget: _Budget,
) -> None:
    category = str(t.get("category") or "")
    encoding = str(t.get("encoding") or "")
    try:
        nbytes = int(t.get("numberOfBytes") or 32)
    except Exception as exc:
        raise FootprintIncomplete(f"invalid_numberOfBytes:{path}:{t.get('numberOfBytes')}") from exc
    details = t.get("details") or {}

    if category == "mapping" or encoding == "mapping":
        namespaces.append(_namespace(
            kind="mapping_namespace", root_name=root_name, path=path,
            root_ast_id=root_ast_id, declaring_contract=declaring_contract,
            slot=slot, type_meta=t,
        ))
        return

    if category == "dynamic_array" or encoding == "dynamic_array":
        direct.append(_direct(
            root_name=root_name, leaf_name=leaf_name, path=path,
            root_ast_id=root_ast_id, declaring_contract=declaring_contract,
            slot=slot, offset_bytes=0, size_bytes=32, type_meta=t, budget=budget,
        ))
        namespaces.append(_namespace(
            kind="dynamic_array_namespace", root_name=root_name, path=path,
            root_ast_id=root_ast_id, declaring_contract=declaring_contract,
            slot=slot, type_meta=t,
        ))
        return

    if encoding == "bytes" or category in {"string", "bytes_dynamic"}:
        direct.append(_direct(
            root_name=root_name, leaf_name=leaf_name, path=path,
            root_ast_id=root_ast_id, declaring_contract=declaring_contract,
            slot=slot, offset_bytes=0, size_bytes=32, type_meta=t, budget=budget,
        ))
        namespaces.append(_namespace(
            kind="bytes_namespace", root_name=root_name, path=path,
            root_ast_id=root_ast_id, declaring_contract=declaring_contract,
            slot=slot, type_meta=t,
        ))
        return

    if category == "struct":
        members = details.get("members") or []
        if not isinstance(members, list):
            raise FootprintIncomplete(f"struct_members_invalid:{path}")
        for member in members:
            if not isinstance(member, dict):
                raise FootprintIncomplete(f"struct_member_invalid:{path}")
            mt = member.get("type") or {}
            member_label = str(member.get("label") or "member")
            _emit_type(
                direct, namespaces,
                root_name=root_name,
                leaf_name=member_label,
                root_ast_id=root_ast_id,
                declaring_contract=declaring_contract,
                slot=slot + int(member.get("slot") or 0),
                offset_bytes=int(member.get("offset") or 0),
                t=mt,
                path=f"{path}.{member_label}",
                budget=budget,
            )
        return

    if category == "fixed_array":
        base = details.get("base") or {}
        try:
            length = int(details.get("length") or 0)
        except Exception as exc:
            raise FootprintIncomplete(f"fixed_array_length_invalid:{path}") from exc
        if length <= 0:
            raise FootprintIncomplete(f"fixed_array_length_invalid:{path}:{length}")

        # Some proxy-storage frameworks reserve the remainder of an enormous
        # logical layout with declarations such as ``uint256[2**64 - 40] __endGap``.
        # Expanding billions/trillions of reserved words is neither meaningful nor
        # feasible.  Preserve the reconstructed slot arithmetic but omit only these
        # explicitly named, oversized padding arrays from leaf-footprint expansion.
        leaf = str(path or "").split(".")[-1].lower()
        if length > budget.max_direct and re.fullmatch(r"_*(?:end)?gap(?:_reserved)?", leaf):
            return

        base_packable = bool(base.get("packable"))
        base_bytes = int(base.get("numberOfBytes") or 32)
        base_slots = max(1, int(base.get("slots") or 1))
        if base_packable and base_bytes <= 32:
            per_slot = max(1, 32 // base_bytes)
            for i in range(length):
                _emit_type(
                    direct, namespaces,
                    root_name=root_name,
                    leaf_name=f"{leaf_name}[{i}]",
                    root_ast_id=root_ast_id,
                    declaring_contract=declaring_contract,
                    slot=slot + i // per_slot,
                    offset_bytes=(i % per_slot) * base_bytes,
                    t=base,
                    path=f"{path}[{i}]",
                    budget=budget,
                )
        else:
            for i in range(length):
                _emit_type(
                    direct, namespaces,
                    root_name=root_name,
                    leaf_name=f"{leaf_name}[{i}]",
                    root_ast_id=root_ast_id,
                    declaring_contract=declaring_contract,
                    slot=slot + i * base_slots,
                    offset_bytes=0,
                    t=base,
                    path=f"{path}[{i}]",
                    budget=budget,
                )
        return

    if encoding == "inplace" and nbytes <= 32:
        direct.append(_direct(
            root_name=root_name, leaf_name=leaf_name, path=path,
            root_ast_id=root_ast_id, declaring_contract=declaring_contract,
            slot=slot, offset_bytes=offset_bytes, size_bytes=nbytes,
            type_meta=t, budget=budget,
        ))
        return

    raise FootprintIncomplete(
        f"unsupported_storage_type:{path}:category={category}:encoding={encoding}:bytes={nbytes}"
    )


def layout_footprints(layout: dict[str, Any], *, max_direct_footprints: int = 50000) -> dict[str, Any]:
    direct: list[dict[str, Any]] = []
    namespaces: list[dict[str, Any]] = []
    budget = _Budget(max_direct=max(1, int(max_direct_footprints)))

    for item in layout.get("storage") or []:
        if not isinstance(item, dict):
            raise FootprintIncomplete("storage_item_not_object")
        t = item.get("type") or {}
        label = str(item.get("label") or "variable")
        ast_id = int(item["astId"]) if isinstance(item.get("astId"), int) else None
        try:
            slot = int(str(item.get("slot") or "0"), 0)
            offset = int(item.get("offset") or 0)
        except Exception as exc:
            raise FootprintIncomplete(f"invalid_storage_location:{label}") from exc
        _emit_type(
            direct, namespaces,
            root_name=label,
            leaf_name=label,
            root_ast_id=ast_id,
            declaring_contract=str(item.get("declaringContract") or ""),
            slot=slot,
            offset_bytes=offset,
            t=t,
            path=label,
            budget=budget,
        )

    direct.sort(key=lambda x: (x["slot"], x["slot_bit_start"], x["slot_bit_end"], x["path"]))
    namespaces.sort(key=lambda x: (x["slot"], x["kind"], x["path"]))
    return {
        "scope": "declared_direct_storage_and_namespace_seeds",
        "direct_complete": True,
        "direct": direct,
        "namespaces": namespaces,
        "direct_count": len(direct),
        "namespace_count": len(namespaces),
    }
