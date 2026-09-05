from __future__ import annotations

from pathlib import Path
from typing import Any

from slotwarner_layout_validate.compiler import all_asts, compile_ast_selecting_version, compile_with_version
from slotwarner_layout_validate.reconstruct import AstProgram, ReconstructionIncomplete, reconstruct_storage_layout
from slotwarner_layout_validate.utils import extract_pragmas

from .footprints import FootprintIncomplete, layout_footprints


def _select_contract(asts: dict[str, dict[str, Any]], primary_key: str, hint: str) -> tuple[str, str]:
    program = AstProgram(asts, primary_key)
    if hint:
        try:
            program.target_contract(hint)
            return hint, "exact_hint"
        except Exception:
            pass

    primary_base = primary_key.replace("\\", "/").split("/")[-1]
    concrete: list[str] = []
    for (source_key, name), items in program.contracts_by_source_name.items():
        if source_key.replace("\\", "/").split("/")[-1] != primary_base:
            continue
        for c in items:
            if str(c.get("contractKind") or "contract") != "contract":
                continue
            if c.get("abstract") is True:
                continue
            concrete.append(str(name))
    concrete = list(dict.fromkeys(concrete))
    if len(concrete) == 1:
        return concrete[0], "single_concrete_contract"
    raise ReconstructionIncomplete(
        f"target_contract_not_resolved:hint={hint};concrete_candidates={concrete[:12]}"
    )


def analyze_artifact(task: dict[str, Any]) -> dict[str, Any]:
    path = Path(task["source_path"])
    hint = str(task.get("contract_hint") or "")
    base: dict[str, Any] = {
        "schema": "slotwarner_v4_artifact_v1",
        "artifact_key": task["artifact_key"],
        "source_sha256": task["source_sha256"],
        "source_path": str(path),
        "contract_hint": hint,
        "success": False,
        "layout_mode": "none",
        "compiler_version": None,
        "contract_name": None,
        "target_selection": None,
        "footprints": None,
        "layout_end_slot": None,
        "layout_end_offset": None,
        "error_category": None,
        "error": None,
    }

    try:
        raw = path.read_text(encoding="utf-8-sig", errors="replace")
    except Exception as exc:
        base["error_category"] = "source_read_failed"
        base["error"] = f"{type(exc).__name__}:{exc}"
        return base

    pragmas = extract_pragmas(raw)
    preferred_version = str(task.get("preferred_compiler_version") or "").strip()
    preferred_failure = None
    if preferred_version:
        compile_result = compile_with_version(
            path, preferred_version, phase="ast", install=bool(task.get("install_solc"))
        )
        if not compile_result.ok:
            preferred_failure = f"preferred_solc={preferred_version}: {compile_result.error_text or compile_result.failure_category}"
            compile_result = compile_ast_selecting_version(
                path,
                pragmas,
                install=bool(task.get("install_solc")),
                policy=str(task.get("compiler_policy") or "lowest"),
                max_attempts=int(task.get("max_version_attempts") or 8),
            )
    else:
        compile_result = compile_ast_selecting_version(
            path,
            pragmas,
            install=bool(task.get("install_solc")),
            policy=str(task.get("compiler_policy") or "lowest"),
            max_attempts=int(task.get("max_version_attempts") or 8),
        )
    if not compile_result.ok or not compile_result.output:
        base["error_category"] = compile_result.failure_category or "compile_failed"
        base["error"] = ((preferred_failure + "\n") if preferred_failure else "") + str(compile_result.error_text or "")
        base["compiler_version"] = compile_result.compiler_version
        return base

    try:
        asts = all_asts(compile_result.output)
        primary_key = compile_result.primary_source_key or path.name
        cname, selection = _select_contract(asts, primary_key, hint)
        source_texts = dict(compile_result.source_bundle_texts or {})
        primary_text = source_texts.get(primary_key, raw)
        layout = reconstruct_storage_layout(
            asts,
            primary_key,
            cname,
            primary_text,
            source_texts,
        )
        footprints = layout_footprints(
            layout,
            max_direct_footprints=int(task.get("max_direct_footprints") or 50000),
        )
        base.update({
            "success": True,
            "layout_mode": "validated_ast_v1_4",
            "compiler_version": compile_result.compiler_version,
            "contract_name": cname,
            "target_selection": selection,
            "footprints": footprints,
            "layout_end_slot": layout.get("end_slot"),
            "layout_end_offset": layout.get("end_offset"),
            "bundle_sha256": compile_result.source_bundle_sha256,
            "bundle_sources": compile_result.source_bundle_sources,
            "bundle_transformations": compile_result.source_bundle_transformations or [],
        })
        return base
    except FootprintIncomplete as exc:
        base["error_category"] = "footprint_incomplete"
        base["error"] = str(exc)
        base["compiler_version"] = compile_result.compiler_version
        return base
    except ReconstructionIncomplete as exc:
        base["error_category"] = "layout_reconstruction_incomplete"
        base["error"] = str(exc)
        base["compiler_version"] = compile_result.compiler_version
        return base
    except Exception as exc:
        base["error_category"] = "layout_analysis_exception"
        base["error"] = f"{type(exc).__name__}:{exc}"
        base["compiler_version"] = compile_result.compiler_version
        return base
