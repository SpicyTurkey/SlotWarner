from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .artifact import analyze_artifact
from .ast_taint import analyze_contract_taint, compile_contract_model
from .compare import compare_pair
from .detector import _single_result_row, run_upgradeable_and_single_detection
from .utils import read_jsonl, sha256_file, write_jsonl


def _json_dump(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _artifact_key(path: Path, contract: str) -> str:
    raw = f"{path.resolve()}|{contract}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def _local_address(tag: str) -> str:
    return "0x" + hashlib.sha256(tag.encode("utf-8", errors="replace")).hexdigest()[-40:]


def _artifact_task(path: Path, contract: str, *, install_solc: bool) -> dict[str, Any]:
    return {
        "artifact_key": _artifact_key(path, contract),
        "source_sha256": sha256_file(path),
        "source_path": str(path.resolve()),
        "contract_hint": contract,
        "install_solc": bool(install_solc),
        "max_version_attempts": 8,
        "max_direct_footprints": 50000,
    }


def _warning_one(path: Path, contract: str, *, install_solc: bool) -> dict[str, Any]:
    task = _artifact_task(path, contract, install_solc=install_solc)
    layout = analyze_artifact(task)
    if not layout.get("success"):
        return {
            "schema": "slotwarner_user_warning_v1",
            "mode": "single_contract_warning",
            "source_path": str(path.resolve()),
            "contract": contract or None,
            "prediction": "ABSTAIN",
            "reason": layout.get("error_category") or "layout_analysis_failed",
            "detail": layout.get("error"),
            "layout": layout,
        }
    try:
        model = compile_contract_model(
            str(path.resolve()),
            str(layout.get("contract_name") or contract or ""),
            install_solc=install_solc,
            max_version_attempts=8,
            existing_layout=layout,
        )
        analysis = analyze_contract_taint(model, seed_external_inputs=True)
        detail = _single_result_row(str(layout.get("artifact_key")), model, analysis)
        warning = int(detail.get("tainted_state_count") or 0) > 0
        return {
            "schema": "slotwarner_user_warning_v1",
            "mode": "single_contract_warning",
            "source_path": str(path.resolve()),
            "contract": model.contract_name,
            "compiler_version": model.compiler_version,
            "prediction": "WARNING" if warning else "NO_WARNING",
            "interpretation": (
                "Externally influenced persistent storage was found. This is an early warning, not by itself a confirmed storage-collision vulnerability."
                if warning
                else "No externally influenced persistent storage was identified within the supported analysis scope."
            ),
            "tainted_state_count": int(detail.get("tainted_state_count") or 0),
            "direct_external_state_count": int(detail.get("direct_external_state_count") or 0),
            "private_or_internal_downstream_count": int(detail.get("private_or_internal_downstream_count") or 0),
            "direct_external_state_paths": detail.get("direct_external_state_paths") or [],
            "private_or_internal_downstream_paths": detail.get("private_or_internal_downstream_paths") or [],
            "layout": layout,
            "analysis": detail,
        }
    except Exception as exc:
        return {
            "schema": "slotwarner_user_warning_v1",
            "mode": "single_contract_warning",
            "source_path": str(path.resolve()),
            "contract": layout.get("contract_name") or contract or None,
            "prediction": "ABSTAIN",
            "reason": "taint_analysis_failed",
            "detail": f"{type(exc).__name__}:{exc}",
            "layout": layout,
        }


def command_warning(args: argparse.Namespace) -> int:
    src = Path(args.input).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    install_solc = not args.no_install_solc

    if src.is_file():
        if src.suffix.lower() != ".sol":
            raise SystemExit(f"Input must be a Solidity .sol file: {src}")
        result = _warning_one(src, args.contract or "", install_solc=install_solc)
        _json_dump(out / "warning_result.json", result)
        print(f"SlotWarner warning: {result['prediction']}  contract={result.get('contract')}  source={src}")
        if result["prediction"] == "ABSTAIN":
            print(f"Reason: {result.get('reason')}: {result.get('detail')}")
            return 2
        print(f"Tainted state variables: {result.get('tainted_state_count', 0)}")
        print(f"Result: {out / 'warning_result.json'}")
        return 0

    if not src.is_dir():
        raise SystemExit(f"Input path does not exist: {src}")
    if args.contract:
        raise SystemExit("--contract is supported for a single .sol input. For a directory, analyze the target file directly.")

    sol_files = sorted(p for p in src.rglob("*.sol") if p.is_file())
    rows: list[dict[str, Any]] = []
    for i, p in enumerate(sol_files, 1):
        row = _warning_one(p, "", install_solc=install_solc)
        rows.append(row)
        print(f"[{i}/{len(sol_files)}] {p.relative_to(src)} -> {row['prediction']}")
    write_jsonl(out / "warning_results.jsonl", rows)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["prediction"]] = counts.get(r["prediction"], 0) + 1
    summary = {
        "schema": "slotwarner_user_warning_batch_v1",
        "input_root": str(src),
        "solidity_files": len(sol_files),
        "counts": counts,
        "note": "A flattened file with multiple concrete contracts should be analyzed directly with --contract to select the target contract.",
    }
    _json_dump(out / "warning_summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 2 if counts.get("ABSTAIN", 0) else 0


def _prepare_collision_layout(path: Path, contract: str, install_solc: bool) -> dict[str, Any]:
    return analyze_artifact(_artifact_task(path, contract, install_solc=install_solc))


def command_collision(args: argparse.Namespace) -> int:
    first = Path(args.sources[0]).resolve()
    second = Path(args.sources[1]).resolve() if len(args.sources) == 2 else first
    if not first.is_file() or first.suffix.lower() != ".sol":
        raise SystemExit(f"Proxy source must be a Solidity .sol file: {first}")
    if not second.is_file() or second.suffix.lower() != ".sol":
        raise SystemExit(f"Logic source must be a Solidity .sol file: {second}")
    if len(args.sources) == 1 and (not args.proxy_contract or not args.logic_contract):
        raise SystemExit("A single flattened file contains multiple targets; provide both --proxy-contract and --logic-contract.")

    install_solc = not args.no_install_solc
    out = Path(args.out).resolve()
    if out.exists() and args.clean:
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    proxy_layout = _prepare_collision_layout(first, args.proxy_contract or "", install_solc)
    logic_layout = _prepare_collision_layout(second, args.logic_contract or "", install_solc)
    _json_dump(out / "proxy_layout.json", proxy_layout)
    _json_dump(out / "logic_layout.json", logic_layout)

    failed = []
    if not proxy_layout.get("success"):
        failed.append({"side": "proxy", "reason": proxy_layout.get("error_category"), "detail": proxy_layout.get("error")})
    if not logic_layout.get("success"):
        failed.append({"side": "logic", "reason": logic_layout.get("error_category"), "detail": logic_layout.get("error")})
    if failed:
        summary = {
            "schema": "slotwarner_user_collision_v1",
            "mode": "storage_collision_detection",
            "prediction": "ABSTAIN",
            "reason": "layout_or_compilation_failed",
            "failures": failed,
            "proxy_source": str(first),
            "logic_source": str(second),
        }
        _json_dump(out / "collision_summary.json", summary)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 2

    proxy_key = str(proxy_layout["artifact_key"])
    logic_key = str(logic_layout["artifact_key"])
    pair = {
        "pair_id": "LOCAL_PAIR_001",
        "proxy_address": _local_address(f"proxy|{first}|{proxy_layout.get('contract_name')}"),
        "logic_address": _local_address(f"logic|{second}|{logic_layout.get('contract_name')}"),
        "proxy_artifact_key": proxy_key,
        "logic_artifact_key": logic_key,
        "proxy_source_path": str(first),
        "logic_source_path": str(second),
        "relation_kind": "local_source_pair",
        "reference_block": None,
    }
    overlaps, slot_only, namespace_aliases, geom = compare_pair(pair, proxy_layout, logic_layout)
    write_jsonl(out / "pairs.jsonl", [pair])
    write_jsonl(out / "artifact_layouts.jsonl", [proxy_layout, logic_layout])
    write_jsonl(out / "bit_overlap_records.jsonl", overlaps)
    write_jsonl(out / "same_slot_non_overlap_records.jsonl", slot_only)
    write_jsonl(out / "namespace_seed_alias_records.jsonl", namespace_aliases)
    _json_dump(out / "geometry_summary.json", geom)

    detection_dir = out / "detection"
    run_upgradeable_and_single_detection(
        pairs_path=str(out / "pairs.jsonl"),
        artifact_layouts_path=str(out / "artifact_layouts.jsonl"),
        bit_overlaps_path=str(out / "bit_overlap_records.jsonl"),
        out_dir=str(detection_dir),
        install_solc=install_solc,
        workers=max(1, int(args.workers)),
        max_version_attempts=8,
        pair_limit=None,
    )
    pair_rows = list(read_jsonl(detection_dir / "upgradeable_pair_summary.jsonl"))
    skips = list(read_jsonl(detection_dir / "upgradeable_pair_skips.jsonl"))
    findings = list(read_jsonl(detection_dir / "upgradeable_collision_findings.jsonl"))
    row = pair_rows[0] if pair_rows else None
    if row is None or str(row.get("status") or "") != "analyzed":
        summary = {
            "schema": "slotwarner_user_collision_v1",
            "mode": "storage_collision_detection",
            "prediction": "ABSTAIN",
            "reason": "pair_analysis_incomplete",
            "pair_skips": skips,
            "geometry": geom,
            "proxy_contract": proxy_layout.get("contract_name"),
            "logic_contract": logic_layout.get("contract_name"),
        }
        code = 2
    else:
        candidate_count = int(row.get("storage_conflict_candidates") or 0)
        summary = {
            "schema": "slotwarner_user_collision_v1",
            "mode": "storage_collision_detection",
            "prediction": "POSITIVE" if candidate_count > 0 else "NEGATIVE",
            "proxy_contract": proxy_layout.get("contract_name"),
            "logic_contract": logic_layout.get("contract_name"),
            "proxy_source": str(first),
            "logic_source": str(second),
            "compiler_versions": {
                "proxy": proxy_layout.get("compiler_version"),
                "logic": logic_layout.get("compiler_version"),
            },
            "geometric_bit_overlaps": len(overlaps),
            "storage_conflict_candidates": candidate_count,
            "finding_count": len(findings),
            "geometry": geom,
            "interpretation": (
                "At least one operational bit-level storage-conflict candidate was identified."
                if candidate_count > 0
                else "No operational storage-conflict candidate was identified within the supported analysis scope."
            ),
        }
        code = 0
    _json_dump(out / "collision_summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Result directory: {out}")
    return code


def _project_root() -> Path:
    here = Path(__file__).resolve()
    candidates = [Path.cwd(), here.parents[1]]
    for c in candidates:
        if (c / "examples" / "single" / "SingleWarning.sol").is_file():
            return c
    return here.parents[1]


def command_selftest(args: argparse.Namespace) -> int:
    root = _project_root()
    tmp = Path(args.out).resolve()
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True, exist_ok=True)
    print("[1/2] Single-contract early-warning example")
    wargs = argparse.Namespace(
        input=str(root / "examples" / "single" / "SingleWarning.sol"),
        contract="SingleWarning",
        out=str(tmp / "warning"),
        no_install_solc=args.no_install_solc,
    )
    wc = command_warning(wargs)
    w = json.loads((tmp / "warning" / "warning_result.json").read_text(encoding="utf-8"))

    print("\n[2/2] Flattened storage-collision example")
    cargs = argparse.Namespace(
        sources=[str(root / "examples" / "flattened" / "StorageCollisionFlat.sol")],
        proxy_contract="DemoProxy",
        logic_contract="DemoLogic",
        out=str(tmp / "collision"),
        no_install_solc=args.no_install_solc,
        workers=1,
        clean=True,
    )
    cc = command_collision(cargs)
    c = json.loads((tmp / "collision" / "collision_summary.json").read_text(encoding="utf-8"))

    passed = (wc == 0 and w.get("prediction") == "WARNING" and cc == 0 and c.get("prediction") == "POSITIVE")
    summary = {
        "slotwarner_version": __version__,
        "passed": passed,
        "warning_prediction": w.get("prediction"),
        "collision_prediction": c.get("prediction"),
        "output": str(tmp),
    }
    _json_dump(tmp / "selftest_summary.json", summary)
    print("\n" + json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if passed else 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="slotwarner",
        description="SlotWarner: bit-precise storage-collision detection and single-contract early warning.",
    )
    p.add_argument("--version", action="version", version=f"SlotWarner {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    w = sub.add_parser("warning", help="Run single-contract early-warning analysis on a .sol file or source directory.")
    w.add_argument("input", help="Solidity .sol file or a directory recursively containing .sol files")
    w.add_argument("--contract", help="Target contract name when a single file contains multiple concrete contracts")
    w.add_argument("--out", default="results/warning", help="Output directory")
    w.add_argument("--no-install-solc", action="store_true", help="Do not automatically download a compatible solc version")
    w.set_defaults(func=command_warning)

    c = sub.add_parser("collision", help="Detect storage-collision candidates between a Proxy contract and a Logic contract.")
    c.add_argument("sources", nargs="+", help="One flattened .sol file, or two files: PROXY.sol LOGIC.sol")
    c.add_argument("--proxy-contract", help="Proxy contract name; required for a flattened file with multiple contracts")
    c.add_argument("--logic-contract", help="Logic contract name; required for a flattened file with multiple contracts")
    c.add_argument("--out", default="results/collision", help="Output directory")
    c.add_argument("--workers", type=int, default=2, help="Taint-model worker threads")
    c.add_argument("--clean", action="store_true", help="Clear the output directory before analysis")
    c.add_argument("--no-install-solc", action="store_true", help="Do not automatically download a compatible solc version")
    c.set_defaults(func=command_collision)

    s = sub.add_parser("selftest", help="Run the two bundled Solidity examples to verify the installation.")
    s.add_argument("--out", default="results/selftest", help="Output directory")
    s.add_argument("--no-install-solc", action="store_true", help="Use only already installed solc versions")
    s.set_defaults(func=command_selftest)
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "collision" and len(args.sources) not in {1, 2}:
        parser.error("collision accepts either one flattened source file or exactly two source files")
    raise SystemExit(int(args.func(args) or 0))
