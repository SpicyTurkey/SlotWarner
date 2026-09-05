from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import sys
import json
import subprocess
from typing import Any

import semantic_version
import solcx
from filelock import FileLock

from .bundle import SourceBundle, build_source_bundle
from .utils import normalize_pragma_expr

_MIN_LAYOUT_VERSION = semantic_version.Version("0.5.13")
_VERSION_CACHE: dict[bool, list[semantic_version.Version]] = {}


@dataclass
class CompileResult:
    ok: bool
    compiler_version: str | None = None
    output: dict[str, Any] | None = None
    errors: list[dict[str, Any]] | None = None
    failure_category: str | None = None
    error_text: str | None = None
    primary_source_key: str | None = None
    source_bundle_sha256: str | None = None
    source_bundle_sources: int = 0
    source_bundle_transformations: list[str] | None = None
    # Used only inside Phase 1 worker for AST source-span checks; worker output does not persist it.
    source_bundle_texts: dict[str, str] | None = None


def _npm_spec(expr: str) -> semantic_version.NpmSpec:
    return semantic_version.NpmSpec(normalize_pragma_expr(expr))


def _matches_all(version: semantic_version.Version, pragmas: list[str]) -> bool:
    if version < _MIN_LAYOUT_VERSION:
        return False
    try:
        return all(_npm_spec(p).match(version) for p in pragmas)
    except Exception:
        return False


def available_versions(include_installable: bool) -> list[semantic_version.Version]:
    cached = _VERSION_CACHE.get(bool(include_installable))
    if cached is not None:
        return list(cached)
    versions: set[semantic_version.Version] = set()
    for v in solcx.get_installed_solc_versions():
        versions.add(semantic_version.Version(str(v)))
    if include_installable:
        try:
            for v in solcx.get_installable_solc_versions():
                sv = semantic_version.Version(str(v))
                if not sv.prerelease:
                    versions.add(sv)
        except Exception:
            # 网络不可用时仍可使用已安装版本。
            pass
    result = sorted(v for v in versions if v >= _MIN_LAYOUT_VERSION and not v.prerelease)
    _VERSION_CACHE[bool(include_installable)] = result
    return list(result)


def candidate_versions(pragmas: list[str], include_installable: bool, policy: str = "lowest") -> list[str]:
    versions = [v for v in available_versions(include_installable) if _matches_all(v, pragmas)]
    if policy == "highest":
        versions.reverse()
    return [str(v) for v in versions]


def ensure_solc(version: str, install: bool) -> None:
    installed = {str(v) for v in solcx.get_installed_solc_versions()}
    if version in installed:
        return
    if not install:
        raise RuntimeError(f"solc {version} 未安装；请增加 --install-solc")
    lock_path = Path(solcx.get_solcx_install_folder()) / ".slotwarner_layout_solc_install.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with FileLock(str(lock_path), timeout=600):
        installed = {str(v) for v in solcx.get_installed_solc_versions()}
        if version not in installed:
            solcx.install_solc(version, show_progress=False)




def _is_solc_cli(path: Path, expected_version: str | None = None) -> bool:
    """Validate that *path* is the Solidity command-line compiler, not soltest/etc."""
    try:
        if not path.is_file():
            return False
        proc = subprocess.run(
            [str(path), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
        )
        text = (proc.stdout + proc.stderr).decode("utf-8", errors="replace").lower()
        if "solidity compiler" not in text and "solc, the solidity compiler" not in text:
            return False
        if expected_version and expected_version not in text:
            return False
        return proc.returncode == 0 or "version:" in text
    except Exception:
        return False


def _install_windows_solc_binary(version: str, base: Path) -> str | None:
    """Repair a broken py-solc-x Windows install from Solidity's binary index.

    Old Windows releases such as 0.5.13 are distributed as ZIP archives containing
    both solc.exe and soltest.exe.  Earlier emergency code could accidentally select
    soltest.exe simply because it was the first executable found.  This routine
    extracts *only* solc.exe and validates it before returning.
    """
    if os.name != "nt":
        return None
    try:
        import io
        import zipfile
        import requests

        index_url = "https://binaries.soliditylang.org/windows-amd64/list.json"
        response = requests.get(index_url, timeout=30)
        response.raise_for_status()
        release_name = (response.json().get("releases") or {}).get(version)
        if not release_name:
            return None
        binary_url = f"https://binaries.soliditylang.org/windows-amd64/{release_name}"
        binary = requests.get(binary_url, timeout=90)
        binary.raise_for_status()
        content = binary.content

        target_dir = base / f"solc-v{version}"
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / "solc.exe"
        tmp = target.with_suffix(".exe.part")

        if content[:4] == b"PK\x03\x04" or str(release_name).lower().endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                members = [n for n in zf.namelist() if Path(n).name.lower() == "solc.exe"]
                if not members:
                    return None
                tmp.write_bytes(zf.read(sorted(members, key=len)[0]))
        else:
            tmp.write_bytes(content)
        tmp.replace(target)
        if _is_solc_cli(target, version):
            return str(target)
        try:
            target.unlink(missing_ok=True)
        except Exception:
            pass
    except Exception:
        return None
    return None


def resolve_solc_executable(version: str, repair: bool = False) -> str | None:
    """Resolve and validate the concrete solc executable path.

    Crucially, this never accepts ``soltest.exe`` or another executable merely
    because it resides in a versioned py-solc-x directory.
    """
    base = Path(solcx.get_solcx_install_folder())

    candidates: list[Path] = []
    try:
        from solcx.install import get_executable
        candidates.append(Path(get_executable(version)))
    except Exception:
        pass
    candidates.extend([
        base / f"solc-v{version}" / "solc.exe",
        base / f"solc-v{version}.exe",
        base / f"solc-{version}.exe",
        base / f"solc-v{version}",
    ])

    seen: set[str] = set()
    for path in candidates:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        if _is_solc_cli(path, version):
            return str(path)

    # Historical layouts are accepted only when the filename itself is solc-like;
    # never return arbitrary *.exe files such as soltest.exe.
    try:
        for path in base.rglob('*'):
            if not path.is_file():
                continue
            name = path.name.lower()
            low = str(path).lower()
            if version.lower() not in low:
                continue
            if name not in {"solc.exe", f"solc-v{version}.exe", f"solc-{version}.exe", f"solc-v{version}"}:
                continue
            if _is_solc_cli(path, version):
                return str(path)
    except Exception:
        pass

    if repair:
        repaired = _install_windows_solc_binary(version, base)
        if repaired:
            return repaired
    return None


def classify_exception_text(text: str) -> str:
    low = str(text or "").lower()
    if "definition of base has to precede definition of derived contract" in low:
        return "flattened_base_order"
    if "source \"" in low and ("not found" in low or "file not found" in low):
        return "missing_import"
    if "multiple spdx license identifiers" in low:
        return "duplicate_spdx"
    if "abi coder has already been selected" in low or "duplicate experimental feature" in low:
        return "duplicate_abi_coder"
    if "solc_timeout:" in low:
        return "compiler_timeout"
    if "solcnotinstalled" in low or "has not been installed" in low:
        return "solc_not_installed"
    if "docstringparsingerror" in low:
        return "docstring_parse_error"
    if "parsererror" in low or "parser error" in low:
        return "parser_error"
    if "typeerror" in low or "type error" in low:
        return "type_error"
    if "declarationerror" in low or "declaration error" in low:
        return "declaration_error"
    if "syntaxerror" in low or "syntax error" in low:
        return "syntax_error"
    return "compiler_exception"


def classify_compiler_errors(errors: list[dict[str, Any]] | None) -> str:
    text = "\n".join(str(e.get("formattedMessage") or e.get("message") or "") for e in (errors or []))
    low = text.lower()
    if "source" in low and ("not found" in low or "file not found" in low):
        return "missing_import"
    if "parsererror" in low or "parser error" in low:
        return "parser_error"
    if "stack too deep" in low:
        return "stack_too_deep"
    if "typeerror" in low or "type error" in low:
        return "type_error"
    if "declarationerror" in low or "declaration error" in low:
        return "declaration_error"
    if "not supported" in low and "storage" in low:
        return "storage_layout_unsupported"
    return "compile_error"


def _standard_input(bundle: SourceBundle, phase: str) -> dict[str, Any]:
    if phase == "ast":
        selection = {"*": {"": ["ast"]}}
    elif phase == "native":
        selection = {"*": {"*": ["storageLayout"]}}
    else:
        raise ValueError(phase)
    return {
        "language": "Solidity",
        "sources": {k: {"content": v} for k, v in bundle.sources.items()},
        "settings": {
            "optimizer": {"enabled": False},
            "outputSelection": selection,
        },
    }


def _compile_standard_binary(input_data: dict[str, Any], solc_binary: str, timeout_seconds: int = 45) -> dict[str, Any]:
    """Invoke solc --standard-json with a hard wall-clock timeout.

    This avoids indefinite hangs inside py-solc-x/subprocess on Windows.
    The helper is compiler-version agnostic and does not inspect benchmark labels.
    """
    payload = json.dumps(input_data, ensure_ascii=False).encode("utf-8")
    try:
        proc = subprocess.run(
            [str(solc_binary), "--standard-json"],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(5, int(timeout_seconds)),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"solc_timeout:{timeout_seconds}s") from exc
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    if not stdout.strip():
        raise RuntimeError(f"solc_empty_output:rc={proc.returncode};stderr={stderr[:4000]}")
    # Some Windows builds may emit a BOM or a short non-JSON banner before the JSON.
    text = stdout.lstrip("\ufeff\r\n \t")
    start = text.find("{")
    if start > 0:
        text = text[start:]
    try:
        out = json.loads(text)
    except Exception as exc:
        raise RuntimeError(f"solc_invalid_json:rc={proc.returncode};stderr={stderr[:2000]};stdout={stdout[:2000]}") from exc
    if not isinstance(out, dict):
        raise RuntimeError("solc_invalid_output_type")
    return out


def compile_bundle_with_version(bundle: SourceBundle, compiler_version: str, phase: str, install: bool) -> CompileResult:
    meta = dict(
        compiler_version=compiler_version,
        primary_source_key=bundle.primary_source_key,
        source_bundle_sha256=bundle.bundle_sha256,
        source_bundle_sources=len(bundle.sources),
        source_bundle_transformations=list(bundle.transformations),
        source_bundle_texts=dict(bundle.sources),
    )
    try:
        ensure_solc(compiler_version, install=install)
        # Prefer the exact executable path instead of asking py-solc-x to rediscover
        # an already-installed version inside each spawned Windows worker.  On the
        # P100 corpus we observed a real race/state-discovery failure where the
        # parent had installed 0.5.13 but a worker still raised SolcNotInstalled.
        # Passing solc_binary makes the compiler choice process-independent.
        solc_binary = resolve_solc_executable(compiler_version, repair=bool(install))
        if solc_binary:
            # v4.2.12: call the concrete compiler directly and bound every compile.
            # This is specifically to prevent a single pathological solc invocation
            # from occupying a ProcessPool worker forever on Windows.
            output = _compile_standard_binary(
                _standard_input(bundle, phase),
                solc_binary,
                timeout_seconds=int(os.environ.get("SLOTWARNER_SOLC_TIMEOUT", "45")),
            )
        else:
            # Last-resort path.  Prefer an explicit executable whenever possible.
            output = solcx.compile_standard(
                _standard_input(bundle, phase),
                solc_version=compiler_version,
            )
        errors = output.get("errors") or []
        severe = [e for e in errors if e.get("severity") == "error"]
        if severe:
            return CompileResult(
                ok=False,
                output=output,
                errors=severe,
                failure_category=classify_compiler_errors(severe),
                error_text="\n".join(str(e.get("formattedMessage") or e.get("message") or "") for e in severe)[:12000],
                **meta,
            )
        return CompileResult(ok=True, output=output, errors=[], **meta)
    except Exception as exc:
        error_text = f"{type(exc).__name__}: {exc}"
        return CompileResult(
            ok=False,
            failure_category=classify_exception_text(error_text),
            error_text=error_text,
            **meta,
        )


def compile_with_version(path: Path, compiler_version: str, phase: str, install: bool) -> CompileResult:
    try:
        bundle = build_source_bundle(path)
    except Exception as exc:
        return CompileResult(ok=False, compiler_version=compiler_version, failure_category="bundle_build_failed", error_text=f"{type(exc).__name__}: {exc}")
    return compile_bundle_with_version(bundle, compiler_version, phase, install)


def compile_ast_selecting_version(
    path: Path,
    primary_pragmas: list[str],
    install: bool,
    policy: str = "lowest",
    max_attempts: int = 8,
) -> CompileResult:
    try:
        bundle = build_source_bundle(path)
    except Exception as exc:
        return CompileResult(ok=False, failure_category="bundle_build_failed", error_text=f"{type(exc).__name__}: {exc}")

    # 使用完整 source bundle 的 pragma 交集，不只看根源码。
    pragmas = bundle.pragmas or list(primary_pragmas or [])
    candidates = candidate_versions(pragmas, include_installable=install, policy=policy)
    if not candidates:
        return CompileResult(
            ok=False,
            failure_category="no_compatible_solc",
            error_text=f"primary_pragma={primary_pragmas}; bundle_pragma={pragmas}",
            primary_source_key=bundle.primary_source_key,
            source_bundle_sha256=bundle.bundle_sha256,
            source_bundle_sources=len(bundle.sources),
            source_bundle_transformations=list(bundle.transformations),
            source_bundle_texts=dict(bundle.sources),
        )
    attempts: list[str] = []
    last: CompileResult | None = None
    for version in candidates[:max_attempts]:
        attempts.append(version)
        result = compile_bundle_with_version(bundle, version, phase="ast", install=install)
        if result.ok:
            return result
        last = result
        if result.failure_category == "missing_import":
            # 依赖缺失通常与版本无关，不浪费大量solc尝试。
            break
    if last is None:
        return CompileResult(ok=False, failure_category="compile_failed", error_text="no attempts")
    last.error_text = f"tried={attempts}\n{last.error_text or ''}"
    return last


def all_asts(output: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for key, item in (output.get("sources") or {}).items():
        ast = item.get("ast")
        if isinstance(ast, dict):
            out[key] = ast
    return out
