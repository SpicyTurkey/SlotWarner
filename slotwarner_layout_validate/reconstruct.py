from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any


class ReconstructionIncomplete(RuntimeError):
    pass


@dataclass
class TypeLayout:
    category: str
    encoding: str
    number_of_bytes: int
    slots: int
    packable: bool
    label: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def asdict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "encoding": self.encoding,
            "numberOfBytes": self.number_of_bytes,
            "slots": self.slots,
            "packable": self.packable,
            "label": self.label,
            "details": self.details,
        }


class AstProgram:
    def __init__(self, asts: dict[str, dict[str, Any]], primary_source_key: str):
        self.asts = asts
        self.primary_source_key = primary_source_key
        self.by_id: dict[int, dict[str, Any]] = {}
        self.source_of_id: dict[int, str] = {}
        self.contracts: dict[int, dict[str, Any]] = {}
        self.contracts_by_source_name: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self._walk_all()

    def _walk_all(self) -> None:
        def walk(node: Any, source_key: str) -> None:
            if isinstance(node, dict):
                node_id = node.get("id")
                if isinstance(node_id, int):
                    self.by_id[node_id] = node
                    self.source_of_id[node_id] = source_key
                if node.get("nodeType") == "ContractDefinition" and isinstance(node_id, int):
                    self.contracts[node_id] = node
                    self.contracts_by_source_name.setdefault((source_key, str(node.get("name") or "")), []).append(node)
                for value in node.values():
                    walk(value, source_key)
            elif isinstance(node, list):
                for x in node:
                    walk(x, source_key)

        for source_key, ast in self.asts.items():
            walk(ast, source_key)

    def target_contract(self, name: str) -> dict[str, Any]:
        direct = self.contracts_by_source_name.get((self.primary_source_key, name)) or []
        if len(direct) == 1:
            return direct[0]
        # 编译器有时规范化 source key；按 basename 匹配。
        primary_base = self.primary_source_key.replace("\\", "/").split("/")[-1]
        candidates: list[dict[str, Any]] = []
        for (source_key, contract_name), items in self.contracts_by_source_name.items():
            if contract_name == name and source_key.replace("\\", "/").split("/")[-1] == primary_base:
                candidates.extend(items)
        if len(candidates) == 1:
            return candidates[0]
        # 最后只在全编译单元名称唯一时使用。
        candidates = [c for c in self.contracts.values() if c.get("name") == name]
        if len(candidates) == 1:
            return candidates[0]
        raise ReconstructionIncomplete(f"target_contract_not_unique_or_missing:{name}; candidates={len(candidates)}")


class TypeResolver:
    def __init__(self, program: AstProgram):
        self.p = program
        self.cache: dict[str, TypeLayout] = {}
        self.struct_cache: dict[int, TypeLayout] = {}
        self.array_cache: dict[str, TypeLayout] = {}
        self._active_structs: set[int] = set()

    @staticmethod
    def _type_desc(node: dict[str, Any]) -> str:
        return str((node.get("typeDescriptions") or {}).get("typeString") or "")

    def resolve_var(self, var: dict[str, Any]) -> TypeLayout:
        type_node = var.get("typeName")
        if not isinstance(type_node, dict):
            desc = self._type_desc(var)
            raise ReconstructionIncomplete(f"variable_without_typeName:{var.get('name')}:{desc}")
        return self.resolve_type(type_node)

    def resolve_type(self, node: dict[str, Any]) -> TypeLayout:
        node_type = node.get("nodeType")
        cache_key = f"{node_type}|{node.get('id')}|{self._type_desc(node)}|{node.get('name')}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        if node_type == "ElementaryTypeName":
            out = self._elementary(node)
        elif node_type == "UserDefinedTypeName":
            out = self._user_defined(node)
        elif node_type == "Mapping":
            key = node.get("keyType")
            value = node.get("valueType")
            if not isinstance(key, dict) or not isinstance(value, dict):
                raise ReconstructionIncomplete("mapping_missing_key_or_value")
            key_t = self.resolve_type(key)
            value_t = self.resolve_type(value)
            out = TypeLayout(
                category="mapping",
                encoding="mapping",
                number_of_bytes=32,
                slots=1,
                packable=False,
                label=self._type_desc(node) or "mapping",
                details={"key": key_t.asdict(), "value": value_t.asdict()},
            )
        elif node_type == "ArrayTypeName":
            out = self._array(node)
        elif node_type == "FunctionTypeName":
            out = self._function_type(node)
        else:
            raise ReconstructionIncomplete(f"unsupported_type_node:{node_type}:{self._type_desc(node)}")

        self.cache[cache_key] = out
        return out

    def _elementary(self, node: dict[str, Any]) -> TypeLayout:
        name = str(node.get("name") or "")
        desc = self._type_desc(node)
        canonical = name or desc
        if canonical.startswith("address"):
            return TypeLayout("address", "inplace", 20, 1, True, desc or canonical)
        if canonical == "bool":
            return TypeLayout("bool", "inplace", 1, 1, True, desc or canonical)
        if canonical == "string":
            return TypeLayout("string", "bytes", 32, 1, False, desc or canonical)
        if canonical == "bytes":
            return TypeLayout("bytes_dynamic", "bytes", 32, 1, False, desc or canonical)
        m = re.fullmatch(r"bytes([1-9]|[12]\d|3[0-2])", canonical)
        if m:
            n = int(m.group(1))
            return TypeLayout("bytes_fixed", "inplace", n, 1, True, desc or canonical)
        m = re.fullmatch(r"u?int(\d*)", canonical)
        if m:
            bits = int(m.group(1) or "256")
            if bits < 8 or bits > 256 or bits % 8:
                raise ReconstructionIncomplete(f"invalid_integer_width:{canonical}")
            return TypeLayout("integer", "inplace", bits // 8, 1, True, desc or canonical)
        m = re.fullmatch(r"u?fixed(\d+)(?:x\d+)?", canonical)
        if m:
            bits = int(m.group(1))
            if bits < 8 or bits > 256 or bits % 8:
                raise ReconstructionIncomplete(f"invalid_fixed_width:{canonical}")
            return TypeLayout("fixed_point", "inplace", bits // 8, 1, True, desc or canonical)
        raise ReconstructionIncomplete(f"unsupported_elementary:{canonical}:{desc}")

    def _user_defined(self, node: dict[str, Any]) -> TypeLayout:
        ref = node.get("referencedDeclaration")
        if not isinstance(ref, int) or ref not in self.p.by_id:
            raise ReconstructionIncomplete(f"unresolved_user_type:{self._type_desc(node)}")
        decl = self.p.by_id[ref]
        kind = decl.get("nodeType")
        label = self._type_desc(node) or str(decl.get("name") or "")
        if kind == "ContractDefinition":
            return TypeLayout("contract", "inplace", 20, 1, True, label)
        if kind == "StructDefinition":
            return self._struct(ref, decl, label)
        if kind == "EnumDefinition":
            members = decl.get("members") or []
            count = max(1, len(members))
            # Solidity 使用可容纳 enum 值的最小整数宽度；常见 <=256 成员为1字节。
            bits = max(1, (count - 1).bit_length())
            bytes_ = max(1, math.ceil(bits / 8))
            if bytes_ > 32:
                raise ReconstructionIncomplete(f"enum_too_large:{label}:{count}")
            return TypeLayout("enum", "inplace", bytes_, 1, True, label, {"members": count})
        if kind == "UserDefinedValueTypeDefinition":
            underlying = decl.get("underlyingType")
            if not isinstance(underlying, dict):
                raise ReconstructionIncomplete(f"udvt_missing_underlying:{label}")
            base = self.resolve_type(underlying)
            if not base.packable or base.number_of_bytes > 32:
                raise ReconstructionIncomplete(f"udvt_non_value_underlying:{label}")
            return TypeLayout("user_defined_value_type", "inplace", base.number_of_bytes, 1, True, label, {"underlying": base.asdict()})
        raise ReconstructionIncomplete(f"unsupported_user_decl:{kind}:{label}")

    def _struct(self, ref: int, decl: dict[str, Any], label: str) -> TypeLayout:
        if ref in self.struct_cache:
            return self.struct_cache[ref]
        if ref in self._active_structs:
            raise ReconstructionIncomplete(f"recursive_static_struct:{label}")
        self._active_structs.add(ref)
        try:
            members = [m for m in (decl.get("members") or []) if isinstance(m, dict)]
            placed, end_slot, end_offset = self.layout_variables(members, start_slot=0, start_offset=0, member_mode=True)
            slots = end_slot + (1 if end_offset > 0 else 0)
            slots = max(1, slots)
            out = TypeLayout(
                category="struct",
                encoding="inplace",
                number_of_bytes=slots * 32,
                slots=slots,
                packable=False,
                label=label,
                details={"members": placed},
            )
            self.struct_cache[ref] = out
            return out
        finally:
            self._active_structs.discard(ref)

    def _array(self, node: dict[str, Any]) -> TypeLayout:
        base_node = node.get("baseType")
        if not isinstance(base_node, dict):
            raise ReconstructionIncomplete("array_missing_base")
        base = self.resolve_type(base_node)
        length_node = node.get("length")
        label = self._type_desc(node) or "array"
        if length_node is None:
            return TypeLayout(
                category="dynamic_array",
                encoding="dynamic_array",
                number_of_bytes=32,
                slots=1,
                packable=False,
                label=label,
                details={"base": base.asdict()},
            )
        length = self._const_array_length(length_node)
        if length < 0:
            raise ReconstructionIncomplete(f"negative_array_length:{label}")
        if length == 0:
            raise ReconstructionIncomplete(f"zero_length_fixed_array:{label}")
        if base.packable and base.number_of_bytes <= 32:
            per_slot = max(1, 32 // base.number_of_bytes)
            slots = math.ceil(length / per_slot)
        else:
            slots = length * max(1, base.slots)
        return TypeLayout(
            category="fixed_array",
            encoding="inplace",
            number_of_bytes=slots * 32,
            slots=slots,
            packable=False,
            label=label,
            details={"base": base.asdict(), "length": length},
        )

    def _const_array_length(self, node: dict[str, Any]) -> int:
        """Evaluate Solidity compile-time integer expressions used in fixed-array lengths.

        This intentionally supports only side-effect-free integer constant syntax.  It
        handles the patterns emitted by real upgradeable contracts such as
        ``LAYOUT_LENGTH - 40`` where ``LAYOUT_LENGTH`` is a constant ``2**64``.
        """
        active: set[int] = set()

        def ev(n: Any) -> int:
            if not isinstance(n, dict):
                raise ReconstructionIncomplete("const_expr_not_node")
            nt = str(n.get("nodeType") or "")
            if nt == "Literal":
                value = n.get("value")
                if value is None:
                    hv = n.get("hexValue")
                    if hv:
                        return int(str(hv), 16)
                    raise ReconstructionIncomplete("const_literal_without_value")
                text = str(value).replace("_", "")
                # Solidity decimal/hex integer literal.  Rational literals are not
                # valid fixed-array lengths unless the compiler has folded them.
                return int(text, 0)

            if nt == "Identifier":
                ref = n.get("referencedDeclaration")
                if not isinstance(ref, int) or ref not in self.p.by_id:
                    raise ReconstructionIncomplete(f"const_identifier_unresolved:{n.get('name')}")
                if ref in active:
                    raise ReconstructionIncomplete(f"const_identifier_cycle:{n.get('name')}")
                decl = self.p.by_id[ref]
                if decl.get("nodeType") != "VariableDeclaration" or decl.get("constant") is not True:
                    raise ReconstructionIncomplete(f"const_identifier_not_constant:{n.get('name')}")
                value = decl.get("value")
                if not isinstance(value, dict):
                    raise ReconstructionIncomplete(f"const_identifier_without_value:{n.get('name')}")
                active.add(ref)
                try:
                    return ev(value)
                finally:
                    active.discard(ref)

            if nt == "UnaryOperation":
                sub = ev(n.get("subExpression"))
                op = str(n.get("operator") or "")
                if op == "+": return +sub
                if op == "-": return -sub
                if op == "~": return ~sub
                raise ReconstructionIncomplete(f"const_unary_unsupported:{op}")

            if nt == "BinaryOperation":
                a = ev(n.get("leftExpression")); b = ev(n.get("rightExpression"))
                op = str(n.get("operator") or "")
                if op == "+": return a + b
                if op == "-": return a - b
                if op == "*": return a * b
                if op == "/":
                    if b == 0: raise ReconstructionIncomplete("const_div_zero")
                    return a // b
                if op == "%":
                    if b == 0: raise ReconstructionIncomplete("const_mod_zero")
                    return a % b
                if op == "**":
                    if b < 0 or b > 4096: raise ReconstructionIncomplete(f"const_pow_exponent:{b}")
                    return a ** b
                if op == "<<": return a << b
                if op == ">>": return a >> b
                if op == "&": return a & b
                if op == "|": return a | b
                if op == "^": return a ^ b
                raise ReconstructionIncomplete(f"const_binary_unsupported:{op}")

            if nt == "TupleExpression":
                comps = [x for x in (n.get("components") or []) if isinstance(x, dict)]
                if len(comps) == 1:
                    return ev(comps[0])
                raise ReconstructionIncomplete("const_tuple_unsupported")

            if nt == "FunctionCall":
                # Integer type conversion around a constant expression.
                args = [x for x in (n.get("arguments") or []) if isinstance(x, dict)]
                expr = n.get("expression") or {}
                if len(args) == 1 and isinstance(expr, dict) and expr.get("nodeType") in {"ElementaryTypeNameExpression", "Identifier"}:
                    return ev(args[0])
                raise ReconstructionIncomplete("const_function_call_unsupported")

            raise ReconstructionIncomplete(f"non_literal_fixed_array_length:{nt}")

        return ev(node)

    def _function_type(self, node: dict[str, Any]) -> TypeLayout:
        visibility = str(node.get("visibility") or "")
        # Solidity external function value = address(20) + selector(4) = 24 bytes。
        if visibility == "external":
            return TypeLayout("function_external", "inplace", 24, 1, True, self._type_desc(node) or "function external")
        # internal function pointer 的具体持久化编码跨版本不适合作为当前规则验证对象，保守拒绝。
        raise ReconstructionIncomplete(f"unsupported_internal_function_storage:{self._type_desc(node)}")

    def layout_variables(
        self,
        vars_: list[dict[str, Any]],
        start_slot: int = 0,
        start_offset: int = 0,
        member_mode: bool = False,
    ) -> tuple[list[dict[str, Any]], int, int]:
        slot = start_slot
        offset = start_offset
        placed: list[dict[str, Any]] = []
        for var in vars_:
            t = self.resolve_var(var)
            ast_id = var.get("id")
            label = str(var.get("name") or "")
            if t.packable and t.number_of_bytes <= 32:
                size = t.number_of_bytes
                if size == 32:
                    if offset:
                        slot += 1
                        offset = 0
                    pslot, poffset = slot, 0
                    slot += 1
                else:
                    if offset + size > 32:
                        slot += 1
                        offset = 0
                    pslot, poffset = slot, offset
                    offset += size
                    if offset == 32:
                        slot += 1
                        offset = 0
            else:
                if offset:
                    slot += 1
                    offset = 0
                pslot, poffset = slot, 0
                slot += max(1, t.slots)
                offset = 0
            placed.append({
                "astId": ast_id,
                "label": label,
                "slot": str(pslot),
                "offset": poffset,
                "numberOfBytes": t.number_of_bytes,
                "type": t.asdict(),
            })
        return placed, slot, offset


def _is_persistent_state_var(node: dict[str, Any]) -> bool:
    if node.get("nodeType") != "VariableDeclaration":
        return False
    if node.get("stateVariable") is not True:
        return False
    if node.get("constant") is True:
        return False
    if str(node.get("mutability") or "") == "immutable":
        return False
    if str(node.get("storageLocation") or "") == "transient":
        return False
    # 新版 AST 某些字段可能显式给出 transient。
    if node.get("transient") is True:
        return False
    return True


def _strip_comments_and_strings(fragment: str) -> str:
    """Remove comment/string contents before keyword checks while preserving token boundaries.

    This is intentionally a tiny lexer rather than a Solidity parser.  The only purpose is
    to ensure words inside comments or string/hex/unicode literals cannot masquerade as
    declaration modifiers such as ``immutable``.
    """
    out: list[str] = []
    i = 0
    n = len(fragment)
    state = "code"
    quote = ""
    while i < n:
        ch = fragment[i]
        nxt = fragment[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out.extend((" ", " ")); i += 2; state = "line_comment"; continue
            if ch == "/" and nxt == "*":
                out.extend((" ", " ")); i += 2; state = "block_comment"; continue
            if ch in {"'", '"'}:
                quote = ch; out.append(" "); i += 1; state = "string"; continue
            out.append(ch); i += 1; continue
        if state == "line_comment":
            if ch == "\n":
                out.append("\n"); state = "code"
            else:
                out.append(" " )
            i += 1; continue
        if state == "block_comment":
            if ch == "*" and nxt == "/":
                out.extend((" ", " ")); i += 2; state = "code"; continue
            out.append("\n" if ch == "\n" else " "); i += 1; continue
        # string
        if ch == "\\":
            out.append(" " )
            if i + 1 < n:
                out.append(" " ); i += 2
            else:
                i += 1
            continue
        if ch == quote:
            out.append(" " ); i += 1; state = "code"; continue
        out.append("\n" if ch == "\n" else " " ); i += 1
    return "".join(out)


def _source_decl_fragment(
    node: dict[str, Any],
    program: AstProgram,
    source_texts: dict[str, str],
) -> str | None:
    """Return the exact AST source span using Solidity's UTF-8 *byte* offsets.

    Solidity ``src`` uses byte offsets.  Python string slicing uses Unicode code-point
    offsets, so slicing the string directly becomes wrong after non-ASCII comments/text.
    v1.3 did that and could inspect an unrelated nearby fragment.
    """
    node_id = node.get("id")
    if not isinstance(node_id, int):
        return None
    source_key = program.source_of_id.get(node_id)
    text = source_texts.get(str(source_key or ""))
    if not isinstance(text, str):
        return None
    parts = str(node.get("src") or "").split(":")
    if len(parts) < 2:
        return None
    try:
        start, length = int(parts[0]), int(parts[1])
    except Exception:
        return None
    raw = text.encode("utf-8")
    if start < 0 or length <= 0 or start + length > len(raw):
        return None
    try:
        return raw[start:start + length].decode("utf-8")
    except UnicodeDecodeError:
        # A valid compiler span should end on UTF-8 boundaries.  Fail closed rather than
        # search a lossy/shifted fragment and accidentally remove a persistent variable.
        return None


def _source_decl_contains_keyword(
    node: dict[str, Any],
    program: AstProgram,
    source_texts: dict[str, str],
    keyword: str,
) -> bool:
    """Fallback for old ASTs: confirm a declaration modifier from its exact source span.

    The source fragment comes from the same normalized compile unit as the AST.  Keywords
    inside comments/string literals are ignored.  Native ``storageLayout`` is never read.
    """
    fragment = _source_decl_fragment(node, program, source_texts)
    if fragment is None:
        return False
    lexical = _strip_comments_and_strings(fragment)
    return re.search(rf"\b{re.escape(keyword)}\b", lexical, re.IGNORECASE) is not None


def reconstruct_storage_layout(
    asts: dict[str, dict[str, Any]],
    primary_source_key: str,
    contract_name: str,
    source_text: str,
    source_texts: dict[str, str] | None = None,
) -> dict[str, Any]:
    # Solidity 0.8.29+ custom storage base 会整体平移布局。当前验证器宁可标记不完整，也不猜。
    if re.search(r"\blayout\s+at\b", source_text, re.IGNORECASE):
        raise ReconstructionIncomplete("custom_layout_at_not_supported")

    program = AstProgram(asts, primary_source_key)
    target = program.target_contract(contract_name)
    linearized = target.get("linearizedBaseContracts")
    if not isinstance(linearized, list) or not all(isinstance(x, int) for x in linearized):
        raise ReconstructionIncomplete("missing_linearizedBaseContracts")

    ordered_contracts: list[dict[str, Any]] = []
    # AST linearizedBaseContracts 为 most-derived first；storage 规则从 most-base-ward 开始。
    for cid in reversed(linearized):
        c = program.contracts.get(cid)
        if c is None:
            raise ReconstructionIncomplete(f"missing_base_contract_ast:{cid}")
        ordered_contracts.append(c)

    source_texts = dict(source_texts or {primary_source_key: source_text})
    state_vars: list[dict[str, Any]] = []
    declaring_contract_by_ast: dict[int, str] = {}
    skipped_immutable_ast_ids: list[int] = []
    for c in ordered_contracts:
        direct: list[dict[str, Any]] = []
        for n in (c.get("nodes") or []):
            if not isinstance(n, dict) or not _is_persistent_state_var(n):
                continue
            # Solidity 0.6.x era AST can omit/normalize the `mutability=immutable` field.
            # A declaration containing the literal `immutable` keyword does not consume storage.
            if _source_decl_contains_keyword(n, program, source_texts, "immutable"):
                if isinstance(n.get("id"), int):
                    skipped_immutable_ast_ids.append(int(n["id"]))
                continue
            direct.append(n)
        # nodes 本身通常已经按源码顺序，这里再按 src 起点稳定排序。
        def src_pos(n: dict[str, Any]) -> int:
            try:
                return int(str(n.get("src") or "0:0:0").split(":", 1)[0])
            except Exception:
                return 0
        direct.sort(key=src_pos)
        for v in direct:
            state_vars.append(v)
            if isinstance(v.get("id"), int):
                declaring_contract_by_ast[v["id"]] = str(c.get("name") or "")

    resolver = TypeResolver(program)
    placed, end_slot, end_offset = resolver.layout_variables(state_vars, 0, 0)
    for p in placed:
        p["declaringContract"] = declaring_contract_by_ast.get(p.get("astId"), "")

    return {
        "contract": contract_name,
        "linearized_contracts_base_to_derived": [str(c.get("name") or "") for c in ordered_contracts],
        "storage": placed,
        "end_slot": end_slot,
        "end_offset": end_offset,
        "skipped_immutable_ast_ids": skipped_immutable_ast_ids,
        "reconstruction_complete": True,
    }
