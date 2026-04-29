from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional, TypedDict, Union

from ..base import Op
from ..helpers.params import parse_aliases
from ..preview import PreviewSpec
from ..runtime import IdaOperationError, IdaRuntime, ida_undo_restore_point

_FORWARD_DECL_RE = re.compile(
    r"^\s*(?:typedef\s+)?(?:struct|class|union)\s+"
    r"(?P<tag>[A-Za-z_][A-Za-z0-9_:]*)"
    r"(?:\s+(?P<alias>[A-Za-z_][A-Za-z0-9_:]*))?\s*;\s*$",
    re.DOTALL,
)
_CONCRETE_TYPE_RE = re.compile(
    r"\b(?:struct|class|union|enum)\s+(?P<name>[A-Za-z_][A-Za-z0-9_:]*)\s*\{",
    re.DOTALL,
)
_TYPEDEF_ALIAS_RE = re.compile(
    r"^\s*typedef\s+(?:struct|class|union|enum)\s+"
    r"(?:(?P<tag>[A-Za-z_][A-Za-z0-9_:]*)\s*)?"
    r"\{.*\}\s*(?P<alias>[A-Za-z_][A-Za-z0-9_:]*)\s*;\s*$",
    re.DOTALL,
)
_TYPEDEF_FUNC_ALIAS_RE = re.compile(
    r"^\s*typedef\b.*\(\s*\*\s*(?P<alias>[A-Za-z_][A-Za-z0-9_:]*)\s*\)\s*\([^;]*\)\s*;\s*$",
    re.DOTALL,
)
_TYPEDEF_SIMPLE_ALIAS_RE = re.compile(
    r"^\s*typedef\b.*?\b(?P<alias>[A-Za-z_][A-Za-z0-9_:]*)\s*;\s*$",
    re.DOTALL,
)
_BY_VALUE_MEMBER_RE = re.compile(
    r"^(?:typedef\s+)?"
    r"(?:(?:const|volatile|mutable|signed|unsigned|short|long)\s+)*"
    r"(?:(?:struct|class|union)\s+)?"
    r"(?P<type>[A-Za-z_][A-Za-z0-9_:]*)"
    r"(?:\s+(?:const|volatile))*\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[[^\]]+\])?\s*$",
    re.DOTALL,
)
_BUILTIN_MEMBER_TYPES = {
    "bool",
    "char",
    "double",
    "float",
    "int",
    "long",
    "short",
    "signed",
    "size_t",
    "ssize_t",
    "unsigned",
    "void",
    "wchar_t",
    "__int8",
    "__int16",
    "__int32",
    "__int64",
    "__int128",
}

TypeAlias = TypedDict("TypeAlias", {"from": str, "to": str})
AppliedAlias = TypedDict("AppliedAlias", {"from": str, "to": str, "count": int})


class DeclarationChunkDict(TypedDict):
    text: str
    start_line: int
    end_line: int
    terminated: bool


class BlockingMember(TypedDict):
    type_name: str
    member_name: str


class BisectTrial(TypedDict):
    prefix_count: int
    errors: int
    success: bool


class TypeDiagnosticDict(TypedDict, total=False):
    kind: str
    message: str
    line: int
    end_line: int
    snippet: str
    construct: str
    balance: int


class FailingDeclaration(TypedDict, total=False):
    index: int
    line: int
    end_line: int
    snippet: str
    standalone_errors: int
    standalone_success: bool


class TypeDeclareBisectResult(TypedDict, total=False):
    requested: bool
    supported: bool
    mode: str
    declaration_count: int
    message: str
    trials: list[BisectTrial]
    diagnostics: list[TypeDiagnosticDict]
    failing_declaration: FailingDeclaration
    blocking_members: list[BlockingMember]


class TypeDeclareResult(TypedDict, total=False):
    errors: int
    replace: bool
    aliases_applied: list[AppliedAlias]
    diagnostics: list[TypeDiagnosticDict]
    imported_types: list[str]
    replaced_types: list[str]
    declaration_count: int
    success: bool
    bisect: TypeDeclareBisectResult | None


TypeDeclareDiagnostic = TypeDiagnosticDict
NamedTypeSnapshot = dict[str, Optional[str]]


@dataclass(frozen=True)
class DeclarationChunk:
    text: str
    start_line: int
    end_line: int
    terminated: bool

    def to_dict(self) -> DeclarationChunkDict:
        return {
            "text": self.text,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "terminated": self.terminated,
        }


@dataclass(frozen=True)
class TypeDeclareRequest:
    decl: str
    aliases: tuple[TypeAlias, ...]
    replace: bool
    bisect: bool
    clang: bool


ChunkLike = Union[DeclarationChunk, DeclarationChunkDict]


def _make_type_diagnostic(
    *,
    kind: str,
    message: str,
    line: int | None = None,
    end_line: int | None = None,
    snippet: str | None = None,
    construct: str | None = None,
    balance: int | None = None,
) -> TypeDiagnosticDict:
    item: TypeDiagnosticDict = {"kind": kind, "message": message}
    if line is not None:
        item["line"] = line
    if end_line is not None:
        item["end_line"] = end_line
    if snippet:
        item["snippet"] = snippet[:240]
    if construct:
        item["construct"] = construct
    if balance is not None:
        item["balance"] = balance
    return item


def _coerce_chunk(chunk: ChunkLike) -> DeclarationChunk:
    if isinstance(chunk, DeclarationChunk):
        return chunk
    return DeclarationChunk(
        text=str(chunk.get("text") or ""),
        start_line=int(chunk.get("start_line") or 1),
        end_line=int(chunk.get("end_line") or 1),
        terminated=bool(chunk.get("terminated")),
    )


def _coerce_chunks(chunks: list[ChunkLike]) -> list[DeclarationChunk]:
    return [_coerce_chunk(chunk) for chunk in chunks]


def _named_type_map(rows: list[dict[str, Any]]) -> NamedTypeSnapshot:
    return {item["name"]: item.get("decl") for item in rows}


def _named_types_snapshot(runtime: IdaRuntime) -> NamedTypeSnapshot:
    return _named_type_map(runtime.list_named_types())


def _strip_comments_preserve_lines(text: str) -> str:
    out: list[str] = []
    in_string: str | None = None
    in_line_comment = False
    in_block_comment = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if ch == "\n":
                out.append(ch)
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            if ch == "\n":
                out.append(ch)
            i += 1
            continue
        if in_string:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        out.append(ch)
        if ch in {"'", '"'}:
            in_string = ch
        i += 1
    return "".join(out)


def _strip_preprocessor_lines(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_directive_continuation = False
    for line in lines:
        stripped = line.lstrip()
        is_directive = stripped.startswith("#") or in_directive_continuation
        if is_directive:
            newline = "\n" if line.endswith("\n") else ""
            out.append(newline)
            in_directive_continuation = line.rstrip().endswith("\\")
            continue
        in_directive_continuation = False
        out.append(line)
    return "".join(out)


def _sanitize_declaration_text(text: str) -> str:
    return _strip_preprocessor_lines(_strip_comments_preserve_lines(text))


def _parse_request(params: dict[str, object]) -> TypeDeclareRequest:
    decl = _sanitize_declaration_text(str(params.get("decl") or ""))
    if not decl:
        raise IdaOperationError("type declarations are required via --decl or --file")
    try:
        aliases = tuple(parse_aliases(params.get("aliases") or []))
    except ValueError as exc:
        raise IdaOperationError(str(exc)) from exc
    return TypeDeclareRequest(
        decl=decl,
        aliases=aliases,
        replace=bool(params.get("replace")),
        bisect=bool(params.get("bisect")),
        clang=bool(params.get("clang")),
    )


def _normalize_aliases(raw_aliases: Any) -> list[TypeAlias]:
    return parse_aliases(raw_aliases)


def _join_declaration_chunks(chunks: list[DeclarationChunk]) -> str:
    return "\n".join(chunk.text for chunk in chunks)


def _apply_type_aliases(decl: str, aliases: list[TypeAlias]) -> tuple[str, list[AppliedAlias]]:
    updated = decl
    applied: list[AppliedAlias] = []
    for alias in aliases:
        src = alias["from"]
        dst = alias["to"]
        pattern = re.compile(
            rf"(?:(?P<global_prefix>(?:^|(?<=[^A-Za-z0-9_:]))::)|(?<![A-Za-z0-9_:]))"
            rf"(?P<name>{re.escape(src)})(?![A-Za-z0-9_:])"
        )

        def replace(match: re.Match[str], *, replacement: str = dst) -> str:
            prefix = match.group("global_prefix") or ""
            return f"{prefix}{replacement}"

        updated, count = pattern.subn(replace, updated)
        if count:
            applied.append({"from": src, "to": dst, "count": count})
    return updated, applied


def _split_declarations(text: str) -> list[DeclarationChunkDict]:
    chunks, _brace_balance = _parse_declaration_chunks(text)
    return [chunk.to_dict() for chunk in chunks]


def _parse_declaration_chunks(text: str) -> tuple[list[DeclarationChunk], int]:
    chunks: list[DeclarationChunk] = []
    current: list[str] = []
    line = 1
    start_line = 1
    brace_depth = 0
    paren_depth = 0
    in_string: str | None = None
    in_line_comment = False
    in_block_comment = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        current.append(ch)
        if ch == "\n":
            line += 1
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                current.append(nxt)
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if ch == "\\":
                if nxt:
                    current.append(nxt)
                    if nxt == "\n":
                        line += 1
                    i += 2
                    continue
            elif ch == in_string:
                in_string = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            current.append(nxt)
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            current.append(nxt)
            in_block_comment = True
            i += 2
            continue
        if ch in {"'", '"'}:
            in_string = ch
            i += 1
            continue
        if ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth = max(0, brace_depth - 1)
        elif ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth = max(0, paren_depth - 1)
        elif ch == ";" and brace_depth == 0 and paren_depth == 0:
            raw = "".join(current)
            stripped = raw.strip()
            if stripped:
                chunks.append(DeclarationChunk(stripped, start_line, line, True))
            current = []
            start_line = _next_chunk_start_line(text, i + 1, line)
        i += 1
    tail = "".join(current).strip()
    if tail:
        chunks.append(DeclarationChunk(tail, start_line, line, False))
    return chunks, brace_depth


def _next_chunk_start_line(text: str, index: int, line: int) -> int:
    next_line = line
    i = index
    while i < len(text):
        ch = text[i]
        if ch == "\n":
            next_line += 1
            i += 1
            continue
        if ch in {" ", "\t", "\r"}:
            i += 1
            continue
        break
    return next_line


def _append_type_diagnostic(
    diagnostics: list[TypeDiagnosticDict],
    *,
    kind: str,
    message: str,
    line: int | None = None,
    end_line: int | None = None,
    snippet: str | None = None,
    construct: str | None = None,
) -> None:
    diagnostics.append(
        _make_type_diagnostic(
            kind=kind,
            message=message,
            line=line,
            end_line=end_line,
            snippet=snippet,
            construct=construct,
        )
    )


def _chunk_type_diagnostics(
    chunk: DeclarationChunk,
    *,
    aliases_applied: list[AppliedAlias],
) -> list[TypeDiagnosticDict]:
    text = chunk.text
    snippet = text[:240]
    line = chunk.start_line
    end_line = chunk.end_line
    diagnostics: list[TypeDiagnosticDict] = []

    if "__cppobj" in text:
        _append_type_diagnostic(
            diagnostics,
            kind="cppobj_hint",
            message=(
                "IDA may reject `__cppobj` in local type imports; retry with plain `struct` "
                "declarations and concrete placeholder support types"
            ),
            line=line,
            end_line=end_line,
            snippet=snippet,
            construct="__cppobj",
        )
    if re.match(r"^\s*(class|struct|union)\s+[A-Za-z_][A-Za-z0-9_:]*\s*;\s*$", text):
        _append_type_diagnostic(
            diagnostics,
            kind="forward_declaration_hint",
            message=(
                "forward declarations are often insufficient here; import a concrete placeholder "
                "definition instead of only `type_name;`"
            ),
            line=line,
            end_line=end_line,
            snippet=snippet,
            construct="forward_declaration",
        )
    if "__cppobj" not in text and re.search(r"\bclass\s+[A-Za-z_][A-Za-z0-9_:]*\b", text):
        _append_type_diagnostic(
            diagnostics,
            kind="class_keyword_hint",
            message=(
                "if this is a recovered object layout, retry with plain `struct` declarations instead of `class` syntax"
            ),
            line=line,
            end_line=end_line,
            snippet=snippet,
            construct="class",
        )
    if "::" in text and not aliases_applied:
        _append_type_diagnostic(
            diagnostics,
            kind="namespace_hint",
            message="namespace-qualified identifiers may require --alias old=new before import",
            line=line,
            end_line=end_line,
            snippet=snippet,
            construct="::",
        )
    return diagnostics


def _type_declare_diagnostics(
    decl: str,
    *,
    errors: int,
    aliases_applied: list[AppliedAlias],
    chunks: list[DeclarationChunk] | None = None,
    brace_balance: int | None = None,
) -> list[TypeDiagnosticDict]:
    diagnostics: list[TypeDiagnosticDict] = []
    seen: set[tuple[str, int | None, str | None]] = set()

    def add_unique(item: TypeDiagnosticDict) -> None:
        key = (item["kind"], item.get("line"), item.get("construct"))
        if key in seen:
            return
        seen.add(key)
        diagnostics.append(item)

    if chunks is None or brace_balance is None:
        parsed_chunks, parsed_brace_balance = _parse_declaration_chunks(decl)
        if chunks is None:
            chunks = parsed_chunks
        if brace_balance is None:
            brace_balance = parsed_brace_balance
    resolved_chunks = chunks if chunks is not None else []
    resolved_brace_balance = 0 if brace_balance is None else brace_balance
    for chunk in resolved_chunks:
        if not chunk.terminated:
            add_unique(
                _make_type_diagnostic(
                    kind="unterminated_declaration",
                    message="declaration does not end with a top-level semicolon",
                    line=chunk.start_line,
                    end_line=chunk.end_line,
                    snippet=chunk.text[:240],
                )
            )
    if resolved_brace_balance > 0:
        add_unique(
            _make_type_diagnostic(
                kind="unbalanced_braces",
                message="more opening braces than closing braces were found",
                balance=resolved_brace_balance,
            )
        )
    if errors:
        for chunk in resolved_chunks:
            for item in _chunk_type_diagnostics(chunk, aliases_applied=aliases_applied):
                add_unique(item)
    if errors and not diagnostics:
        first = resolved_chunks[0] if resolved_chunks else DeclarationChunk(decl.strip(), 1, 1, False)
        add_unique(
            _make_type_diagnostic(
                kind="parser_error",
                message=f"IDA reported {errors} parser error(s); rerun with smaller declaration batches if needed",
                line=first.start_line,
                end_line=first.end_line,
                snippet=first.text[:240],
            )
        )
    return diagnostics


def _parse_type_declarations(runtime: IdaRuntime, decl: str, *, replace: bool, clang: bool) -> int:
    ida_typeinf = runtime.mod("ida_typeinf")
    if not clang:
        flags = ida_typeinf.PT_REPLACE if replace else 0
        return ida_typeinf.idc_parse_types(decl, flags)

    if replace:
        return _parse_type_declarations_with_clang_replace(runtime, decl)

    return _parse_type_declarations_with_clang(runtime, decl)


def _parse_type_declarations_with_clang(runtime: IdaRuntime, decl: str) -> int:
    ida_typeinf = runtime.mod("ida_typeinf")
    ida_srclang = runtime.mod("ida_srclang")
    hti_flags = ida_typeinf.HTI_DCL | ida_typeinf.HTI_SEMICOLON
    if "::" in decl:
        hti_flags |= getattr(ida_typeinf, "HTI_RELAXED", 0)
    errors = ida_srclang.parse_decls_with_parser_ext("clang", None, decl, hti_flags)
    if errors < 0:
        raise IdaOperationError("clang parser is unavailable for type declare")
    return errors


def _typedef_alias_names(text: str) -> set[str]:
    names: set[str] = set()
    func_alias_match = _TYPEDEF_FUNC_ALIAS_RE.match(text)
    if func_alias_match:
        alias = func_alias_match.group("alias")
        if alias:
            names.add(alias)
        return names
    simple_alias_match = _TYPEDEF_SIMPLE_ALIAS_RE.match(text)
    if simple_alias_match:
        alias = simple_alias_match.group("alias")
        if alias:
            names.add(alias)
    return names


def _declared_type_names(chunks: list[DeclarationChunk]) -> set[str]:
    names: set[str] = set()
    for chunk in chunks:
        names.update(_concrete_type_names(chunk.text))
        names.update(_forward_declared_type_names(chunk.text))
        names.update(_typedef_alias_names(chunk.text))
    return {name for name in names if name}


def _delete_named_types(runtime: IdaRuntime, type_names: set[str]) -> None:
    if not type_names:
        return
    ida_typeinf = runtime.mod("ida_typeinf")
    for name in sorted(type_names):
        if runtime.find_named_type(name) is None:
            continue
        if not ida_typeinf.del_named_type(None, name, ida_typeinf.NTF_TYPE):
            raise IdaOperationError(f"failed to replace existing local type: {name}")


def _parse_type_declarations_with_clang_replace(runtime: IdaRuntime, decl: str) -> int:
    type_names = _declared_type_names(_coerce_chunks(_parse_declaration_chunks(decl)[0]))
    if not type_names:
        return _parse_type_declarations_with_clang(runtime, decl)

    ida_undo = runtime.mod("ida_undo")
    if not ida_undo.create_undo_point(
        action_name="idac_type_declare_clang_replace",
        label="idac type declare clang replace",
    ):
        raise IdaOperationError("type declare --clang --replace requires IDA undo support")

    try:
        _delete_named_types(runtime, type_names)
        errors = _parse_type_declarations_with_clang(runtime, decl)
    except Exception as exc:
        if not ida_undo.perform_undo():
            raise IdaOperationError(
                "type declare --clang --replace could not restore deleted local types via undo"
            ) from exc
        raise
    if errors and not ida_undo.perform_undo():
        raise IdaOperationError("type declare --clang --replace could not restore deleted local types via undo")
    return errors


def _apply_type_declarations(
    runtime: IdaRuntime,
    decl: str,
    *,
    replace: bool,
    clang: bool,
) -> tuple[int, NamedTypeSnapshot, NamedTypeSnapshot]:
    before = _named_types_snapshot(runtime)
    errors = _parse_type_declarations(runtime, decl, replace=replace, clang=clang)
    return errors, before, _named_types_snapshot(runtime)


def _forward_declared_type_names(text: str) -> set[str]:
    match = _FORWARD_DECL_RE.match(text)
    if not match:
        return set()
    names = {match.group("tag")}
    alias = match.group("alias")
    if alias:
        names.add(alias)
    return {name for name in names if name}


def _concrete_type_names(text: str) -> set[str]:
    names = {match.group("name") for match in _CONCRETE_TYPE_RE.finditer(text)}
    alias_match = _TYPEDEF_ALIAS_RE.match(text)
    if alias_match:
        alias = alias_match.group("alias")
        if alias:
            names.add(alias)
        tag = alias_match.group("tag")
        if tag:
            names.add(tag)
    return {name for name in names if name}


def _opaque_by_value_members(
    failing_chunk: ChunkLike,
    *,
    earlier_chunks: list[ChunkLike],
) -> list[BlockingMember]:
    failing_chunk = _coerce_chunk(failing_chunk)
    earlier_chunks = _coerce_chunks(earlier_chunks)
    concrete: set[str] = set()
    forward: set[str] = set()
    for chunk in [*earlier_chunks, failing_chunk]:
        text = chunk.text
        concrete.update(_concrete_type_names(text))
        forward.update(_forward_declared_type_names(text))
    forward -= concrete
    if not forward:
        return []

    owning_types = _concrete_type_names(failing_chunk.text)
    rows: list[BlockingMember] = []
    for raw_stmt in failing_chunk.text.replace("\n", " ").split(";"):
        stmt = raw_stmt.strip()
        if not stmt or any(token in stmt for token in ("*", "&", "(")):
            continue
        if "{" in stmt:
            stmt = stmt.rsplit("{", 1)[-1].strip()
        if "}" in stmt:
            stmt = stmt.split("}", 1)[0].strip()
        if not stmt:
            continue
        match = _BY_VALUE_MEMBER_RE.match(stmt)
        if not match:
            continue
        type_name = match.group("type") or ""
        member_name = match.group("name") or ""
        if not type_name or not member_name:
            continue
        if type_name in owning_types or type_name.lower() in _BUILTIN_MEMBER_TYPES:
            continue
        if type_name not in forward:
            continue
        rows.append({"type_name": type_name, "member_name": member_name})
    return rows


def _trial_type_parse_errors(
    runtime: IdaRuntime,
    decl: str,
    *,
    replace: bool,
    clang: bool,
    label: str,
) -> int:
    action = re.sub(r"[^A-Za-z0-9_]+", "_", label).strip("_") or "trial"
    with ida_undo_restore_point(
        runtime,
        action_name=f"idac_type_declare_{action}",
        label=f"idac type declare {label}",
        unavailable_message="type declare bisect requires IDA undo support",
        restore_error_message="type declare bisect could not restore the trial import via undo",
    ):
        return _parse_type_declarations(runtime, decl, replace=replace, clang=clang)


def _bisect_type_declarations(
    runtime: IdaRuntime,
    chunks: list[ChunkLike],
    *,
    replace: bool,
    clang: bool,
) -> TypeDeclareBisectResult:
    chunks = _coerce_chunks(chunks)
    result: TypeDeclareBisectResult = {
        "requested": True,
        "supported": True,
        "mode": "ordered_prefix",
        "declaration_count": len(chunks),
        "trials": [],
    }
    if not chunks:
        result["supported"] = False
        result["message"] = "no declarations were available for bisect"
        return result

    try:
        if len(chunks) == 1:
            failing_index = 0
            standalone_errors = _trial_type_parse_errors(
                runtime,
                _join_declaration_chunks([chunks[0]]),
                replace=replace,
                clang=clang,
                label="single_decl",
            )
        else:
            low = 1
            high = len(chunks)
            while low < high:
                mid = (low + high) // 2
                errors = _trial_type_parse_errors(
                    runtime,
                    _join_declaration_chunks(chunks[:mid]),
                    replace=replace,
                    clang=clang,
                    label=f"prefix_{mid}",
                )
                result["trials"].append({"prefix_count": mid, "errors": errors, "success": errors == 0})
                if errors:
                    high = mid
                else:
                    low = mid + 1
            failing_index = low - 1
            standalone_errors = _trial_type_parse_errors(
                runtime,
                _join_declaration_chunks([chunks[failing_index]]),
                replace=replace,
                clang=clang,
                label=f"single_{failing_index + 1}",
            )
    except IdaOperationError as exc:
        result["supported"] = False
        result["message"] = str(exc) or exc.__class__.__name__
        result["diagnostics"] = [{"kind": "bisect_unavailable", "message": result["message"]}]
        return result

    failing_chunk = chunks[failing_index]
    diagnostics: list[dict[str, Any]] = [
        {
            "kind": "bisect_culprit",
            "message": "ordered bisect isolated the first failing declaration",
            "line": failing_chunk.start_line,
            "end_line": failing_chunk.end_line,
            "snippet": failing_chunk.text[:240],
        }
    ]
    if standalone_errors == 0 and len(chunks) > 1:
        diagnostics.append(
            {
                "kind": "bisect_context_hint",
                "message": (
                    "the isolated declaration imports alone; the failure depends on earlier "
                    "declarations or ordered batch context"
                ),
                "line": failing_chunk.start_line,
                "end_line": failing_chunk.end_line,
                "snippet": failing_chunk.text[:240],
            }
        )
    blocking_members = _opaque_by_value_members(failing_chunk, earlier_chunks=chunks[:failing_index])
    for member in blocking_members:
        diagnostics.append(
            {
                "kind": "opaque_by_value_member_hint",
                "message": (
                    "by-value member "
                    f"`{member['member_name']}` uses forward-declared or opaque type "
                    f"`{member['type_name']}`; import a concrete placeholder definition first"
                ),
                "line": failing_chunk.start_line,
                "end_line": failing_chunk.end_line,
                "snippet": failing_chunk.text[:240],
                "construct": member["type_name"],
            }
        )
    result["message"] = diagnostics[0]["message"]
    result["failing_declaration"] = {
        "index": failing_index + 1,
        "line": failing_chunk.start_line,
        "end_line": failing_chunk.end_line,
        "snippet": failing_chunk.text[:240],
        "standalone_errors": standalone_errors,
        "standalone_success": standalone_errors == 0,
    }
    if blocking_members:
        result["blocking_members"] = blocking_members
    result["diagnostics"] = diagnostics
    return result


def _bisect_unavailable_result(
    chunks: list[DeclarationChunk],
    exc: IdaOperationError,
) -> TypeDeclareBisectResult:
    message = str(exc) or exc.__class__.__name__
    return {
        "requested": True,
        "supported": False,
        "mode": "ordered_prefix",
        "declaration_count": len(chunks),
        "message": message,
        "diagnostics": [{"kind": "bisect_unavailable", "message": message}],
    }


def _apply_type_declarations_with_optional_bisect(
    runtime: IdaRuntime,
    decl: str,
    *,
    replace: bool,
    clang: bool,
    chunks: list[DeclarationChunk],
    bisect_requested: bool,
) -> tuple[int, NamedTypeSnapshot, NamedTypeSnapshot, TypeDeclareBisectResult | None]:
    if not bisect_requested:
        errors, before, after = _apply_type_declarations(runtime, decl, replace=replace, clang=clang)
        return errors, before, after, None

    try:
        trial_errors = _trial_type_parse_errors(runtime, decl, replace=replace, clang=clang, label="full")
    except IdaOperationError as exc:
        before = _named_types_snapshot(runtime)
        return 1, before, dict(before), _bisect_unavailable_result(chunks, exc)

    if trial_errors == 0:
        errors, before, after = _apply_type_declarations(runtime, decl, replace=replace, clang=clang)
        return errors, before, after, None

    before = _named_types_snapshot(runtime)
    return (
        trial_errors,
        before,
        dict(before),
        _bisect_type_declarations(runtime, chunks, replace=replace, clang=clang),
    )


def _type_declare_result(
    decl: str,
    *,
    replace: bool,
    errors: int,
    before: NamedTypeSnapshot,
    after: NamedTypeSnapshot,
    aliases_applied: list[AppliedAlias],
    chunks: list[DeclarationChunk],
    brace_balance: int,
    bisect: TypeDeclareBisectResult | None = None,
) -> TypeDeclareResult:
    diagnostics = _type_declare_diagnostics(
        decl,
        errors=errors,
        aliases_applied=aliases_applied,
        chunks=chunks,
        brace_balance=brace_balance,
    )
    if bisect is not None:
        existing = {(item["kind"], item.get("line"), item["message"]) for item in diagnostics}
        for item in bisect.get("diagnostics") or []:
            key = (item["kind"], item.get("line"), item["message"])
            if key in existing:
                continue
            diagnostics.append(item)
            existing.add(key)
    return {
        "errors": errors,
        "replace": replace,
        "aliases_applied": aliases_applied,
        "diagnostics": diagnostics,
        "imported_types": sorted(set(after) - set(before)),
        "replaced_types": sorted(name for name in set(after) & set(before) if before.get(name) != after.get(name)),
        "declaration_count": len(chunks),
        "success": errors == 0,
        "bisect": bisect,
    }


def _preview_snapshot(runtime: IdaRuntime, params: Mapping[str, Any]) -> dict[str, object]:
    del params
    names = runtime.list_named_types()
    return {
        "type_count": len(names),
        "class_count": len(runtime.list_named_classes()),
        "type_names_sample": [str(item.get("name") or "") for item in names[:10]],
    }


def _type_declare(runtime: IdaRuntime, request: TypeDeclareRequest) -> TypeDeclareResult:
    decl, aliases_applied = _apply_type_aliases(request.decl, list(request.aliases))
    chunks, brace_balance = _parse_declaration_chunks(decl)
    errors, before, after, bisect = _apply_type_declarations_with_optional_bisect(
        runtime,
        decl,
        replace=request.replace,
        clang=request.clang,
        chunks=chunks,
        bisect_requested=request.bisect,
    )
    return _type_declare_result(
        decl,
        replace=request.replace,
        errors=errors,
        before=before,
        after=after,
        aliases_applied=aliases_applied,
        chunks=chunks,
        brace_balance=brace_balance,
        bisect=bisect,
    )


def _run_type_declare(runtime: IdaRuntime, params: Mapping[str, Any]) -> TypeDeclareResult:
    return _type_declare(runtime, _parse_request(params))


TYPE_DECLARE_OPS: dict[str, Op] = {
    "type_declare": Op(
        run=_run_type_declare,
        mutating=True,
        preview=PreviewSpec(
            capture_before=_preview_snapshot,
            capture_after=_preview_snapshot,
            use_undo=True,
        ),
    ),
}


__all__ = [
    "TYPE_DECLARE_OPS",
    "AppliedAlias",
    "BlockingMember",
    "DeclarationChunk",
    "DeclarationChunkDict",
    "TypeAlias",
    "TypeDeclareBisectResult",
    "TypeDeclareDiagnostic",
    "TypeDeclareRequest",
    "TypeDeclareResult",
    "_apply_type_aliases",
    "_bisect_type_declarations",
    "_normalize_aliases",
    "_opaque_by_value_members",
    "_split_declarations",
    "_type_declare_diagnostics",
]
