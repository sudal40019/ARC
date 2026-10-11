"""Structural Solidity parser.

This is not a full compiler frontend. It recovers contracts, state variables,
and function bodies well enough to order external calls against state writes.
Malformed source degrades to a smaller model instead of raising.
"""

from __future__ import annotations

import re

from arc_auditor.models import Contract, Function, Region, SourceUnit
from arc_auditor.pragma import classify_pragma
from arc_auditor.textutil import (
    line_starts,
    match_keyword,
    match_pair,
    read_ident,
    skip_string,
    skip_ws,
    split_commas,
    strip_comments,
)

_PRAGMA = re.compile(r"pragma\s+solidity\s+([^;]+);")
_CALLABLES = ("constructor", "function", "modifier", "fallback", "receive")
_TYPE_WORDS = {
    "uint",
    "int",
    "bool",
    "address",
    "string",
    "byte",
    "bytes",
    "fixed",
    "ufixed",
    "mapping",
    "struct",
    "enum",
}
_SKIP_WORDS = _TYPE_WORDS | {
    "public",
    "private",
    "internal",
    "external",
    "constant",
    "immutable",
    "override",
    "virtual",
    "indexed",
    "payable",
    "memory",
    "calldata",
    "storage",
    "pure",
    "view",
    "returns",
    "return",
}


def _is_builtin_type(token: str) -> bool:
    if token in _TYPE_WORDS:
        return True
    if re.fullmatch(r"u?int\d+", token):
        return True
    if re.fullmatch(r"bytes\d+", token):
        return True
    if re.fullmatch(r"u?fixed\d+x\d+", token):
        return True
    return False


def _keyword_at(text: str, i: int) -> str:
    for word in ("constructor", "function", "modifier", "fallback", "receive", "struct", "enum"):
        if match_keyword(text, i, word):
            return word
    return ""


def _looks_like_callable(text: str, i: int, keyword: str, end: int) -> bool:
    if keyword in {"function", "constructor"}:
        return True
    j = skip_ws(text, i + len(keyword), end)
    if j >= end:
        return False
    ch = text[j]
    if ch in "=;":
        return False
    return ch == "(" or ch == "{" or ch.isalpha() or ch == "_"


def _parse_header_flags(header: str) -> tuple[str, str, list[str]]:
    cleaned = re.sub(r"\boverride\b(?:\s*\([^)]*\))?", " ", header)
    cleaned = re.sub(r"\breturns\b\s*\([^)]*\)", " ", cleaned)
    visibility = "unspecified"
    mutability = ""
    modifiers: list[str] = []
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cleaned):
        if token in {"public", "private", "internal", "external"}:
            visibility = token
        elif token in {"view", "pure"}:
            mutability = token
        elif token == "payable":
            if mutability not in {"view", "pure"}:
                mutability = "payable"
        elif token in {
            "virtual",
            "memory",
            "calldata",
            "storage",
            "constant",
            "immutable",
            "indexed",
        }:
            continue
        else:
            modifiers.append(token)
    return visibility, mutability, modifiers


def _parse_parents(header: str) -> list[str]:
    match = re.search(r"\bis\b(.*)$", header, flags=re.S)
    if not match:
        return []
    names: list[str] = []
    for part in split_commas(match.group(1)):
        idents = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", part)
        if idents:
            names.append(idents[0])
    return names


def _state_var_name(statement: str) -> str | None:
    text = " ".join(statement.split())
    if not text.endswith(";"):
        return None
    head_ident = re.match(r"[A-Za-z_]+", text)
    head = head_ident.group(0) if head_ident else ""
    if head in {
        "using",
        "import",
        "event",
        "error",
        "struct",
        "enum",
        "type",
        "function",
        "constructor",
        "modifier",
        "receive",
        "fallback",
    }:
        return None
    # `=>` inside a mapping type is not an assignment.
    text = text.replace("=>", " ")
    left = text.split("=", 1)[0]
    idents = [
        token
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", left)
        if token not in _SKIP_WORDS and not _is_builtin_type(token)
    ]
    if not idents:
        return None
    return idents[-1]


def _parse_region(text: str, i: int, end: int, keyword: str, kind: str, starts: list[int]) -> Region | None:
    j = skip_ws(text, i + len(keyword), end)
    header = ""
    if kind == "assembly" and j < end and text[j] == "(":
        close = match_pair(text, j, end, "(", ")")
        if close < 0:
            return None
        j = skip_ws(text, close + 1, end)
    if kind == "loop":
        if j >= end or text[j] != "(":
            return None
        close_paren = match_pair(text, j, end, "(", ")")
        if close_paren < 0:
            return None
        header = text[j : close_paren + 1]
        j = skip_ws(text, close_paren + 1, end)
    if j >= end or text[j] != "{":
        if kind == "loop" and j < end:
            # Single-statement body: consume through the next top-level semicolon.
            k = j
            paren = bracket = 0
            while k < end:
                ch = text[k]
                if ch in "\"'":
                    k = skip_string(text, k)
                    continue
                if ch == "(":
                    paren += 1
                elif ch == ")":
                    paren = max(0, paren - 1)
                elif ch == "[":
                    bracket += 1
                elif ch == "]":
                    bracket = max(0, bracket - 1)
                elif ch == ";" and paren == 0 and bracket == 0:
                    return Region("loop", j, k + 1, _line_of(starts, i), header)
                k += 1
        return None
    close = match_pair(text, j, end, "{", "}")
    if close < 0:
        return None
    return Region(kind, j + 1, close, _line_of(starts, i), header)


def _line_of(starts: list[int], index: int) -> int:
    lo, hi = 0, len(starts) - 1
    if hi < 0:
        return 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= index:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


def _find_regions(text: str, start: int, end: int, starts: list[int]) -> list[Region]:
    regions: list[Region] = []
    i = start
    while i < end:
        ch = text[i]
        if ch in "\"'":
            i = skip_string(text, i)
            continue
        matched = False
        for keyword, kind in (
            ("unchecked", "unchecked"),
            ("assembly", "assembly"),
            ("for", "loop"),
            ("while", "loop"),
        ):
            if match_keyword(text, i, keyword):
                region = _parse_region(text, i, end, keyword, kind, starts)
                if region is not None:
                    regions.append(region)
                i += len(keyword)
                matched = True
                break
        if not matched:
            i += 1
    return regions


def _parse_callable(
    text: str,
    i: int,
    end: int,
    keyword: str,
    starts: list[int],
    contract_name: str,
) -> tuple[Function | None, int]:
    start = i
    i = skip_ws(text, i + len(keyword), end)
    name = keyword
    if keyword in {"function", "modifier"}:
        if i < end and (text[i].isalpha() or text[i] == "_"):
            name, i = read_ident(text, i)
            i = skip_ws(text, i, end)
        elif keyword == "function":
            name = "fallback"
    params = ""
    if i < end and text[i] == "(":
        close = match_pair(text, i, end, "(", ")")
        if close < 0:
            return None, min(end, i + 1)
        params = text[i : close + 1]
        i = close + 1
    header_start = i
    paren = 0
    bracket = 0
    while i < end:
        ch = text[i]
        if ch in "\"'":
            i = skip_string(text, i)
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == ";" and paren == 0 and bracket == 0:
            return None, i + 1
        elif ch == "{" and paren == 0 and bracket == 0:
            close = match_pair(text, i, end, "{", "}")
            if close < 0:
                close = end - 1
            header = text[header_start:i]
            visibility, mutability, modifiers = _parse_header_flags(header)
            fn = Function(
                name=name or keyword,
                kind="function" if keyword == "function" else keyword,
                line=_line_of(starts, start),
                header=header,
                body=text[i + 1 : close],
                body_start=i + 1,
                body_end=close,
                params_src=params,
                visibility=visibility,
                mutability=mutability,
                modifiers=modifiers,
                contract=contract_name,
                regions=_find_regions(text, i + 1, close, starts),
            )
            return fn, close + 1
        i += 1
    return None, end


def _parse_members(
    text: str,
    start: int,
    end: int,
    starts: list[int],
    contract_name: str,
) -> tuple[list[Function], list[str]]:
    functions: list[Function] = []
    state_vars: list[str] = []
    i = start
    depth = 0
    stmt_start = start
    while i < end:
        ch = text[i]
        if ch in "\"'":
            i = skip_string(text, i)
            continue
        if depth == 0:
            keyword = _keyword_at(text, i)
            if keyword in _CALLABLES and _looks_like_callable(text, i, keyword, end):
                fn, nxt = _parse_callable(text, i, end, keyword, starts, contract_name)
                if nxt <= i:
                    i += 1
                else:
                    i = nxt
                stmt_start = i
                if fn is not None:
                    functions.append(fn)
                continue
        if ch == "{":
            depth += 1
            i += 1
            continue
        if ch == "}":
            depth = max(0, depth - 1)
            i += 1
            if depth == 0:
                stmt_start = i
            continue
        if ch == ";" and depth == 0:
            name = _state_var_name(text[stmt_start : i + 1])
            if name:
                state_vars.append(name)
            i += 1
            stmt_start = i
            continue
        i += 1
    return functions, state_vars


def _parse_contract(text: str, i: int, end: int, kind: str, starts: list[int]) -> tuple[Contract | None, int]:
    start = i
    i = skip_ws(text, i + len(kind), end)
    if i >= end or not (text[i].isalpha() or text[i] == "_"):
        return None, min(end, i + 1)
    name, i = read_ident(text, i)
    header_start = i
    brace = -1
    j = i
    while j < end:
        ch = text[j]
        if ch in "\"'":
            j = skip_string(text, j)
            continue
        if ch == "{":
            brace = j
            break
        if ch == ";":
            return None, j + 1
        j += 1
    if brace < 0:
        return None, end
    header = text[header_start:brace]
    close = match_pair(text, brace, end, "{", "}")
    if close < 0:
        close = end - 1
    functions, state_vars = _parse_members(text, brace + 1, close, starts, name)
    contract = Contract(
        name=name,
        kind=kind,
        line=_line_of(starts, start),
        parents=_parse_parents(header),
        functions=functions,
        state_vars=state_vars,
    )
    return contract, close + 1


def inherited_state(contracts: list[Contract]) -> dict[str, set[str]]:
    """State names visible inside each contract, including same-file parents."""
    by_name = {contract.name: contract for contract in contracts}
    cache: dict[str, set[str]] = {}

    def walk(name: str, stack: set[str]) -> set[str]:
        if name in cache:
            return set(cache[name])
        if name in stack or name not in by_name:
            return set()
        stack.add(name)
        found = set(by_name[name].state_vars)
        for parent in by_name[name].parents:
            found |= walk(parent, stack)
        stack.remove(name)
        cache[name] = found
        return set(found)

    return {contract.name: walk(contract.name, set()) for contract in contracts}


def parse_source(raw: str, path: str) -> SourceUnit:
    if raw.startswith("\ufeff"):
        raw = raw[1:]
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    clean = strip_comments(raw)
    starts = line_starts(clean)
    pragma = ""
    pragma_line = 0
    match = _PRAGMA.search(clean)
    if match:
        pragma = " ".join(match.group(1).split())
        pragma_line = _line_of(starts, match.start())
    contracts: list[Contract] = []
    i = 0
    n = len(clean)
    while i < n:
        ch = clean[i]
        if ch in " \t\r\n":
            i += 1
            continue
        if ch in "\"'":
            i = skip_string(clean, i)
            continue
        kind = ""
        for word in ("contract", "library", "interface"):
            if match_keyword(clean, i, word):
                kind = word
                break
        if not kind:
            i += 1
            continue
        contract, nxt = _parse_contract(clean, i, n, kind, starts)
        if nxt <= i:
            i += 1
            continue
        i = nxt
        if contract is not None:
            contracts.append(contract)
    return SourceUnit(
        path=path,
        raw=raw,
        clean=clean,
        line_starts=starts,
        raw_lines=raw.splitlines(),
        pragma=pragma,
        pragma_line=pragma_line,
        protection=classify_pragma(pragma) if pragma else "unknown",
        contracts=contracts,
    )
