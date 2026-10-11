"""Detectors. Each one is a structural heuristic, not a proof of safety."""

from __future__ import annotations

import re
from dataclasses import dataclass

from arc_auditor.models import SEVERITY_RANK, Finding, Function, SourceUnit
from arc_auditor.parser import inherited_state, parse_source
from arc_auditor.textutil import mask_strings, skip_string, split_commas

DETECTOR_INFO: list[tuple[str, str, str]] = [
    ("reentrancy", "SWC-107", "External call before a later state write in the same function"),
    ("arithmetic", "SWC-101", "Wrapping arithmetic under a pre-0.8 pragma or inside unchecked"),
    ("unchecked-return", "SWC-104", "Low-level call or token transfer whose success is ignored"),
    ("dangerous-delegatecall", "SWC-112", "delegatecall, which runs foreign code in this contract's storage"),
    ("tx-origin", "SWC-115", "Authorization that uses tx.origin instead of msg.sender"),
    ("unprotected-selfdestruct", "SWC-106", "selfdestruct or suicide without an obvious access check"),
    ("unprotected-ether", "SWC-105", "Sends the whole contract balance without an access check"),
    ("weak-randomness", "SWC-120", "keccak of a miner-influenced block value"),
    ("timestamp-dependence", "SWC-116", "Control flow that compares block.timestamp or now"),
    ("unbounded-loop", "SWC-128", "Loop bounded by a storage array length"),
    ("storage-in-loop", "SWC-128", "Storage write on every iteration of a loop"),
    ("transfer-gas-stipend", "SWC-134", "address.transfer or send, which forward only 2300 gas"),
    ("floating-pragma", "SWC-103", "Pragma that does not pin an exact compiler"),
    ("deprecated-syntax", "SWC-111", "suicide, sha3, throw, or callcode"),
    ("strict-balance", "SWC-132", "Strict equality on the contract's ether balance"),
]

_SENSITIVE = re.compile(
    r"\b(balance|balances|_balance|_balances|amount|amounts|_amount|supply|totalSupply|"
    r"shares|share|deposit|stake|staked|reward|rewards|fee|fees|liquidity|reserve|"
    r"reserves|collateral|debt|principal)\b",
    re.I,
)
_LOCK_NAMES = {
    "locked",
    "lock",
    "_locked",
    "_lock",
    "reentrancyLock",
    "_status",
    "entered",
    "_entered",
    "_notEntered",
    "mutex",
    "_mutex",
}
_ACL = re.compile(
    r"\bonlyOwner\b|\bonlyRole\b|\bonlyAdmin\b|\bonlyGovernance\b|"
    r"\b_checkOwner\b|\brequire\s*\(\s*msg\s*\.\s*sender\s*==|"
    r"\bmsg\s*\.\s*sender\s*==\s*[A-Za-z_][\w]*"
)
_CALL = re.compile(
    r"""(?x)
    \.\s*call\s*\.\s*value\s*\(
    | \.\s*(?P<kind>call|delegatecall|staticcall|send|transferFrom|safeTransferFrom|safeTransfer|transfer)
      \s*(?P<open>[\(\{])
    """
)
_LOCAL_DECL = re.compile(
    r"\b(?:uint\d*|int\d*|bool|address|string|bytes\d*|bytes)\s+"
    r"(?:(?:memory|storage|calldata|constant)\s+)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\b"
)
_CUSTOM_LOCAL = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*)\s+(?:(?:memory|storage|calldata)\s+)+"
    r"([A-Za-z_][A-Za-z0-9_]*)\b"
)
_DEPRECATED = (
    (re.compile(r"\bsuicide\s*\("), "suicide", "selfdestruct"),
    (re.compile(r"\bsha3\s*\("), "sha3", "keccak256"),
    (re.compile(r"\bthrow\b"), "throw", "revert"),
    (re.compile(r"\.callcode\s*\("), "callcode", "delegatecall"),
)

_CALL_SEVERITY = {
    "call": "critical",
    "delegatecall": "critical",
    "staticcall": "medium",
    "send": "high",
    "transfer": "high",
    "transferFrom": "high",
    "safeTransfer": "high",
    "safeTransferFrom": "high",
}


@dataclass
class _Hit:
    pos: int
    line: int
    root: str = ""
    kind: str = ""
    is_lock: bool = False


def _locals_of(fn: Function) -> set[str]:
    names: set[str] = set()
    params = fn.params_src.strip()
    if params.startswith("(") and params.endswith(")"):
        params = params[1:-1]
    for part in split_commas(params):
        idents = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", part)
        idents = [token for token in idents if not _is_type_or_keyword(token)]
        if idents:
            names.add(idents[-1])
    body = fn.body
    names.update(_LOCAL_DECL.findall(body))
    for match in _CUSTOM_LOCAL.finditer(body):
        names.add(match.group(2))
    return names


def _is_type_or_keyword(token: str) -> bool:
    if token in {
        "memory",
        "calldata",
        "storage",
        "indexed",
        "payable",
        "mapping",
        "struct",
        "enum",
        "public",
        "private",
        "internal",
        "external",
        "constant",
        "immutable",
        "return",
        "returns",
    }:
        return True
    if token in {"uint", "int", "bool", "address", "string", "byte", "bytes", "fixed", "ufixed"}:
        return True
    if re.fullmatch(r"u?int\d+", token) or re.fullmatch(r"bytes\d+", token):
        return True
    return False


def _assignment_roots(masked: str) -> list[tuple[int, str]]:
    """Return (index of operator, root identifier of the left-hand side)."""
    found: list[tuple[int, str]] = []
    i = 0
    n = len(masked)
    while i < n:
        if masked.startswith(("==", "!=", "<=", ">="), i):
            i += 2
            continue
        if masked.startswith(("=>",), i):
            i += 2
            continue
        op_len = 0
        if masked.startswith(("+=", "-=", "*=", "/=", "%="), i):
            op_len = 2
        elif masked[i] == "=":
            prev = masked[i - 1] if i else ""
            nxt = masked[i + 1] if i + 1 < n else ""
            if prev not in "=<>!" and nxt not in "=>":
                op_len = 1
        if op_len:
            lhs = masked[:i]
            # Keep only the current statement's left side.
            cut = max(lhs.rfind(";"), lhs.rfind("{"), lhs.rfind("}"))
            segment = lhs[cut + 1 :]
            if not segment.strip().startswith("("):
                root = _lvalue_root(segment)
                if root:
                    found.append((i, root))
            i += op_len
            continue
        i += 1
    return found


def _lvalue_root(lhs: str) -> str | None:
    """Outermost identifier being assigned, ignoring indexes and member names."""
    kept: list[str] = []
    depth = 0
    for ch in lhs:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        elif depth == 0:
            kept.append(ch)
    flat = "".join(kept).strip()
    if not flat or flat[0] in "({":
        return None
    idents = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", flat)
    if not idents:
        return None
    root = idents[0] if "." in flat else idents[-1]
    if root in {"require", "assert", "revert", "if", "while", "return", "emit", "delete", "new", "for"}:
        return None
    if _is_type_or_keyword(root) and root != idents[-1]:
        root = idents[-1]
    if _is_type_or_keyword(root):
        return None
    return root


def _state_writes(fn: Function, state_vars: set[str], unit: SourceUnit) -> list[_Hit]:
    if not state_vars:
        return []
    masked = mask_strings(fn.body)
    locals_ = _locals_of(fn)
    hits: list[_Hit] = []

    def add(pos: int, root: str) -> None:
        if root not in state_vars or root in locals_:
            return
        hits.append(
            _Hit(
                pos=pos,
                line=unit.line_of(fn.body_start + pos),
                root=root,
                is_lock=root in _LOCK_NAMES,
            )
        )

    for match in re.finditer(r"\bdelete\s+([A-Za-z_][A-Za-z0-9_]*)", masked):
        add(match.start(), match.group(1))
    for match in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:push|pop)\s*\(",
        masked,
    ):
        add(match.start(), match.group(1))
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+\+|--)", masked):
        add(match.start(), match.group(1))
    for match in re.finditer(r"(?:\+\+|--)\s*([A-Za-z_][A-Za-z0-9_]*)", masked):
        add(match.start(), match.group(1))
    for pos, root in _assignment_roots(masked):
        add(pos, root)
    hits.sort(key=lambda item: item.pos)
    return hits


def _calls(fn: Function, unit: SourceUnit) -> list[_Hit]:
    masked = mask_strings(fn.body)
    hits: list[_Hit] = []
    for match in _CALL.finditer(masked):
        kind = match.group("kind") or "call"
        hits.append(
            _Hit(
                pos=match.start(),
                line=unit.line_of(fn.body_start + match.start()),
                kind=kind,
            )
        )
    return hits


def _has_guard(fn: Function) -> bool:
    return any(re.search(r"reentr", name, re.I) for name in fn.modifiers)


def _line_has_arithmetic(line: str) -> bool:
    scrubbed = mask_strings(line)
    scrubbed = re.sub(r"==|!=|<=|>=|&&|\|\||<<|>>|\+\+|--|=>", " ", scrubbed)
    if re.search(r"\+=|-=|\*=|/=|%=", scrubbed):
        return True
    return bool(re.search(r"[\w)\]]\s*[+\-*/%]\s*[\w(]", scrubbed))


def _overlaps(unit: SourceUnit, line: int, fn: Function, kind: str) -> bool:
    if line < 1 or line > len(unit.line_starts):
        return False
    start = unit.line_starts[line - 1]
    end = unit.line_starts[line] if line < len(unit.line_starts) else len(unit.clean)
    return any(region.kind == kind and region.start < end and start < region.end for region in fn.regions)


def _finding(
    unit: SourceUnit,
    *,
    detector: str,
    severity: str,
    swc: str,
    title: str,
    message: str,
    recommendation: str,
    line: int,
    contract: str = "",
    function: str = "",
    related_line: int | None = None,
) -> Finding:
    return Finding(
        detector=detector,
        severity=severity,
        swc=swc,
        title=title,
        message=message,
        recommendation=recommendation,
        file=unit.path,
        line=line,
        snippet=unit.snippet(line),
        contract=contract,
        function=function,
        related_line=related_line,
        related_snippet=unit.snippet(related_line) if related_line else "",
    )


def _iter_functions(unit: SourceUnit):
    state = inherited_state(unit.contracts)
    for contract in unit.contracts:
        names = state.get(contract.name, set(contract.state_vars))
        for fn in contract.functions:
            yield contract, fn, names


def detect_reentrancy(unit: SourceUnit) -> list[Finding]:
    findings: list[Finding] = []
    for contract, fn, state_vars in _iter_functions(unit):
        if fn.is_view_like or _has_guard(fn) or not fn.body.strip():
            continue
        writes = [item for item in _state_writes(fn, state_vars, unit) if not item.is_lock]
        if not writes:
            continue
        calls = _calls(fn, unit)
        culprit = None
        later = None
        for call in calls:
            after = [item for item in writes if item.pos > call.pos]
            if after:
                culprit = call
                later = after[0]
                break
        if culprit is None or later is None:
            continue
        severity = _CALL_SEVERITY.get(culprit.kind, "high")
        findings.append(
            _finding(
                unit,
                detector="reentrancy",
                severity=severity,
                swc="SWC-107",
                title="External call before state update",
                message=(
                    f"{fn.qualified_name} performs .{culprit.kind} and only afterwards writes "
                    f"`{later.root}` (line {later.line}). A callee can re-enter before that write."
                ),
                recommendation=(
                    "Apply checks-effects-interactions: write every storage update before the "
                    "external call, or guard the function with OpenZeppelin's nonReentrant modifier."
                ),
                line=culprit.line,
                contract=contract.name,
                function=fn.name,
                related_line=later.line,
            )
        )
    return findings


def detect_arithmetic(unit: SourceUnit) -> list[Finding]:
    findings: list[Finding] = []
    protected = unit.protection == "yes"
    for contract, fn, _state in _iter_functions(unit):
        if "safemath" in contract.name.lower():
            continue
        if not fn.body.strip():
            continue
        clean_lines = unit.clean.splitlines()
        start = unit.line_of(fn.body_start)
        end = unit.line_of(max(fn.body_start, fn.body_end - 1))
        for line_no in range(start, end + 1):
            if line_no < 1 or line_no > len(clean_lines):
                continue
            if _overlaps(unit, line_no, fn, "assembly"):
                continue
            in_unchecked = _overlaps(unit, line_no, fn, "unchecked")
            if protected and not in_unchecked:
                continue
            text = clean_lines[line_no - 1]
            if not _line_has_arithmetic(text):
                continue
            sensitive = bool(_SENSITIVE.search(text))
            severity = "high" if sensitive else "medium"
            if protected and in_unchecked:
                title = "Arithmetic inside an unchecked block"
                message = (
                    f"{fn.qualified_name} does arithmetic inside `unchecked` "
                    "under Solidity 0.8+, so the compiler will not revert on overflow."
                )
                recommendation = (
                    "Move the operation out of `unchecked`, or document a bound that makes wrapping impossible."
                )
            elif unit.protection == "partial":
                title = "Arithmetic under a pragma that still allows pre-0.8 compilers"
                message = (
                    f"The pragma `{unit.pragma}` includes compilers without built-in overflow checks, "
                    f"and {fn.qualified_name} uses raw arithmetic."
                )
                recommendation = (
                    "Narrow the pragma to 0.8 or newer, or replace the operator with a checked SafeMath call."
                )
            elif unit.protection == "unknown":
                title = "Arithmetic with no Solidity pragma"
                message = (
                    f"{fn.qualified_name} uses raw arithmetic and the file has no pragma solidity, "
                    "so it is not possible to assume 0.8 overflow checks."
                )
                recommendation = "Add an exact `pragma solidity 0.8.x` or wrap the operation in SafeMath."
            else:
                title = "Arithmetic without overflow checks"
                message = (
                    f"The pragma `{unit.pragma or 'unknown'}` selects a compiler that wraps on overflow, "
                    f"and {fn.qualified_name} does not use a SafeMath call on this line."
                )
                recommendation = (
                    "Pin Solidity 0.8 or newer, or call a checked SafeMath method such as `.sub` or `.add`."
                )
            findings.append(
                _finding(
                    unit,
                    detector="arithmetic",
                    severity=severity,
                    swc="SWC-101",
                    title=title,
                    message=message,
                    recommendation=recommendation,
                    line=line_no,
                    contract=contract.name,
                    function=fn.name,
                )
            )
    return findings


def _statement_spans(body: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = 0
    i = 0
    paren = bracket = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch in "\"'":
            i = skip_string(body, i)
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
            spans.append((start, i + 1))
            start = i + 1
        i += 1
    if start < n and body[start:].strip():
        spans.append((start, n))
    return spans


def _span_at(spans: list[tuple[int, int]], pos: int, n: int) -> tuple[int, int]:
    for start, end in spans:
        if start <= pos < end:
            return start, end
    return 0, n


def _captured_names(statement: str) -> set[str]:
    names: set[str] = set()
    match = re.search(r"\(([^)]*)\)\s*=", statement)
    if match:
        for part in match.group(1).split(","):
            idents = [token for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", part) if not _is_type_or_keyword(token)]
            if idents:
                names.add(idents[-1])
    match = re.search(
        r"\bbool\s+(?:(?:memory|storage|calldata)\s+)*([A-Za-z_][A-Za-z0-9_]*)\s*=",
        statement,
    )
    if match:
        names.add(match.group(1))
    return names


def _call_is_checked(masked: str, pos: int) -> bool:
    spans = _statement_spans(masked)
    start, end = _span_at(spans, pos, len(masked))
    statement = masked[start:end]
    if re.search(r"\b(require|assert|if)\s*\(", statement):
        return True
    names = _captured_names(statement)
    if not names:
        return False
    rest = masked[end:]
    for name in names:
        if re.search(rf"\b(require|assert|if|while)\s*\([^;]{{0,500}}\b{re.escape(name)}\b", rest):
            return True
    return False


def _arg_count(masked: str, open_paren: int) -> int:
    if open_paren >= len(masked) or masked[open_paren] != "(":
        return -1
    depth = 0
    i = open_paren
    buf: list[str] = []
    parts: list[str] = []
    while i < len(masked):
        ch = masked[i]
        if ch in "\"'":
            j = skip_string(masked, i)
            if depth > 0:
                buf.append(masked[i:j])
            i = j
            continue
        if ch == "(":
            depth += 1
            if depth > 1:
                buf.append(ch)
        elif ch == ")":
            depth -= 1
            if depth == 0:
                parts.append("".join(buf))
                break
            buf.append(ch)
        elif ch == "," and depth == 1:
            parts.append("".join(buf))
            buf = []
        elif depth >= 1:
            buf.append(ch)
        i += 1
    return sum(1 for part in parts if part.strip())


def detect_calls(unit: SourceUnit) -> list[Finding]:
    """Unchecked return values, delegatecall, and the 2300-gas stipend."""
    findings: list[Finding] = []
    for contract, fn, _state in _iter_functions(unit):
        if not fn.body.strip():
            continue
        masked = mask_strings(fn.body)
        for match in _CALL.finditer(masked):
            kind = match.group("kind") or "call"
            open_ch = match.group("open")
            ether_transfer = False
            token_transfer = False
            if kind == "send":
                ether_transfer = True
            elif kind == "transfer":
                open_at = match.end() - 1
                count = _arg_count(masked, open_at) if open_ch == "(" else -1
                if count <= 1:
                    ether_transfer = True
                else:
                    token_transfer = True
            elif kind == "transferFrom":
                token_transfer = True

            if kind == "delegatecall":
                target_window = masked[max(0, match.start() - 80) : match.start()]
                param_names = _locals_of(fn)
                controlled = any(re.search(rf"\b{re.escape(name)}\b", target_window) for name in param_names)
                severity = "critical" if controlled or fn.visibility in {"public", "external", "unspecified"} else "high"
                findings.append(
                    _finding(
                        unit,
                        detector="dangerous-delegatecall",
                        severity=severity,
                        swc="SWC-112",
                        title="delegatecall to an external target",
                        message=(
                            f"{fn.qualified_name} uses delegatecall, so the callee runs with this "
                            "contract's storage and balance."
                        ),
                        recommendation=(
                            "Hard-code an immutable, audited implementation, or authenticate the "
                            "caller and the target. Do not delegatecall an address taken from calldata."
                        ),
                        line=unit.line_of(fn.body_start + match.start()),
                        contract=contract.name,
                        function=fn.name,
                    )
                )

            if ether_transfer:
                findings.append(
                    _finding(
                        unit,
                        detector="transfer-gas-stipend",
                        severity="low",
                        swc="SWC-134",
                        title="Ether send forwards only 2300 gas",
                        message=(
                            f"{fn.qualified_name} uses `.{kind}`, which stipends 2300 gas. "
                            "A contract recipient can fail the transfer just by having a fallback "
                            "that needs more gas."
                        ),
                        recommendation=(
                            "Use `call{value: amount}(\"\")`, check the returned boolean, and update "
                            "storage before the call."
                        ),
                        line=unit.line_of(fn.body_start + match.start()),
                        contract=contract.name,
                        function=fn.name,
                    )
                )

            needs_check = kind in {"call", "delegatecall", "staticcall", "send"} or token_transfer
            if kind in {"safeTransfer", "safeTransferFrom"}:
                needs_check = False
            if needs_check and not _call_is_checked(masked, match.start()):
                if token_transfer:
                    title = "Token transfer return value ignored"
                    detail = "A token can return false instead of reverting."
                    recommendation = "Use OpenZeppelin SafeERC20, or require the returned boolean."
                else:
                    title = "Low-level call return value ignored"
                    detail = "A failed call is then indistinguishable from success."
                    recommendation = "Capture the boolean and require it before any later logic."
                findings.append(
                    _finding(
                        unit,
                        detector="unchecked-return",
                        severity="medium",
                        swc="SWC-104",
                        title=title,
                        message=f"{fn.qualified_name} ignores the boolean returned by `.{kind}`. {detail}",
                        recommendation=recommendation,
                        line=unit.line_of(fn.body_start + match.start()),
                        contract=contract.name,
                        function=fn.name,
                    )
                )
    return findings


def _has_acl(fn: Function) -> bool:
    return bool(_ACL.search(fn.header) or _ACL.search(fn.body))


def detect_access(unit: SourceUnit) -> list[Finding]:
    findings: list[Finding] = []
    for contract, fn, _state in _iter_functions(unit):
        masked = mask_strings(fn.body)
        for match in re.finditer(r"\btx\s*\.\s*origin\b", masked):
            findings.append(
                _finding(
                    unit,
                    detector="tx-origin",
                    severity="high",
                    swc="SWC-115",
                    title="Authorization uses tx.origin",
                    message=(
                        f"{fn.qualified_name} compares `tx.origin`. A malicious contract in the "
                        "call chain can pass that check while the real user is msg.sender."
                    ),
                    recommendation="Authenticate with msg.sender, or an explicit role, and never with tx.origin.",
                    line=unit.line_of(fn.body_start + match.start()),
                    contract=contract.name,
                    function=fn.name,
                )
            )
        if re.search(r"\b(selfdestruct|suicide)\s*\(", masked):
            protected = _has_acl(fn)
            if fn.kind == "constructor":
                severity = "high"
            elif protected:
                severity = "medium"
            elif fn.visibility in {"internal", "private"}:
                severity = "medium"
            else:
                severity = "critical"
            line = unit.line_of(fn.body_start + re.search(r"\b(selfdestruct|suicide)\s*\(", masked).start())
            findings.append(
                _finding(
                    unit,
                    detector="unprotected-selfdestruct",
                    severity=severity,
                    swc="SWC-106",
                    title="Contract can be destroyed",
                    message=(
                        f"{fn.qualified_name} calls selfdestruct"
                        + (" behind an access check." if protected else " with no obvious access check.")
                        + " Destruction forwards the balance and bricks the contract."
                    ),
                    recommendation=(
                        "Remove selfdestruct. If a pause is required, use an access-controlled flag "
                        "instead of deleting the contract."
                    ),
                    line=line,
                    contract=contract.name,
                    function=fn.name,
                )
            )
        sends_value = bool(
            re.search(r"\.call\s*\{[^}]*\bvalue\b", masked)
            or re.search(r"\.call\s*\.\s*value\s*\(", masked)
            or re.search(r"\.(?:transfer|send)\s*\(", masked)
        )
        full_balance = bool(re.search(r"(?:this\s*\.\s*balance|address\s*\(\s*this\s*\)\s*\.\s*balance)", masked))
        per_user = bool(re.search(r"\bbalances\s*\[\s*msg\s*\.\s*sender\s*\]", masked))
        if (
            sends_value
            and full_balance
            and not per_user
            and not _has_acl(fn)
            and fn.visibility in {"public", "external", "unspecified"}
            and not fn.is_view_like
        ):
            line_match = re.search(
                r"(?:this\s*\.\s*balance|address\s*\(\s*this\s*\)\s*\.\s*balance|\.(?:transfer|send|call)\s*)",
                masked,
            )
            line = unit.line_of(fn.body_start + (line_match.start() if line_match else 0))
            findings.append(
                _finding(
                    unit,
                    detector="unprotected-ether",
                    severity="high",
                    swc="SWC-105",
                    title="Anyone can withdraw the contract balance",
                    message=(
                        f"{fn.qualified_name} sends `address(this).balance` and neither an access "
                        "modifier nor a per-user balance check is visible."
                    ),
                    recommendation=(
                        "Restrict the function to an owner or role, or debit a per-account ledger "
                        "before sending ether."
                    ),
                    line=line,
                    contract=contract.name,
                    function=fn.name,
                )
            )
    return findings


def detect_time_and_random(unit: SourceUnit) -> list[Finding]:
    findings: list[Finding] = []
    for contract, fn, _state in _iter_functions(unit):
        masked = mask_strings(fn.body)
        weak = bool(re.search(r"\bkeccak256\s*\(|\bsha3\s*\(", masked)) and bool(
            re.search(r"\bblock\s*\.\s*(?:timestamp|number|difficulty|prevrandao)\b|\bnow\b", masked)
        )
        if weak:
            match = re.search(r"\bkeccak256\s*\(|\bsha3\s*\(", masked)
            findings.append(
                _finding(
                    unit,
                    detector="weak-randomness",
                    severity="high",
                    swc="SWC-120",
                    title="Randomness depends on a block value",
                    message=(
                        f"{fn.qualified_name} folds a block field into a hash. Miners and validators "
                        "can bias that value."
                    ),
                    recommendation="Take randomness from a commit-reveal scheme or an oracle such as Chainlink VRF.",
                    line=unit.line_of(fn.body_start + match.start()),
                    contract=contract.name,
                    function=fn.name,
                )
            )
            continue
        for match in re.finditer(r"\bblock\s*\.\s*timestamp\b|\bnow\b", masked):
            line = unit.line_of(fn.body_start + match.start())
            snippet = unit.snippet(line)
            if not re.search(r"(<|>|==|!=)", snippet):
                continue
            findings.append(
                _finding(
                    unit,
                    detector="timestamp-dependence",
                    severity="low",
                    swc="SWC-116",
                    title="Control flow depends on the block timestamp",
                    message=(
                        f"{fn.qualified_name} compares the block timestamp. Producers can shift it "
                        "by a small margin, which matters for tight deadlines."
                    ),
                    recommendation="Do not use the timestamp as a source of randomness or as a precise clock.",
                    line=line,
                    contract=contract.name,
                    function=fn.name,
                )
            )
    return findings


def detect_gas(unit: SourceUnit) -> list[Finding]:
    findings: list[Finding] = []
    for contract, fn, state_vars in _iter_functions(unit):
        locals_ = _locals_of(fn)
        writes = [item for item in _state_writes(fn, state_vars, unit) if not item.is_lock]
        for region in fn.regions:
            if region.kind != "loop":
                continue
            match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*length\b", region.header)
            if match:
                name = match.group(1)
                if name in state_vars and name not in locals_:
                    findings.append(
                        _finding(
                            unit,
                            detector="unbounded-loop",
                            severity="medium",
                            swc="SWC-128",
                            title="Loop walks an unbounded storage array",
                            message=(
                                f"{fn.qualified_name} iterates `{name}.length`. Anyone who can grow "
                                "that array can push the loop past the block gas limit and freeze the function."
                            ),
                            recommendation=(
                                "Page the work with a start index and a fixed maximum, or account for "
                                "each user individually so one transaction never walks the whole set."
                            ),
                            line=region.line,
                            contract=contract.name,
                            function=fn.name,
                        )
                    )
            inner = [item for item in writes if region.start <= fn.body_start + item.pos < region.end]
            if inner:
                findings.append(
                    _finding(
                        unit,
                        detector="storage-in-loop",
                        severity="low",
                        swc="SWC-128",
                        title="Storage write inside a loop",
                        message=(
                            f"{fn.qualified_name} writes `{inner[0].root}` on each iteration. "
                            "Storage writes are the expensive part of a loop and amplify a gas-griefing DoS."
                        ),
                        recommendation="Cap the iteration count, or move the per-item write out of the shared loop.",
                        line=region.line,
                        contract=contract.name,
                        function=fn.name,
                        related_line=inner[0].line,
                    )
                )
    return findings


def detect_style(unit: SourceUnit) -> list[Finding]:
    findings: list[Finding] = []
    if unit.pragma and re.search(r"[\^~<>]", unit.pragma):
        findings.append(
            _finding(
                unit,
                detector="floating-pragma",
                severity="info",
                swc="SWC-103",
                title="Compiler version is not pinned",
                message=(
                    f"`pragma solidity {unit.pragma}` accepts more than one compiler. "
                    "Two builds that both satisfy the range can still differ."
                ),
                recommendation="Pin an exact version, for example `pragma solidity 0.8.24;`, and record it in the audit.",
                line=unit.pragma_line or 1,
            )
        )
    masked = mask_strings(unit.clean)
    lines = masked.splitlines()
    for index, line in enumerate(lines, start=1):
        for pattern, old, new in _DEPRECATED:
            if pattern.search(line):
                findings.append(
                    _finding(
                        unit,
                        detector="deprecated-syntax",
                        severity="low",
                        swc="SWC-111",
                        title=f"Deprecated Solidity feature `{old}`",
                        message=f"Line {index} uses `{old}`, which current compilers reject or treat as obsolete.",
                        recommendation=f"Replace `{old}` with `{new}`.",
                        line=index,
                    )
                )
                break
        if re.search(r"(?:this\s*\.\s*balance|address\s*\(\s*this\s*\)\s*\.\s*balance)\s*==", line):
            findings.append(
                _finding(
                    unit,
                    detector="strict-balance",
                    severity="low",
                    swc="SWC-132",
                    title="Strict equality on the contract ether balance",
                    message=(
                        "A contract can be forced to hold ether via selfdestruct or a coinbase reward, "
                        "so `balance == amount` can be broken by an outsider."
                    ),
                    recommendation="Track deposits in a state variable and compare that ledger, not address(this).balance.",
                    line=index,
                )
            )
    return findings


_DETECTORS = (
    detect_reentrancy,
    detect_arithmetic,
    detect_calls,
    detect_access,
    detect_time_and_random,
    detect_gas,
    detect_style,
)


def audit_source(raw: str, path: str = "<memory>") -> tuple[SourceUnit, list[Finding]]:
    unit = parse_source(raw, path)
    findings: list[Finding] = []
    for detector in _DETECTORS:
        findings.extend(detector(unit))
    unique: list[Finding] = []
    seen: set[tuple] = set()
    for finding in findings:
        key = (finding.detector, finding.file, finding.line, finding.title)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    unique.sort(key=lambda item: (item.file, item.line, -SEVERITY_RANK[item.severity], item.detector))
    return unit, unique
