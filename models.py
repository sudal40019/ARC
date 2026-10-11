"""Shared data types for the auditor."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Region:
    """A brace-delimited region inside a function body. Indices are absolute."""

    kind: str  # unchecked | assembly | loop
    start: int
    end: int
    line: int
    header: str = ""


@dataclass
class Function:
    name: str
    kind: str
    line: int
    header: str
    body: str
    body_start: int
    body_end: int
    params_src: str
    visibility: str
    mutability: str
    modifiers: list[str]
    contract: str
    regions: list[Region] = field(default_factory=list)

    @property
    def is_view_like(self) -> bool:
        return self.mutability in {"view", "pure"}

    @property
    def qualified_name(self) -> str:
        if self.contract:
            return f"{self.contract}.{self.name}"
        return self.name


@dataclass
class Contract:
    name: str
    kind: str  # contract | library | interface
    line: int
    parents: list[str]
    functions: list[Function]
    state_vars: list[str]


@dataclass
class SourceUnit:
    path: str
    raw: str
    clean: str
    line_starts: list[int]
    raw_lines: list[str]
    pragma: str
    pragma_line: int
    protection: str  # yes | no | partial | unknown
    contracts: list[Contract]

    def line_of(self, index: int) -> int:
        starts = self.line_starts
        lo, hi = 0, len(starts) - 1
        if hi < 0:
            return 1
        if index < 0:
            index = 0
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= index:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def snippet(self, line: int) -> str:
        if line < 1 or line > len(self.raw_lines):
            return ""
        return self.raw_lines[line - 1].strip()


@dataclass
class Finding:
    detector: str
    severity: str
    swc: str
    title: str
    message: str
    recommendation: str
    file: str
    line: int
    snippet: str
    contract: str = ""
    function: str = ""
    related_line: int | None = None
    related_snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def location(self) -> str:
        if self.contract and self.function:
            return f"{self.contract}.{self.function}"
        return self.function or self.contract or ""
