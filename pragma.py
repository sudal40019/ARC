"""Classify whether a Solidity pragma still needs overflow guards."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int


_CLAUSE = re.compile(r"(?P<op>\^|~|>=|<=|>|<|=)?\s*(?P<ver>\d+\.\d+(?:\.\d+)?)")
_V8 = Version(0, 8, 0)


def parse_version(text: str) -> Version:
    major, minor, *rest = text.split(".")
    patch = rest[0] if rest else "0"
    return Version(int(major), int(minor), int(patch))


def _bump_patch(version: Version) -> Version:
    return Version(version.major, version.minor, version.patch + 1)


def classify_and(spec: str) -> str:
    """Classify a single AND-combined version constraint.

    Returns ``yes`` (every allowed compiler is 0.8+), ``no`` (none are),
    ``partial`` (the range crosses 0.8), or ``unknown``.
    """
    found = list(_CLAUSE.finditer(spec))
    if not found:
        return "unknown"
    lower = Version(0, 0, 0)
    upper = Version(99, 0, 0)  # exclusive
    for match in found:
        op = match.group("op") or "="
        version = parse_version(match.group("ver"))
        if op == "^":
            if version.major > 0:
                cap = Version(version.major + 1, 0, 0)
            elif version.minor > 0:
                cap = Version(0, version.minor + 1, 0)
            else:
                cap = Version(0, 0, version.patch + 1)
            lower = max(lower, version)
            upper = min(upper, cap)
        elif op == "~":
            lower = max(lower, version)
            upper = min(upper, Version(version.major, version.minor + 1, 0))
        elif op == ">=":
            lower = max(lower, version)
        elif op == ">":
            lower = max(lower, _bump_patch(version))
        elif op == "<=":
            upper = min(upper, _bump_patch(version))
        elif op == "<":
            upper = min(upper, version)
        else:
            lower = max(lower, version)
            upper = min(upper, _bump_patch(version))
    if lower >= upper:
        return "unknown"
    if lower >= _V8:
        return "yes"
    if upper <= _V8:
        return "no"
    return "partial"


def classify_pragma(spec: str) -> str:
    """Classify a pragma solidity expression, including ``||`` alternatives."""
    text = " ".join(spec.split())
    if not text:
        return "unknown"
    parts = [part.strip() for part in text.split("||") if part.strip()]
    if not parts:
        return "unknown"
    results = [classify_and(part) for part in parts]
    if all(item == "yes" for item in results):
        return "yes"
    if all(item == "no" for item in results):
        return "no"
    if any(item == "unknown" for item in results) and all(
        item in {"unknown", "yes", "no"} for item in results
    ) and not any(item == "partial" for item in results):
        # An unparsable alternative mixed with a clear one is not proof.
        if any(item == "no" for item in results) and any(item == "yes" for item in results):
            return "partial"
        if any(item == "yes" for item in results):
            return "partial"
        return "unknown"
    return "partial"
