"""Length-preserving Solidity text helpers.

Comment stripping and string masking keep the original indexes and newlines so
detector line numbers match the file the author opened.
"""

from __future__ import annotations


def skip_string(text: str, i: int) -> int:
    """Return the index just after a quoted literal that starts at i."""
    n = len(text)
    if i >= n:
        return i
    quote = text[i]
    if quote not in "\"'":
        return i + 1
    i += 1
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    return n


def strip_comments(src: str) -> str:
    """Replace // and /* */ comments with spaces. Newlines and length stay."""
    out = list(src)
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if ch in "\"'":
            j = skip_string(src, i)
            i = j
            continue
        if ch == "/" and nxt == "/":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and nxt == "*":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n - 1 and not (src[i] == "*" and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n - 1:
                out[i] = " "
                out[i + 1] = " "
                i += 2
            else:
                while i < n:
                    if src[i] != "\n":
                        out[i] = " "
                    i += 1
            continue
        i += 1
    return "".join(out)


def mask_strings(src: str) -> str:
    """Blank the contents of string literals without changing length."""
    out = list(src)
    i = 0
    n = len(src)
    while i < n:
        if src[i] not in "\"'":
            i += 1
            continue
        quote = src[i]
        out[i] = " "
        i += 1
        while i < n:
            if src[i] == "\\":
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
                continue
            if src[i] == quote:
                out[i] = " "
                i += 1
                break
            if src[i] != "\n":
                out[i] = " "
            i += 1
    return "".join(out)


def line_starts(text: str) -> list[int]:
    starts = [0]
    for index, ch in enumerate(text):
        if ch == "\n":
            starts.append(index + 1)
    return starts


def match_keyword(text: str, i: int, word: str) -> bool:
    if not text.startswith(word, i):
        return False
    before = text[i - 1] if i else ""
    end = i + len(word)
    after = text[end] if end < len(text) else ""
    if before.isalnum() or before == "_":
        return False
    if after.isalnum() or after == "_":
        return False
    return True


def read_ident(text: str, i: int) -> tuple[str, int]:
    j = i
    n = len(text)
    while j < n and (text[j].isalnum() or text[j] == "_"):
        j += 1
    return text[i:j], j


def skip_ws(text: str, i: int, end: int | None = None) -> int:
    n = len(text) if end is None else end
    while i < n and text[i] in " \t\r\n":
        i += 1
    return i


def match_pair(text: str, open_at: int, end: int, open_ch: str, close_ch: str) -> int:
    """Index of the closing delimiter that matches text[open_at], or -1."""
    if open_at >= end or open_at >= len(text) or text[open_at] != open_ch:
        return -1
    depth = 0
    i = open_at
    while i < end:
        ch = text[i]
        if ch in "\"'":
            i = skip_string(text, i)
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def split_commas(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            j = skip_string(text, i)
            buf.append(text[i:j])
            i = j
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        parts.append("".join(buf))
    return parts
