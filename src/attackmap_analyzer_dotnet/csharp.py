"""A small C# reader for ASP.NET Core route extraction (#2).

This is a lexer-level reader, not a parser. It masks comments and
preprocessor lines, skips string literals (regular, verbatim, interpolated
and raw) so brackets inside them don't confuse it, reads attribute sections
(`[HttpGet("{id}", Name = "GetUser")]`, `[HttpGet, Authorize]`), groups them
into per-declaration blocks, finds class bodies by brace matching, and parses
fluent call chains (`app.MapGroup("/api").MapGet("/x", h).RequireAuthorization()`).
Anything it can't read, such as a route template held in a constant, yields
no route rather than a guessed one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_WORD_RE = re.compile(r"[A-Za-z_]\w*")
_CLASS_DECL_RE = re.compile(r"(?<![\w.@])(?:class|record|struct|interface)\s+(?:class\s+|struct\s+)?([A-Za-z_]\w*)")
_MODIFIERS = frozenset(
    {
        "public", "private", "protected", "internal", "static", "sealed", "abstract",
        "partial", "virtual", "override", "async", "readonly", "new", "unsafe",
        "extern", "file", "required", "ref", "volatile", "const",
    }
)
_CLASS_KEYWORDS = frozenset({"class", "record", "struct", "interface"})
# Words that can follow `record` etc. in ordinary code (`foreach (var record in x)`).
_NOT_TYPE_NAMES = frozenset({"in", "is", "as", "where", "when", "and", "or", "not", "with"})
# A `[` opens an attribute section only at a declaration position: after one
# of these (or at the start of the file), never after an expression.
_ATTRIBUTE_PRECEDERS = frozenset("{};],(")


# ---------- Lexing ----------


def skip_literal(text: str, i: int) -> int | None:
    """If a string or char literal starts at ``i``, return the index past it."""
    c = text[i]
    if c not in "\"'@$":
        return None
    if c == "'":
        j = i + 1
        while j < len(text) and j < i + 12:
            if text[j] == "\\":
                j += 2
                continue
            if text[j] == "'":
                return j + 1
            if text[j] == "\n":
                break
            j += 1
        return None
    j = i
    prefix = ""
    while j < len(text) and text[j] in "@$" and len(prefix) < 4:
        prefix += text[j]
        j += 1
    if j >= len(text) or text[j] != '"':
        return None
    if text.startswith('"""', j):
        end = text.find('"""', j + 3)
        if end == -1:
            return len(text)
        end += 3
        while end < len(text) and text[end] == '"':
            end += 1
        return end
    j += 1
    verbatim = "@" in prefix
    while j < len(text):
        ch = text[j]
        if verbatim:
            if ch == '"':
                if j + 1 < len(text) and text[j + 1] == '"':
                    j += 2
                    continue
                return j + 1
        else:
            if ch == "\\":
                j += 2
                continue
            if ch == '"' or ch == "\n":
                return j + 1
        j += 1
    return len(text)


def mask_comments(content: str) -> str:
    """``content`` with comments and preprocessor lines blanked (offsets kept)."""
    out = list(content)
    i, n = 0, len(content)
    line_start = True
    while i < n:
        c = content[i]
        if c == "\n":
            line_start = True
            i += 1
            continue
        if line_start and c in " \t":
            i += 1
            continue
        if line_start and c == "#":
            end = content.find("\n", i)
            end = n if end == -1 else end
            for j in range(i, end):
                out[j] = " "
            i = end
            continue
        line_start = False
        skipped = skip_literal(content, i)
        if skipped is not None:
            i = skipped
            continue
        if content.startswith("//", i):
            end = content.find("\n", i)
            end = n if end == -1 else end
            for j in range(i, end):
                out[j] = " "
            i = end
        elif content.startswith("/*", i):
            end = content.find("*/", i + 2)
            end = n if end == -1 else end + 2
            for j in range(i, end):
                if out[j] != "\n":
                    out[j] = " "
            i = end
        else:
            i += 1
    return "".join(out)


def match_bracket(text: str, open_at: int) -> int | None:
    """Index just past the bracket closing the one at ``open_at`` (None if unbalanced)."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    stack = [pairs[text[open_at]]]
    i = open_at + 1
    n = len(text)
    while i < n:
        skipped = skip_literal(text, i)
        if skipped is not None:
            i = skipped
            continue
        c = text[i]
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")}]":
            if c != stack[-1]:
                return None
            stack.pop()
            if not stack:
                return i + 1
        i += 1
    return None


def split_top_level(text: str, sep: str = ",") -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    i = 0
    n = len(text)
    while i < n:
        skipped = skip_literal(text, i)
        if skipped is not None:
            i = skipped
            continue
        c = text[i]
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
        elif c == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


def string_literal(value: str) -> str | None:
    """The value of a C# string literal expression, or None if it isn't one."""
    v = value.strip()
    m = re.fullmatch(r'"((?:[^"\\\n]|\\.)*)"', v)
    if m:
        return m.group(1)
    m = re.fullmatch(r'@"((?:[^"]|"")*)"', v)
    if m:
        return m.group(1).replace('""', '"')
    m = re.fullmatch(r'"""(.*?)"""', v, re.DOTALL)
    if m:
        return m.group(1).strip()
    return None


def string_literals(value: str) -> list[str]:
    """Every string literal element of an array-ish value (`new[] { "GET" }`, `["GET"]`)."""
    return [m.group(1) for m in re.finditer(r'"((?:[^"\\\n]|\\.)*)"', value)]


def _skip_ws(text: str, i: int) -> int:
    n = len(text)
    while i < n and text[i].isspace():
        i += 1
    return i


# ---------- Arguments ----------


@dataclass
class Args:
    positional: list[str] = field(default_factory=list)
    named: dict[str, str] = field(default_factory=dict)

    def first_string(self, *names: str) -> str | None:
        """The first positional argument, or a named one, as a string literal.

        Returns None if absent or not a literal.
        """
        for name in names:
            if name in self.named:
                return string_literal(self.named[name])
        if self.positional:
            return string_literal(self.positional[0])
        return None

    def has_template(self, *names: str) -> bool:
        return bool(self.positional) or any(name in self.named for name in names)


def parse_args(text: str | None) -> Args:
    args = Args()
    if text is None:
        return args
    for part in split_top_level(text):
        # `Name = value` (attribute property) or `name: value` (named argument).
        m = re.match(r"([A-Za-z_]\w*)\s*(?:=(?![=>])|:(?!:))\s*(.*)\Z", part, re.DOTALL)
        if m:
            args.named[m.group(1)] = m.group(2).strip()
        else:
            args.positional.append(part)
    return args


# ---------- Attributes ----------


@dataclass
class Attribute:
    name: str  # last segment, without an `Attribute` suffix
    start: int
    args: Args


@dataclass
class AttributeBlock:
    """Attribute sections on one declaration."""

    attributes: list[Attribute]
    start: int
    end: int
    class_keyword_at: int | None = None

    def get(self, name: str) -> list[Attribute]:
        return [a for a in self.attributes if a.name == name]

    def has(self, name: str) -> bool:
        return any(a.name == name for a in self.attributes)


def _previous_significant(masked: str, i: int) -> str:
    j = i - 1
    while j >= 0 and masked[j].isspace():
        j -= 1
    return masked[j] if j >= 0 else ""


def _parse_section(masked: str, open_at: int, close: int) -> list[Attribute]:
    inner = masked[open_at + 1 : close - 1]
    inner_offset = open_at + 1
    # Optional target: `[return: X]`, `[assembly: X]`.
    m = re.match(r"\s*(?:assembly|module|return|method|field|property|param|type|event)\s*:(?!:)", inner)
    skip = m.end() if m else 0
    attributes: list[Attribute] = []
    pos = skip
    for part in split_top_level(inner[skip:]):
        name_match = re.match(r"(?:global::)?([A-Za-z_][\w.]*)\s*(\(.*\))?\Z", part, re.DOTALL)
        if name_match is None:
            return []  # not an attribute list (a collection expression, an index)
        name = name_match.group(1).rsplit(".", 1)[-1]
        if name.endswith("Attribute") and name != "Attribute":
            name = name[: -len("Attribute")]
        arg_text = name_match.group(2)
        args = parse_args(arg_text[1:-1] if arg_text else None)
        found = inner.find(part, pos)
        start = inner_offset + (found if found != -1 else pos)
        pos = found + len(part) if found != -1 else pos
        attributes.append(Attribute(name=name, start=start, args=args))
    return attributes


def attribute_blocks(masked: str) -> list[AttributeBlock]:
    """Every attribute block in ``masked``, in file order."""
    blocks: list[AttributeBlock] = []
    current: list[Attribute] = []
    current_start = current_end = -1
    i = 0
    n = len(masked)
    while i < n:
        skipped = skip_literal(masked, i)
        if skipped is not None:
            i = skipped
            continue
        if masked[i] != "[":
            i += 1
            continue
        prev = _previous_significant(masked, i)
        if prev and prev not in _ATTRIBUTE_PRECEDERS:
            i += 1
            continue
        close = match_bracket(masked, i)
        if close is None:
            i += 1
            continue
        attributes = _parse_section(masked, i, close)
        if not attributes:
            i += 1
            continue
        if current and masked[current_end:i].strip() == "":
            current.extend(attributes)
        else:
            if current:
                blocks.append(_finish_block(masked, current, current_start, current_end))
            current = list(attributes)
            current_start = i
        current_end = close
        i = close
    if current:
        blocks.append(_finish_block(masked, current, current_start, current_end))
    return blocks


def _finish_block(masked: str, attributes: list[Attribute], start: int, end: int) -> AttributeBlock:
    i = end
    n = len(masked)
    while True:
        i = _skip_ws(masked, i)
        m = _WORD_RE.match(masked, i) if i < n else None
        if m is None:
            return AttributeBlock(attributes, start, end)
        word = m.group(0)
        if word in _CLASS_KEYWORDS:
            return AttributeBlock(attributes, start, end, class_keyword_at=i)
        if word not in _MODIFIERS:
            return AttributeBlock(attributes, start, end)
        i = m.end()


def member_name(masked: str, end: int) -> str | None:
    """Name of the method declared after an attribute block ending at ``end``."""
    window = masked[end : end + 400]
    m = re.search(r"([A-Za-z_]\w*)\s*(?:<[^<>()]*>)?\s*\(", window)
    return m.group(1) if m else None


# ---------- Class scopes ----------


@dataclass
class ClassScope:
    name: str
    keyword_at: int
    body_start: int
    body_end: int


def class_scopes(masked: str) -> list[ClassScope]:
    scopes: list[ClassScope] = []
    for m in _CLASS_DECL_RE.finditer(masked):
        name = m.group(1)
        if name in _NOT_TYPE_NAMES or name in _CLASS_KEYWORDS:
            continue
        body_open = _find_body_open(masked, m.end())
        if body_open is None:
            continue
        close = match_bracket(masked, body_open)
        scopes.append(ClassScope(name, m.start(), body_open, close if close is not None else len(masked)))
    return scopes


def _find_body_open(masked: str, i: int) -> int | None:
    n = len(masked)
    while i < n:
        skipped = skip_literal(masked, i)
        if skipped is not None:
            i = skipped
            continue
        c = masked[i]
        if c == "{":
            return i
        if c in "([":
            close = match_bracket(masked, i)
            if close is None:
                return None
            i = close
            continue
        if c in ";}=":
            return None
        i += 1
    return None


def innermost_scope(scopes: list[ClassScope], offset: int) -> ClassScope | None:
    best: ClassScope | None = None
    for scope in scopes:
        if scope.body_start < offset < scope.body_end:
            if best is None or scope.body_start > best.body_start:
                best = scope
    return best


# ---------- Fluent call chains ----------


@dataclass
class Call:
    name: str
    name_at: int
    generic: str | None
    args: Args
    raw_args: str


@dataclass
class Chain:
    base: str
    start: int
    end: int
    calls: list[Call]
    assigned_to: str | None


_GENERIC_RE = re.compile(r"\s*<([^<>()]*(?:<[^<>()]*>[^<>()]*)*)>")


def parse_chains(masked: str, first_call: re.Pattern[str]) -> list[Chain]:
    """Fluent chains `base.Call(...).Call(...)` whose first call matches ``first_call``.

    ``first_call`` is matched against the member name right after `base.`.
    """
    chains: list[Chain] = []
    base_re = re.compile(r"(?<![\w.$@\"])([A-Za-z_]\w*)\s*\.\s*(?=([A-Za-z_]\w*))")
    pos = 0
    n = len(masked)
    while pos < n:
        m = base_re.search(masked, pos)
        if m is None:
            break
        if not first_call.fullmatch(m.group(2)):
            pos = m.end()
            continue
        calls: list[Call] = []
        i = m.end(1)
        while True:
            dot = _skip_ws(masked, i)
            if dot >= n or masked[dot] != ".":
                break
            name_at = _skip_ws(masked, dot + 1)
            name_match = _WORD_RE.match(masked, name_at)
            if name_match is None:
                break
            j = name_match.end()
            generic = None
            g = _GENERIC_RE.match(masked, j)
            if g:
                generic = g.group(1).strip()
                j = g.end()
            paren = _skip_ws(masked, j)
            if paren >= n or masked[paren] != "(":
                break
            close = match_bracket(masked, paren)
            if close is None:
                break
            raw = masked[paren + 1 : close - 1]
            calls.append(Call(name_match.group(0), name_at, generic, parse_args(raw), raw))
            i = close
        if calls:
            chains.append(Chain(m.group(1), m.start(1), i, calls, _assignment_target(masked, m.start(1))))
            pos = i
        else:
            pos = m.end()
    return chains


def _assignment_target(masked: str, base_at: int) -> str | None:
    line_start = masked.rfind("\n", 0, base_at) + 1
    # Look back over the current statement (a declaration can wrap).
    stmt_start = max(masked.rfind(";", 0, base_at), masked.rfind("{", 0, base_at), masked.rfind("}", 0, base_at)) + 1
    before = masked[min(stmt_start, line_start) : base_at]
    m = re.search(r"([A-Za-z_]\w*)\s*=\s*\Z", before)
    if m is None:
        return None
    eq = m.end(1)
    rest = before[eq:].lstrip()
    if rest.startswith("==") or rest.startswith("=>"):
        return None
    return m.group(1)


__all__ = [
    "Args",
    "Attribute",
    "AttributeBlock",
    "Call",
    "Chain",
    "ClassScope",
    "attribute_blocks",
    "class_scopes",
    "innermost_scope",
    "mask_comments",
    "match_bracket",
    "member_name",
    "parse_args",
    "parse_chains",
    "skip_literal",
    "split_top_level",
    "string_literal",
    "string_literals",
]
