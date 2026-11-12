"""Split a source snapshot into analysis units (files and C functions) with tree-sitter."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_c
from tree_sitter import Language, Node, Parser

from .config import Project

_C = Language(tree_sitter_c.language())


@dataclass(frozen=True)
class Unit:
    key: str  # stable identity across snapshots: "path" or "path::func[@n]"
    kind: str  # "file" | "function"
    path: str
    symbol: str | None
    start_line: int  # 1-based, inclusive
    end_line: int
    content_hash: str
    area: str
    priority: int


def content_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:32]


# --- preprocessor conditionals ---------------------------------------------
#
# tree-sitter does not preprocess. Code such as `#if A\n if (x) {\n#else\n if
# (y) {\n#endif`, or #if inside a parameter list, wrecks the parse. A single
# branch of each #if group is normally well-formed on its own, so we parse
# *renderings* of the file that keep one branch per group (blanking the rest
# and the directives, preserving line numbers) and merge what they find.

_PP_COND = re.compile(rb"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b")
_CLOSE_BRACE = re.compile(rb"^}\s*$")

Path_ = tuple[tuple[int, int], ...]  # enclosing (group id, branch index) chain
Chooser = Callable[[int, int], int]  # (group id, branch count) -> branch to keep


def _leaves_comment_open(text: bytes) -> bool:
    """True if `text` ends inside a /* block comment."""
    i, inside = 0, False
    while i < len(text) - 1:
        pair = text[i : i + 2]
        if inside and pair == b"*/":
            inside, i = False, i + 2
        elif not inside and pair == b"/*":
            inside, i = True, i + 2
        elif not inside and pair == b"//":
            return False
        else:
            i += 1
    return inside


@dataclass
class _Conditionals:
    lines: list[bytes]
    counts: list[int]  # branches per group
    paths: list[Path_]  # per line
    directive: list[bool]  # line belongs to a conditional directive
    comment_open: list[bool]  # directive ends inside a /* comment


def _scan(data: bytes) -> _Conditionals:
    lines = data.split(b"\n")
    pp = _Conditionals(lines, [], [], [False] * len(lines), [False] * len(lines))
    stack: list[tuple[int, int]] = []
    cont = False
    directive: list[bytes] = []
    for i, line in enumerate(lines):
        m = None if cont else _PP_COND.match(line)
        if cont or m:
            pp.directive[i] = True
            directive = [*directive, line] if cont else [line]
            if m:
                d = m.group(1)
                if d in (b"if", b"ifdef", b"ifndef"):
                    pp.counts.append(1)
                    stack.append((len(pp.counts) - 1, 0))
                elif stack and d in (b"elif", b"else"):
                    g, b = stack.pop()
                    pp.counts[g] += 1
                    stack.append((g, b + 1))
                elif stack and d == b"endif":
                    stack.pop()
            cont = line.rstrip().endswith(b"\\")
            # `#endif /* a ||\n b */`: the comment must stay open in the rendering.
            if not cont:
                pp.comment_open[i] = _leaves_comment_open(b"\n".join(directive))
        pp.paths.append(tuple(stack))
    return pp


def _render(pp: _Conditionals, choose: Chooser) -> bytes:
    out = []
    for i, line in enumerate(pp.lines):
        if pp.directive[i]:
            out.append(b"/*" if pp.comment_open[i] else b"")
        elif all(choose(g, pp.counts[g]) == b for g, b in pp.paths[i]):
            out.append(line)
        else:
            out.append(b"")
    return b"\n".join(out)


def select_branches(data: bytes, keep: str) -> bytes:
    """Render `data` keeping the first (or last) branch of every #if group."""
    pp = _scan(data)
    return _render(pp, (lambda g, n: 0) if keep == "first" else (lambda g, n: n - 1))


# --- function extraction ---------------------------------------------------


def _declarator_name(node: Node) -> str | None:
    """Name of a function_definition, looking through pointer/paren declarators."""
    d = node.child_by_field_name("declarator")
    while d is not None and d.type != "function_declarator":
        d = d.child_by_field_name("declarator")
    if d is None:
        return None
    inner = d.child_by_field_name("declarator")
    while inner is not None and inner.type not in ("identifier", "field_identifier"):
        nxt = inner.child_by_field_name("declarator")
        inner = nxt if nxt is not None else next(iter(inner.named_children), None)
    return inner.text.decode(errors="replace") if inner is not None else None


def _functions(root: Node) -> Iterator[Node]:
    """Function definitions in document order."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            yield node
            continue
        stack.extend(reversed(node.children))


def _find_spans(data: bytes) -> list[tuple[str, int, int]]:
    """(name, start, end) of every function definition, across #if variants.

    Parses the first-branch and last-branch renderings, then, for any column-0
    `}` still outside every known function (a definition in a branch mix neither
    rendering kept), parses once more with exactly that line's branch path.
    """
    pp = _scan(data)
    parser = Parser(_C)
    spans: dict[tuple[str, int], int] = {}

    def parse(choose: Chooser) -> None:
        for fn in _functions(parser.parse(_render(pp, choose)).root_node):
            name = _declarator_name(fn)
            if name is None:  # e.g. `STRUCT_PACKED foo { ... }` misread as a function
                continue
            k = (name, fn.start_point.row + 1)
            spans[k] = max(spans.get(k, 0), fn.end_point.row + 1)

    parse(lambda g, n: 0)
    if pp.counts:
        parse(lambda g, n: n - 1)
        for i, line in enumerate(pp.lines):
            if pp.directive[i] or not pp.paths[i] or not _CLOSE_BRACE.match(line):
                continue
            lineno = i + 1
            if any(s <= lineno <= e for (_n, s), e in spans.items()):
                continue
            path = dict(pp.paths[i])
            parse(lambda g, n, path=path: path.get(g, 0))

    # Same name, overlapping spans: one function whose signature varies by
    # branch (`#if A\n int f(a,\n#else\n int f(\n#endif\n x) {`).
    merged: list[tuple[str, int, int]] = []
    for (name, start), end in sorted(spans.items()):
        if merged and merged[-1][0] == name and start <= merged[-1][2]:
            merged[-1] = (name, merged[-1][1], max(end, merged[-1][2]))
        else:
            merged.append((name, start, end))
    return sorted(merged, key=lambda m: (m[1], m[0]))


def extract_source(path: str, data: bytes, area: str, priority: int) -> list[Unit]:
    """Units for one C file: the file itself, then each function definition.

    A name defined more than once (#if variants) gets `@2`, `@3`, ... in line
    order. Function hashes cover the *original* lines, so a change in any
    branch invalidates the unit.
    """
    lines = data.split(b"\n")
    nlines = len(lines) - (1 if data.endswith(b"\n") else 0)
    units = [Unit(path, "file", path, None, 1, max(nlines, 1), content_hash(data), area, priority)]
    seen: Counter[str] = Counter()
    for name, start, end in _find_spans(data):
        seen[name] += 1
        key = f"{path}::{name}" if seen[name] == 1 else f"{path}::{name}@{seen[name]}"
        units.append(
            Unit(
                key=key,
                kind="function",
                path=path,
                symbol=name,
                start_line=start,
                end_line=end,
                content_hash=content_hash(b"\n".join(lines[start - 1 : end])),
                area=area,
                priority=priority,
            )
        )
    return units


def extract_tree(project: Project, tree_root: Path) -> list[Unit]:
    """All in-scope units under a snapshot directory, in path order."""
    units: list[Unit] = []
    for f in sorted(tree_root.rglob("*")):
        if not f.is_file() or f.is_symlink():
            continue
        rel = f.relative_to(tree_root).as_posix()
        if not project.in_scope(rel):
            continue
        area = project.area_for(rel)
        units.extend(extract_source(rel, f.read_bytes(), area.name, area.priority))
    return units
