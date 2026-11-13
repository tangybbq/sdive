"""Benchmark blindness for the analysis agents (a PreToolUse hook).

The ground truth (`analysis/truth/`) and zepsec's analysis trees and threat
model must never reach an analysis agent. Project-level permission deny rules
would enforce that, but they bind every session in the repo, including the
ones that legitimately review results, score a round or export findings. So
the restriction is applied here instead, per agent: Claude Code runs this hook
before every Read, Grep and Glob call in any session, and it denies the call
only when it comes from an `sdive-*` subagent (`agent_type` in the hook input)
and touches a protected path.

Read is denied if its file resolves into a protected path. Grep and Glob are
denied if their search root is inside a protected path or contains one (the
project root, `~/ai`, `/`): a hook can only allow or refuse a call, not filter
its results, so a broad search that could return protected content is refused
outright. The agents search the snapshot by explicit path and lose nothing.

Headless `sdive run` sessions also get the same paths as hard `--disallowedTools`
rules (`deny_rules`), which bind the whole session, orchestrator included.

Standard library only: the hook runs this file directly
(`uv run --no-project python -I .../blind.py`) so it doesn't depend on the
project environment.
"""

from __future__ import annotations

import json
import os
import sys
from fnmatch import fnmatchcase
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
AGENT_PREFIX = "sdive-"

# Protected paths (pattern, is a directory), patterns matched one path
# component at a time.
PROTECTED = (
    (str(PROJECT / "analysis" / "truth"), True),
    ("~/ai/zepsec*/analysis", True),
    ("~/ai/zepsec/threat-model.md", False),
)


def _patterns() -> list[tuple[str, ...]]:
    return [Path(os.path.expanduser(pat)).parts for pat, _ in PROTECTED]


def _match(path: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    return len(path) == len(pattern) and all(
        fnmatchcase(a, b) for a, b in zip(path, pattern, strict=True))


def _resolve(path: str, cwd: str) -> tuple[str, ...]:
    p = Path(os.path.expanduser(path))
    if not p.is_absolute():
        p = Path(cwd) / p
    return Path(os.path.realpath(p)).parts


def inside(path: str, cwd: str) -> bool:
    """`path` is a protected path or lies under one."""
    parts = _resolve(path, cwd)
    return any(_match(parts[:len(pat)], pat) for pat in _patterns())


def covers(root: str, cwd: str) -> bool:
    """A search rooted at `root` could reach protected content: the root is
    inside a protected path, or a protected path lies under it."""
    parts = _resolve(root, cwd)
    if inside(root, cwd):
        return True
    return any(len(pat) > len(parts) and _match(parts, pat[:len(parts)])
               for pat in _patterns())


def _static_prefix(pattern: str) -> str:
    """The leading wildcard-free directories of a glob pattern."""
    keep = []
    for part in Path(pattern).parts:
        if any(c in part for c in "*?[{"):
            break
        keep.append(part)
    return str(Path(*keep)) if keep else "."


def decide(event: dict) -> str | None:
    """The denial reason for a hook event, or None to let the call through."""
    agent = event.get("agent_type") or ""
    if not agent.startswith(AGENT_PREFIX):
        return None
    tool = event.get("tool_name")
    args = event.get("tool_input") or {}
    cwd = event.get("cwd") or os.getcwd()
    if tool == "Read":
        path = args.get("file_path") or ""
        if path and inside(path, cwd):
            return f"{path} is outside what analysis agents may read (benchmark blindness)."
    elif tool in ("Grep", "Glob"):
        roots = [args.get("path") or cwd]
        if tool == "Glob" and (pattern := args.get("pattern")):
            # An absolute pattern, or one climbing out with `..`, moves the root.
            joined = os.path.join(os.path.expanduser(roots[0]), os.path.expanduser(pattern))
            roots.append(_static_prefix(os.path.normpath(joined)))
        for root in roots:
            if covers(root, cwd):
                return (f"{tool} rooted at {root} could reach paths analysis agents may not "
                        "read (benchmark blindness); search the snapshot by explicit path.")
    return None


def deny_rules() -> list[str]:
    """The protected paths as permission rules (`//` = absolute path)."""
    out = []
    for pat, is_dir in PROTECTED:
        p = pat if pat.startswith("~") else "/" + pat
        out.append(f"Read({p}/**)" if is_dir else f"Read({p})")
    return out


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError) as e:
        # Can't tell who is calling: refuse (exit 2 blocks the call).
        print(f"blind guard: unreadable hook input ({e})", file=sys.stderr)
        return 2
    reason = decide(event)
    if reason:
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": "deny",
                                          "permissionDecisionReason": reason}}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
