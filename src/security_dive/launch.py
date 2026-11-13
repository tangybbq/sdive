"""`sdive run`: launch a Claude Code session that runs one skill.

sdive itself still makes no model calls: this builds a skill invocation (what
to run next, and how much), then starts the `claude` CLI on it in this repo,
headless (`-p`) by default. Progress is streamed (stream-json) and summarised;
the full event stream and the session's reported cost are saved under the
ledger's `sessions/` directory, so cost per run can be calibrated from real
numbers rather than run time.

`ANTHROPIC_API_KEY` is removed from the child's environment unless asked for,
so a session can't silently bill an API account instead of the logged-in plan.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import blind

DEFAULT_MODEL = "claude-mythos-5-2"
# What a headless session may do without asking: the skills' sdive calls,
# reading, subagents, and writing result files in the ledger's staging
# directory (granted per run in `command`) — nothing else is writable. The
# benchmark-blind paths are hard-denied for the whole session (orchestrator
# included), on top of the per-agent hook in .claude/settings.json.
ALLOWED_TOOLS = ("Bash(uv run sdive:*)", "Read", "Grep", "Glob", "Agent", "SendMessage",
                 "Skill")


@dataclass
class Plan:
    kind: str          # dive | sweep | verify
    lens: str | None   # for sweeps (and non-default dive lenses)
    reason: str


def choose(kind: str | None, lens: str | None, pending: int,
           sweep_runs: Callable[[str], int], sweep_order: Iterable[str]) -> Plan | None:
    """What to run. Explicit kind wins; otherwise (auto): verify pending
    hypotheses first, then the first lens in `sweep_order` with sweep work
    left, then dives. None when the requested work is already done."""
    if kind == "verify" or (kind is None and pending):
        if not pending:
            return None
        return Plan("verify", None, f"{pending} hypotheses awaiting verification")
    if kind in (None, "sweep"):
        lenses = [lens] if lens else list(sweep_order)
        for name in lenses:
            if (n := sweep_runs(name)):
                return Plan("sweep", name, f"lens {name}: {n} sweep runs left")
        if kind == "sweep":
            return None
    return Plan("dive", lens if kind == "dive" else None, "sweeps done; dives next"
                if kind is None else "dives requested")


def invocation(plan: Plan, project: str, ledger: str, runs: int | None,
               minutes: float | None, parallel: int) -> str:
    """The slash-command prompt for the session."""
    parts = [f"/sdive-{plan.kind}", project]
    if plan.kind == "sweep":
        parts.append(plan.lens)
    if minutes:
        parts += ["--minutes", f"{minutes:g}"]
    else:
        parts.append(str(runs or 1))
    if plan.kind == "dive" and plan.lens:
        parts += ["--lens", plan.lens]
    if parallel > 1:
        parts += ["--parallel", str(parallel)]
    if ledger != "main":
        parts += ["--ledger", ledger]
    return " ".join(parts)


def command(prompt: str, model: str, headless: bool, staging: Path) -> list[str]:
    argv = ["claude", "--model", model]
    if headless:
        # `//` marks an absolute path in permission rules.
        writable = f"/{staging.resolve()}/**"
        argv += ["-p", "--output-format", "stream-json", "--verbose",
                 "--disallowedTools", *blind.deny_rules(),
                 "--allowedTools", *ALLOWED_TOOLS, f"Write({writable})", f"Edit({writable})",
                 "--"]
    return [*argv, prompt]


def child_env(keep_api_key: bool) -> dict[str, str]:
    env = dict(os.environ)
    if not keep_api_key:
        env.pop("ANTHROPIC_API_KEY", None)
    return env


def describe(event: dict) -> str | None:
    """One progress line for a stream-json event, or None to stay quiet.
    Subagent traffic (parent_tool_use_id set) is suppressed; the orchestrator's
    own text and tool calls are shown."""
    if event.get("parent_tool_use_id"):
        return None
    if event.get("type") == "assistant":
        out = []
        for block in event.get("message", {}).get("content", []):
            if block.get("type") == "text" and block.get("text", "").strip():
                out.append(block["text"].strip())
            elif block.get("type") == "tool_use":
                inp = block.get("input", {})
                what = inp.get("command") or inp.get("prompt") or inp.get("skill") or ""
                out.append(f"→ {block.get('name')}: {str(what).splitlines()[0][:110]}"
                           if what else f"→ {block.get('name')}")
        return "\n".join(out) or None
    if event.get("type") == "result":
        return None
    return None


def summarise(result: dict | None, elapsed: float) -> str:
    if result is None:
        return f"session ended without a result event after {elapsed / 60:.1f} min"
    cost = result.get("total_cost_usd")
    usage = result.get("usage") or {}
    toks = sum(usage.get(k, 0) or 0 for k in (
        "input_tokens", "output_tokens", "cache_creation_input_tokens",
        "cache_read_input_tokens"))
    secs = (result.get("duration_ms") or elapsed * 1000) / 1000
    bits = [f"{result.get('subtype', '?')}",
            f"{secs / 60:.1f} min" if secs >= 60 else f"{secs:.0f} s",
            f"{result.get('num_turns', '?')} turns"]
    if cost is not None:
        bits.append(f"reported cost ${cost:.2f}" if cost >= 1 else f"reported cost ${cost:.4f}")
    if toks:
        bits.append(f"{toks:,} tokens (orchestrator)")
    return ", ".join(bits)


def run(argv: list[str], env: dict[str, str], cwd: Path, log_dir: Path, meta: dict,
        out=sys.stdout) -> int:
    """Run a headless session, streaming progress; save the event log and a
    summary JSON in `log_dir`. Returns claude's exit status."""
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    log_path = log_dir / f"{stamp}.jsonl"
    started = datetime.now(UTC)
    result, last = None, None
    with log_path.open("w") as log, subprocess.Popen(
            argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=None, text=True,
            bufsize=1) as proc:
        for line in proc.stdout:
            log.write(line)
            log.flush()
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(line.rstrip(), file=out, flush=True)
                continue
            if event.get("type") == "result":
                result = event
            if (msg := describe(event)):
                print(msg, file=out, flush=True)
                last = msg
        status = proc.wait()
    elapsed = (datetime.now(UTC) - started).total_seconds()
    final = (result or {}).get("result") or ""
    if final.strip() and final.strip() != (last or "").strip():
        print("\n" + final.strip(), file=out)
    print(f"\n[{summarise(result, elapsed)}; log {log_path}]", file=out)
    summary = {**meta, "started": started.isoformat(timespec="seconds"),
               "elapsed_s": round(elapsed), "exit_status": status,
               "result": {k: v for k, v in (result or {}).items() if k != "result"},
               "log": str(log_path)}
    (log_dir / f"{stamp}.json").write_text(json.dumps(summary, indent=2) + "\n")
    return status
