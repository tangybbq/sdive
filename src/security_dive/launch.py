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
import sqlite3
import subprocess
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import blind, rank

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
           sweep_runs: Callable[[str], int], sweep_order: Iterable[str],
           spent: Mapping[tuple[str, str | None], float] | None = None,
           sweep_share: float = 0.5,
           dive_left: Callable[[], bool] = lambda: True) -> Plan | None:
    """What to run. Explicit kind wins. Otherwise (auto): verify pending
    hypotheses first; then share the time between sweeps and dives, so both
    breadth (a lens across whole areas) and depth (the best-ranked files)
    advance together. `spent` is the agent-minutes already recorded at this
    snapshot per (kind, lens); the side behind its share (`sweep_share` of
    the total for sweeps) goes next, and among sweep lenses with work left,
    the one with the least time so far (ties: `sweep_order`). None when the
    requested work is already done."""
    if kind == "verify" or (kind is None and pending):
        if not pending:
            return None
        return Plan("verify", None, f"{pending} hypotheses awaiting verification")
    if kind == "dive":
        return Plan("dive", lens, "dives requested")
    lenses = [lens] if lens else list(sweep_order)
    left = {name: n for name in lenses if (n := sweep_runs(name))}
    if kind == "sweep":
        if not left:
            return None
        name = next(iter(left))
        return Plan("sweep", name, f"lens {name}: {left[name]} sweep runs left")
    spent = spent or {}
    sweeps = sum(m for (k, _l), m in spent.items() if k == "sweep")
    dives = sum(m for (k, _l), m in spent.items() if k == "dive")
    total = sweeps + dives
    share = f"sweeps {sweeps:.0f} / dives {dives:.0f} agent-min"
    if left and (sweeps <= sweep_share * total or not dive_left()):
        order = list(left)
        name = min(order, key=lambda n: (spent.get(("sweep", n), 0.0), order.index(n)))
        return Plan("sweep", name, f"{share}; lens {name}: {left[name]} sweep runs left")
    if dive_left():
        return Plan("dive", None, f"{share}; dive next")
    return None


def invocation(plan: Plan, project: str, ledger: str, runs: int | None,
               minutes: float | None, parallel: int, area: str | None = None) -> str:
    """The slash-command prompt for the session. `area` restricts sweeps and
    dives; verification is not per area."""
    parts = [f"/sdive-{plan.kind}", project]
    if plan.kind == "sweep":
        parts.append(plan.lens)
    if minutes:
        parts += ["--minutes", f"{minutes:g}"]
    else:
        parts.append(str(runs or 1))
    if plan.kind == "dive" and plan.lens:
        parts += ["--lens", plan.lens]
    if area and plan.kind in ("sweep", "dive"):
        parts += ["--area", area]
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


# --- ranking without an orchestrator ----------------------------------------
#
# A rank brief needs no judgement to hand out or record, so `sdive rank run`
# drives the ranker agent directly: each brief is one headless `claude -p
# --agent sdive-ranker` session (on the agent's own model), and this loop
# writes briefs, records results and retries a rejected result once by
# resuming the agent's session with the error. No orchestrating model reads
# hundreds of hand-backs.

RANK_TOOLS = ("Read", "Grep", "Glob")


def agent_command(agent: str, prompt: str, staging: Path, model: str | None = None,
                  resume: str | None = None) -> list[str]:
    writable = f"/{staging.resolve()}/**"
    argv = ["claude", "-p", "--agent", agent, "--output-format", "json"]
    if model:
        argv += ["--model", model]
    if resume:
        argv += ["--resume", resume]
    return [*argv, "--disallowedTools", *blind.deny_rules(),
            "--allowedTools", *RANK_TOOLS, f"Write({writable})", "--", prompt]


def run_agent(argv: list[str], env: dict[str, str], cwd: Path, log_path: Path) -> dict | None:
    """Run one headless agent session; save its result JSON to `log_path`.
    Returns the result event, or None if claude printed none."""
    proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        result = None
    log_path.write_text(json.dumps({"exit_status": proc.returncode, "result": result,
                                    "stderr": proc.stderr[-4000:]}, indent=2) + "\n")
    return result


def recover_rank_briefs(conn: sqlite3.Connection, cfg, out=sys.stdout) -> None:
    """Record leftover rank briefs that have a result; drop the rest (which
    releases their functions)."""
    for bpath in sorted(cfg.staging.glob("rank-*.brief.json")):
        brief_id = bpath.name.removeprefix("rank-").removesuffix(".brief.json")
        try:
            n, _ = rank.record(conn, cfg, brief_id)
            print(f"recovered brief {brief_id}: {n} functions", file=out)
        except rank.RankError as e:
            print(f"dropped leftover brief {brief_id}: {str(e).splitlines()[0]}", file=out)
            result = json.loads(bpath.read_text()).get("result_path")
            bpath.unlink()
            if result:
                Path(result).unlink(missing_ok=True)


def rank_loop(conn: sqlite3.Connection, cfg, project, snap: int, limit: int | None,
              parallel: int, min_priority: int, env: dict[str, str],
              model: str | None = None, agent_runner=run_agent, out=sys.stdout,
              area: str | None = None) -> dict:
    """Rank up to `limit` briefs (None: all), `parallel` at a time, of
    `area`'s functions if given. Stops handing out briefs after an agent
    session fails (e.g. a usage limit). Returns totals: briefs, functions,
    failed, cost (as claude reports it)."""
    log_dir = cfg.ledger_dir / "sessions" / "rank"
    totals = {"briefs": 0, "functions": 0, "failed": 0, "shortened": 0, "cost": 0.0}
    pending: dict[Future, tuple[dict, bool]] = {}
    state = {"started": 0, "stop": False}

    def drop(b: dict) -> None:
        Path(b["brief_path"]).unlink(missing_ok=True)
        Path(b["result_path"]).unlink(missing_ok=True)
        totals["failed"] += 1

    with ThreadPoolExecutor(parallel) as ex:
        def start(b: dict, prompt: str, resume: str | None = None) -> None:
            tag = "-retry" if resume else ""
            argv = agent_command(b["agent"], prompt, cfg.staging, model, resume)
            fut = ex.submit(agent_runner, argv, env, cfg.root,
                            log_dir / f"rank-{b['brief_id']}{tag}.json")
            pending[fut] = (b, resume is not None)

        def fill() -> None:
            while (len(pending) < parallel and not state["stop"]
                   and (limit is None or state["started"] < limit)):
                b = rank.write_brief(conn, cfg, project, snap, min_priority=min_priority,
                                     area=area)
                if b is None:
                    state["stop"] = True
                    return
                state["started"] += 1
                start(b, f"Brief: {b['brief_path']}")

        fill()
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for fut in done:
                b, retried = pending.pop(fut)
                res = fut.result() or {}
                totals["cost"] += res.get("total_cost_usd") or 0.0
                name = ", ".join(f["path"].rsplit("/", 1)[-1] for f in b["files"])
                if res.get("is_error") or not res:
                    state["stop"] = True
                    why = res.get("result") or res.get("subtype") or "no result"
                    print(f"✗ {name}: agent session failed ({str(why)[:200]}); "
                          "stopping after the briefs in flight", file=out)
                    drop(b)
                    continue
                try:
                    levels = Counter(u.get("reach") for u in json.loads(
                        Path(b["result_path"]).read_text()).get("units", []))
                except (OSError, ValueError, AttributeError):
                    levels = Counter()
                try:
                    n, cut = rank.record(conn, cfg, b["brief_id"])
                except rank.RankError as e:
                    if not retried and res.get("session_id"):
                        start(b, f"`sdive rank record` rejected your result:\n{e}\n"
                                 f"Fix {b['result_path']} and write it again.",
                              resume=res["session_id"])
                        continue
                    print(f"✗ {name}: {str(e).splitlines()[0]}", file=out)
                    drop(b)
                    continue
                totals["briefs"] += 1
                totals["functions"] += n
                totals["shortened"] += cut
                dist = " ".join(f"{lvl}:{levels.get(lvl, 0)}" for lvl in (3, 2, 1, 0))
                print(f"✓ {name}: {n} functions (reach {dist}) "
                      f"${res.get('total_cost_usd') or 0:.4f}"
                      f"{' after retry' if retried else ''}", file=out, flush=True)
            fill()
    return totals
