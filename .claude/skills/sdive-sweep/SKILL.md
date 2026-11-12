---
name: sdive-sweep
description: Run security-dive sweep runs — sdive-auditor passes over uncovered in-scope code through a single focused lens, a few whole areas per run — and record coverage and hypotheses. Invoke as /sdive-sweep <project> <lens|all> [N|all] [--minutes M] [--parallel P] [--area A] [--rev R] [--ledger X]. Use when the user wants a broad pass over a code base for one class of vulnerability.
argument-hint: "<project> <lens|all> [N|all] [--minutes M] [--parallel P] [--area A] [--rev R] [--ledger main]"
allowed-tools: Bash, Read, Agent, SendMessage
---

You orchestrate **sweep runs**: broad passes through one lens each. A run
takes whole areas in priority order up to a line budget (~3000 lines), so a
lens covers the code base in several runs. The analysis happens in the
`sdive-auditor` subagent.

## Arguments

`<project>`; `<lens>` or `all` (every lens in `projects/<project>/lenses/`
except `holistic`, which is for dives — list them with
`uv run sdive lenses <project>`); a count `N` (default 1) — the total
number of runs to do before stopping, across lenses, which is how the user
bounds the cost of a session; optional `--area`, `--rev`; `--ledger` (default
`main`). Every command is `uv run sdive --ledger <ledger> ...`.
`uv run sdive --ledger <ledger> todo <project>` shows how many runs each lens
has left.

## Before the loop: interrupted runs

A session stopped mid-run leaves runs `started`; their targets stay leased
(skipped by `next`) for 12 hours. Unless the user says another session is
working on this ledger right now, tidy them first:
`uv run sdive --ledger <ledger> runs <project> --status started --limit 0`.
For each one of this skill's kind, run `uv run sdive --ledger <ledger> record <id>`
(the agent may have finished writing its result); if that says there is no
result file, `uv run sdive --ledger <ledger> abandon <id>`.

## For each lens, repeat until it is done or N runs are used

1. `uv run sdive --ledger <ledger> next <project> --kind sweep --lens <lens> [--area A] [--rev R]`
   - Exit status 3: nothing left to sweep under this lens; go to the next lens.
   - Other failure: report and stop.
2. Dispatch the agent named in `agent` with exactly the prompt
   `Brief: <brief_path>` — nothing more.
3. Run `record_command`. On a validation error, SendMessage the error to the same
   agent to fix `result_path`, then record again (at most two rounds); if it still
   fails, `uv run sdive --ledger <ledger> abandon <run_id>`.
4. Print one line: lens, units covered/partial, hypothesis titles.

**Sizing a session:** the user bounds cost with a run count or `--minutes M`
(agent-minutes; roughly proportional to cost, and summed across parallel
runs). For `--minutes`, run `uv run sdive --ledger <ledger> todo <project> --kind sweep --minutes M`
and use the "runs in M min" figure as N; say so in one line before starting.

**Parallel:** `--parallel P` (default 1, at most 4) keeps up to P runs in
flight: start P runs, dispatch their agents in one message so they run
concurrently, record each as it returns, and start the next while the budget
lasts. Leases keep runs from sharing targets; prefer running different lenses side by side (each lens keeps its own coverage), rather than several runs of one lens. Parallelism saves
wall-clock time, not cost.

## Finish

`uv run sdive --ledger <ledger> todo <project>`, then a short summary (runs
done, hypotheses, sweep runs left per lens) and, if there are new hypotheses,
suggest `/sdive-verify`. Stopping is always safe: the next session continues
from the ledger.

## Invariants

- Never write result files, lenses, the threat model or dossiers yourself.
- Never read `analysis/truth/` or any zepsec analysis directory, and never pass
  their contents to an agent.
