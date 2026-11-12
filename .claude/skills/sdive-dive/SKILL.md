---
name: sdive-dive
description: Run security-dive deep-dive analysis runs. Each run takes the uncovered functions of the highest-priority file, has the sdive-auditor subagent examine them in depth, and records coverage and vulnerability hypotheses in the ledger. Invoke as /sdive-dive <project> [N|all] [--minutes M] [--parallel P] [--lens L] [--area A] [--rev R] [--ledger X]. Use when the user wants to deep-dive code for vulnerabilities or work through the dive queue.
argument-hint: "<project> [N|all] [--minutes M] [--parallel P] [--lens holistic] [--area A] [--rev R] [--ledger main]"
allowed-tools: Bash, Read, Agent, SendMessage
---

You orchestrate **dive runs**. The analysis happens in the `sdive-auditor`
subagent; you only start runs, dispatch, record, and summarize. `sdive` is the
only thing that touches the ledger.

## Arguments

`<project>` (required); a count `N` (default 1) or `all` — the number of runs
to do before stopping, which is how the user bounds the cost of a session
(each run is at most one file's worth, ≤600 lines); `--lens` (default
`holistic`); optional `--area`, `--rev` (default: the project's default branch);
`--ledger` (default `main`). Every `sdive` command below is
`uv run sdive --ledger <ledger> ...`, run from the repo root.

## Before the loop: interrupted runs

A session stopped mid-run leaves runs `started`; their targets stay leased
(skipped by `next`) for 12 hours. Unless the user says another session is
working on this ledger right now, tidy them first:
`uv run sdive --ledger <ledger> runs <project> --status started --limit 0`.
For each one of this skill's kind, run `uv run sdive --ledger <ledger> record <id>`
(the agent may have finished writing its result); if that says there is no
result file, `uv run sdive --ledger <ledger> abandon <id>`.

## Loop (repeat N times, or until the queue is empty)

1. **Start a run:**
   `uv run sdive --ledger <ledger> next <project> --kind dive --lens <lens> [--area A] [--rev R]`
   - Exit status 3 means the queue is empty: stop the loop.
   - Any other failure: report the error and stop.
   - On success it prints the brief JSON (also written to `brief_path`). Take
     `run_id`, `brief_path`, `agent`, `record_command`, and the target count.
2. **Dispatch** the agent named in `agent` (the Agent tool, `subagent_type`
   set to it) with exactly this prompt, nothing more:
   `Brief: <brief_path>`
   Do not add hints, prior findings, or your own view of the code.
3. **Record:** run `record_command`.
   - If it reports a validation error, send the error text back to the same
     agent (SendMessage to it) asking it to correct `result_path`, then record
     again. At most two correction rounds.
   - If it still fails, run `uv run sdive --ledger <ledger> abandon <run_id>`
     and note it.
4. Print one line: run id, file, units covered/partial, hypothesis titles.

**Sizing a session:** the user bounds cost with a run count or `--minutes M`
(agent-minutes; roughly proportional to cost, and summed across parallel
runs). For `--minutes`, run `uv run sdive --ledger <ledger> todo <project> --kind dive --lens <lens> --minutes M`
and use the "runs in M min" figure as N; say so in one line before starting.

**Parallel:** `--parallel P` (default 1, at most 4) keeps up to P runs in
flight: start P runs, dispatch their agents in one message so they run
concurrently, record each as it returns, and start the next while the budget
lasts. Leases keep runs from sharing targets, and `next` starts each concurrent dive in an area no other in-flight dive is in (their dossier notes only reach each other once recorded). Parallelism saves
wall-clock time, not cost.

## Finish

Run `uv run sdive --ledger <ledger> todo <project> --lens <lens>` and give a short
summary: runs done, hypotheses raised (titles), anything abandoned, and the
dive runs left. Suggest `/sdive-verify` if there are new hypotheses. Stopping
is always safe: coverage is recorded per run, so the next session picks up
where this one ended.

## Invariants

- Never write or edit result files, lenses, the threat model or dossiers
  yourself. Never record a result on an agent's behalf.
- Never read `analysis/truth/` or any zepsec analysis directory, and never pass
  their contents to an agent.
